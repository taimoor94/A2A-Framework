"""The job runner: owns a Verified System Change job end to end, durably.

intake -> (``require_spec_review``: ``awaiting_spec`` until the spec is confirmed) -> plan ->
fail-on-base reproduction -> edit steps (by dependency layer; steps in one repository
serialised in plan order, different repositories in parallel), each an attempt loop of worker
-> candidate commit -> ranked checks -> planner decision -> whole-system checks -> privileged
steps through the gate -> ``accepted``.

Verification never runs in the tree a worker controlled. After the worker, its tree is turned
into a candidate commit (``WorkspaceManager.snapshot``; the diff hash and the ``touched_tests``
flags are taken from it); the ranked checks run in a detached throwaway checkout of that commit
(``verify.verify_step``), with the acceptance files written there only; a passed candidate
becomes the job branch's head (``advance``). The next attempt or step starts from the last
passed commit the store recorded for the repository (else the base), whatever the worker did
to the branch. Whole-system checks run the same way over throwaway checkouts of those commits
(``verify.run_whole``), with the check's whole-system acceptance files written into them; no
acceptance file ever reaches a job branch.

Fail-on-base (spec §7.6 #2): before the first worker attempt of a job, every per-system
acceptance test must FAIL at its system's base (``verify.reproduction_before``) and every
whole-system check with whole-system acceptance tests must FAIL on the bases with the files
written in (``verify.reproduction_before_whole``). A test that passes on base, or whose run is
inconclusive, fails the job with reason ``verification`` before any worker token is spent. Each
result is a ``vsc.check`` audit row (``detail.check = "reproduction_before"``).

Coverage fails closed: a system with nothing that could execute (no gate, no tests, no
acceptance test with a command, no whole-system acceptance test of a check over it) fails the
job (``no checks``) before any worker runs; every
configured whole-system check that names an edited system runs (systems the plan does not
edit get a workspace at their base).

Every attempt is a new ``vsc_steps`` row; an attempt number is never reused, and an attempt
that is cancelled (job cancel, deadline, a failing sibling) is closed ``failed`` with
``{"reason": "interrupted"}``. Interrupted attempts do not count against the step's attempts
budget; they are capped separately at twice it (``budget``, limit ``interrupted``). After a
restart, ``resume_all`` closes attempts a dead process left ``running`` the same way, resets
their worktrees to the last passed commit, and continues each job from its first step that has
not passed; a job whose whole-system checks already passed (``whole_passed``) goes straight
back to its privileged steps. A job that cannot be resumed fails (``resume``); the others go on.

When every whole-system check passed, the heads they ran on are recorded per repository
(``verified_heads_json``); a merge only fast-forwards its target to the verified head, and
only while the job branch still points at it. A merge target is checked again at merge time
(an existing local branch; the system's ``default_branch`` unless listed in
``merge_targets``).

The planner never sees acceptance-test contents: ``plan`` and ``replan`` get ``_planner_view``
of the spec (file names only); failure tails it gets may quote test output. Its usage
(``Planner.usage``, cumulative) is charged to the job after every planner call, like a
worker's, and each of its A2A turns is audited (``vsc.planner``: task id and usage).

Budgets (the tighter of ``cfg.budgets`` and the spec's) are enforced here: tokens and cost after
every worker and planner turn; attempts per step (counted from the step's stored rows, so the
bound holds across whole-system rounds and restarts); the deadline bounds active time
(``vsc_jobs.active_s``: planning, running, verifying), never time awaiting approval or a spec
review. Exceeding one fails the job with reason ``budget``.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import logging
import time
import uuid
from collections.abc import Awaitable, Callable, Coroutine
from contextlib import suppress
from dataclasses import dataclass
from typing import Any

from a2agw.adapters._sidecar import ConsultFn
from a2agw.ops.audit import AuditEvent, AuditLog
from a2agw.ops.bus import EventBus, GatewayEvent
from a2agw.vsc.budget import Budget, BudgetExceeded, RetryPolicy, deadline, stronger, tighter
from a2agw.vsc.config import BudgetConfig, VscConfig
from a2agw.vsc.gate import Gate, Rejected
from a2agw.vsc.plan import (
    DECISION_MAX_CHARS,
    Decision,
    Plan,
    PlanStep,
    order,
    plan_hash,
    validate_plan,
)
from a2agw.vsc.planner import Planner, PlannerError, guard_replan
from a2agw.vsc.spec import REQUEST_MAX_CHARS, ExecutableSpec, spec_hash, validate_against
from a2agw.vsc.store import JobState, StepState, VscStore
from a2agw.vsc.verify import (
    CheckKind,
    CheckResult,
    all_passed,
    executable_checks,
    reproduction_before,
    reproduction_before_whole,
    run_whole,
    verify_step,
)
from a2agw.vsc.workers import WorkerSpec, WorkerTask, run_worker
from a2agw.vsc.workspace import GitError, MergeRefused, Workspace, WorkspaceManager

__all__ = ["Budget", "BudgetExceeded", "JobFailed", "JobRunner", "RetryPolicy"]

log = logging.getLogger(__name__)

_AGENT = "deliver"
CHECK_TIMEOUT_S = 1800.0
TERMINAL_STATES = ("accepted", "failed", "cancelled")
_INTERRUPTED = ("running", "verifying")
_ACTIVE_STATES = ("planning", "running", "verifying")
_INTERRUPTED_RESULT = {"reason": "interrupted"}
# Interrupted attempts of a step are capped at this multiple of its attempts budget.
INTERRUPTED_FACTOR = 2
_EMPTY_SHA = hashlib.sha256(b"").hexdigest()


class JobFailed(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _decision(kind: str, text: str, step_id: str | None = None) -> Decision:
    return Decision(ts=time.time(), step_id=step_id, text=text[:DECISION_MAX_CHARS], kind=kind)  # type: ignore[arg-type]


def _planner_view(spec: ExecutableSpec) -> ExecutableSpec:
    """The spec as the planner sees it after intake: acceptance tests keep their id, system,
    check, run and file *names*; the file contents (the hidden tests) are emptied. The full spec
    is only for verification."""
    return spec.model_copy(
        update={
            "acceptance": [
                t.model_copy(update={"files": dict.fromkeys(t.files, "")}) for t in spec.acceptance
            ]
        }
    )


def _planner_usage(planner: Planner) -> tuple[int, int, float]:
    usage = getattr(planner, "usage", None)
    return usage() if usage is not None else (0, 0, 0.0)


def _planner_turns(planner: Planner) -> list[dict[str, Any]]:
    """The planner's A2A turns so far (``AgentPlanner.turns``): task id and usage each."""
    turns = getattr(planner, "turns", None)
    return list(turns()) if turns is not None else []


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _loads(text: str | None) -> Any:
    return json.loads(text) if text else None


def _interrupted(row: dict[str, Any]) -> bool:
    return _loads(row.get("result_json")) == _INTERRUPTED_RESULT


def _brief(c: CheckResult) -> dict[str, Any]:
    """A check result as audited: no stderr tail."""
    return {
        "kind": c.kind,
        "id": c.id,
        "command": list(c.command),
        "exit_code": c.exit_code,
        "passed": c.passed,
        "duration_s": c.duration_s,
        "log_sha256": c.log_sha256,
        "reason": c.reason,
    }


def _check_failure(kind: CheckKind, id: str, reason: str) -> CheckResult:
    return CheckResult(
        kind=kind,
        id=id,
        command=[],
        exit_code=None,
        passed=False,
        duration_s=0.0,
        log_sha256=_EMPTY_SHA,
        stderr_tail="",
        reason=reason[:512],
    )


def _worker_failure(spec: WorkerSpec, error: str) -> CheckResult:
    return _check_failure("worker", spec.id, f"worker: {error}")


async def _all_or_cancel(coros: list[Coroutine[Any, Any, None]]) -> None:
    """Run concurrently; the first error cancels the rest and is raised."""
    if len(coros) <= 1:
        for c in coros:
            await c
        return
    tasks = [asyncio.ensure_future(c) for c in coros]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    for t in tasks:
        if not t.cancelled() and t.exception() is not None:
            raise t.exception()  # type: ignore[misc]


@dataclass
class _Run:
    job_id: str
    owner: str
    state: str
    planner: Planner
    spec: ExecutableSpec
    plan: Plan
    budget: Budget
    retry: RetryPolicy


class JobRunner:
    def __init__(
        self,
        *,
        store: VscStore,
        workspaces: WorkspaceManager,
        workers: list[WorkerSpec],
        planner_factory: Callable[[str], Planner],
        cfg: VscConfig,
        audit: AuditLog | None,
        bus: EventBus | None,
        consult: ConsultFn | None,
        gate: Gate,
        on_accepted: Callable[[str], Awaitable[None]] | None = None,
        retry: RetryPolicy | None = None,
    ) -> None:
        if not workers:
            raise ValueError("the job runner needs at least one worker")
        self._store = store
        self._ws = workspaces
        self._workers = list(workers)
        self._by_id = {w.id: w for w in workers}
        self._planner_factory = planner_factory
        self._cfg = cfg
        self._systems = {s.id: s for s in cfg.systems}
        self._audit = audit
        self._bus = bus
        self._consult = consult
        self._gate = gate
        self._on_accepted = on_accepted
        self._retry = retry or RetryPolicy()
        self._tasks: dict[str, asyncio.Task[dict[str, Any]]] = {}  # background runs
        self._running: dict[str, asyncio.Task[Any]] = {}  # any run, for cancel
        self._locks: dict[str, asyncio.Lock] = {}
        self._cancelled: set[str] = set()
        self._active_since: dict[str, float] = {}  # job id -> loop time it became active
        # job id -> the planner's cumulative usage when last charged
        self._planner_seen: dict[str, tuple[int, int, float]] = {}
        # job id -> how many of the planner's turns are audited already
        self._turns_seen: dict[str, int] = {}

    # -- public API ----------------------------------------------------------------------

    @property
    def tasks(self) -> dict[str, asyncio.Task[dict[str, Any]]]:
        """Background runs still in progress, by job id."""
        return dict(self._tasks)

    async def submit(self, request: str, *, owner: str, context_id: str | None = None) -> str:
        if len(request) > REQUEST_MAX_CHARS:
            raise ValueError(f"request longer than {REQUEST_MAX_CHARS} characters")
        job_id = uuid.uuid4().hex
        await self._store.create_job(job_id, request, owner, context_id=context_id)
        await self._transition(job_id, "submitted", actor=owner)
        return job_id

    def start(self, job_id: str) -> asyncio.Task[dict[str, Any]]:
        """Run the job in the background (once); the task's result is the final job row."""
        task = self._tasks.get(job_id)
        if task is not None and not task.done():
            return task
        task = asyncio.create_task(self.run(job_id), name=f"vsc-job-{job_id}")
        self._tasks[job_id] = task

        def forget(done: asyncio.Task[Any]) -> None:
            if self._tasks.get(job_id) is done:
                del self._tasks[job_id]

        task.add_done_callback(forget)
        return task

    async def resume_all(self) -> list[str]:
        """Resume every unfinished job; one that cannot be resumed (its workspace is gone,
        git fails, ...) is failed with reason ``resume`` and the others still resume."""
        resumed: list[str] = []
        for job_id in await self._store.resumable():
            if job_id in self._tasks or job_id in self._running:
                continue
            try:
                await self._discard_interrupted(job_id)
            except Exception:
                log.exception("vsc job %s: cannot be resumed", job_id)
                with suppress(Exception):
                    await self._fail(job_id, "resume")
                continue
            self.start(job_id)
            resumed.append(job_id)
        return resumed

    def repo_id(self, system_id: str) -> str:
        """The repository id (workspace, ``verified_heads_json`` key) of a system."""
        return self._ws.repo_id(system_id)

    async def job_for_task(self, task_id: str) -> str | None:
        """The unfinished job the A2A task ``task_id`` currently follows, if any."""
        job = await self._store.job_for_task(task_id)
        return job["job_id"] if job is not None and job["state"] not in TERMINAL_STATES else None

    async def cancel(self, job_id: str, *, actor: str) -> None:
        job = await self._store.get_job(job_id)
        if job is None:
            raise KeyError(job_id)
        if job["state"] in TERMINAL_STATES:
            return
        self._cancelled.add(job_id)
        await self._transition(job_id, "cancelled", actor=actor)
        task = self._running.get(job_id)
        if task is not None and not task.done() and task is not asyncio.current_task():
            task.cancel()

    async def aclose(self) -> None:
        """Stop the background runs (their jobs stay resumable)."""
        tasks = list(self._tasks.values())
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    async def run(self, job_id: str) -> dict[str, Any]:
        async with self._locks.setdefault(job_id, asyncio.Lock()):
            current = asyncio.current_task()
            if current is not None:
                self._running[job_id] = current
            try:
                return await self._run(job_id)
            finally:
                self._running.pop(job_id, None)

    # -- the job -------------------------------------------------------------------------

    async def _run(self, job_id: str) -> dict[str, Any]:
        job = await self._store.get_job(job_id)
        if job is None:
            raise KeyError(job_id)
        if job["state"] in TERMINAL_STATES:
            return job
        planner = self._planner_factory(job_id)
        self._planner_seen[job_id] = _planner_usage(planner)
        self._turns_seen[job_id] = len(_planner_turns(planner))
        try:
            await self._drive(job, planner)
        except asyncio.CancelledError:
            current = asyncio.current_task()
            if job_id not in self._cancelled or current is None:
                raise
            current.uncancel()
        except BudgetExceeded as e:
            log.info("vsc job %s: budget exceeded (%s)", job_id, e.what)
            await self._fail(job_id, "budget", limit=e.what)
        except Rejected:
            await self._fail(job_id, "rejected")
        except JobFailed as e:
            await self._fail(job_id, e.reason)
        except Exception:
            log.exception("vsc job %s failed", job_id)
            await self._fail(job_id, "error")
        finally:
            self._planner_seen.pop(job_id, None)
            self._turns_seen.pop(job_id, None)
            with suppress(Exception):
                await self._tick(job_id, keep=False)
            aclose = getattr(planner, "aclose", None)
            if aclose is not None:
                with suppress(Exception):
                    await aclose()
        row = await self._store.get_job(job_id)
        assert row is not None
        return row

    @staticmethod
    def _budget(job: dict[str, Any], cfg: BudgetConfig, start: float) -> Budget:
        """``start`` is the loop time this run began; the job's earlier active time counts."""
        return Budget.from_config(
            cfg,
            deadline=start + cfg.deadline_s - job["active_s"],
            used_tokens=job["tokens_in"] + job["tokens_out"],
            used_cost=job["cost"],
        )

    async def _drive(self, job: dict[str, Any], planner: Planner) -> None:
        job_id, cfg = job["job_id"], self._cfg
        state = job["state"]
        start = asyncio.get_running_loop().time()
        if state in _ACTIVE_STATES:
            self._active_since[job_id] = start
        budget = self._budget(job, cfg.budgets, start)
        async with deadline(budget.deadline):
            if job["spec_json"]:
                spec = ExecutableSpec.model_validate_json(job["spec_json"])
            else:
                state = await self._move(job_id, state, "planning")
                try:
                    spec = await planner.intake(job["request"], cfg.systems, cfg.checks)
                    # the receipt's request is the caller's, verbatim, never a rewording
                    spec = spec.model_copy(update={"request": job["request"]})
                    validate_against(spec, cfg)
                except (PlannerError, ValueError) as e:
                    log.warning("vsc job %s: intake failed: %s", job_id, e)
                    await self._charge_planner(job_id, planner, None)
                    raise JobFailed("planner") from e
                await self._charge_planner(job_id, planner, budget)
                await self._store.set_spec(job_id, spec)
                if cfg.require_spec_review:
                    # paused until the spec is confirmed (``PUT .../spec`` starts it again)
                    await self._transition(job_id, "awaiting_spec", spec_hash=spec_hash(spec))
                    return
            limits = tighter(cfg.budgets, spec.budgets)
            budget = dataclasses.replace(  # keep what this run has charged so far
                self._budget(job, limits, start),
                used_tokens=budget.used_tokens,
                used_cost=budget.used_cost,
            )
            budget.charge(0, 0, 0.0)  # the spec's limits may be tighter
            if job["plan_json"]:
                plan = Plan.model_validate_json(job["plan_json"])
            else:
                state = await self._move(job_id, state, "planning")
                try:
                    plan = await planner.plan(_planner_view(spec))
                    validate_plan(plan, spec, cfg)
                except (PlannerError, ValueError) as e:
                    log.warning("vsc job %s: planning failed: %s", job_id, e)
                    await self._charge_planner(job_id, planner, None)
                    raise JobFailed("planner") from e
                await self._charge_planner(job_id, planner, budget)
                plan.decisions.append(_decision("plan", f"{len(plan.steps)} steps"))
                await self._save_plan(job_id, plan)
            for seq, step in enumerate(plan.steps):  # idempotent
                await self._store.add_step(job_id, step.model_dump(mode="json"), seq)
        retry = dataclasses.replace(self._retry, max_attempts=limits.attempts)
        ctx = _Run(job_id, job["owner"], state, planner, spec, plan, budget, retry)
        if not job["whole_passed"]:  # else: everything up to the gate is done already
            async with deadline(budget.deadline):
                await self._move_ctx(ctx, "running")
                await self._prepare(ctx, fresh=job["attempts"] == 0)
                await self._run_edits(ctx)
                await self._move_ctx(ctx, "verifying")
                await self._whole_system(ctx)
        await self._privileged(ctx)
        await self._move_ctx(ctx, "accepted")
        if self._on_accepted is not None:
            try:
                await self._on_accepted(job_id)
            except Exception:
                log.exception("vsc job %s: on_accepted hook failed", job_id)

    # -- before the first worker ---------------------------------------------------------

    def _edited(self, ctx: _Run) -> list[str]:
        return [s.system for s in ctx.plan.steps if s.kind == "edit"]

    def _whole_checks(self, ctx: _Run) -> list[Any]:
        """Every configured whole-system check that names an edited system."""
        edited = set(self._edited(ctx))
        return [c for c in self._cfg.checks if set(c.systems) & edited]

    async def _workspace(self, job_id: str, system_id: str) -> Workspace:
        ws = await self._ws.create(job_id, system_id)
        await self._store.set_base_ref(job_id, ws.repo_id, ws.base_ref)
        return ws

    async def _prepare(self, ctx: _Run, *, fresh: bool) -> None:
        """Fail closed before any worker runs: every edited system must have a check that can
        execute; and (``fresh``: no worker attempt yet) every acceptance test must fail on the
        base (``JobFailed("verification")`` otherwise)."""
        for sid in self._edited(ctx):
            if not executable_checks(self._systems[sid], ctx.spec, self._cfg.checks):
                log.warning("vsc job %s: system %s has no executable check", ctx.job_id, sid)
                raise JobFailed("no checks")
        if not fresh:
            return
        loop = asyncio.get_running_loop()
        for test in ctx.spec.acceptance:
            if test.system is None:
                continue
            ws = await self._workspace(ctx.job_id, test.system)
            timeout = min(CHECK_TIMEOUT_S, max(1.0, ctx.budget.deadline - loop.time()))
            res = await reproduction_before(
                self._ws, ws, test, self._systems[test.system], timeout_s=timeout
            )
            await self._job_check(ctx.job_id, "reproduction_before", res, system=test.system)
            if not res.passed:
                raise JobFailed("verification")
        for check in self._whole_checks(ctx):
            wss = {sid: await self._workspace(ctx.job_id, sid) for sid in check.systems}
            timeout = min(check.timeout_s, max(1.0, ctx.budget.deadline - loop.time()))
            whole = await reproduction_before_whole(
                self._ws, check, wss, ctx.spec.acceptance, timeout_s=timeout
            )
            if whole is None:
                continue
            await self._job_check(ctx.job_id, "reproduction_before", whole)
            if not whole.passed:
                raise JobFailed("verification")

    # -- edit steps ----------------------------------------------------------------------

    async def _rows(self, job_id: str) -> dict[str, dict[str, Any]]:
        return {r["step_id"]: r for r in await self._store.steps(job_id)}

    async def _run_edits(self, ctx: _Run) -> None:
        rows = await self._rows(ctx.job_id)
        for layer in order(ctx.plan):
            groups: dict[str, list[PlanStep]] = {}
            for step in layer:
                if step.kind != "edit" or rows[step.id]["state"] == "passed":
                    continue
                ws = await self._workspace(ctx.job_id, step.system)
                groups.setdefault(ws.repo_id, []).append(step)  # plan order within a repo

            async def serial(steps: list[PlanStep]) -> None:
                for s in steps:
                    await self._run_step(ctx, s.id)

            await _all_or_cancel([serial(steps) for steps in groups.values()])

    async def _attempt_counts(self, job_id: str, step_id: str) -> tuple[int, int]:
        """(attempts that count against the budget, interrupted attempts) of a step so far."""
        rows = [
            r
            for r in await self._store.attempts(job_id)
            if r["step_id"] == step_id and r["attempt"] > 0
        ]
        interrupted = sum(1 for r in rows if _interrupted(r))
        return len(rows) - interrupted, interrupted

    async def _verified_base(self, job_id: str, ws: Workspace) -> str:
        """The repository's last passed commit in this job (the store's record, whatever a
        worker did to the branch), else the workspace's base."""
        best: tuple[float, str] | None = None
        for r in await self._store.attempts(job_id):
            if r["kind"] != "edit" or r["state"] != "passed":
                continue
            if self._ws.repo_id(r["system"]) != ws.repo_id:
                continue
            commit = (_loads(r["result_json"]) or {}).get("commit")
            if isinstance(commit, str) and (best is None or (r["ended_at"] or 0.0) >= best[0]):
                best = (r["ended_at"] or 0.0, commit)
        return best[1] if best is not None else ws.base_ref

    async def _run_step(
        self,
        ctx: _Run,
        step_id: str,
        *,
        failure: CheckResult | None = None,
        escalate: bool = False,
    ) -> None:
        """The attempt loop of one edit step: returns when an attempt passed. The step's
        attempts so far are read from the store, so its bound holds across calls and restarts;
        interrupted attempts are counted apart (``INTERRUPTED_FACTOR``)."""
        loop = asyncio.get_running_loop()
        row = (await self._rows(ctx.job_id))[step_id]
        first = next(s for s in ctx.plan.steps if s.id == step_id)
        system = self._systems[first.system]
        ws = await self._workspace(ctx.job_id, system.id)
        current = self._by_id.get(row["worker"] or "", self._workers[0])
        if escalate:
            current = stronger(self._workers, current)
        attempt, limit = row["attempt"], ctx.retry.max_attempts
        counted, interrupted = await self._attempt_counts(ctx.job_id, step_id)
        while True:
            if counted >= limit:
                raise BudgetExceeded("attempts")
            if interrupted >= INTERRUPTED_FACTOR * limit:
                raise BudgetExceeded("interrupted")
            step = next(s for s in ctx.plan.steps if s.id == step_id)  # a replan may reword it
            ctx.budget.check_deadline(loop.time())
            await self._store.add_attempt(ctx.job_id)
            attempt += 1
            base = await self._verified_base(ctx.job_id, ws)
            await self._ws.reset(ws, base)  # start from the last passed step, nothing else
            await self._store.start_attempt(ctx.job_id, step_id, attempt, current.id, str(ws.path))
            closed = False
            try:
                task = WorkerTask(
                    job_id=ctx.job_id,
                    step_id=step_id,
                    attempt=attempt,
                    system=system,
                    spec=ctx.spec,
                    step=step,
                    failure=failure,
                )
                res = await run_worker(
                    current, task, ws, consult=self._consult, audit=self._audit, actor=ctx.owner
                )
                own = dataclasses.replace(ws, base_ref=base)  # this attempt's change only
                # The candidate (and its diff hash) is taken from the worker's tree before any
                # check runs; the checks run in a throwaway checkout of it.
                candidate = await self._ws.snapshot(
                    own, f"vsc {ctx.job_id}: {step_id} (attempt {attempt})"
                )
                result: dict[str, Any] = {
                    "base": base,
                    "candidate": candidate,
                    "diff_sha256": _sha256(await self._ws.diff_commits(own, base, candidate)),
                    "touched_tests": await self._ws.touched_tests(own, base, candidate),
                }
                if res.failed is not None:
                    checks = [_worker_failure(current, res.failed)]
                else:
                    timeout = min(CHECK_TIMEOUT_S, max(1.0, ctx.budget.deadline - loop.time()))
                    checks = await verify_step(
                        own,
                        system,
                        ctx.spec,
                        manager=self._ws,
                        timeout_s=timeout,
                        candidate=candidate,
                        whole_covered=not executable_checks(system, ctx.spec),
                    )
                passed = all_passed(checks)
                result["checks"] = [dataclasses.asdict(c) for c in checks]
                if passed:
                    result["commit"] = await self._ws.advance(ws, candidate)
                usage = {
                    "tokens_in": res.tokens_in,
                    "tokens_out": res.tokens_out,
                    "cost": res.cost,
                    "usage_reported": res.usage_reported,
                }
                await self._store.end_attempt(
                    ctx.job_id, step_id, attempt, "passed" if passed else "failed", result, usage
                )
                closed = True
            finally:
                if not closed:
                    await self._close_interrupted(ctx.job_id, step_id, attempt)
            counted += 1
            await self._tick(ctx.job_id)
            await self._audit_check(ctx.job_id, checks, passed, step=step_id, attempt=attempt)
            await self._store.add_usage(ctx.job_id, res.tokens_in, res.tokens_out, res.cost)
            ctx.budget.charge(res.tokens_in, res.tokens_out, res.cost)
            if passed:
                return
            if counted >= limit:  # no planner turn for an attempt that cannot happen
                raise BudgetExceeded("attempts")
            failure = next(c for c in checks if not c.passed)
            d = await self._replan(ctx, failure, step_id)
            await self._record(ctx, d)
            if d.kind == "stop":
                raise JobFailed("verification")
            if d.kind == "escalate":
                current = stronger(self._workers, current)
            else:
                current = ctx.retry.next_worker(self._workers, counted, current)

    async def _close_interrupted(self, job_id: str, step_id: str, attempt: int) -> None:
        """Close an attempt that was cancelled before it could finish."""
        with suppress(Exception):
            await self._store.end_attempt(
                job_id, step_id, attempt, "failed", _INTERRUPTED_RESULT, {}
            )

    # -- planner decisions ---------------------------------------------------------------

    async def _replan(self, ctx: _Run, failure: CheckResult, step_id: str | None) -> Decision:
        steps = [
            {k: r[k] for k in ("step_id", "system", "kind", "attempt", "state", "worker")}
            for r in await self._store.steps(ctx.job_id)
        ]
        try:
            d = await ctx.planner.replan(_planner_view(ctx.spec), ctx.plan, failure, steps)
        except (PlannerError, ValueError) as e:
            log.warning("vsc job %s: replan failed: %s", ctx.job_id, e)
            await self._charge_planner(ctx.job_id, ctx.planner, None)
            raise JobFailed("planner") from e
        await self._charge_planner(ctx.job_id, ctx.planner, ctx.budget)
        d = guard_replan(ctx.plan, d)
        if d.step_id is None and step_id is not None:
            d = d.model_copy(update={"step_id": step_id})
        return d

    async def _charge_planner(self, job_id: str, planner: Planner, budget: Budget | None) -> None:
        """Record the planner's usage since the last charge on the job and (unless ``budget`` is
        None: the call failed anyway) charge it to the budget."""
        now = _planner_usage(planner)
        i0, o0, c0 = self._planner_seen.get(job_id, (0, 0, 0.0))
        self._planner_seen[job_id] = now
        di, do, dc = now[0] - i0, now[1] - o0, now[2] - c0
        if di or do or dc:
            await self._store.add_usage(job_id, di, do, dc)
        await self._audit_turns(job_id, planner)
        if budget is not None:
            budget.charge(di, do, dc)

    async def _audit_turns(self, job_id: str, planner: Planner) -> None:
        """One ``vsc.planner`` row per planner A2A turn not audited yet (task id, usage)."""
        turns = _planner_turns(planner)
        seen = self._turns_seen.get(job_id, 0)
        self._turns_seen[job_id] = len(turns)
        if self._audit is None:
            return
        for turn in turns[seen:]:
            await self._audit.emit(
                AuditEvent(
                    actor="system",
                    action="vsc.planner",
                    agent_id=_AGENT,
                    task_id=job_id,
                    outcome="turn",
                    detail={k: turn.get(k) for k in ("task_id", "tokens_in", "tokens_out", "cost")},
                )
            )

    async def _record(self, ctx: _Run, d: Decision) -> None:
        """Append to the decision log; an accepted replan's plan replaces the stored plan."""
        if d.kind == "replan" and d.plan is not None:
            validate_plan(d.plan, ctx.spec, self._cfg)
            logged = d.model_copy(update={"plan": None})
            ctx.plan = d.plan.model_copy(update={"decisions": [*ctx.plan.decisions, logged]})
        else:
            ctx.plan.decisions.append(d)
        await self._save_plan(ctx.job_id, ctx.plan)

    async def _save_plan(self, job_id: str, plan: Plan) -> None:
        await self._store.set_plan(job_id, plan.model_dump(mode="json"), plan_hash(plan))

    # -- whole-system checks -------------------------------------------------------------

    async def _verified_heads(self, ctx: _Run) -> dict[str, str]:
        """Repository id -> last passed commit (else base) of every repository the job edits
        or a whole-system check of it names."""
        sids = {*self._edited(ctx), *(sid for c in self._whole_checks(ctx) for sid in c.systems)}
        heads: dict[str, str] = {}
        for sid in sorted(sids):
            ws = await self._workspace(ctx.job_id, sid)
            if ws.repo_id not in heads:
                heads[ws.repo_id] = await self._verified_base(ctx.job_id, ws)
        return heads

    async def _whole_system(self, ctx: _Run) -> None:
        loop = asyncio.get_running_loop()
        checks = self._whole_checks(ctx)
        rounds = 0
        while True:
            failed = None
            heads = await self._verified_heads(ctx)
            for check in checks:
                wss: dict[str, Workspace] = {
                    sid: await self._workspace(ctx.job_id, sid) for sid in check.systems
                }
                timeout = min(check.timeout_s, max(1.0, ctx.budget.deadline - loop.time()))
                # over throwaway checkouts of the verified heads, with the check's whole-system
                # acceptance files written into them (never into the job's workspaces)
                res = await run_whole(
                    self._ws, check, wss, heads, ctx.spec.acceptance, timeout_s=timeout
                )
                await self._job_check(ctx.job_id, "whole_system", res, heads=heads)
                if not res.passed:
                    failed = (check, res)
                    break
            if failed is None:
                await self._store.set_verified_heads(ctx.job_id, heads)
                await self._store.set_whole_passed(ctx.job_id, True)
                return
            check, res = failed
            rounds += 1
            if rounds >= ctx.retry.max_attempts:
                d = _decision("stop", f"whole-system check {check.id} failed {rounds} times")
            else:
                d = await self._replan(ctx, res, None)
            await self._record(ctx, d)
            if d.kind == "stop":
                raise JobFailed("whole_system")
            await self._move_ctx(ctx, "running")
            for layer in order(ctx.plan):
                for step in layer:
                    if step.kind == "edit" and step.system in check.systems:
                        await self._run_step(
                            ctx, step.id, failure=res, escalate=d.kind == "escalate"
                        )
            await self._move_ctx(ctx, "verifying")

    # -- privileged steps ----------------------------------------------------------------

    async def _privileged(self, ctx: _Run) -> None:
        rows = await self._rows(ctx.job_id)
        for layer in order(ctx.plan):
            for step in layer:
                if step.kind == "edit" or rows[step.id]["state"] == "passed":
                    continue
                await self._privileged_step(ctx, step, rows[step.id]["attempt"] + 1)

    async def _privileged_step(self, ctx: _Run, step: PlanStep, attempt: int) -> None:
        job_id = ctx.job_id
        ws = await self._workspace(job_id, step.system)
        await self._store.start_attempt(job_id, step.id, attempt, "gate", str(ws.path))
        closed = False

        async def close(state: StepState, result: dict[str, Any]) -> None:
            nonlocal closed
            await self._store.end_attempt(job_id, step.id, attempt, state, result, {})
            closed = True

        try:
            auto = self._cfg.auto_approved(step.system, step.kind, step.target_branch)
            if not auto and not await self._gate.already_approved(job_id, step.id):
                await self._move_ctx(ctx, "awaiting_approval")
            try:
                approval = await self._gate.wait(job_id, step)
            except Rejected as e:
                await close("failed", {"rejected": True, "note": e.note})
                raise
            result: dict[str, Any] = {"approval": dataclasses.asdict(approval), "executed": False}
            if step.kind == "merge":
                assert step.target_branch is not None
                job = await self._store.get_job(job_id)
                heads = (_loads(job["verified_heads_json"]) if job else None) or {}
                expected = heads.get(ws.repo_id)
                result.update(target_branch=step.target_branch, verified_head=expected)
                try:
                    if expected is None:
                        raise MergeRefused(f"no verified head for repository {ws.repo_id}")
                    if not self._cfg.merge_target_allowed(step.system, step.target_branch):
                        raise MergeRefused(f"merge target {step.target_branch!r} not allowed")
                    result["head"] = await self._ws.merge_ff(
                        ws, step.target_branch, expected_head=expected
                    )
                except MergeRefused as e:
                    await close("failed", {**result, "reason": str(e)})
                    raise JobFailed("merge_refused") from e
                result["executed"] = True
            await close("passed", result)
        finally:
            if not closed:
                await self._close_interrupted(job_id, step.id, attempt)

    # -- resume --------------------------------------------------------------------------

    async def _discard_interrupted(self, job_id: str) -> None:
        for row in await self._store.steps(job_id):
            if row["state"] not in _INTERRUPTED:
                continue
            if row["kind"] == "edit":
                ws = await self._ws.create(job_id, row["system"])
                if not ws.path.is_dir():
                    raise GitError(f"workspace {ws.path} is gone")
                # keep the passed steps' commits (the store's record), drop the half-done edit
                await self._ws.reset(ws, await self._verified_base(job_id, ws))
            await self._store.end_attempt(
                job_id, row["step_id"], row["attempt"], "failed", _INTERRUPTED_RESULT, {}
            )
            if self._audit is not None:
                await self._audit.emit(
                    AuditEvent(
                        actor="system",
                        action="vsc.step",
                        agent_id=_AGENT,
                        task_id=job_id,
                        outcome="discarded",
                        detail={"step": row["step_id"], "attempt": row["attempt"]},
                    )
                )

    # -- state, audit, events ------------------------------------------------------------

    async def _move(self, job_id: str, current: str, state: JobState) -> str:
        if current != state:
            await self._transition(job_id, state)
        return state

    async def _move_ctx(self, ctx: _Run, state: JobState) -> None:
        ctx.state = await self._move(ctx.job_id, ctx.state, state)

    async def _tick(self, job_id: str, *, keep: bool = True) -> None:
        """Bank the active time since the job last became active (or was last ticked)."""
        since = self._active_since.pop(job_id, None)
        if since is None:
            return
        now = asyncio.get_running_loop().time()
        if keep:
            self._active_since[job_id] = now
        await self._store.add_active(job_id, now - since)

    async def _fail(self, job_id: str, reason: str, *, limit: str | None = None) -> None:
        await self._transition(job_id, "failed", reason=reason, limit=limit)

    async def _transition(
        self,
        job_id: str,
        state: JobState,
        *,
        reason: str | None = None,
        limit: str | None = None,
        actor: str = "system",
        spec_hash: str | None = None,
    ) -> None:
        if job_id in self._cancelled and state != "cancelled":
            return  # a cancelled job never changes state again
        now = asyncio.get_running_loop().time()
        since = self._active_since.pop(job_id, None)
        if state in _ACTIVE_STATES:
            self._active_since[job_id] = now
        active = now - since if since is not None else 0.0
        await self._store.set_state(job_id, state, reason=reason, active_s=active)
        detail: dict[str, Any] = {}
        if reason:
            detail["reason"] = reason
        if limit:
            detail["limit"] = limit
        if spec_hash:
            detail["spec_hash"] = spec_hash
        if self._audit is not None:
            await self._audit.emit(
                AuditEvent(
                    actor=actor,
                    action="vsc.job",
                    agent_id=_AGENT,
                    task_id=job_id,
                    outcome=state,
                    detail=detail,
                )
            )
        if self._bus is not None:
            data: dict[str, Any] = {"job_id": job_id, "state": state, "reason": reason}
            if spec_hash:
                data["spec_hash"] = spec_hash
            self._bus.publish(GatewayEvent(kind="vsc.job", agent_id=_AGENT, data=data))

    async def _append(self, ev: AuditEvent) -> int | None:
        """Append an audit row and return its seq; like ``emit``, never raises (None)."""
        if self._audit is None:
            return None
        try:
            return await self._audit.append(ev)
        except Exception as exc:  # noqa: BLE001 - audit must not break the job
            self._audit.audit_errors += 1
            log.warning("audit append failed for %s: %s", ev.action, type(exc).__name__)
            return None

    async def _job_check(
        self,
        job_id: str,
        check: str,
        res: CheckResult,
        *,
        system: str | None = None,
        heads: dict[str, str] | None = None,
    ) -> None:
        """A job-level check (``check``: ``reproduction_before`` or ``whole_system``): one
        ``vsc.check`` row (exit code and log hash, never output) and the full result in the
        job's ``checks_json``, citing the row's seq."""
        detail: dict[str, Any] = {
            "check": check,
            "check_id": res.id,
            "exit_code": res.exit_code,
            "log_sha256": res.log_sha256,
            "reason": f"{res.kind}:{res.id}" + (f": {res.reason}" if res.reason else ""),
        }
        seq = await self._append(
            AuditEvent(
                actor="system",
                action="vsc.check",
                agent_id=_AGENT,
                task_id=job_id,
                outcome="passed" if res.passed else "failed",
                detail=detail,
            )
        )
        entry = {
            "check": check,
            **_brief(res),
            "outcome": "passed" if res.passed else "failed",
            "system": system,
            "audit_seq": seq,
        }
        if heads is not None:
            entry["heads"] = dict(heads)
        await self._store.add_check(job_id, entry)

    async def _audit_check(
        self,
        job_id: str,
        checks: list[CheckResult],
        passed: bool,
        *,
        step: str,
        attempt: int,
    ) -> None:
        """One ``vsc.check`` row for a step attempt's ranked checks."""
        if self._audit is None:
            return
        bad = next((c for c in checks if not c.passed), None)
        detail: dict[str, Any] = {"step": step, "attempt": attempt}
        last = bad or (checks[-1] if checks else None)
        if last is not None:
            detail["reason"] = f"{last.kind}:{last.id}" + (f": {last.reason}" if bad else "")
        await self._audit.emit(
            AuditEvent(
                actor="system",
                action="vsc.check",
                agent_id=_AGENT,
                task_id=job_id,
                outcome="passed" if passed else "failed",
                detail=detail,
            )
        )
