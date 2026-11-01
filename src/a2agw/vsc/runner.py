"""The job runner: owns a Verified System Change job end to end, durably.

intake -> plan -> edit steps (by dependency layer; steps in one repository serialised in plan
order, different repositories in parallel), each an attempt loop of worker -> ranked checks ->
planner decision -> whole-system checks -> privileged steps through the gate -> ``accepted``.

Every attempt is a new ``vsc_steps`` row; an attempt number is never reused. A passed edit step
is committed on the job branch of its repository, so later steps (and a resumed job) start from
it and verify only their own change. After a restart, ``resume_all`` closes interrupted attempts
(``failed``, ``{"reason": "interrupted"}``), discards or cleans their half-done worktrees and
continues each job from its first step that has not passed.

Budgets (the tighter of ``cfg.budgets`` and the spec's) are enforced here: tokens and cost after
every worker and planner turn, attempts before every worker attempt, the deadline (measured from
the job's creation) around everything but human approval waits. Exceeding one fails the job with
reason ``budget``.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
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
    load_plan,
    order,
    plan_hash,
    validate_plan,
)
from a2agw.vsc.planner import Planner, PlannerError, guard_replan
from a2agw.vsc.spec import REQUEST_MAX_CHARS, ExecutableSpec, validate_against
from a2agw.vsc.store import JobState, VscStore
from a2agw.vsc.verify import CheckResult, all_passed, verify_step, verify_whole
from a2agw.vsc.workers import WorkerSpec, WorkerTask, run_worker
from a2agw.vsc.workspace import MergeRefused, Workspace, WorkspaceManager

__all__ = ["Budget", "BudgetExceeded", "JobFailed", "JobRunner", "RetryPolicy"]

log = logging.getLogger(__name__)

_AGENT = "deliver"
CHECK_TIMEOUT_S = 1800.0
TERMINAL_STATES = ("accepted", "failed", "cancelled")
_INTERRUPTED = ("running", "verifying")
_EMPTY_SHA = hashlib.sha256(b"").hexdigest()


class JobFailed(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _decision(kind: str, text: str, step_id: str | None = None) -> Decision:
    return Decision(ts=time.time(), step_id=step_id, text=text[:DECISION_MAX_CHARS], kind=kind)  # type: ignore[arg-type]


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _worker_failure(spec: WorkerSpec, error: str) -> CheckResult:
    return CheckResult(
        kind="worker",
        id=spec.id,
        command=[],
        exit_code=None,
        passed=False,
        duration_s=0.0,
        log_sha256=_EMPTY_SHA,
        stderr_tail="",
        reason=f"worker: {error}"[:512],
    )


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

    # -- public API ----------------------------------------------------------------------

    @property
    def tasks(self) -> dict[str, asyncio.Task[dict[str, Any]]]:
        """Background runs still in progress, by job id."""
        return dict(self._tasks)

    async def submit(self, request: str, *, owner: str) -> str:
        if len(request) > REQUEST_MAX_CHARS:
            raise ValueError(f"request longer than {REQUEST_MAX_CHARS} characters")
        job_id = uuid.uuid4().hex
        await self._store.create_job(job_id, request, owner)
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
        resumed: list[str] = []
        for job_id in await self._store.resumable():
            if job_id in self._tasks or job_id in self._running:
                continue
            await self._discard_interrupted(job_id)
            self.start(job_id)
            resumed.append(job_id)
        return resumed

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
            aclose = getattr(planner, "aclose", None)
            if aclose is not None:
                with suppress(Exception):
                    await aclose()
        row = await self._store.get_job(job_id)
        assert row is not None
        return row

    def _budget(self, job: dict[str, Any], cfg: BudgetConfig) -> Budget:
        elapsed = max(0.0, time.time() - job["created_at"])
        return Budget.from_config(
            cfg,
            deadline=asyncio.get_running_loop().time() + cfg.deadline_s - elapsed,
            used_tokens=job["tokens_in"] + job["tokens_out"],
            used_cost=job["cost"],
            used_attempts=job["attempts"],
        )

    async def _drive(self, job: dict[str, Any], planner: Planner) -> None:
        job_id, cfg = job["job_id"], self._cfg
        state = job["state"]
        budget = self._budget(job, cfg.budgets)
        async with deadline(budget.deadline):
            if job["spec_json"]:
                spec = ExecutableSpec.model_validate_json(job["spec_json"])
            else:
                state = await self._move(job_id, state, "planning")
                try:
                    spec = await planner.intake(job["request"], cfg.systems, cfg.checks)
                    validate_against(spec, cfg)
                except (PlannerError, ValueError) as e:
                    log.warning("vsc job %s: intake failed: %s", job_id, e)
                    raise JobFailed("planner") from e
                budget.charge(0, 0, 0.0)  # planner usage is not reported to the runner
                await self._store.set_spec(job_id, spec)
            budget = self._budget(job, tighter(cfg.budgets, spec.budgets))
            if job["plan_json"]:
                plan = load_plan(job["plan_json"])
            else:
                state = await self._move(job_id, state, "planning")
                try:
                    plan = await planner.plan(spec)
                    validate_plan(plan, spec)
                except (PlannerError, ValueError) as e:
                    log.warning("vsc job %s: planning failed: %s", job_id, e)
                    raise JobFailed("planner") from e
                budget.charge(0, 0, 0.0)
                plan.decisions.append(_decision("plan", f"{len(plan.steps)} steps"))
                await self._save_plan(job_id, plan)
            for seq, step in enumerate(plan.steps):  # idempotent
                await self._store.add_step(job_id, step.model_dump(mode="json"), seq)
        ctx = _Run(job_id, job["owner"], state, planner, spec, plan, budget)
        async with deadline(budget.deadline):
            await self._move_ctx(ctx, "running")
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
                ws = await self._ws.create(ctx.job_id, step.system)
                groups.setdefault(ws.repo_id, []).append(step)  # plan order within a repo

            async def serial(steps: list[PlanStep]) -> None:
                for s in steps:
                    await self._run_step(ctx, s.id, rows[s.id])

            await _all_or_cancel([serial(steps) for steps in groups.values()])

    async def _run_step(
        self,
        ctx: _Run,
        step_id: str,
        row: dict[str, Any],
        *,
        failure: CheckResult | None = None,
        escalate: bool = False,
    ) -> None:
        """The attempt loop of one edit step: returns when an attempt passed."""
        loop = asyncio.get_running_loop()
        first = next(s for s in ctx.plan.steps if s.id == step_id)
        system = self._systems[first.system]
        ws = await self._ws.create(ctx.job_id, system.id)
        current = self._by_id.get(row["worker"] or "", self._workers[0])
        if escalate:
            current = stronger(self._workers, current)
        attempt, local = row["attempt"], 0
        while True:
            step = next(s for s in ctx.plan.steps if s.id == step_id)  # a replan may reword it
            ctx.budget.check_deadline(loop.time())
            ctx.budget.attempt()
            await self._store.add_attempt(ctx.job_id)
            attempt, local = attempt + 1, local + 1
            base = await self._ws.head(ws)
            await self._ws.reset(ws, base)  # start from the last passed step, nothing else
            await self._store.start_attempt(ctx.job_id, step_id, attempt, current.id, str(ws.path))
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
            if res.failed is not None:
                checks = [_worker_failure(current, res.failed)]
            else:
                checks = await verify_step(
                    own,
                    system,
                    ctx.spec,
                    manager=self._ws,
                    timeout_s=min(CHECK_TIMEOUT_S, max(1.0, ctx.budget.deadline - loop.time())),
                )
            passed = all_passed(checks)
            result: dict[str, Any] = {
                "checks": [dataclasses.asdict(c) for c in checks],
                "diff_sha256": _sha256(await self._ws.diff(own)),
            }
            if passed:
                result["commit"] = await self._ws.commit(
                    ws, f"vsc {ctx.job_id}: {step_id} (attempt {attempt})"
                )
            usage = {
                "tokens_in": res.tokens_in,
                "tokens_out": res.tokens_out,
                "cost": res.cost,
                "usage_reported": res.usage_reported,
            }
            await self._store.end_attempt(
                ctx.job_id, step_id, attempt, "passed" if passed else "failed", result, usage
            )
            await self._audit_check(ctx.job_id, checks, passed, step=step_id, attempt=attempt)
            await self._store.add_usage(ctx.job_id, res.tokens_in, res.tokens_out, res.cost)
            ctx.budget.charge(res.tokens_in, res.tokens_out, res.cost)
            if passed:
                return
            failure = next(c for c in checks if not c.passed)
            if local >= self._retry.max_attempts:
                d = _decision("stop", f"{local} attempts failed", step_id)
            else:
                d = await self._replan(ctx, failure, step_id)
            await self._record(ctx, d)
            if d.kind == "stop":
                raise JobFailed("verification")
            if d.kind == "escalate":
                current = stronger(self._workers, current)
            else:
                current = self._retry.next_worker(self._workers, local, current)

    # -- planner decisions ---------------------------------------------------------------

    async def _replan(self, ctx: _Run, failure: CheckResult, step_id: str | None) -> Decision:
        steps = [
            {k: r[k] for k in ("step_id", "system", "kind", "attempt", "state", "worker")}
            for r in await self._store.steps(ctx.job_id)
        ]
        try:
            d = await ctx.planner.replan(ctx.spec, ctx.plan, failure, steps)
        except (PlannerError, ValueError) as e:
            log.warning("vsc job %s: replan failed: %s", ctx.job_id, e)
            raise JobFailed("planner") from e
        ctx.budget.charge(0, 0, 0.0)
        d = guard_replan(ctx.plan, d)
        if d.step_id is None and step_id is not None:
            d = d.model_copy(update={"step_id": step_id})
        return d

    async def _record(self, ctx: _Run, d: Decision) -> None:
        """Append to the decision log; an accepted replan's plan replaces the stored plan."""
        if d.kind == "replan" and d.plan is not None:
            validate_plan(d.plan, ctx.spec)
            logged = d.model_copy(update={"plan": None})
            ctx.plan = d.plan.model_copy(update={"decisions": [*ctx.plan.decisions, logged]})
        else:
            ctx.plan.decisions.append(d)
        await self._save_plan(ctx.job_id, ctx.plan)

    async def _save_plan(self, job_id: str, plan: Plan) -> None:
        await self._store.set_plan(job_id, plan.model_dump(mode="json"), plan_hash(plan))

    # -- whole-system checks -------------------------------------------------------------

    async def _whole_system(self, ctx: _Run) -> None:
        loop = asyncio.get_running_loop()
        checks = [c for c in self._cfg.checks if set(c.systems) <= set(ctx.spec.systems)]
        rounds = 0
        while True:
            failed = None
            for check in checks:
                wss: dict[str, Workspace] = {
                    sid: await self._ws.create(ctx.job_id, sid) for sid in check.systems
                }
                timeout = min(check.timeout_s, max(1.0, ctx.budget.deadline - loop.time()))
                res = await verify_whole(check, wss, timeout_s=timeout)
                await self._audit_check(ctx.job_id, [res], res.passed)
                if not res.passed:
                    failed = (check, res)
                    break
            if failed is None:
                return
            check, res = failed
            rounds += 1
            if rounds >= self._retry.max_attempts:
                d = _decision("stop", f"whole-system check {check.id} failed {rounds} times")
            else:
                d = await self._replan(ctx, res, None)
            await self._record(ctx, d)
            if d.kind == "stop":
                raise JobFailed("whole_system")
            await self._move_ctx(ctx, "running")
            rows = await self._rows(ctx.job_id)
            for layer in order(ctx.plan):
                for step in layer:
                    if step.kind == "edit" and step.system in check.systems:
                        await self._run_step(
                            ctx, step.id, rows[step.id], failure=res, escalate=d.kind == "escalate"
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
        ws = await self._ws.create(job_id, step.system)
        await self._store.start_attempt(job_id, step.id, attempt, "gate", str(ws.path))
        auto = any(
            a.system == step.system and a.action == step.kind for a in self._cfg.auto_approve
        )
        if not auto and not await self._gate.already_approved(job_id, step.id):
            await self._move_ctx(ctx, "awaiting_approval")
        try:
            approval = await self._gate.wait(job_id, step)
        except Rejected as e:
            await self._store.end_attempt(
                job_id, step.id, attempt, "failed", {"rejected": True, "note": e.note}, {}
            )
            raise
        result: dict[str, Any] = {"approval": dataclasses.asdict(approval), "executed": False}
        if step.kind == "merge":
            assert step.target_branch is not None
            try:
                result["head"] = await self._ws.merge_ff(ws, step.target_branch)
            except MergeRefused as e:
                await self._store.end_attempt(
                    job_id, step.id, attempt, "failed", {**result, "reason": str(e)}, {}
                )
                raise JobFailed("merge_refused") from e
            result["executed"] = True
        await self._store.end_attempt(job_id, step.id, attempt, "passed", result, {})

    # -- resume --------------------------------------------------------------------------

    async def _discard_interrupted(self, job_id: str) -> None:
        for row in await self._store.steps(job_id):
            if row["state"] not in _INTERRUPTED:
                continue
            if row["kind"] == "edit":
                ws = await self._ws.create(job_id, row["system"])
                if await self._ws.head(ws) == ws.base_ref:  # nothing passed here: recreate it
                    await self._ws.discard(job_id, ws.repo_id)
                    await self._ws.create(job_id, row["system"])
                else:  # keep the passed steps' commits, drop the half-done edit
                    await self._ws.reset(ws, "HEAD")
            await self._store.end_attempt(
                job_id, row["step_id"], row["attempt"], "failed", {"reason": "interrupted"}, {}
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
    ) -> None:
        if job_id in self._cancelled and state != "cancelled":
            return  # a cancelled job never changes state again
        await self._store.set_state(job_id, state, reason=reason)
        detail: dict[str, Any] = {}
        if reason:
            detail["reason"] = reason
        if limit:
            detail["limit"] = limit
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
            self._bus.publish(
                GatewayEvent(
                    kind="vsc.job",
                    agent_id=_AGENT,
                    data={"job_id": job_id, "state": state, "reason": reason},
                )
            )

    async def _audit_check(
        self,
        job_id: str,
        checks: list[CheckResult],
        passed: bool,
        *,
        step: str | None = None,
        attempt: int | None = None,
    ) -> None:
        if self._audit is None:
            return
        bad = next((c for c in checks if not c.passed), None)
        detail: dict[str, Any] = {}
        if step is not None:
            detail.update(step=step, attempt=attempt)
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
