"""Run a benchmark corpus in one mode and record a ``BenchResult`` per task.

Every task gets fresh repositories in a temporary directory: an ``estate`` task runs its
estate's ``init_estate.py``; a ``history`` task clones its origin (the clone's remote is
removed, so nothing can be pushed back) and puts the default branch on the base commit. The
configured systems whose repository id is in ``task.base`` are pointed at those copies; the other
systems, and the checks that need them, are left out. Auto-approval is never configured: the
bench measures the change, not its delivery.

Modes:

- ``vsc``: a ``JobRunner`` (its own SQLite store and audit log per task) with the configured
  planner and workers. The planner is wrapped so the spec carries the task's systems, acceptance
  tests and budget (the benchmark's tests, not the planner's own) and the plan has no privileged
  steps. The result's ``tokens``/``cost`` are the job's recorded usage; its receipt is built and
  checked with ``verify_receipt``.
- ``single``: one worker (the first configured) in ONE workspace holding every repository of the
  task as a sub-directory (``<ws>/<repo id>/``), given the request and that layout, then verified
  with the same per-system checks (path confinement aside: one agent may edit every repository)
  and the whole-system checks. Up to ``budget.attempts`` turns in the same workspace, each after
  the first told which check failed. Its token budget is the ``vsc`` run's recorded tokens for
  the task when ``out/vsc/<task>.json`` exists (the matched budget), else ``budget.tokens``.
- ``oracle``: apply ``reference_patch`` and verify the same way (validates the corpus).

``failure_class`` (``classify``): ``timeout`` (the deadline, or a check that timed out),
``budget`` (tokens or cost), ``worker_error`` (the worker, planner or harness failed, or the
reference patch does not apply), ``missed_system`` (the failing check needed a repository that
was left unchanged: one the reference patch touches, or any task system without one), else
``wrong_behaviour``.

Tests drive this with the scripted planner and the fake worker: ``planner_factory`` and
``single_prompt`` let them hand the worker the reference solution as files.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
import subprocess
import sys
import tempfile
import time
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

from a2agw.ops.audit import AuditLog
from a2agw.serve.store import create_engine
from a2agw.vsc.bench.corpus import BenchResult, BenchTask, FailureClass, Mode, split_patch
from a2agw.vsc.config import BudgetConfig, CheckConfig, SystemConfig, VscConfig
from a2agw.vsc.gate import Gate
from a2agw.vsc.plan import Decision, Plan, PlanStep
from a2agw.vsc.planner import Planner, ScriptedPlanner
from a2agw.vsc.receipt import build_receipt, verify_receipt
from a2agw.vsc.runner import JobRunner
from a2agw.vsc.spec import REQUEST_MAX_CHARS, ExecutableSpec
from a2agw.vsc.store import VscStore
from a2agw.vsc.verify import (
    CheckResult,
    all_passed,
    verify_step,
    verify_whole,
    write_whole_files,
)
from a2agw.vsc.workers import WorkerSpec, WorkerTask, run_worker
from a2agw.vsc.workspace import Workspace, WorkspaceManager

__all__ = ["BenchPlanner", "classify", "default_single_prompt", "run_bench"]

PlannerFactory = Callable[[BenchTask], Planner]
SinglePrompt = Callable[[BenchTask, str], str]

_OWNER = "bench"
_GIT_TIMEOUT_S = 300.0


def classify(
    *,
    solved: bool,
    kind: str | None,
    reason: str = "",
    limit: str | None = None,
    missed: bool = False,
) -> FailureClass:
    """The failure class from the failing check's kind and reason, the budget limit hit (if
    any) and whether the failing check needed a repository that was left unchanged."""
    if solved:
        return "none"
    if limit == "deadline" or reason == "timeout":
        return "timeout"
    if limit in ("tokens", "cost"):
        return "budget"
    if kind is None or kind == "worker":
        return "worker_error"
    return "missed_system" if missed else "wrong_behaviour"


class BenchPlanner:
    """Wraps a planner for one task: the spec has the task's systems, acceptance tests and budget;
    the plan has no privileged steps (the bench never approves one)."""

    def __init__(self, inner: Planner, task: BenchTask, budget: BudgetConfig) -> None:
        self._inner = inner
        self._task = task
        self._budget = budget

    async def intake(
        self, request: str, systems: list[SystemConfig], checks: list[CheckConfig]
    ) -> ExecutableSpec:
        spec = await self._inner.intake(request, systems, checks)
        return spec.model_copy(
            update={
                "systems": list(self._task.systems),
                "acceptance": list(self._task.acceptance),
                "budgets": self._budget,
            }
        )

    async def plan(self, spec: ExecutableSpec) -> Plan:
        plan = await self._inner.plan(spec)
        edits = [s for s in plan.steps if s.kind == "edit"]
        ids = {s.id for s in edits}
        steps = [
            s.model_copy(update={"depends_on": [d for d in s.depends_on if d in ids]})
            for s in edits
        ]
        return plan.model_copy(update={"steps": steps})

    async def replan(
        self, spec: ExecutableSpec, plan: Plan, failure: CheckResult, steps: list[dict]
    ) -> Decision:
        return await self._inner.replan(spec, plan, failure, steps)

    async def aclose(self) -> None:
        aclose = getattr(self._inner, "aclose", None)
        if aclose is not None:
            await aclose()


class _Unconfined(WorkspaceManager):
    """single/oracle: one change may span every repository, so no path confinement."""

    def confine(self, ws: Workspace, system_id: str, paths: list[str]) -> list[str]:
        return []


class _PromptTask(WorkerTask):
    text: str = ""

    def prompt(self) -> str:
        return self.text


def default_single_prompt(task: BenchTask, layout: str) -> str:
    return (
        "You are working in one directory that holds every repository of the system as a "
        f"sub-directory:\n{layout}\n"
        "Make the requested change across whichever repositories need it. The change is "
        "verified by each repository's gate and tests plus the cross-system checks.\n"
        f"Request:\n{task.request}"
    )


def _run(command: list[str], cwd: Path) -> str:
    """A harness subprocess; ValueError (with its stderr tail) when it fails."""
    try:
        res = subprocess.run(
            command, cwd=cwd, check=True, capture_output=True, text=True, timeout=_GIT_TIMEOUT_S
        )
    except subprocess.CalledProcessError as e:
        raise ValueError(f"{' '.join(command[:2])} failed: {e.stderr.strip()[-300:]}") from None
    except subprocess.TimeoutExpired:
        raise ValueError(f"{' '.join(command[:2])} timed out") from None
    return res.stdout.strip()


def _git(cwd: Path, *args: str) -> str:
    return _run(["git", *args], cwd)


def _prepare(
    task: BenchTask, cfg: VscConfig, config_dir: Path, tmp: Path
) -> tuple[VscConfig, dict[str, str]]:
    """Fresh repositories for the task; the config pointed at them; the resolved base."""
    origin = Path(task.origin)
    repos: dict[str, Path] = {}
    if task.source == "estate":
        target = tmp / "estate"
        _run([sys.executable, str(origin / "init_estate.py"), str(target)], tmp)
        repos = {rid: target / rid for rid in task.base}
    else:
        for rid in task.base:
            dst = tmp / "repos" / rid
            dst.parent.mkdir(parents=True, exist_ok=True)
            _git(tmp, "clone", "-q", str(origin), str(dst))
            _git(dst, "remote", "remove", "origin")
            repos[rid] = dst
    ids = WorkspaceManager(tmp / "ids", cfg.systems, config_dir)
    systems: list[SystemConfig] = []
    branches: dict[str, str] = {}
    for s in cfg.systems:
        rid = ids.repo_id(s.id)
        if rid in repos:
            systems.append(s.model_copy(update={"repo": str(repos[rid])}))
            branches.setdefault(rid, s.default_branch)
    missing = sorted(set(task.systems) - {s.id for s in systems})
    if missing:
        raise ValueError(
            f"task {task.id}: systems not in the configuration's repositories: {missing}"
        )
    base: dict[str, str] = {}
    for rid, repo in repos.items():
        if rid not in branches:
            continue
        _git(repo, "checkout", "-q", "-B", branches[rid], task.base[rid])
        base[rid] = _git(repo, "rev-parse", "HEAD")
    kept = {s.id for s in systems}
    checks = [c for c in cfg.checks if set(c.systems) <= kept]
    tcfg = cfg.model_copy(update={"systems": systems, "checks": checks, "auto_approve": []})
    return tcfg, base


def _needed(task: BenchTask, repo_of: dict[str, str]) -> set[str]:
    """Repository ids a solution must change: those the reference patch touches, else every
    repository of the task's systems."""
    if task.reference_patch:
        with contextlib.suppress(ValueError):
            return set(split_patch(task.reference_patch))
    return {repo_of[s] for s in task.systems if s in repo_of}


async def _changed(
    manager: WorkspaceManager, wss: dict[str, Workspace], task: BenchTask
) -> set[str]:
    """Repository ids whose workspace differs from the base (commits and working tree), not
    counting the acceptance files the verification itself wrote."""
    ours: dict[str, set[str]] = {}
    for t in task.acceptance:
        if t.system is not None and t.system in wss:
            ours.setdefault(wss[t.system].repo_id, set()).update(t.files)
        elif t.system is None:
            for rel in t.files:
                rid, _, rest = rel.partition("/")
                ours.setdefault(rid, set()).add(rest)
    out = set()
    for ws in {w.repo_id: w for w in wss.values()}.values():
        if set(await manager.changed_paths(ws)) - ours.get(ws.repo_id, set()):
            out.add(ws.repo_id)
    return out


def _brief(c: CheckResult) -> dict[str, object]:
    return {"kind": c.kind, "id": c.id, "passed": c.passed, "reason": c.reason}


def _reason(c: CheckResult) -> str:
    return f"{c.kind}:{c.id}" + (f": {c.reason}" if c.reason else "")


async def _verify_all(
    task: BenchTask,
    cfg: VscConfig,
    manager: WorkspaceManager,
    wss: dict[str, Workspace],
    spec: ExecutableSpec,
    deadline: float,
) -> list[tuple[str | None, CheckResult]]:
    """Per-system checks of every task system, then the whole-system checks, each with the
    system it checked (None: whole-system); stops at the first failure."""
    loop = asyncio.get_running_loop()
    systems = {s.id: s for s in cfg.systems}
    results: list[tuple[str | None, CheckResult]] = []
    for sid in [s.id for s in cfg.systems if s.id in task.systems]:
        timeout = max(1.0, deadline - loop.time())
        res = await verify_step(wss[sid], systems[sid], spec, manager=manager, timeout_s=timeout)
        results += [(sid, c) for c in res]
        if not all_passed(res):
            return results
    for check in cfg.checks:
        if not set(check.systems) <= set(task.systems):
            continue
        cws = {sid: wss[sid] for sid in check.systems}
        err = write_whole_files(spec.acceptance, check.id, {w.repo_id: w for w in cws.values()})
        if err:
            results.append((None, _failed("whole_system", check.id, err)))
            return results
        timeout = min(check.timeout_s, max(1.0, deadline - loop.time()))
        res = await verify_whole(check, cws, timeout_s=timeout)
        results.append((None, res))
        if not res.passed:
            return results
    return results


def _failed(kind: Any, id: str, reason: str) -> CheckResult:
    return CheckResult(
        kind=kind,
        id=id,
        command=[],
        exit_code=None,
        passed=False,
        duration_s=0.0,
        log_sha256="",
        stderr_tail="",
        reason=reason[:512],
    )


def _spec(task: BenchTask, budget: BudgetConfig) -> ExecutableSpec:
    return ExecutableSpec(
        request=task.request[:REQUEST_MAX_CHARS],
        done=task.request[:REQUEST_MAX_CHARS],
        systems=list(task.systems),
        acceptance=list(task.acceptance),
        budgets=budget,
    )


def _outcome(
    checks: list[tuple[str | None, CheckResult]],
    changed: set[str],
    needed: set[str],
    repo_of: dict[str, str],
    check_systems: dict[str, list[str]],
) -> tuple[bool, FailureClass, str]:
    solved = all_passed(c for _, c in checks)
    bad = next(((sid, c) for sid, c in checks if not c.passed), None)
    if solved or bad is None:
        return solved, classify(solved=solved, kind=None), "" if solved else "no checks ran"
    sid, c = bad
    missed = _missed(c.kind, c.id, changed, needed, repo_of, check_systems, sid)
    return False, classify(solved=False, kind=c.kind, reason=c.reason, missed=missed), _reason(c)


def _missed(
    kind: str,
    id: str,
    changed: set[str],
    needed: set[str],
    repo_of: dict[str, str],
    check_systems: dict[str, list[str]],
    system: str | None,
) -> bool:
    if kind == "whole_system":
        repos = {repo_of[s] for s in check_systems.get(id, []) if s in repo_of}
        return bool((repos & needed) - changed)
    if system is None:  # no system known: any needed repository left unchanged
        return bool(needed - changed)
    rid = repo_of.get(system)
    return rid in needed and rid not in changed


async def _run_single(
    task: BenchTask,
    cfg: VscConfig,
    tmp: Path,
    budget: BudgetConfig,
    worker: WorkerSpec,
    token_budget: int,
    prompt_hook: SinglePrompt | None,
) -> BenchResult:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + budget.deadline_s
    manager = _Unconfined(tmp / "ws", cfg.systems, tmp)
    job = "single"
    wss = {s.id: await manager.create(job, s.id) for s in cfg.systems}
    repo_of = {sid: ws.repo_id for sid, ws in wss.items()}
    root = manager.root / job
    owners: dict[str, list[str]] = {}
    for s in cfg.systems:
        owners.setdefault(repo_of[s.id], []).append(
            f"system {s.id}" + ("" if s.path == "." else f" under {s.path}/")
        )
    layout = "\n".join(f"  {rid}/  ({', '.join(owned)})" for rid, owned in sorted(owners.items()))
    text = default_single_prompt(task, layout)
    if prompt_hook is not None:
        text = prompt_hook(task, text)
    spec = _spec(task, budget)
    first = cfg.systems[0]
    step = PlanStep(id="single", system=first.id, instructions="see the prompt")
    tokens, cost = 0, 0.0
    checks: list[tuple[str | None, CheckResult]] = []
    failure: CheckResult | None = None
    limit: str | None = None
    for attempt in range(1, budget.attempts + 1):
        prompt = text
        if failure is not None:  # before the task text, which (like a step's) comes last
            prompt = (
                f"The previous attempt failed check {failure.id} ({failure.kind}): "
                f"{failure.reason or 'failed'}\nstderr tail:\n{failure.stderr_tail[-2000:]}\n"
                "The workspace keeps that attempt's changes.\n" + text
            )
        wtask = _PromptTask(
            job_id=job, step_id="single", attempt=attempt, system=first, spec=spec, step=step,
            text=prompt,
        )  # fmt: skip
        try:
            async with asyncio.timeout(max(0.0, deadline - loop.time())):
                res = await run_worker(
                    worker, wtask, Workspace(job, "single", root, "", ""),
                    consult=None, audit=None, actor=_OWNER,
                )  # fmt: skip
        except TimeoutError:
            limit = "deadline"
            break
        tokens += res.tokens_in + res.tokens_out
        cost += res.cost
        if tokens > token_budget:
            limit = "tokens"
            break
        if cost > budget.cost_usd:
            limit = "cost"
            break
        if res.failed is not None:
            checks = [(None, _failed("worker", worker.id, f"worker: {res.failed}"))]
        else:
            checks = await _verify_all(task, cfg, manager, wss, spec, deadline)
        if all_passed(c for _, c in checks):
            break
        failure = next(c for _, c in checks if not c.passed)
        if loop.time() >= deadline:
            limit = "deadline"
            break
    changed = await _changed(manager, wss, task)
    check_systems = {c.id: list(c.systems) for c in cfg.checks}
    if limit is not None:
        solved, fclass, reason = (
            False,
            classify(solved=False, kind=None, limit=limit),
            f"budget: {limit}",
        )
    else:
        solved, fclass, reason = _outcome(
            checks, changed, _needed(task, repo_of), repo_of, check_systems
        )
    return BenchResult(
        task_id=task.id,
        mode="single",
        solved=solved,
        tokens=tokens,
        cost=cost,
        failure_class=fclass,
        reason=reason,
        budget_tokens=token_budget,
        layout=sorted(p.name for p in root.iterdir() if p.is_dir()),
        checks=[_brief(c) for _, c in checks],
    )


async def _run_oracle(
    task: BenchTask, cfg: VscConfig, tmp: Path, budget: BudgetConfig
) -> BenchResult:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + budget.deadline_s
    manager = _Unconfined(tmp / "ws", cfg.systems, tmp)
    wss = {s.id: await manager.create("oracle", s.id) for s in cfg.systems}
    repo_of = {sid: ws.repo_id for sid, ws in wss.items()}
    by_repo = {ws.repo_id: ws for ws in wss.values()}
    assert task.reference_patch is not None
    try:
        parts = split_patch(task.reference_patch, set(by_repo))
        for rid, chunk in parts.items():
            await asyncio.to_thread(
                subprocess.run,
                ["git", "apply", "-p2", "--whitespace=nowarn", "-"],
                cwd=by_repo[rid].path,
                input=chunk,
                text=True,
                check=True,
                capture_output=True,
                timeout=_GIT_TIMEOUT_S,
            )
    except (ValueError, subprocess.CalledProcessError) as e:
        why = e.stderr.strip()[:256] if isinstance(e, subprocess.CalledProcessError) else str(e)
        return BenchResult(
            task_id=task.id,
            mode="oracle",
            solved=False,
            failure_class="worker_error",
            reason=f"reference_patch: {why}",
        )
    checks = await _verify_all(task, cfg, manager, wss, _spec(task, budget), deadline)
    changed = await _changed(manager, wss, task)
    check_systems = {c.id: list(c.systems) for c in cfg.checks}
    solved, fclass, reason = _outcome(
        checks, changed, _needed(task, repo_of), repo_of, check_systems
    )
    return BenchResult(
        task_id=task.id,
        mode="oracle",
        solved=solved,
        failure_class=fclass,
        reason=reason,
        checks=[_brief(c) for _, c in checks],
    )


def _parse_reason(text: str) -> tuple[str, str, str]:
    """``kind:id: why`` (the runner's ``vsc.check`` detail) -> (kind, id, why)."""
    kind, _, rest = text.partition(":")
    cid, _, why = rest.partition(": ")
    return kind, cid, why


def _audited(row: dict[str, Any]) -> dict[str, object]:
    """A ``vsc.check`` audit row as a check summary (its last check, or its failing one)."""
    detail = row["detail"] or {}
    kind, cid, why = _parse_reason(str(detail.get("reason", "")))
    out: dict[str, object] = {"kind": kind, "id": cid, "passed": row["outcome"] == "passed"}
    out["reason"] = why
    if "step" in detail:
        out["step"] = detail["step"]
    return out


async def _run_vsc(
    task: BenchTask,
    cfg: VscConfig,
    tmp: Path,
    budget: BudgetConfig,
    workers: list[WorkerSpec],
    planners: PlannerFactory,
) -> BenchResult:
    engine = await create_engine(f"sqlite+aiosqlite:///{tmp / 'bench.db'}")
    try:
        store, audit = VscStore(engine), AuditLog(engine)
        await store.initialize()
        await audit.initialize()
        manager = WorkspaceManager(tmp / "ws", cfg.systems, tmp)
        planner = BenchPlanner(planners(task), task, budget)
        runner = JobRunner(
            store=store,
            workspaces=manager,
            workers=workers,
            planner_factory=lambda job_id: planner,
            cfg=cfg.model_copy(update={"budgets": budget}),
            audit=audit,
            bus=None,
            consult=None,
            gate=Gate(cfg, audit),
        )
        job_id = await runner.submit(task.request[:REQUEST_MAX_CHARS], owner=_OWNER)
        job = await runner.run(job_id)
        solved = job["state"] == "accepted"
        mine: list[dict[str, Any]] = []
        cursor: str | None = None
        while True:
            rows, cursor = await audit.query({"agent": "deliver"}, 500, cursor, ascending=True)
            mine += [r for r in rows if r["task_id"] == job_id]
            if cursor is None:
                break
        limit = next(
            (
                (r["detail"] or {}).get("limit")
                for r in reversed(mine)
                if r["action"] == "vsc.job" and r["outcome"] == "failed"
            ),
            None,
        )
        bad = next(
            (r for r in reversed(mine) if r["action"] == "vsc.check" and r["outcome"] == "failed"),
            None,
        )
        wss = {s.id: await manager.create(job_id, s.id) for s in cfg.systems}
        repo_of = {sid: ws.repo_id for sid, ws in wss.items()}
        changed = await _changed(manager, wss, task)
        reason = job["reason"] or ""
        if solved:
            fclass: FailureClass = "none"
        elif limit in ("deadline", "tokens", "cost"):
            fclass = classify(solved=False, kind=None, limit=limit)
            reason = f"budget: {limit}"
        elif bad is not None and job["reason"] in ("verification", "whole_system", "budget"):
            detail = bad["detail"] or {}
            kind, cid, why = _parse_reason(str(detail.get("reason", "")))
            plan = {s.id: s.system for s in Plan.model_validate_json(job["plan_json"]).steps}
            missed = _missed(
                kind,
                cid,
                changed,
                _needed(task, repo_of),
                repo_of,
                {c.id: list(c.systems) for c in cfg.checks},
                plan.get(detail.get("step", "")),
            )
            fclass = classify(solved=False, kind=kind, reason=why, missed=missed)
            reason = str(detail.get("reason", reason))
        else:
            fclass = classify(solved=False, kind=None)
        receipt = await build_receipt(store, audit, job_id)
        return BenchResult(
            task_id=task.id,
            mode="vsc",
            solved=solved,
            tokens=int(job["tokens_in"]) + int(job["tokens_out"]),
            cost=float(job["cost"]),
            failure_class=fclass,
            reason=reason,
            budget_tokens=budget.tokens,
            checks=[_audited(r) for r in mine if r["action"] == "vsc.check"],
            receipt_problems=verify_receipt(json.loads(json.dumps(receipt))),
        )
    finally:
        await engine.dispose()


@contextlib.asynccontextmanager
async def _default_planners(cfg: VscConfig, tmp: Path) -> AsyncIterator[PlannerFactory]:
    """The configured planner: ``scripted`` in process; ``claude`` through a local host's
    ``vsc-planner`` agent (no auth, its own database)."""
    if cfg.planner == "scripted":
        yield lambda task: ScriptedPlanner()
        return
    from a2agw.serve.host import AgentHost
    from a2agw.vsc.planner import AgentPlanner, claude_planner_adapter, planner_agent

    host = AgentHost(
        "http://bench", db_url=f"sqlite+aiosqlite:///{tmp / 'planner.db'}", admin=False
    )
    host.add(planner_agent(claude_planner_adapter(cfg)))
    await host.startup()
    try:
        yield lambda task: AgentPlanner(host, job_id=task.id)
    finally:
        await host.shutdown()


def _safe_name(task_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "-", task_id)


async def run_bench(
    corpus: list[BenchTask],
    *,
    mode: Mode,
    cfg: VscConfig,
    budget: BudgetConfig,
    out: Path,
    config_dir: Path = Path("."),
    workers: list[WorkerSpec] | None = None,
    planner_factory: PlannerFactory | None = None,
    single_prompt: SinglePrompt | None = None,
) -> list[BenchResult]:
    """Run every task of ``corpus`` in ``mode``; each result is also written to
    ``out/<mode>/<task id>.json``. ``workers`` defaults to ``cfg.workers``; ``planner_factory``
    (task -> planner, vsc) to the configured planner; ``single_prompt`` ((task, prompt) ->
    prompt) rewrites the single worker's prompt."""
    out = Path(out)
    if mode == "oracle":
        lacking = [t.id for t in corpus if not t.reference_patch]
        if lacking:
            raise ValueError(f"oracle mode needs a reference_patch: {', '.join(lacking)}")
    specs = workers if workers is not None else [WorkerSpec.from_config(w) for w in cfg.workers]
    if mode != "oracle" and not specs:
        raise ValueError(f"mode {mode} needs at least one worker (vsc.workers)")
    (out / mode).mkdir(parents=True, exist_ok=True)
    results: list[BenchResult] = []
    with tempfile.TemporaryDirectory(prefix="a2agw-bench-") as scratch:
        async with contextlib.AsyncExitStack() as stack:
            planners = planner_factory
            if mode == "vsc" and planners is None:
                planners = await stack.enter_async_context(_default_planners(cfg, Path(scratch)))
            for n, task in enumerate(corpus):
                tmp = Path(scratch) / f"{n:04d}"
                tmp.mkdir()
                tcfg, base = await asyncio.to_thread(_prepare, task, cfg, Path(config_dir), tmp)
                started = time.monotonic()
                if mode == "oracle":
                    result = await _run_oracle(task, tcfg, tmp, budget)
                elif mode == "single":
                    vsc_file = out / "vsc" / f"{_safe_name(task.id)}.json"
                    tokens = budget.tokens
                    if vsc_file.is_file():
                        tokens = BenchResult.model_validate_json(vsc_file.read_text()).tokens
                    result = await _run_single(
                        task, tcfg, tmp, budget, specs[0], tokens, single_prompt
                    )
                else:
                    assert planners is not None
                    result = await _run_vsc(task, tcfg, tmp, budget, specs, planners)
                result = result.model_copy(
                    update={"wall_s": round(time.monotonic() - started, 3), "base": base}
                )
                path = out / mode / f"{_safe_name(task.id)}.json"
                path.write_text(result.model_dump_json(indent=2) + "\n", encoding="utf-8")
                results.append(result)
    return results
