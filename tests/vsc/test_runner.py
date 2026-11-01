"""The job runner: end to end over real git repositories, scripted planners and stdio workers."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

from a2agw.ops.audit import AuditLog
from a2agw.ops.bus import EventBus
from a2agw.serve.store import create_engine
from a2agw.vsc.config import BudgetConfig, CheckConfig, SystemConfig, VscConfig
from a2agw.vsc.gate import Gate
from a2agw.vsc.plan import Decision, Plan, PlanStep, plan_hash
from a2agw.vsc.planner import ScriptedPlanner
from a2agw.vsc.runner import Budget, BudgetExceeded, JobRunner, RetryPolicy
from a2agw.vsc.spec import AcceptanceTest
from a2agw.vsc.store import VscStore
from a2agw.vsc.workspace import WorkspaceManager

from .conftest import make_repo, worker

PY = sys.executable
TESTS = [PY, "-B", "-m", "unittest", "discover", "-s", "tests"]
TEST_FILE = (
    "import unittest\n\nfrom greet import hello\n\n\n"
    "class T(unittest.TestCase):\n    def test_hello(self):\n"
    "        self.assertEqual(hello(), 'hi')\n"
)
GREET = "def hello():\n    return 'hi'\n"
REPO_FILES = {".gitignore": "__pycache__/\n", "tests/test_x.py": TEST_FILE}


def git(repo, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()


def instructions(files: dict[str, str], extra: str = "") -> str:
    return f"add the greeting{extra}\n---FILES---\n" + json.dumps({"files": files})


def edit(sid: str, files: dict[str, str] | None = None, *, extra: str = "", deps=()) -> PlanStep:
    return PlanStep(
        id=f"edit-{sid}",
        system=sid,
        depends_on=list(deps),
        instructions=instructions(files if files is not None else {"greet.py": GREET}, extra),
    )


class FixedPlanner(ScriptedPlanner):
    """ScriptedPlanner (intake, replan) with a fixed plan."""

    def __init__(self, steps: list[PlanStep], budgets: BudgetConfig | None = None) -> None:
        super().__init__()
        self._steps = steps
        self._budgets = budgets
        self.plans = 0
        self.intakes = 0

    async def intake(self, request, systems, checks):
        self.intakes += 1
        spec = await super().intake(request, systems, checks)
        return spec if self._budgets is None else spec.model_copy(update={"budgets": self._budgets})

    async def plan(self, spec):
        self.plans += 1
        return Plan(steps=self._steps)


async def until(pred, timeout: float = 30.0) -> None:
    """Poll the async predicate until it holds; fail after ``timeout`` seconds."""

    async def poll() -> None:
        while not await pred():
            await asyncio.sleep(0.05)

    await asyncio.wait_for(poll(), timeout)


class CrashingStore(VscStore):
    """A store whose writes stop once ``crashed`` is set: the process died mid-step, so no
    attempt row is closed on the way down."""

    crashed = False

    async def end_attempt(self, *args, **kw):
        if not self.crashed:
            await super().end_attempt(*args, **kw)

    async def _update_job(self, *args, **kw):
        if not self.crashed:
            await super()._update_job(*args, **kw)


@dataclass
class Env:
    tmp: Path
    store: VscStore
    audit: AuditLog
    engine: object

    def runner(self, cfg, planner, workers, **kw) -> JobRunner:
        kw.setdefault("gate", Gate(cfg, self.audit))
        return JobRunner(
            store=kw.pop("store", self.store),
            workspaces=WorkspaceManager(self.tmp / "root", cfg.systems, self.tmp),
            workers=workers,
            planner_factory=lambda job_id: planner,
            cfg=cfg,
            audit=self.audit,
            bus=kw.pop("bus", None),
            consult=None,
            **kw,
        )

    async def rows(self, action: str, job_id: str) -> list[dict]:
        rows, _ = await self.audit.query({"action": action}, 500, ascending=True)
        return [r for r in rows if r["task_id"] == job_id]

    async def state(self, job_id: str) -> str:
        return (await self.store.get_job(job_id))["state"]

    async def whole_checks(self, job_id: str) -> list[dict]:
        return [r for r in await self.rows("vsc.check", job_id) if "step" not in r["detail"]]

    async def edit_attempts(self, job_id: str) -> list[tuple]:
        rows = await self.store.attempts(job_id)
        return [(x["step_id"], x["attempt"], x["state"]) for x in rows if x["attempt"] > 0]


@pytest.fixture
async def env(tmp_path):
    engine = await create_engine(f"sqlite+aiosqlite:///{tmp_path / 'g.db'}")
    store, audit = VscStore(engine), AuditLog(engine)
    await store.initialize()
    await audit.initialize()
    try:
        yield Env(tmp_path, store, audit, engine)
    finally:
        await engine.dispose()


async def _is(env: Env, job_id: str, state: str) -> bool:
    return await env.state(job_id) == state


async def _step_is(env: Env, job_id: str, step_id: str, state: str) -> bool:
    rows = {s["step_id"]: s for s in await env.store.steps(job_id)}
    return step_id in rows and rows[step_id]["state"] == state


def sys_cfg(sid: str, repo: Path, path: str = ".") -> SystemConfig:
    return SystemConfig(id=sid, repo=str(repo), path=path, tests=TESTS)


def named(mode: str, wid: str, cost_class: str = "cheap", **kw):
    return dataclasses.replace(worker(mode, **kw), id=wid, cost_class=cost_class)


EXISTS_CHECK = [
    PY,
    "-c",
    (
        "import os, sys; sys.exit(0 if all(os.path.exists(os.path.join(os.environ[k], 'greet.py'))"
        " for k in ('VSC_WS_ALPHA', 'VSC_WS_BETA')) else 1)"
    ),
]


def two_repo_cfg(tmp, *, run=EXISTS_CHECK, budgets=None) -> VscConfig:
    a = make_repo(tmp, "repo-a", REPO_FILES)
    b = make_repo(tmp, "repo-b", REPO_FILES)
    return VscConfig(
        systems=[sys_cfg("alpha", a), sys_cfg("beta", b)],
        checks=[CheckConfig(id="whole", systems=["alpha", "beta"], run=run, timeout_s=60)],
        budgets=budgets or BudgetConfig(),
    )


def test_budget_and_retry_policy_units():
    b = Budget.from_config(BudgetConfig(tokens=15, cost_usd=1.0), deadline=10.0)
    b.charge(5, 10, 0.5)  # exactly at the limit is fine
    with pytest.raises(BudgetExceeded) as e:
        b.charge(1, 0, 0)
    assert e.value.what == "tokens"
    with pytest.raises(BudgetExceeded, match="deadline"):
        b.check_deadline(10.0)
    assert not hasattr(b, "attempt")  # attempts are bounded per step, by the runner
    cheap, std, strong = named("x", "c"), named("x", "s", "standard"), named("x", "g", "strong")
    p = RetryPolicy()
    assert p.next_worker([cheap, strong, std], 1, cheap) is cheap
    assert p.next_worker([cheap, strong, std], 2, cheap) is strong
    assert p.next_worker([cheap, std, strong], 2, cheap) is std
    assert p.next_worker([cheap, strong], 2, strong) is strong


def test_stored_plan_with_logged_replan_roundtrips():
    plan = Plan(steps=[edit("alpha")])
    replan = Decision(ts=1.0, kind="replan", text="reword", plan=plan)
    plan.decisions.append(replan.model_copy(update={"plan": None}))
    loaded = Plan.model_validate_json(json.dumps(plan.model_dump(mode="json")))
    assert [(d.kind, d.plan) for d in loaded.decisions] == [("replan", None)]
    assert plan_hash(loaded) == plan_hash(plan)


async def test_job_accepted_end_to_end_two_repos(env):
    cfg = two_repo_cfg(env.tmp)
    accepted: list[str] = []

    async def hook(job_id: str) -> None:
        accepted.append(job_id)

    bus = EventBus()
    sub = bus.subscribe()
    planner = FixedPlanner([edit("alpha"), edit("beta")])
    r = env.runner(cfg, planner, [worker("apply")], on_accepted=hook, bus=bus)
    job_id = await r.submit("greet everywhere systems: alpha, beta", owner="key:a")
    job = await r.run(job_id)
    assert job["state"] == "accepted", job
    assert accepted == [job_id]
    steps = await env.store.steps(job_id)
    assert [(s["step_id"], s["attempt"], s["state"]) for s in steps] == [
        ("edit-alpha", 1, "passed"),
        ("edit-beta", 1, "passed"),
    ]
    result = json.loads(steps[0]["result_json"])
    assert len(result["diff_sha256"]) == 64 and result["commit"]
    assert all(c["passed"] for c in result["checks"])
    for repo in ("repo-a", "repo-b"):
        branch = f"vsc/{job_id}/{repo}"
        assert git(env.tmp / repo, "branch", "--list", branch)
        assert git(env.tmp / repo, "show", f"{branch}:greet.py") == GREET.strip()
        assert not (env.tmp / repo / "greet.py").exists()  # main untouched
    states = [row["outcome"] for row in await env.rows("vsc.job", job_id)]
    assert states == ["submitted", "planning", "running", "verifying", "accepted"]
    events = []
    while not sub._queue.empty():
        events.append(sub._queue.get_nowait())
    assert [e.data["state"] for e in events if e.kind == "vsc.job"] == states
    plan = json.loads(job["plan_json"])
    assert [d["kind"] for d in plan["decisions"]] == ["plan"]
    assert job["attempts"] == 2


async def test_step_retries_then_escalates(env):
    repo = make_repo(env.tmp, "repo-a", REPO_FILES)
    cfg = VscConfig(systems=[sys_cfg("alpha", repo)])
    workers = [named("fail", "cheap"), named("apply", "strong", "strong")]
    r = env.runner(cfg, FixedPlanner([edit("alpha")]), workers)
    job_id = await r.submit("greet", owner="key:a")
    job = await r.run(job_id)
    assert job["state"] == "accepted", job
    rows = await env.store.attempts(job_id)
    assert [(x["attempt"], x["worker"], x["state"]) for x in rows if x["attempt"] > 0] == [
        (1, "cheap", "failed"),
        (2, "cheap", "failed"),
        (3, "strong", "passed"),
    ]
    first = json.loads(rows[1]["result_json"])
    assert first["checks"][0]["kind"] == "worker" and "gave up" in first["checks"][0]["reason"]
    decisions = json.loads(job["plan_json"])["decisions"]
    assert [d["kind"] for d in decisions] == ["plan", "retry", "escalate"]
    assert decisions[2]["step_id"] == "edit-alpha"


async def test_budget_attempts_exhausted_fails_job(env):
    """The attempts budget is per step: the second step still gets its own two attempts."""
    a = make_repo(env.tmp, "repo-a", REPO_FILES)
    b = make_repo(env.tmp, "repo-b", REPO_FILES)
    cfg = VscConfig(
        systems=[sys_cfg("alpha", a), sys_cfg("beta", b)], budgets=BudgetConfig(attempts=2)
    )
    steps = [edit("alpha"), edit("beta", {"nothing.txt": "x"}, deps=["edit-alpha"])]
    r = env.runner(cfg, FixedPlanner(steps), [worker("apply")])
    job_id = await r.submit("greet", owner="key:a")
    job = await r.run(job_id)
    assert (job["state"], job["reason"]) == ("failed", "budget")
    assert job["attempts"] == 3  # job-wide count is a statistic only
    assert await env.edit_attempts(job_id) == [
        ("edit-alpha", 1, "passed"),
        ("edit-beta", 1, "failed"),
        ("edit-beta", 2, "failed"),
    ]
    decisions = json.loads(job["plan_json"])["decisions"]
    assert [d["kind"] for d in decisions] == ["plan", "retry"]  # no planner turn after the last
    last = (await env.rows("vsc.job", job_id))[-1]
    assert last["outcome"] == "failed" and last["detail"] == {
        "reason": "budget",
        "limit": "attempts",
    }


async def test_token_budget_enforced(env):
    repo = make_repo(env.tmp, "repo-a", REPO_FILES)
    cfg = VscConfig(systems=[sys_cfg("alpha", repo)], budgets=BudgetConfig(tokens=15))
    r = env.runner(cfg, FixedPlanner([edit("alpha")]), [worker("usage")])
    job_id = await r.submit("greet", owner="key:a")
    job = await r.run(job_id)
    assert (job["state"], job["reason"]) == ("failed", "budget")
    assert (job["tokens_in"], job["tokens_out"], job["cost"]) == (10, 20, 0.01)
    (step,) = await env.store.steps(job_id)
    assert json.loads(step["usage_json"]) == {
        "tokens_in": 10,
        "tokens_out": 20,
        "cost": 0.01,
        "usage_reported": True,
    }


async def test_two_systems_one_repo_serialised(env):
    repo = make_repo(
        env.tmp,
        "mono",
        {
            ".gitignore": "__pycache__/\n",
            "a/tests/test_x.py": TEST_FILE,
            "b/tests/test_x.py": TEST_FILE,
        },
    )
    cfg = VscConfig(systems=[sys_cfg("sa", repo, "a"), sys_cfg("sb", repo, "b")])
    planner = FixedPlanner([edit("sa", {"a/greet.py": GREET}), edit("sb", {"b/greet.py": GREET})])
    r = env.runner(cfg, planner, [worker("apply")])
    job_id = await r.submit("greet both", owner="key:a")
    job = await r.run(job_id)
    assert job["state"] == "accepted", job
    sa, sb = await env.store.steps(job_id)
    assert (sa["step_id"], sb["step_id"]) == ("edit-sa", "edit-sb")
    assert sa["state"] == sb["state"] == "passed"
    assert sa["ended_at"] <= sb["started_at"]  # serialised in plan order
    assert sa["workspace"] == sb["workspace"]
    assert [p.name for p in (env.tmp / "root" / job_id).iterdir()] == ["mono"]
    branch = f"vsc/{job_id}/mono"
    assert git(repo, "show", f"{branch}:a/greet.py") == GREET.strip()
    assert git(repo, "show", f"{branch}:b/greet.py") == GREET.strip()


async def test_resume_after_restart(env):
    cfg = two_repo_cfg(env.tmp)
    steps = [edit("alpha"), edit("beta", extra=" HANG", deps=["edit-alpha"])]
    crashing = CrashingStore(env.engine)
    r1 = env.runner(cfg, FixedPlanner(steps), [worker("hang_marked")], store=crashing)
    job_id = await r1.submit("greet", owner="key:a")
    task = asyncio.create_task(r1.run(job_id))

    await until(lambda: _step_is(env, job_id, "edit-beta", "running"))
    stale = {s["step_id"]: s for s in await env.store.steps(job_id)}["edit-beta"]
    assert stale["attempt"] == 1
    junk = Path(stale["workspace"]) / "half-done.txt"
    junk.write_text("interrupted edit\n")
    crashing.crashed = True  # the gateway dies mid-step: nothing more reaches the store
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert (await env.store.get_job(job_id))["state"] == "running"

    planner2 = FixedPlanner(steps)
    r2 = env.runner(cfg, planner2, [worker("apply")])
    assert await r2.resume_all() == [job_id]
    job = await asyncio.wait_for(r2.tasks[job_id], 60)
    assert job["state"] == "accepted", job
    assert planner2.plans == 0  # plan and spec come from the store
    rows = [(x["step_id"], x["attempt"], x["state"]) for x in await env.store.attempts(job_id)]
    assert [x for x in rows if x[1] > 0] == [
        ("edit-alpha", 1, "passed"),  # not re-run
        ("edit-beta", 1, "failed"),  # the interrupted attempt, closed as such
        ("edit-beta", 2, "passed"),  # continued as a new attempt
    ]
    interrupted = next(
        x
        for x in await env.store.attempts(job_id)
        if (x["step_id"], x["attempt"]) == ("edit-beta", 1)
    )
    assert json.loads(interrupted["result_json"]) == {"reason": "interrupted"}
    assert not junk.exists()  # the half-done worktree was discarded and recreated
    discarded = [r for r in await env.rows("vsc.step", job_id) if r["outcome"] == "discarded"]
    assert [(d["detail"]["step"], d["detail"]["attempt"]) for d in discarded] == [("edit-beta", 1)]
    assert git(env.tmp / "repo-b", "show", f"vsc/{job_id}/repo-b:greet.py") == GREET.strip()


async def test_whole_system_failure_replans_and_stops(env):
    cfg = two_repo_cfg(env.tmp, run=[PY, "-c", "import sys; sys.exit(1)"])
    r = env.runner(cfg, FixedPlanner([edit("alpha"), edit("beta")]), [worker("apply")])
    job_id = await r.submit("greet", owner="key:a")
    job = await r.run(job_id)
    assert (job["state"], job["reason"]) == ("failed", "whole_system")
    decisions = json.loads(job["plan_json"])["decisions"]
    assert [d["kind"] for d in decisions] == ["plan", "retry", "escalate", "stop"]
    # each step stays within its own attempts budget (3) across the whole-system rounds
    rows = [(x[0], x[1]) for x in await env.edit_attempts(job_id)]
    assert sorted(rows) == [("edit-alpha", n) for n in (1, 2, 3)] + [
        ("edit-beta", n) for n in (1, 2, 3)
    ]
    checks = [x for x in await env.rows("vsc.check", job_id) if x["outcome"] == "failed"]
    assert len(checks) == 3


async def test_merge_step_waits_for_approval_then_fast_forwards(env):
    repo = make_repo(env.tmp, "repo-a", REPO_FILES)
    cfg = VscConfig(systems=[sys_cfg("alpha", repo)])
    merge = PlanStep(
        id="merge-alpha",
        system="alpha",
        kind="merge",
        target_branch="main",
        depends_on=["edit-alpha"],
        instructions="merge",
    )
    gate = Gate(cfg, env.audit)
    r = env.runner(cfg, FixedPlanner([edit("alpha"), merge]), [worker("apply")], gate=gate)
    job_id = await r.submit("greet", owner="key:a")
    task = asyncio.create_task(r.run(job_id))
    await until(lambda: _is(env, job_id, "awaiting_approval"))
    assert "greet.py" not in git(repo, "ls-tree", "--name-only", "main")
    await gate.approve(job_id, "merge-alpha", actor="alice", note="ok")
    job = await asyncio.wait_for(task, 30)
    assert job["state"] == "accepted", job
    assert git(repo, "rev-parse", "main") == git(repo, "rev-parse", f"vsc/{job_id}/repo-a")
    step = (await env.store.steps(job_id))[1]
    res = json.loads(step["result_json"])
    assert res["executed"] is True and res["approval"]["actor"] == "alice"


async def test_rejected_privileged_step_fails_job(env):
    repo = make_repo(env.tmp, "repo-a", REPO_FILES)
    cfg = VscConfig(systems=[sys_cfg("alpha", repo)])
    deploy = PlanStep(id="deploy-alpha", system="alpha", kind="deploy", instructions="deploy")
    gate = Gate(cfg, env.audit)
    await gate.reject("pending", "x", actor="bob", note="-")  # unrelated decision is ignored
    r = env.runner(cfg, FixedPlanner([edit("alpha"), deploy]), [worker("apply")], gate=gate)
    job_id = await r.submit("greet", owner="key:a")
    task = asyncio.create_task(r.run(job_id))
    await until(lambda: _is(env, job_id, "awaiting_approval"))
    await gate.reject(job_id, "deploy-alpha", actor="bob", note="no")
    job = await asyncio.wait_for(task, 30)
    assert (job["state"], job["reason"]) == ("failed", "rejected")


async def test_cancel_running_job(env):
    repo = make_repo(env.tmp, "repo-a", REPO_FILES)
    cfg = VscConfig(systems=[sys_cfg("alpha", repo)])
    r = env.runner(cfg, FixedPlanner([edit("alpha")]), [worker("hang")])
    job_id = await r.submit("greet", owner="key:a")
    task = r.start(job_id)
    assert r.tasks[job_id] is task
    await until(lambda: _step_is(env, job_id, "edit-alpha", "running"))
    await r.cancel(job_id, actor="key:b")
    job = await asyncio.wait_for(task, 30)
    assert job["state"] == "cancelled"
    # the cancelled attempt is closed, never left running
    assert await env.edit_attempts(job_id) == [("edit-alpha", 1, "failed")]
    (row,) = await env.store.steps(job_id)
    assert json.loads(row["result_json"]) == {"reason": "interrupted"}
    last = (await env.rows("vsc.job", job_id))[-1]
    assert (last["outcome"], last["actor"]) == ("cancelled", "key:b")
    assert await r.resume_all() == []


async def test_attempts_bound_survives_restart(env):
    """An interrupted attempt counts: after a restart the step only gets what is left."""
    repo = make_repo(env.tmp, "repo-a", REPO_FILES)
    cfg = VscConfig(systems=[sys_cfg("alpha", repo)], budgets=BudgetConfig(attempts=2))
    crashing = CrashingStore(env.engine)
    r1 = env.runner(cfg, FixedPlanner([edit("alpha")]), [worker("hang")], store=crashing)
    job_id = await r1.submit("greet", owner="key:a")
    task = asyncio.create_task(r1.run(job_id))
    await until(lambda: _step_is(env, job_id, "edit-alpha", "running"))
    crashing.crashed = True
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    r2 = env.runner(cfg, FixedPlanner([edit("alpha")]), [worker("fail")])
    assert await r2.resume_all() == [job_id]
    job = await asyncio.wait_for(r2.tasks[job_id], 60)
    assert (job["state"], job["reason"]) == ("failed", "budget")
    assert await env.edit_attempts(job_id) == [
        ("edit-alpha", 1, "failed"),  # interrupted
        ("edit-alpha", 2, "failed"),  # the only attempt left
    ]


def merge_step() -> PlanStep:
    return PlanStep(
        id="merge-alpha",
        system="alpha",
        kind="merge",
        target_branch="main",
        depends_on=["edit-alpha"],
        instructions="merge",
    )


async def test_resume_awaiting_approval_ignores_deadline_and_skips_checks(env):
    """Waiting for a human is not active time; a resumed approval goes straight to the gate."""
    cfg = two_repo_cfg(env.tmp, budgets=BudgetConfig(deadline_s=600))
    steps = [edit("alpha"), edit("beta"), merge_step()]
    r1 = env.runner(cfg, FixedPlanner(steps), [worker("apply")])
    job_id = await r1.submit("greet", owner="key:a")
    task = asyncio.create_task(r1.run(job_id))
    await until(lambda: _is(env, job_id, "awaiting_approval"))
    task.cancel()  # restart while waiting for the approval
    with pytest.raises(asyncio.CancelledError):
        await task
    job = await env.store.get_job(job_id)
    assert job["whole_passed"] and 0 < job["active_s"] < 600
    # long ago by the wall clock, far past the deadline
    await env.store._update_job(job_id, created_at=job["created_at"] - 10_000)
    checks_before = len(await env.whole_checks(job_id))
    attempts_before = [x for x in await env.edit_attempts(job_id) if x[0] != "merge-alpha"]

    gate2 = Gate(cfg, env.audit)
    r2 = env.runner(cfg, FixedPlanner(steps), [worker("apply")], gate=gate2)
    assert await r2.resume_all() == [job_id]
    await until(lambda: _step_is(env, job_id, "merge-alpha", "running"))
    assert await env.state(job_id) == "awaiting_approval"
    await gate2.approve(job_id, "merge-alpha", actor="alice")
    job = await asyncio.wait_for(r2.tasks[job_id], 60)
    assert job["state"] == "accepted", job
    assert len(await env.whole_checks(job_id)) == checks_before  # not re-run
    after = [x for x in await env.edit_attempts(job_id) if x[0] != "merge-alpha"]
    assert after == attempts_before  # no edit re-run
    repo_a = env.tmp / "repo-a"
    assert git(repo_a, "rev-parse", "main") == git(repo_a, "rev-parse", f"vsc/{job_id}/repo-a")


async def test_resume_in_verifying_reruns_whole_checks_once(env):
    marker = env.tmp / "check-ran"
    hang_first = [
        PY,
        "-c",
        (
            f"import os, sys, time\np = {str(marker)!r}\n"
            "if os.path.exists(p): sys.exit(0)\nopen(p, 'w').close()\ntime.sleep(60)"
        ),
    ]
    cfg = two_repo_cfg(env.tmp, run=hang_first)
    steps = [edit("alpha"), edit("beta")]
    crashing = CrashingStore(env.engine)
    r1 = env.runner(cfg, FixedPlanner(steps), [worker("apply")], store=crashing)
    job_id = await r1.submit("greet", owner="key:a")
    task = asyncio.create_task(r1.run(job_id))
    await until(lambda: _is(env, job_id, "verifying"))

    async def started() -> bool:
        return marker.exists()

    await until(started)
    crashing.crashed = True
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert await env.whole_checks(job_id) == []
    edits = await env.edit_attempts(job_id)

    r2 = env.runner(cfg, FixedPlanner(steps), [worker("apply")])
    assert await r2.resume_all() == [job_id]
    job = await asyncio.wait_for(r2.tasks[job_id], 60)
    assert job["state"] == "accepted", job
    assert [r["outcome"] for r in await env.whole_checks(job_id)] == ["passed"]
    assert await env.edit_attempts(job_id) == edits  # the passed edits are not re-run


async def test_submitted_and_planning_jobs_resume(env):
    repo = make_repo(env.tmp, "repo-a", REPO_FILES)
    cfg = VscConfig(systems=[sys_cfg("alpha", repo)])
    planner = FixedPlanner([edit("alpha")])
    r1 = env.runner(cfg, planner, [worker("apply")])
    fresh = await r1.submit("greet", owner="key:a")  # never started
    planned = await r1.submit("greet again", owner="key:a")
    spec = await planner.intake("greet again", cfg.systems, cfg.checks)
    await env.store.set_spec(planned, spec)  # intake done, then the gateway stopped
    await env.store.set_state(planned, "planning")

    planner2 = FixedPlanner([edit("alpha")])
    r2 = env.runner(cfg, planner2, [worker("apply")])
    assert sorted(await r2.resume_all()) == sorted([fresh, planned])
    jobs = await asyncio.wait_for(asyncio.gather(*r2.tasks.values()), 60)
    assert {j["state"] for j in jobs} == {"accepted"}
    assert planner2.intakes == 1  # only the job without a stored spec redoes intake
    assert planner2.plans == 2


class AcceptancePlanner(FixedPlanner):
    """FixedPlanner whose spec carries the given acceptance tests."""

    def __init__(self, steps, acceptance) -> None:
        super().__init__(steps)
        self._acceptance = acceptance

    async def intake(self, request, systems, checks):
        spec = await super().intake(request, systems, checks)
        return spec.model_copy(update={"acceptance": self._acceptance})


WHOLE_FILE = "tests/whole_e2e.txt"
ABSENT = [PY, "-c", f"import os, sys; sys.exit(1 if os.path.exists({WHOLE_FILE!r}) else 0)"]
PRESENT = [
    PY,
    "-c",
    (
        "import os, sys; p = lambda k: os.path.join(os.environ[k], *'tests/whole_e2e.txt'.split('/'));"
        " sys.exit(0 if open(p('VSC_WS_ALPHA')).read() == 'a' and open(p('VSC_WS_BETA')).read() == 'b'"
        " else 1)"
    ),
]


async def test_whole_system_acceptance_files_written_before_check(env):
    """A whole-system acceptance test's files (``<repo id>/<path>``) are in the named repository's
    workspace when the check runs, and not before: the per-system tests assert their absence."""
    a = make_repo(env.tmp, "repo-a", REPO_FILES)
    b = make_repo(env.tmp, "repo-b", REPO_FILES)
    cfg = VscConfig(
        systems=[
            SystemConfig(id="alpha", repo=str(a), tests=ABSENT),
            SystemConfig(id="beta", repo=str(b), tests=ABSENT),
        ],
        checks=[CheckConfig(id="whole", systems=["alpha", "beta"], run=PRESENT, timeout_s=60)],
    )
    acceptance = [
        AcceptanceTest(
            id="e2e",
            check="whole",
            files={f"repo-a/{WHOLE_FILE}": "a", f"repo-b/{WHOLE_FILE}": "b"},
        ),
    ]
    planner = AcceptancePlanner([edit("alpha"), edit("beta")], acceptance)
    r = env.runner(cfg, planner, [worker("apply")])
    job_id = await r.submit("greet systems: alpha, beta", owner="key:a")
    job = await r.run(job_id)
    assert job["state"] == "accepted", job
    assert [x["outcome"] for x in await env.whole_checks(job_id)] == ["passed"]
    for repo in ("repo-a", "repo-b"):
        with pytest.raises(subprocess.CalledProcessError):  # never committed on the job branch
            git(env.tmp / repo, "cat-file", "-e", f"vsc/{job_id}/{repo}:{WHOLE_FILE}")


async def test_whole_system_acceptance_file_outside_workspace_fails_check(env):
    cfg = two_repo_cfg(env.tmp)
    acceptance = [AcceptanceTest(id="e2e", check="whole", files={"repo-a/../../escape.txt": "x"})]
    planner = AcceptancePlanner([edit("alpha"), edit("beta")], acceptance)
    r = env.runner(cfg, planner, [worker("apply")])
    job_id = await r.submit("greet systems: alpha, beta", owner="key:a")
    job = await r.run(job_id)
    assert (job["state"], job["reason"]) == ("failed", "whole_system"), job
    reasons = [x["detail"]["reason"] for x in await env.whole_checks(job_id)]
    assert reasons and all("outside the workspace" in x for x in reasons), reasons
    assert not (env.tmp / "escape.txt").exists()


class SeeingPlanner(AcceptancePlanner):
    """Records the specs handed to plan and replan."""

    def __init__(self, steps, acceptance) -> None:
        super().__init__(steps, acceptance)
        self.seen: list = []

    async def plan(self, spec):
        self.seen.append(spec)
        return await super().plan(spec)

    async def replan(self, spec, plan, failure, steps):
        self.seen.append(spec)
        return await super().replan(spec, plan, failure, steps)


async def test_planner_sees_acceptance_names_not_contents(env):
    repo = make_repo(env.tmp, "repo-a", REPO_FILES)
    cfg = VscConfig(systems=[sys_cfg("alpha", repo)], budgets=BudgetConfig(attempts=2))
    hidden = "import unittest\n\n\nclass H(unittest.TestCase):\n    def test_no(self):\n        self.fail('HIDDEN-BODY')\n"
    acceptance = [AcceptanceTest(id="hidden", system="alpha", files={"tests/test_h.py": hidden})]
    planner = SeeingPlanner([edit("alpha")], acceptance)
    r = env.runner(cfg, planner, [worker("apply")])
    job_id = await r.submit("greet", owner="key:a")
    job = await r.run(job_id)
    # verification ran the real (failing) body ...
    assert job["state"] == "failed", job
    steps = await env.store.attempts(job_id)
    checks = json.loads(steps[-1]["result_json"])["checks"]
    assert any(c["kind"] == "reproduction_after" and not c["passed"] for c in checks)
    # ... while the planner only ever saw the file's name
    assert len(planner.seen) >= 2  # plan and at least one replan
    for spec in planner.seen:
        (t,) = spec.acceptance
        assert (t.id, t.system, t.check, t.run) == ("hidden", "alpha", None, None)
        assert t.files == {"tests/test_h.py": ""}
    assert json.loads(job["spec_json"])["acceptance"][0]["files"]["tests/test_h.py"] == hidden


class UsagePlanner(FixedPlanner):
    """Every planner call costs 10 tokens in, 5 out and 0.01."""

    def __init__(self, steps, budgets=None) -> None:
        super().__init__(steps, budgets)
        self._u = (0, 0, 0.0)

    def _spend(self) -> None:
        i, o, c = self._u
        self._u = (i + 10, o + 5, c + 0.01)

    def usage(self):
        return self._u

    async def intake(self, request, systems, checks):
        self._spend()
        return await super().intake(request, systems, checks)

    async def plan(self, spec):
        self._spend()
        return await super().plan(spec)


async def test_planner_usage_is_charged_to_the_job(env):
    cfg = two_repo_cfg(env.tmp)
    r = env.runner(cfg, UsagePlanner([edit("alpha"), edit("beta")]), [worker("apply")])
    job_id = await r.submit("greet systems: alpha, beta", owner="key:a")
    job = await r.run(job_id)
    assert job["state"] == "accepted", job
    assert (job["tokens_in"], job["tokens_out"]) == (20, 10)  # intake + plan; workers report 0
    assert job["cost"] == pytest.approx(0.02)


async def test_planner_usage_counts_against_the_budget(env):
    cfg = two_repo_cfg(env.tmp, budgets=BudgetConfig(tokens=25))
    r = env.runner(cfg, UsagePlanner([edit("alpha"), edit("beta")]), [worker("apply")])
    job_id = await r.submit("greet systems: alpha, beta", owner="key:a")
    job = await r.run(job_id)
    assert (job["state"], job["reason"]) == ("failed", "budget"), (
        job
    )  # 15 after intake, 30 after plan
    limits = [x["detail"].get("limit") for x in await env.rows("vsc.job", job_id)]
    assert "tokens" in limits
