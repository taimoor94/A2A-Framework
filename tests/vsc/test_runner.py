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
from a2agw.vsc.plan import Decision, Plan, PlanStep, load_plan, plan_hash
from a2agw.vsc.planner import ScriptedPlanner
from a2agw.vsc.runner import Budget, BudgetExceeded, JobRunner, RetryPolicy
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

    async def intake(self, request, systems, checks):
        spec = await super().intake(request, systems, checks)
        return spec if self._budgets is None else spec.model_copy(update={"budgets": self._budgets})

    async def plan(self, spec):
        self.plans += 1
        return Plan(steps=self._steps)


@dataclass
class Env:
    tmp: Path
    store: VscStore
    audit: AuditLog

    def runner(self, cfg, planner, workers, **kw) -> JobRunner:
        kw.setdefault("gate", Gate(cfg, self.audit))
        return JobRunner(
            store=self.store,
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


@pytest.fixture
async def env(tmp_path):
    engine = await create_engine(f"sqlite+aiosqlite:///{tmp_path / 'g.db'}")
    store, audit = VscStore(engine), AuditLog(engine)
    await store.initialize()
    await audit.initialize()
    try:
        yield Env(tmp_path, store, audit)
    finally:
        await engine.dispose()


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
    b = Budget.from_config(BudgetConfig(tokens=15, attempts=1, cost_usd=1.0), deadline=10.0)
    b.charge(5, 10, 0.5)  # exactly at the limit is fine
    with pytest.raises(BudgetExceeded) as e:
        b.charge(1, 0, 0)
    assert e.value.what == "tokens"
    b.attempt()
    with pytest.raises(BudgetExceeded, match="attempts"):
        b.attempt()
    cheap, std, strong = named("x", "c"), named("x", "s", "standard"), named("x", "g", "strong")
    p = RetryPolicy()
    assert p.next_worker([cheap, strong, std], 1, cheap) is cheap
    assert p.next_worker([cheap, strong, std], 2, cheap) is strong
    assert p.next_worker([cheap, std, strong], 2, cheap) is std
    assert p.next_worker([cheap, strong], 2, strong) is strong


def test_stored_plan_with_logged_replan_loads():
    plan = Plan(steps=[edit("alpha")])
    replan = Decision(ts=1.0, kind="replan", text="reword", plan=plan)
    plan.decisions.append(replan.model_copy(update={"plan": None}))
    loaded = load_plan(json.dumps(plan.model_dump(mode="json")))
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
    repo = make_repo(env.tmp, "repo-a", REPO_FILES)
    cfg = VscConfig(systems=[sys_cfg("alpha", repo)], budgets=BudgetConfig(attempts=1))
    r = env.runner(cfg, FixedPlanner([edit("alpha")]), [worker("fail")])
    job_id = await r.submit("greet", owner="key:a")
    job = await r.run(job_id)
    assert (job["state"], job["reason"]) == ("failed", "budget")
    assert job["attempts"] == 1
    rows = [x for x in await env.store.attempts(job_id) if x["attempt"] > 0]
    assert [(x["attempt"], x["state"]) for x in rows] == [(1, "failed")]
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
    r1 = env.runner(cfg, FixedPlanner(steps), [worker("hang_marked")])
    job_id = await r1.submit("greet", owner="key:a")
    task = asyncio.create_task(r1.run(job_id))

    async def beta_running() -> dict:
        while True:
            rows = {s["step_id"]: s for s in await env.store.steps(job_id)}
            beta = rows.get("edit-beta")
            if beta is not None and beta["state"] == "running":
                return beta
            await asyncio.sleep(0.05)

    stale = await asyncio.wait_for(beta_running(), 30)
    assert stale["attempt"] == 1
    junk = Path(stale["workspace"]) / "half-done.txt"
    junk.write_text("interrupted edit\n")
    task.cancel()  # the gateway dies mid-step
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
    cfg = two_repo_cfg(
        env.tmp, run=[PY, "-c", "import sys; sys.exit(1)"], budgets=BudgetConfig(attempts=10)
    )
    # the spec's budget is capped by the configured one: both allow the six attempts here
    planner = FixedPlanner([edit("alpha"), edit("beta")], budgets=cfg.budgets)
    r = env.runner(cfg, planner, [worker("apply")])
    job_id = await r.submit("greet", owner="key:a")
    job = await r.run(job_id)
    assert (job["state"], job["reason"]) == ("failed", "whole_system")
    decisions = json.loads(job["plan_json"])["decisions"]
    assert [d["kind"] for d in decisions] == ["plan", "retry", "escalate", "stop"]
    rows = [(x["step_id"], x["attempt"]) for x in await env.store.attempts(job_id) if x["attempt"]]
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
    while (await env.store.get_job(job_id))["state"] != "awaiting_approval":
        await asyncio.sleep(0.05)
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
    while (await env.store.get_job(job_id))["state"] != "awaiting_approval":
        await asyncio.sleep(0.05)
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
    while not await env.store.steps(job_id) or (await env.store.steps(job_id))[0]["state"] != (
        "running"
    ):
        await asyncio.sleep(0.05)
    await r.cancel(job_id, actor="key:b")
    job = await asyncio.wait_for(task, 30)
    assert job["state"] == "cancelled"
    last = (await env.rows("vsc.job", job_id))[-1]
    assert (last["outcome"], last["actor"]) == ("cancelled", "key:b")
    assert await r.resume_all() == []
