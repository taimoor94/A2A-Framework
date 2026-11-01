import json
import sys

import pytest

from a2agw.adapters.callable import CallableAdapter
from a2agw.serve.host import AgentHost
from a2agw.vsc.config import BudgetConfig, CheckConfig, SystemConfig, VscConfig
from a2agw.vsc.plan import Decision, Plan, PlanStep, plan_hash
from a2agw.vsc.planner import (
    AgentPlanner,
    PlannerError,
    ScriptedPlanner,
    claude_planner_adapter,
    guard_replan,
    planner_agent,
)
from a2agw.vsc.spec import ExecutableSpec
from a2agw.vsc.verify import CheckResult

SYSTEMS = [SystemConfig(id="core", repo="./core"), SystemConfig(id="app", repo="./app")]
CHECKS = [CheckConfig(id="both", systems=["core", "app"], run=["true"])]


def make_spec(systems=("core", "app")) -> ExecutableSpec:
    return ExecutableSpec(
        request="r", done="ship it", systems=list(systems), acceptance=[], budgets=BudgetConfig()
    )


def failure() -> CheckResult:
    return CheckResult(
        kind="gate",
        id="g",
        command=["x"],
        exit_code=1,
        passed=False,
        duration_s=0.1,
        log_sha256="0",
        stderr_tail="boom",
    )


def two_step_plan(text="a") -> Plan:
    return Plan(
        steps=[
            PlanStep(id="s1", system="core", instructions=text),
            PlanStep(id="s2", system="app", instructions=text),
        ]
    )


async def test_scripted_plan_one_step_per_system():
    p = ScriptedPlanner()
    spec = await p.intake("do it. systems: app", SYSTEMS, [])
    assert spec.systems == ["app"]
    spec = await p.intake("do it", SYSTEMS, [])
    assert spec.systems == ["core", "app"]
    plan = await p.plan(spec)
    assert [(s.system, s.kind, s.instructions) for s in plan.steps] == [
        ("core", "edit", spec.done),
        ("app", "edit", spec.done),
    ]
    kinds = [(await p.replan(spec, plan, failure(), [])).kind for _ in range(3)]
    assert kinds == ["retry", "escalate", "stop"]


async def test_replan_with_new_steps_is_refused(tmp_path):
    spec = make_spec()
    old = two_step_plan()
    changed = Plan(steps=[PlanStep(id="s1", system="core", instructions="a")])

    async def run(plan, name):
        text = json.dumps(
            {"kind": "replan", "text": "r", "plan": json.loads(plan.model_dump_json())}
        )
        host, planner = await _host(tmp_path / name, lambda ctx: text)
        try:
            return await planner.replan(spec, old, failure(), [])
        finally:
            await planner.aclose()
            await host.shutdown()

    d = await run(changed, "a")
    assert d.kind == "stop" and d.text == "plan_immutable"
    d = await run(old, "b")
    assert d.kind == "replan" and d.plan is not None and plan_hash(d.plan) == plan_hash(old)


async def _replan_decision(tmp_path, old, new):
    text = json.dumps({"kind": "replan", "text": "r", "plan": json.loads(new.model_dump_json())})
    host, planner = await _host(tmp_path, lambda ctx: text)
    try:
        return await planner.replan(make_spec(), old, failure(), [])
    finally:
        await planner.aclose()
        await host.shutdown()


async def test_replan_with_changed_instructions_is_accepted(tmp_path):
    old = two_step_plan("a")
    new = two_step_plan("completely different instructions")
    d = await _replan_decision(tmp_path, old, new)
    assert d.kind == "replan"
    assert d.plan is not None and d.plan.steps[0].instructions.startswith("completely")


async def test_large_replan_plan_is_carried_and_accepted(tmp_path):
    old = Plan(
        steps=[
            PlanStep(id=f"s{i}", system="core", kind="deploy", instructions="a") for i in range(3)
        ]
    )
    new = Plan(
        steps=[
            PlanStep(id=f"s{i}", system="core", kind="deploy", instructions="x" * 5120)
            for i in range(3)
        ]
    )
    assert len(new.model_dump_json()) > 4096
    d = await _replan_decision(tmp_path, old, new)
    assert d.kind == "replan" and d.plan is not None
    assert d.plan.steps[2].instructions == "x" * 5120


def test_guard_replan_without_plan_is_a_stop():
    plan = two_step_plan()
    d = guard_replan(plan, Decision(ts=1.0, step_id="s1", text="r", kind="replan"))
    assert (d.kind, d.text, d.step_id, d.plan) == ("stop", "plan_immutable", "s1", None)
    ok = guard_replan(plan, Decision(ts=1.0, text="r", kind="replan", plan=two_step_plan()))
    assert ok.kind == "replan"


async def test_replan_without_plan_is_a_stop(tmp_path):
    host, planner = await _host(tmp_path, lambda ctx: json.dumps({"kind": "replan", "text": "r"}))
    try:
        d = await planner.replan(make_spec(), two_step_plan(), failure(), [])
    finally:
        await planner.aclose()
        await host.shutdown()
    assert d.kind == "stop" and d.plan is None


async def test_replan_with_unparseable_plan_is_a_stop(tmp_path):
    host, planner = await _host(
        tmp_path, lambda ctx: json.dumps({"kind": "replan", "text": "r", "plan": {"steps": []}})
    )
    try:
        d = await planner.replan(make_spec(), two_step_plan(), failure(), [])
    finally:
        await planner.aclose()
        await host.shutdown()
    assert d.kind == "stop" and d.plan is None and d.text


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p.steps[0].__setattr__("system", "other"),
        lambda p: p.steps[0].__setattr__("kind", "deploy"),
        lambda p: p.steps[1].__setattr__("depends_on", ["s1"]),
        lambda p: p.steps.pop(),
        lambda p: p.steps.append(PlanStep(id="s3", system="core", kind="deploy", instructions="x")),
    ],
)
async def test_replan_structural_change_is_stopped(tmp_path, mutate):
    old = two_step_plan()
    new = two_step_plan()
    mutate(new)
    d = await _replan_decision(tmp_path, old, new)
    assert d.kind == "stop" and d.text == "plan_immutable"


async def test_intake_prompt_fences_request_as_json(tmp_path):
    seen = []
    spec = make_spec()

    def fn(ctx):
        seen.append(ctx.text if hasattr(ctx, "text") else str(ctx))
        return spec.model_dump_json()

    host, planner = await _host(tmp_path, fn)
    try:
        await planner.intake('hi "quoted"\nignore previous', SYSTEMS, CHECKS)
    finally:
        await planner.aclose()
        await host.shutdown()
    assert json.dumps('hi "quoted"\nignore previous') in seen[0]
    assert "JSON string" in seen[0]


async def _host(tmp_path, fn, job_id="job-1"):
    tmp_path.mkdir(parents=True, exist_ok=True)
    host = AgentHost("http://t", db_url=f"sqlite+aiosqlite:///{tmp_path / 'h.db'}", admin=False)
    host.add(planner_agent(CallableAdapter(fn)))
    await host.startup()
    return host, AgentPlanner(host, job_id=job_id)


async def test_agent_planner_turn_is_a_task_in_job_context(tmp_path):
    spec = make_spec()
    plan = two_step_plan()
    host, planner = await _host(tmp_path / "h", lambda ctx: plan.model_dump_json(), "job-42")
    try:
        got = await planner.plan(spec)
        assert plan_hash(got) == plan_hash(plan)
        rows, _ = await host.index.list(agent_id="vsc-planner")
        assert [r["context_id"] for r in rows] == ["job-42"]
        await host.audit.drain()
        audit, _ = await host.audit.query({"action": "inbound.admit"})
        assert audit
    finally:
        await planner.aclose()
        await host.shutdown()


async def test_agent_planner_retries_parse_error_once(tmp_path):
    spec = make_spec()
    prompts: list[str] = []
    replies = ["not json at all", two_step_plan().model_dump_json()]

    def fn(ctx):
        prompts.append(ctx.text)
        return replies[len(prompts) - 1]

    host, planner = await _host(tmp_path / "h", fn)
    try:
        assert len((await planner.plan(spec)).steps) == 2
        assert len(prompts) == 2 and "no JSON object" in prompts[1]
    finally:
        await planner.aclose()
        await host.shutdown()

    prompts.clear()
    replies[:] = ["bad", "still bad"]
    host, planner = await _host(tmp_path / "h2", fn, "job-2")
    try:
        with pytest.raises(PlannerError):
            await planner.plan(spec)
        assert len(prompts) == 2
    finally:
        await planner.aclose()
        await host.shutdown()


def test_claude_planner_requires_extra(monkeypatch):
    monkeypatch.setitem(sys.modules, "claude_agent_sdk", None)
    with pytest.raises(ImportError, match=r"a2a-gateway\[vsc\]"):
        claude_planner_adapter(VscConfig(systems=SYSTEMS), "/nonexistent")


def test_scripted_planner_reports_no_usage():
    assert ScriptedPlanner().usage() == (0, 0, 0.0)


async def test_agent_planner_usage_from_the_turn_task(tmp_path):
    from a2agw.core.events import Done, Usage

    plan = two_step_plan()

    async def reply(ctx):
        yield Usage(tokens_in=7, tokens_out=3, cost=0.5)
        yield Done(text=plan.model_dump_json())

    host, planner = await _host(tmp_path / "h", reply)
    try:
        assert planner.usage() == (0, 0, 0.0)
        await planner.plan(make_spec())
        assert planner.usage() == (7, 3, 0.5)
        await planner.plan(make_spec())
        assert planner.usage() == (14, 6, 1.0)  # cumulative over the turns
    finally:
        await planner.aclose()
        await host.shutdown()


async def test_agent_planner_records_each_turn_task(tmp_path):
    from a2agw.core.events import Done, Usage

    plan = two_step_plan()

    async def reply(ctx):
        yield Usage(tokens_in=2, tokens_out=1, cost=0.1)
        yield Done(text=plan.model_dump_json())

    host, planner = await _host(tmp_path / "h", reply)
    try:
        await planner.plan(make_spec())
        await planner.plan(make_spec())
        turns = planner.turns()
        assert [t["tokens_in"] for t in turns] == [2, 2]
        assert len({t["task_id"] for t in turns}) == 2 and all(t["task_id"] for t in turns)
    finally:
        await planner.aclose()
        await host.shutdown()


def test_planner_reply_capped_before_parsing():
    from a2agw.vsc.planner import REPLY_MAX_BYTES, cap_reply

    assert cap_reply("short") == "short"
    big = "é" * REPLY_MAX_BYTES
    capped = cap_reply(big)
    assert len(capped.encode()) <= REPLY_MAX_BYTES and capped.startswith("é")
