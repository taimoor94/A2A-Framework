import pytest

from a2agw.vsc.config import BudgetConfig
from a2agw.vsc.plan import (
    Decision,
    Plan,
    PlanParseError,
    PlanStep,
    order,
    parse_plan,
    plan_hash,
    validate_plan,
)
from a2agw.vsc.spec import ExecutableSpec


def step(id, system="a", kind="edit", deps=(), **kw):
    return PlanStep(id=id, system=system, kind=kind, depends_on=list(deps), instructions="do", **kw)


def test_plan_hash_ignores_decisions():
    p = Plan(steps=[step("s1")])
    h = plan_hash(p)
    p2 = Plan(steps=[step("s1")], decisions=[Decision(ts=1.0, step_id=None, text="x", kind="plan")])
    assert plan_hash(p2) == h
    assert plan_hash(Plan(steps=[step("s2")])) != h


def test_decision_plan_only_for_replan():
    plan = Plan(steps=[step("s1")])
    assert Decision(ts=1.0, text="why", kind="replan", plan=plan).plan == plan
    # a logged replan carries no plan (its plan replaced the stored one)
    assert Decision(ts=1.0, text="why", kind="replan").plan is None
    with pytest.raises(ValueError, match="plan"):
        Decision(ts=1.0, text="why", kind="retry", plan=plan)
    assert Decision(ts=1.0, text="why", kind="stop").plan is None


def test_plan_hash_ignores_instructions():
    a = Plan(steps=[step("s1")])
    b = Plan(steps=[PlanStep(id="s1", system="a", instructions="something else entirely")])
    assert plan_hash(a) == plan_hash(b)
    assert plan_hash(Plan(steps=[step("s1", system="b")])) != plan_hash(a)
    assert plan_hash(Plan(steps=[step("s1", kind="deploy")])) != plan_hash(a)
    assert plan_hash(Plan(steps=[step("s1", contracts=["c"])])) != plan_hash(a)


def test_cycle_rejected():
    with pytest.raises(ValueError, match="cycle"):
        Plan(steps=[step("a1", "a", deps=["b1"]), step("b1", "b", deps=["a1"])])


def test_two_edit_steps_same_system_rejected():
    with pytest.raises(ValueError, match="edit"):
        Plan(steps=[step("s1"), step("s2")])


def test_parse_plan_from_fenced_json():
    text = 'Here:\n```json\n{"steps": [{"id": "s1", "system": "a", "instructions": "go {x}"}]}\n```\nok'
    assert parse_plan(text).steps[0].id == "s1"


def test_parse_plan_bare_json_with_prose():
    text = 'Plan follows {"steps": [{"id": "s1", "system": "a", "instructions": "a } b"}]} thanks'
    assert parse_plan(text).steps[0].instructions == "a } b"


PLAN = '{"steps": [{"id": "s1", "system": "a", "instructions": "go"}]}'


def test_parse_plan_failure():
    with pytest.raises(PlanParseError):
        parse_plan("no json here " * 50)
    with pytest.raises(PlanParseError, match="steps"):
        parse_plan('{"steps": []}')
    with pytest.raises(PlanParseError, match="system"):
        parse_plan('{"steps": [{"id": "s1", "instructions": "x"}]}')
    with pytest.raises(PlanParseError, match="target_branch"):
        parse_plan('{"steps": [{"id": "s1", "system": "a", "kind": "merge", "instructions": "x"}]}')


def test_parse_plan_error_does_not_leak_input():
    with pytest.raises(PlanParseError) as ei:
        parse_plan('{"steps": [{"id": "s1", "system": "a", "instructions": "x", "bogus": "SECRETVALUE"}]}')
    assert "SECRETVALUE" not in str(ei.value)
    assert len(str(ei.value)) <= 230


def test_parse_plan_prose_balanced_braces_before_plan():
    assert parse_plan("use {x} here, then " + PLAN).steps[0].id == "s1"


def test_parse_plan_unclosed_brace_in_prose():
    assert parse_plan("a stray { in prose\n" + PLAN).steps[0].id == "s1"


def test_parse_plan_second_fence():
    text = "```json\n{\"note\": 1}\n```\nand\n```json\n" + PLAN + "\n```"
    assert parse_plan(text).steps[0].id == "s1"


def test_parse_plan_bare_and_uppercase_fences():
    assert parse_plan("```\n" + PLAN + "\n```").steps[0].id == "s1"
    assert parse_plan("```JSON\n" + PLAN + "\n```").steps[0].id == "s1"


def test_target_branch_only_for_merge():
    with pytest.raises(ValueError, match="needs a target_branch"):
        step("m1", kind="merge")
    with pytest.raises(ValueError, match="target_branch is only for merge steps"):
        step("e1", target_branch="main")


def test_self_dependency_rejected():
    with pytest.raises(ValueError, match="cycle"):
        Plan(steps=[step("a1", deps=["a1"])])


def test_unknown_dependency_rejected():
    with pytest.raises(ValueError, match="unknown step 'zz'"):
        Plan(steps=[step("a1", deps=["zz"])])


def test_order_layers():
    p = Plan(
        steps=[
            step("c1", "c", deps=["a1", "b1"]),
            step("a1", "a"),
            step("b1", "b"),
            step("m1", "a", kind="merge", deps=["a1"], target_branch="main"),
        ]
    )
    assert [[s.id for s in layer] for layer in order(p)] == [["a1", "b1"], ["c1", "m1"]]


def test_validate_plan_unknown_system():
    spec = ExecutableSpec(request="r", done="d", systems=["a"], acceptance=[], budgets=BudgetConfig())
    validate_plan(Plan(steps=[step("s1", "a")]), spec)
    with pytest.raises(ValueError, match="s2"):
        validate_plan(Plan(steps=[step("s1", "a"), step("s2", "zz")]), spec)
