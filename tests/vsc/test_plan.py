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


def test_parse_plan_failure():
    with pytest.raises(PlanParseError):
        parse_plan("no json here " * 50)
    with pytest.raises(PlanParseError):
        parse_plan('{"steps": []}')


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
