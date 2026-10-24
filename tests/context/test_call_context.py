import pytest

from a2agw.context.call_context import (
    METADATA_KEY,
    BudgetExceeded,
    CallContext,
    CallContextViolation,
    CycleDetected,
    DeadlineExceeded,
    HopLimitExceeded,
    current_call,
    use_call,
)

NOW = 1_000_000.0


def test_new_defaults():
    cc = CallContext.new("a", deadline_s=10)
    assert cc.root_agent == "a" and cc.path == ("a",) and cc.hop == 0
    assert len(cc.origin) == 32 and cc.traceparent is None
    assert cc.deadline is not None and cc.deadline > 0
    assert CallContext.new("a").deadline is None


def test_round_trip():
    cc = CallContext(
        origin="o", root_agent="a", hop=2, max_hops=5, path=("a", "b"), deadline=NOW + 5,
        traceparent="00-x-y-01", on_behalf_of="u", max_calls=10, calls_used=3,
    )
    md = cc.to_metadata()
    assert md[METADATA_KEY]["path"] == ["a", "b"]
    assert CallContext.from_metadata(md) == cc


def test_from_metadata_absent_and_float_ints():
    assert CallContext.from_metadata({}) is None
    cc = CallContext.from_metadata(
        {METADATA_KEY: {"origin": "o", "root_agent": "a", "hop": 1.0, "max_hops": 8.0,
                        "path": ["a"]}}
    )
    assert cc is not None and cc.hop == 1 and isinstance(cc.hop, int)


@pytest.mark.parametrize(
    "bad",
    [
        "notadict",
        {"root_agent": "a"},
        {"origin": "o"},
        {"origin": "o", "root_agent": "a", "hop": "x"},
        {"origin": "o", "root_agent": "a", "hop": 1.5},
        {"origin": "o", "root_agent": "a", "path": "abc"},
        {"origin": "o", "root_agent": "a", "path": [1]},
        {"origin": "o", "root_agent": "a", "deadline": "soon"},
        {"origin": 5, "root_agent": "a"},
    ],
)
def test_malformed_metadata_raises(bad):
    with pytest.raises(ValueError):
        CallContext.from_metadata({METADATA_KEY: bad})


def test_clamp_caps_forged_values():
    cc = CallContext(origin="o", root_agent="a", hop=-5, max_hops=1000, deadline=NOW + 86400)
    out = cc.clamp(local_max_hops=8, local_max_deadline_s=60, now=NOW)
    assert out.hop == 0 and out.max_hops == 8
    assert out.deadline is not None and out.deadline <= NOW + 60


def test_clamp_sets_missing_deadline_and_keeps_tighter():
    cc = CallContext(origin="o", root_agent="a")
    assert cc.clamp(local_max_hops=8, local_max_deadline_s=60, now=NOW).deadline == NOW + 60
    tight = CallContext(origin="o", root_agent="a", deadline=NOW + 5, max_hops=3)
    out = tight.clamp(local_max_hops=8, local_max_deadline_s=60, now=NOW)
    assert out.deadline == NOW + 5 and out.max_hops == 3


def test_child_increments_and_appends():
    cc = CallContext(origin="o", root_agent="a", path=("a",))
    ch = cc.child("b")
    assert (ch.hop, ch.calls_used, ch.path) == (1, 1, ("a", "b"))
    assert cc.hop == 0 and cc.path == ("a",)


def test_cycle_detected():
    cc = CallContext(origin="o", root_agent="a", path=("a", "b"))
    with pytest.raises(CycleDetected):
        cc.check_admit("a")
    cc.check_admit("a", allow_reentry=True)
    cc.check_admit("c")


def test_hop_limit():
    cc = CallContext(origin="o", root_agent="a", hop=3, max_hops=3)
    with pytest.raises(HopLimitExceeded) as ei:
        cc.check_admit("z")
    assert isinstance(ei.value, CallContextViolation)


def test_deadline_exceeded():
    cc = CallContext(origin="o", root_agent="a", deadline=NOW - 1)
    assert cc.remaining(NOW) == -1
    with pytest.raises(DeadlineExceeded):
        cc.check_admit("z", now=NOW)
    assert CallContext(origin="o", root_agent="a").remaining(NOW) is None


def test_budget_exceeded():
    cc = CallContext(origin="o", root_agent="a", max_calls=2, calls_used=3)
    with pytest.raises(BudgetExceeded):
        cc.check_admit("z")
    CallContext(origin="o", root_agent="a", max_calls=2, calls_used=2).check_admit("z")


def test_use_call_sets_and_resets():
    cc = CallContext.new("a")
    assert current_call.get() is None
    with use_call(cc):
        assert current_call.get() is cc
    assert current_call.get() is None


@pytest.mark.parametrize(
    "bad",
    [
        {"deadline": float("nan")},
        {"deadline": float("inf")},
        {"deadline": float("-inf")},
        {"deadline": 10**400},
        {"hop": True},
        {"max_calls": -1},
        {"path": {"a": 1}},
        {"path": [f"a{i}" for i in range(65)]},
        {"path": ["x" * 257]},
        {"origin": "x" * 257},
        {"root_agent": "x" * 257},
    ],
)
def test_adversarial_metadata_raises(bad):
    base = {"origin": "o", "root_agent": "a"}
    with pytest.raises(ValueError):
        CallContext.from_metadata({METADATA_KEY: {**base, **bad}})


@pytest.mark.parametrize("md", [None, "x", 5, ["a"]])
def test_non_mapping_md_raises(md):
    with pytest.raises(ValueError):
        CallContext.from_metadata(md)


def test_64_entry_path_ok():
    md = {METADATA_KEY: {"origin": "o", "root_agent": "a", "path": ["p"] * 64}}
    assert len(CallContext.from_metadata(md).path) == 64


def test_clamp_replaces_nan_deadline_and_check_fails_closed():
    cc = CallContext(origin="o", root_agent="a", deadline=float("nan"))
    assert cc.clamp(local_max_hops=8, local_max_deadline_s=60, now=NOW).deadline == NOW + 60
    with pytest.raises(DeadlineExceeded):
        cc.check_admit("z", now=NOW)


def test_clamp_floors_calls_used_and_caps_max_calls():
    cc = CallContext(origin="o", root_agent="a", calls_used=-9, max_calls=1000)
    out = cc.clamp(local_max_hops=8, local_max_deadline_s=60, now=NOW, local_max_calls=20)
    assert out.calls_used == 0 and out.max_calls == 20
    none = CallContext(origin="o", root_agent="a")
    assert none.clamp(
        local_max_hops=8, local_max_deadline_s=60, now=NOW, local_max_calls=20
    ).max_calls == 20
    assert none.clamp(local_max_hops=8, local_max_deadline_s=60, now=NOW).max_calls is None
