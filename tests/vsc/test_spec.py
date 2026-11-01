import pytest
from pydantic import ValidationError

from a2agw.vsc.config import BudgetConfig
from a2agw.vsc.spec import AcceptanceTest, Contract, ExecutableSpec, spec_hash, validate_against

from .conftest import vsc_config


def _spec(**over):
    base = {
        "request": "make it so",
        "done": "it is so",
        "systems": ["core"],
        "acceptance": [{"id": "a1", "system": "core"}],
        "budgets": BudgetConfig(),
    }
    base.update(over)
    return ExecutableSpec.model_validate(base)


def test_spec_hash_is_stable_across_key_order():
    a = _spec(acceptance=[{"id": "a1", "system": "core", "files": {"a": "1", "b": "2"}}])
    b = _spec(acceptance=[{"files": {"b": "2", "a": "1"}, "system": "core", "id": "a1"}])
    assert spec_hash(a) == spec_hash(b)
    assert len(spec_hash(a)) == 64
    assert spec_hash(a) != spec_hash(_spec(done="other"))


def test_request_over_64k_rejected():
    _spec(request="x" * 65536)
    with pytest.raises(ValidationError):
        _spec(request="x" * 65537)


def test_validate_unknown_system():
    cfg = vsc_config()
    validate_against(_spec(systems=["core", "node-coder"]), cfg)
    with pytest.raises(ValueError, match="unknown system 'nope'"):
        validate_against(_spec(systems=["nope"]), cfg)
    with pytest.raises(ValueError, match="unknown system 'zzz'"):
        validate_against(_spec(acceptance=[{"id": "a", "system": "zzz"}]), cfg)
    with pytest.raises(ValueError, match="unknown system 'q'"):
        validate_against(_spec(contracts=[Contract(name="c", systems=["q"], path=None, text="t")]), cfg)


def test_validate_unknown_check():
    cfg = vsc_config()
    validate_against(_spec(acceptance=[{"id": "a", "system": None, "check": "sidecar"}]), cfg)
    with pytest.raises(ValueError, match="unknown check 'y'"):
        validate_against(_spec(acceptance=[{"id": "a", "system": None, "check": "y"}]), cfg)


def test_whole_system_acceptance_needs_check_id():
    with pytest.raises(ValidationError, match="whole-system acceptance test needs a check id"):
        AcceptanceTest(id="a", system=None)
    with pytest.raises(ValidationError):
        AcceptanceTest(id="a", system="core", check="sidecar")



def test_validate_against_fails_closed():
    from a2agw.vsc.config import CheckConfig, SystemConfig, VscConfig

    cfg = VscConfig(
        systems=[
            SystemConfig(id="a", repo="./a"),
            SystemConfig(id="b", repo="./b"),
            SystemConfig(id="c", repo="./c"),
        ],
        checks=[CheckConfig(id="ab", systems=["a", "b"], run=["true"])],
    )

    def spec(systems, acceptance=()):
        return ExecutableSpec(
            request="r",
            done="d",
            systems=systems,
            acceptance=list(acceptance),
            budgets=BudgetConfig(),
        )

    validate_against(spec(["a"]), cfg)
    validate_against(spec(["a", "b"]), cfg)
    with pytest.raises(ValueError, match="no whole-system check covers system"):
        validate_against(spec(["a", "c"]), cfg)
    with pytest.raises(ValueError, match="not in the spec"):
        validate_against(spec(["a"], [AcceptanceTest(id="t", system="b")]), cfg)
    with pytest.raises(ValueError, match="duplicate acceptance test id"):
        validate_against(
            spec(["a"], [AcceptanceTest(id="t", system="a"), AcceptanceTest(id="t", system="a")]),
            cfg,
        )
    with pytest.raises(ValueError, match="none of the spec's systems"):
        validate_against(spec(["c"], [AcceptanceTest(id="w", check="ab")]), cfg)
