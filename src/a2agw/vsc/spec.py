"""The executable specification: what a job must achieve, which later phases plan against and
verify. Pure data plus a stable content hash."""

from __future__ import annotations

import hashlib

from pydantic import BaseModel, ConfigDict, Field, model_validator

from a2agw.ops.audit import canonical_json
from a2agw.vsc.config import BudgetConfig, VscConfig

_FORBID = ConfigDict(extra="forbid")
# 64 KiB, counted in characters (not bytes).
REQUEST_MAX_CHARS = 65536


class AcceptanceTest(BaseModel):
    model_config = _FORBID
    id: str
    system: str | None = None  # None = whole-system test, which names a check
    check: str | None = None
    files: dict[str, str] = Field(default_factory=dict)  # relative path -> content
    run: list[str] | None = None  # defaults to the system's ``tests``

    @model_validator(mode="after")
    def _system_xor_check(self) -> AcceptanceTest:
        if self.system is None and self.check is None:
            raise ValueError("whole-system acceptance test needs a check id")
        if self.system is not None and self.check is not None:
            raise ValueError("a per-system acceptance test must not set a check id")
        return self


class Contract(BaseModel):
    model_config = _FORBID
    name: str
    systems: list[str]
    path: str | None = None
    text: str | None = None


class ExecutableSpec(BaseModel):
    model_config = _FORBID
    request: str = Field(max_length=REQUEST_MAX_CHARS)
    done: str
    systems: list[str] = Field(min_length=1)
    acceptance: list[AcceptanceTest]
    contracts: list[Contract] = Field(default_factory=list)
    budgets: BudgetConfig


def spec_hash(spec: ExecutableSpec) -> str:
    return hashlib.sha256(canonical_json(spec.model_dump(mode="json")).encode()).hexdigest()


def uncovered_systems(systems: list[str], cfg: VscConfig) -> list[str]:
    """Of ``systems`` (two or more), those no configured check covers together with another of
    them: a change across systems must have a whole-system check over each of them. Empty for
    a single system."""
    if len(set(systems)) < 2:
        return []
    wanted = set(systems)
    covered: set[str] = set()
    for check in cfg.checks:
        inside = wanted & set(check.systems)
        if len(inside) >= 2:
            covered |= inside
    return [s for s in systems if s not in covered]


def validate_against(spec: ExecutableSpec, cfg: VscConfig) -> None:
    """ValueError unless the spec fits the configuration, failing closed: known systems and
    checks only; acceptance ids unique; a per-system acceptance test names a system of the
    spec, a whole-system one a check over at least one system of the spec; and a spec of two
    or more systems has whole-system checks covering every one of them."""
    systems = {s.id for s in cfg.systems}
    checks = {c.id: c for c in cfg.checks}

    def system(sid: str) -> None:
        if sid not in systems:
            raise ValueError(f"unknown system '{sid}'")

    for sid in spec.systems:
        system(sid)
    seen: set[str] = set()
    for test in spec.acceptance:
        if test.id in seen:
            raise ValueError(f"duplicate acceptance test id '{test.id}'")
        seen.add(test.id)
        if test.system is not None:
            system(test.system)
            if test.system not in spec.systems:
                raise ValueError(
                    f"acceptance test '{test.id}' names system '{test.system}' not in the spec"
                )
        if test.check is not None:
            if test.check not in checks:
                raise ValueError(f"unknown check '{test.check}'")
            if not set(checks[test.check].systems) & set(spec.systems):
                raise ValueError(
                    f"acceptance test '{test.id}' names check '{test.check}' over none of "
                    "the spec's systems"
                )
    for contract in spec.contracts:
        for sid in contract.systems:
            system(sid)
    missing = uncovered_systems(spec.systems, cfg)
    if missing:
        raise ValueError(
            "no whole-system check covers system(s) " + ", ".join(repr(s) for s in missing)
        )
