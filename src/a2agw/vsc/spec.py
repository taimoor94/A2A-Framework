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


def validate_against(spec: ExecutableSpec, cfg: VscConfig) -> None:
    systems = {s.id for s in cfg.systems}
    checks = {c.id for c in cfg.checks}

    def system(sid: str) -> None:
        if sid not in systems:
            raise ValueError(f"unknown system '{sid}'")

    for sid in spec.systems:
        system(sid)
    for test in spec.acceptance:
        if test.system is not None:
            system(test.system)
        if test.check is not None and test.check not in checks:
            raise ValueError(f"unknown check '{test.check}'")
    for contract in spec.contracts:
        for sid in contract.systems:
            system(sid)
