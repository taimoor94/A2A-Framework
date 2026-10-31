"""The ``vsc:`` configuration section. Pure pydantic models with no further dependencies, so
``a2agw.config`` can import them without pulling in the rest of the package."""

from __future__ import annotations

from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_FORBID = ConfigDict(extra="forbid")
_ID = r"^[a-z0-9][a-z0-9-]{0,62}$"
_Command = Annotated[list[Annotated[str, Field(min_length=1)]], Field(min_length=1)]
_URL_SCHEMES = {"http", "https", "ssh", "git"}


class SystemConfig(BaseModel):
    model_config = _FORBID
    id: str = Field(pattern=_ID)
    repo: str = Field(min_length=1)
    path: str = "."
    default_branch: str = Field(default="main", min_length=1)
    gate: _Command | None = None
    tests: _Command | None = None
    index: list[str] = Field(default_factory=list)

    @field_validator("repo")
    @classmethod
    def _local_repo(cls, v: str) -> str:
        at, colon = v.find("@"), v.find(":")
        if urlsplit(v).scheme in _URL_SCHEMES or (0 <= at < colon):
            raise ValueError("clone URLs are Phase 5b")
        return v


class CheckConfig(BaseModel):
    model_config = _FORBID
    id: str = Field(pattern=_ID)
    systems: list[str] = Field(min_length=2)
    run: _Command
    timeout_s: float = Field(default=1800.0, gt=0)


class BudgetConfig(BaseModel):
    model_config = _FORBID
    tokens: int = Field(default=2_000_000, gt=0)
    cost_usd: float = Field(default=50.0, gt=0)
    attempts: int = Field(default=3, gt=0)
    deadline_s: float = Field(default=7200.0, gt=0)


class WorkerConfig(BaseModel):
    model_config = _FORBID
    id: str = Field(pattern=_ID)
    command: _Command
    model: str = ""
    cost_class: Literal["cheap", "standard", "strong"] = "standard"
    reports_usage: bool = True
    env: dict[str, str] = Field(default_factory=dict)
    timeout_s: float = Field(default=1800.0, gt=0)


class AutoApprove(BaseModel):
    model_config = _FORBID
    system: str
    action: Literal["merge", "deploy", "migrate", "send"]


class VscConfig(BaseModel):
    model_config = _FORBID
    systems: list[SystemConfig] = Field(min_length=1)
    checks: list[CheckConfig] = Field(default_factory=list)
    workers: list[WorkerConfig] = Field(default_factory=list)
    budgets: BudgetConfig = Field(default_factory=BudgetConfig)
    planner: Literal["claude", "scripted"] = "claude"
    workspace_dir: str = ".a2agw/vsc"
    auto_approve: list[AutoApprove] = Field(default_factory=list)

    @model_validator(mode="after")
    def _refs_exist(self) -> VscConfig:
        ids = [s.id for s in self.systems]
        dup = sorted({i for i in ids if ids.count(i) > 1})
        if dup:
            raise ValueError(f"systems: duplicate id {dup[0]!r}")
        for n, c in enumerate(self.checks):
            for s in c.systems:
                if s not in ids:
                    raise ValueError(f"checks[{n}].systems: unknown system {s!r}")
        for n, a in enumerate(self.auto_approve):
            if a.system not in ids:
                raise ValueError(f"auto_approve[{n}].system: unknown system {a.system!r}")
        return self
