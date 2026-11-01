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
# The API-key principal id of the gateway's in-process planner caller (``key:vsc-internal``):
# no configured key may claim it.
RESERVED_PRINCIPAL_ID = "vsc-internal"


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
    """Policy approval of one privileged action on one system. A ``merge`` rule names the one
    target branch it approves (``target_branch``, required); other actions have none."""

    model_config = _FORBID
    system: str
    action: Literal["merge", "deploy", "migrate", "send"]
    target_branch: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def _merge_names_target(self) -> AutoApprove:
        if self.action == "merge" and self.target_branch is None:
            raise ValueError("an auto_approve rule for merge needs a target_branch")
        if self.action != "merge" and self.target_branch is not None:
            raise ValueError("target_branch is only for merge rules")
        return self

    def covers(self, system: str, action: str, target_branch: str | None) -> bool:
        return (
            self.system == system
            and self.action == action
            and (action != "merge" or self.target_branch == target_branch)
        )


class VscConfig(BaseModel):
    model_config = _FORBID
    systems: list[SystemConfig] = Field(min_length=1)
    checks: list[CheckConfig] = Field(default_factory=list)
    workers: list[WorkerConfig] = Field(default_factory=list)
    budgets: BudgetConfig = Field(default_factory=BudgetConfig)
    planner: Literal["claude", "scripted"] = "claude"
    workspace_dir: str = ".a2agw/vsc"
    auto_approve: list[AutoApprove] = Field(default_factory=list)
    # Pause after intake (``awaiting_spec``) until the spec is confirmed or edited
    # (``PUT /a2agw/admin/vsc/jobs/{id}/spec``).
    require_spec_review: bool = False
    # Principal ids (``key:ops``) whose approvals count; empty: anyone but the job's owner
    # (unless ``allow_self_approval``). Admins may always approve.
    approvers: list[Annotated[str, Field(min_length=1)]] = Field(default_factory=list)
    allow_self_approval: bool = False
    # Branches a merge step may target besides each system's ``default_branch``.
    merge_targets: list[Annotated[str, Field(min_length=1)]] = Field(default_factory=list)

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
        for n, t in enumerate(self.merge_targets):
            if t.startswith("-"):
                raise ValueError(f"merge_targets[{n}]: a branch name must not start with '-'")
        return self

    def auto_approved(self, system: str, action: str, target_branch: str | None) -> bool:
        return any(a.covers(system, action, target_branch) for a in self.auto_approve)

    def merge_target_allowed(self, system: str, target_branch: str) -> bool:
        default = next((s.default_branch for s in self.systems if s.id == system), None)
        return target_branch == default or target_branch in self.merge_targets
