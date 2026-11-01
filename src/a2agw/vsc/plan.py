"""The plan: the coordinator's fixed set of steps. Its hash (structure only) is what makes
plan-then-execute enforceable; instructions may be reworded and decisions are an append-only
log, so both are deliberately excluded from it."""

from __future__ import annotations

import hashlib
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from a2agw.ops.audit import canonical_json
from a2agw.vsc.config import VscConfig
from a2agw.vsc.spec import ExecutableSpec, uncovered_systems

_FORBID = ConfigDict(extra="forbid")
_FENCE = re.compile(r"```[^\n`]*\n(.*?)```", re.DOTALL)
# A plain branch name (git check-ref-format is applied again at merge time).
_BRANCH = re.compile(r"[A-Za-z0-9._/-]{1,200}")

StepKind = Literal["edit", "merge", "deploy", "migrate", "send"]
PRIVILEGED_KINDS: frozenset[str] = frozenset({"merge", "deploy", "migrate", "send"})
# 16 KiB / 4 KiB, counted in characters.
INSTRUCTIONS_MAX_CHARS = 16384
DECISION_MAX_CHARS = 4096


class PlanParseError(ValueError):
    pass


class PlanStep(BaseModel):
    model_config = _FORBID
    id: str
    system: str
    kind: StepKind = "edit"
    depends_on: list[str] = Field(default_factory=list)
    contracts: list[str] = Field(default_factory=list)
    instructions: str = Field(max_length=INSTRUCTIONS_MAX_CHARS)
    target_branch: str | None = None  # merge only

    @model_validator(mode="after")
    def _merge_needs_target(self) -> PlanStep:
        if self.kind == "merge" and not self.target_branch:
            raise ValueError(f"merge step '{self.id}' needs a target_branch")
        if self.kind != "merge" and self.target_branch is not None:
            raise ValueError("target_branch is only for merge steps")
        return self


class Decision(BaseModel):
    model_config = _FORBID
    ts: float
    step_id: str | None = None
    text: str = Field(max_length=DECISION_MAX_CHARS)
    kind: Literal["plan", "retry", "escalate", "replan", "gate", "stop"]
    # Only a replan decision carries a plan (text is then a short reason). A replan in the job's
    # decision log has none: its plan replaced the stored plan. ``guard_replan`` turns a
    # plan-less replan from the planner into a stop.
    plan: Plan | None = None

    @model_validator(mode="after")
    def _plan_only_for_replan(self) -> Decision:
        if self.kind != "replan" and self.plan is not None:
            raise ValueError("plan is only for replan decisions")
        return self


class Plan(BaseModel):
    model_config = _FORBID
    steps: list[PlanStep] = Field(min_length=1)
    decisions: list[Decision] = Field(default_factory=list)

    @model_validator(mode="after")
    def _structure(self) -> Plan:
        ids: set[str] = set()
        for s in self.steps:
            if s.id in ids:
                raise ValueError(f"duplicate step id '{s.id}'")
            ids.add(s.id)
        for s in self.steps:
            for dep in s.depends_on:
                if dep not in ids:
                    raise ValueError(f"step '{s.id}' depends on unknown step '{dep}'")
        edit_systems: set[str] = set()
        for s in self.steps:
            if s.kind == "edit":
                if s.system in edit_systems:
                    raise ValueError(f"more than one edit step for system '{s.system}'")
                edit_systems.add(s.system)
        if sum(map(len, _layers(self.steps))) != len(self.steps):
            raise ValueError("plan has a dependency cycle")
        return self


Decision.model_rebuild()


def _layers(steps: list[PlanStep]) -> list[list[PlanStep]]:
    """Kahn layers; stops short (fewer steps than input) when there is a cycle."""
    remaining = list(steps)
    done: set[str] = set()
    layers: list[list[PlanStep]] = []
    while remaining:
        layer = [s for s in remaining if all(d in done for d in s.depends_on)]
        if not layer:
            break
        layers.append(layer)
        done.update(s.id for s in layer)
        remaining = [s for s in remaining if s.id not in done]
    return layers


def order(plan: Plan) -> list[list[PlanStep]]:
    return _layers(plan.steps)


_STRUCTURAL = ("id", "system", "kind", "depends_on", "contracts", "target_branch")


def plan_hash(plan: Plan) -> str:
    """Hash of the plan's structure only: per step id, system, kind, depends_on, contracts and
    target_branch. Instructions and decisions are excluded, so a replan may reword instructions
    but never change the steps."""
    payload = {"steps": [{k: getattr(s, k) for k in _STRUCTURAL} for s in plan.steps]}
    return hashlib.sha256(canonical_json(payload).encode()).hexdigest()


def validate_plan(plan: Plan, spec: ExecutableSpec, cfg: VscConfig | None = None) -> None:
    """ValueError unless the plan fits the spec (and, given ``cfg``, the configuration),
    failing closed: every step targets a system of the spec; no edit step depends on a
    privileged step; a merge targets a plain branch name. With ``cfg``: a merge targets the
    system's ``default_branch`` or one of ``merge_targets``; the edited systems (two or more)
    are covered by whole-system checks; every acceptance test will run (a per-system one's
    system is edited, a whole-system one's check is over an edited system)."""
    kinds = {s.id: s.kind for s in plan.steps}
    for s in plan.steps:
        if s.system not in spec.systems:
            raise ValueError(f"step '{s.id}' targets system '{s.system}' not in the spec")
        if s.kind == "edit":
            for dep in s.depends_on:
                if kinds.get(dep) in PRIVILEGED_KINDS:
                    raise ValueError(f"edit step '{s.id}' depends on privileged step '{dep}'")
        if s.target_branch is not None and (
            s.target_branch.startswith("-") or not _BRANCH.fullmatch(s.target_branch)
        ):
            raise ValueError(f"merge step '{s.id}': invalid target_branch")
    if cfg is None:
        return
    for s in plan.steps:
        if s.kind == "merge" and not cfg.merge_target_allowed(s.system, s.target_branch or ""):
            raise ValueError(
                f"merge step '{s.id}' targets '{s.target_branch}', which is neither the "
                "system's default_branch nor in merge_targets"
            )
    edited = [s.system for s in plan.steps if s.kind == "edit"]
    missing = uncovered_systems(edited, cfg)
    if missing:
        raise ValueError(
            "no whole-system check covers edited system(s) "
            + ", ".join(repr(s) for s in missing)
        )
    checks = {c.id: c for c in cfg.checks}
    for test in spec.acceptance:
        if test.system is not None and test.system not in edited:
            raise ValueError(f"acceptance test '{test.id}': system '{test.system}' is not edited")
        check = checks.get(test.check) if test.check is not None else None
        if test.check is not None and (check is None or not set(check.systems) & set(edited)):
            raise ValueError(f"acceptance test '{test.id}': check '{test.check}' would not run")


def _balanced_at(text: str, start: int) -> str | None:
    """The balanced `{...}` object starting at text[start], or None if it never closes."""
    depth, in_str, esc = 0, False, False
    for i in range(start, len(text)):
        c = text[i]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def json_candidates(text: str):
    """Fenced blocks (any info string) in order, then the whole text; yield each `{` object."""
    segments = [m.group(1) for m in _FENCE.finditer(text)] + [text]
    for seg in segments:
        start = seg.find("{")
        while start != -1:
            obj = _balanced_at(seg, start)
            if obj is not None:
                yield obj
            start = seg.find("{", start + 1)


def _error_detail(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        parts = []
        for e in exc.errors():
            loc = ".".join(str(x) for x in e["loc"])
            parts.append(f"{loc}: {e['msg']}" if loc else str(e["msg"]))
        return "; ".join(parts)[:200]
    return (str(exc) or type(exc).__name__).splitlines()[0][:200]


def parse_plan(text: str) -> Plan:
    semantic: str | None = None  # valid JSON, invalid plan: the most informative error
    syntactic: str | None = None
    for candidate in json_candidates(text):
        try:
            return Plan.model_validate_json(candidate)
        except ValidationError as exc:
            msg = f"invalid plan: {_error_detail(exc)}"
            if exc.errors()[0]["type"] == "json_invalid":
                syntactic = syntactic or msg
            else:
                semantic = semantic or msg
    found = semantic or syntactic
    if found is None:
        raise PlanParseError(f"no JSON object found in: {text[:200]!r}")
    raise PlanParseError(found)
