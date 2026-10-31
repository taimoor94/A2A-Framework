"""The plan: the coordinator's fixed set of steps. Its hash is what makes plan-then-execute
enforceable; decisions are an append-only log and are deliberately excluded from it."""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from a2agw.ops.audit import canonical_json
from a2agw.vsc.spec import ExecutableSpec

_FORBID = ConfigDict(extra="forbid")

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
        return self


class Decision(BaseModel):
    model_config = _FORBID
    ts: float
    step_id: str | None = None
    text: str = Field(max_length=DECISION_MAX_CHARS)
    kind: Literal["plan", "retry", "escalate", "replan", "gate", "stop"]


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


def plan_hash(plan: Plan) -> str:
    payload = {"steps": [s.model_dump(mode="json") for s in plan.steps]}
    return hashlib.sha256(canonical_json(payload).encode()).hexdigest()


def validate_plan(plan: Plan, spec: ExecutableSpec) -> None:
    for s in plan.steps:
        if s.system not in spec.systems:
            raise ValueError(f"step '{s.id}' targets system '{s.system}' not in the spec")


def _first_object(text: str) -> str | None:
    start = text.find("{")
    while start != -1:
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
    return None


def parse_plan(text: str) -> Plan:
    candidate: str | None = None
    fence = text.find("```json")
    if fence != -1:
        end = text.find("```", fence + 7)
        if end != -1:
            candidate = _first_object(text[fence + 7 : end])
    if candidate is None:
        candidate = _first_object(text)
    if candidate is None:
        raise PlanParseError(f"no JSON object found in: {text[:200]!r}")
    try:
        json.loads(candidate)
        return Plan.model_validate_json(candidate)
    except (ValidationError, ValueError) as exc:
        first = str(exc).splitlines()[0][:200] if str(exc) else type(exc).__name__
        raise PlanParseError(f"invalid plan: {first}") from None
