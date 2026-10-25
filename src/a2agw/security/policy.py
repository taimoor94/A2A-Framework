"""Declarative policy: authorization, egress ceilings and partner routing.

A policy file is YAML validated with ``extra="forbid"`` at every level, so a typo stops
startup with an error naming the field path (``load_policy`` -> ``PolicyError``)::

    version: 1
    authz:
      - {id: alice, principal: "key:alice", agents: [billing], skills: "*", effect: allow}
    egress:
      tier_ceilings: {internal: restricted, partner: confidential, public: public}
      partner_ceilings: {acme: restricted}
    routing:
      - {agent: billing, match: {tags_any: [eu]}, partners: [acme], mode: prefer}
    defaults:
      agent_classification: {hr: confidential}
      unknown_classification: public

``PolicyEngine`` is pure evaluation (no I/O). Semantics:

authorize(principal, agent_id, skill_id)
    A rule matches when its principal matches, the agent is listed (or ``agents: "*"``) and
    the skill is listed (or ``skills: "*"``). Matching is conservative in the deny
    direction:

    - ``skill_id`` None (skill unknown): an allow rule matches only if ``skills: "*"``; a
      deny rule matches whatever its ``skills`` list says.
    - ``principal: "*"``: on an allow rule it matches any authenticated caller but never
      an anonymous or None principal (those match only an exact ``"anonymous"`` rule); on
      a deny rule it matches every caller, anonymous and None included.

    Principals in rules are ``"*"``, ``"anonymous"``, ``key:<id>`` or ``jwt:<sub>``.
    Any matching deny -> deny. Else any matching allow -> allow. Else, if any rule mentions
    the agent (listed or ``"*"``, whatever its principal/skills/effect) -> deny ("no
    matching allow rule"). Else allow ("no authz rules for agent"): Phase 1
    ``AgentAccess`` applies. Note the consequence: a lone deny rule is a lockdown, not a
    blocklist. ``{principal: "key:mallory", agents: [billing], effect: deny}`` with no
    allow rule for ``billing`` denies every caller on ``billing``; add an allow rule
    (e.g. ``principal: "*"``) to deny only mallory.
    ``Decision.rule`` is the rule's ``id`` or ``authz[i]``; ids must be unique.

egress(agent_id, partner, classification, text, data)
    effective = max(explicit classification if given,
    ``defaults.agent_classification[agent]`` if set else ``defaults.unknown_classification``,
    classifier result if a classifier is configured). Labels only ever raise the level: an
    explicit label (which may come from an LLM tool argument) can never go below the agent
    default or ``unknown_classification``, and neither can the classifier. The classifier
    sees the message text and ``data``, not file attachments. ceiling = ``egress.partner_ceilings[partner.id]`` if set,
    else ``egress.tier_ceilings[partner.tier]`` (missing tiers keep their defaults).
    Allowed iff effective <= ceiling. ``Decision.classification`` is the effective value.

route(agent_id, partners)
    Rules whose ``agent`` equals ``agent_id`` apply, in file order, to the rule's listed
    partners that are present in ``partners`` and match ``match``: ``tags_any`` against the
    record tags plus the card's skill tags, ``skills_any`` against the card's skill ids
    (either hit suffices; no/empty match means every partner). ``forbid`` removes partners
    from ``visible``; ``force`` lists them in ``forced``; ``prefer`` moves them to the front
    of ``visible`` in rule order and lists them in ``preferred``. Forbid wins: a partner
    both forced and forbidden is in neither list and is reported in ``conflicts``. Rule
    ids must be unique.

Fail closed: an exception during evaluation yields ``Decision(False, "policy evaluation
error", None, None)`` (or an empty ``RoutePlan``) and is logged by exception class only.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Literal

import yaml
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    PlainSerializer,
    ValidationError,
    field_validator,
)

from a2agw.consult.netguard import Tier
from a2agw.security.classify import Classification, Classifier
from a2agw.security.principal import Principal

if TYPE_CHECKING:
    from a2agw.consult.registry import PartnerRecord

log = logging.getLogger(__name__)

EVALUATION_ERROR = "policy evaluation error"


class PolicyError(ValueError):
    """The policy file is missing, unreadable or invalid."""


def _coerce_classification(value: Any) -> Classification:
    if isinstance(value, Classification):
        return value
    if isinstance(value, str):
        return Classification.parse(value)
    raise ValueError("classification must be one of public, internal, confidential, restricted")


ClassificationName = Annotated[
    Classification,
    BeforeValidator(_coerce_classification),
    PlainSerializer(lambda c: c.name.lower(), return_type=str),
]

DEFAULT_TIER_CEILINGS: dict[Tier, Classification] = {
    "internal": Classification.RESTRICTED,
    "partner": Classification.CONFIDENTIAL,
    "public": Classification.PUBLIC,
}


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


_PRINCIPAL = re.compile(r"\*|anonymous|(?:key|jwt):\S(?:.*\S)?", re.DOTALL)


class AuthzRule(_Strict):
    id: str | None = None
    principal: str
    agents: list[str] | Literal["*"]
    skills: list[str] | Literal["*"] = "*"
    effect: Literal["allow", "deny"]

    @field_validator("principal")
    @classmethod
    def _check_principal(cls, v: str) -> str:
        if not _PRINCIPAL.fullmatch(v):
            raise ValueError(
                'principal must be "*", "anonymous", "key:<id>" or "jwt:<sub>" '
                "with no surrounding whitespace"
            )
        return v


def _unique_ids(rules: list[Any], section: str) -> None:
    seen: set[str] = set()
    for i, rule in enumerate(rules):
        if rule.id is None:
            continue
        if rule.id in seen:
            raise ValueError(f"duplicate rule id at {section}[{i}]")
        seen.add(rule.id)


class Egress(_Strict):
    tier_ceilings: dict[Tier, ClassificationName] = Field(
        default_factory=lambda: dict(DEFAULT_TIER_CEILINGS)
    )
    partner_ceilings: dict[str, ClassificationName] = Field(default_factory=dict)

    @field_validator("tier_ceilings")
    @classmethod
    def _fill_tiers(cls, v: dict[Tier, Classification]) -> dict[Tier, Classification]:
        return {**DEFAULT_TIER_CEILINGS, **v}


class RouteMatch(_Strict):
    tags_any: list[str] | None = None
    skills_any: list[str] | None = None


class RoutingRule(_Strict):
    id: str | None = None
    agent: str
    match: RouteMatch | None = None
    partners: list[str]
    mode: Literal["force", "prefer", "forbid"]


class Defaults(_Strict):
    agent_classification: dict[str, ClassificationName] = Field(default_factory=dict)
    unknown_classification: ClassificationName = Classification.PUBLIC


class Policy(_Strict):
    version: Literal[1]
    authz: list[AuthzRule] = Field(default_factory=list)
    egress: Egress = Field(default_factory=Egress)
    routing: list[RoutingRule] = Field(default_factory=list)
    defaults: Defaults = Field(default_factory=Defaults)

    @field_validator("authz")
    @classmethod
    def _unique_authz(cls, v: list[AuthzRule]) -> list[AuthzRule]:
        _unique_ids(v, "authz")
        return v

    @field_validator("routing")
    @classmethod
    def _unique_routing(cls, v: list[RoutingRule]) -> list[RoutingRule]:
        _unique_ids(v, "routing")
        return v


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    rule: str | None
    classification: Classification | None


@dataclass(frozen=True)
class RoutePlan:
    visible: list[str] = field(default_factory=list)
    forced: list[str] = field(default_factory=list)
    preferred: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)


def _failed(where: str, exc: BaseException) -> Decision:
    log.warning("policy %s evaluation failed: %s", where, type(exc).__name__)
    return Decision(False, EVALUATION_ERROR, None, None)


def _mentions(names: list[str] | Literal["*"], value: str) -> bool:
    return names == "*" or value in names


class PolicyEngine:
    def __init__(self, policy: Policy, classifier: Classifier | None = None) -> None:
        self.policy = policy
        self.classifier = classifier

    # -- authz ---------------------------------------------------------------------------

    def authorize(
        self, principal: Principal | None, agent_id: str, skill_id: str | None
    ) -> Decision:
        try:
            return self._authorize(principal, agent_id, skill_id)
        except Exception as exc:  # noqa: BLE001 - fail closed
            return _failed("authz", exc)

    def _authorize(
        self, principal: Principal | None, agent_id: str, skill_id: str | None
    ) -> Decision:
        if principal is None:
            pid, anonymous = "anonymous", True
        else:
            pid, anonymous = principal.id, principal.kind == "anonymous"
        mentioned = False
        allow: str | None = None
        for i, rule in enumerate(self.policy.authz):
            if not _mentions(rule.agents, agent_id):
                continue
            mentioned = True
            deny = rule.effect == "deny"
            if rule.principal == "*":
                if anonymous and not deny:
                    continue
            elif rule.principal != pid:
                continue
            if skill_id is None:
                if rule.skills != "*" and not deny:
                    continue
            elif not _mentions(rule.skills, skill_id):
                continue
            name = rule.id or f"authz[{i}]"
            if deny:
                return Decision(False, "denied by rule", name, None)
            if allow is None:
                allow = name
        if allow is not None:
            return Decision(True, "allowed by rule", allow, None)
        if mentioned:
            return Decision(False, "no matching allow rule", None, None)
        return Decision(True, "no authz rules for agent", None, None)

    # -- egress --------------------------------------------------------------------------

    def egress(
        self,
        agent_id: str,
        partner: PartnerRecord,
        classification: Classification | None,
        text: str,
        data: dict[str, Any] | None,
    ) -> Decision:
        try:
            return self._egress(agent_id, partner, classification, text, data)
        except Exception as exc:  # noqa: BLE001 - fail closed
            return _failed("egress", exc)

    def _egress(
        self,
        agent_id: str,
        partner: PartnerRecord,
        classification: Classification | None,
        text: str,
        data: dict[str, Any] | None,
    ) -> Decision:
        defaults = self.policy.defaults
        # Raise-only: the floor is the agent default, else unknown_classification.
        eff = defaults.agent_classification.get(agent_id, defaults.unknown_classification)
        if classification is not None:
            eff = max(eff, Classification(classification))
        if self.classifier is not None:
            eff = max(eff, Classification(self.classifier.classify(text, data)))

        egress = self.policy.egress
        if partner.id in egress.partner_ceilings:
            ceiling = egress.partner_ceilings[partner.id]
            rule = f"egress.partner_ceilings[{partner.id}]"
        else:
            ceiling = egress.tier_ceilings[partner.tier]
            rule = f"egress.tier_ceilings[{partner.tier}]"
        if eff <= ceiling:
            reason = f"classification {eff.name.lower()} within {ceiling.name.lower()} ceiling"
            return Decision(True, reason, rule, eff)
        reason = (
            f"classification {eff.name.lower()} exceeds {ceiling.name.lower()} ceiling "
            f"for partner {partner.id}"
        )
        return Decision(False, reason, rule, eff)

    # -- routing -------------------------------------------------------------------------

    def route(self, agent_id: str, partners: list[PartnerRecord]) -> RoutePlan:
        try:
            return self._route(agent_id, partners)
        except Exception as exc:  # noqa: BLE001 - fail closed
            log.warning("policy route evaluation failed: %s", type(exc).__name__)
            return RoutePlan()

    def _route(self, agent_id: str, partners: list[PartnerRecord]) -> RoutePlan:
        by_id: dict[str, PartnerRecord] = {}
        for rec in partners:
            by_id.setdefault(rec.id, rec)
        forbidden: set[str] = set()
        forced: list[str] = []
        preferred: list[str] = []
        for rule in self.policy.routing:
            if rule.agent != agent_id:
                continue
            for pid in rule.partners:
                target = by_id.get(pid)
                if target is None or not _route_match(rule.match, target):
                    continue
                if rule.mode == "forbid":
                    forbidden.add(pid)
                elif rule.mode == "force":
                    if pid not in forced:
                        forced.append(pid)
                elif pid not in preferred:
                    preferred.append(pid)
        conflicts = [p for p in forced if p in forbidden]
        forced = [p for p in forced if p not in forbidden]
        preferred = [p for p in preferred if p not in forbidden]
        rest = [p for p in by_id if p not in forbidden and p not in preferred]
        return RoutePlan(
            visible=preferred + rest, forced=forced, preferred=preferred, conflicts=conflicts
        )


def _card_skills(rec: PartnerRecord) -> list[dict[str, Any]]:
    raw = rec.card.get("skills")
    return [s for s in raw if isinstance(s, dict)] if isinstance(raw, list) else []


def _route_match(match: RouteMatch | None, rec: PartnerRecord) -> bool:
    if match is None or (not match.tags_any and not match.skills_any):
        return True
    skills = _card_skills(rec)
    if match.tags_any:
        tags = set(rec.tags)
        for s in skills:
            raw = s.get("tags")
            if isinstance(raw, list):
                tags.update(t for t in raw if isinstance(t, str))
        if tags.intersection(match.tags_any):
            return True
    if match.skills_any:
        ids = {s["id"] for s in skills if isinstance(s.get("id"), str)}
        if ids.intersection(match.skills_any):
            return True
    return False


# -- loading -----------------------------------------------------------------------------


def _describe_errors(exc: ValidationError) -> str:
    # Dotted field path and error type only; never the offending input values.
    # Our own validators' messages (type value_error) never include the input, so they
    # are shown too.
    parts = []
    for err in exc.errors(include_input=False, include_url=False):
        loc = ".".join(str(p) for p in err["loc"]) or "<root>"
        detail = err["type"]
        if detail == "value_error":
            detail = err["msg"].removeprefix("Value error, ")
        parts.append(f"{loc} ({detail})")
    return "; ".join(parts)


def load_policy(path: Path) -> Policy:
    """Read and validate a YAML policy file; any problem raises ``PolicyError``."""
    path = Path(path)
    try:
        raw_text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise PolicyError(f"policy file not found: {path}") from None
    except (OSError, UnicodeDecodeError) as exc:
        raise PolicyError(f"cannot read policy file {path}: {type(exc).__name__}") from None
    try:
        doc = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" at line {mark.line + 1}" if mark is not None else ""
        raise PolicyError(f"policy file {path} is not valid YAML{where}") from None
    if doc is None:
        raise PolicyError(f"policy file {path} is empty")
    if not isinstance(doc, dict):
        raise PolicyError(f"policy file {path} must be a mapping")
    try:
        return Policy.model_validate(doc)
    except ValidationError as exc:
        raise PolicyError(f"invalid policy file {path}: {_describe_errors(exc)}") from None
