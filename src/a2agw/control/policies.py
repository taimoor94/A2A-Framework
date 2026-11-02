"""Console API: versioned policies, their assignment to gateways, and the dry-run.

A policy (``cp_policies``: id, unique name) has numbered versions (``cp_policy_versions``),
each a validated document stored in its normalized form (``Policy.model_dump``, every
default filled in) with its ``policy_hash``, the hash the gateway audits when it applies
it. Versions are never edited: a change is a new version.

- ``POST /api/v1/policies`` (``policy.edit``) ``{name, doc, comment?}``: version 1.
- ``POST /api/v1/policies/{id}/versions`` (``policy.edit``) ``{doc, comment?}``: the next
  version. Gateways that follow the latest version are marked dirty.
- ``GET /api/v1/policies``, ``GET /api/v1/policies/{id}`` (``read``): the versions, and in
  the detail each version's document with a unified diff from the version before (text
  over canonical YAML) and the gateways it is assigned to.
- ``PUT /api/v1/gateways/{gid}/policy`` (``assign``) ``{policy_id, version}``: the
  gateway's one policy; ``version: null`` follows the latest version.
- ``POST /api/v1/policies/dry-run`` (``policy.edit``) ``{doc, gateway_ids?, days}``: replay
  the gateways' recent audit rows against a candidate (``replay``).

A document that does not validate is a 422 whose ``fields`` are the dotted paths of the
offending fields under ``body.doc`` (never their values). Create and version responses
carry ``warnings``: a lone deny (a lockdown, not a blocklist: see ``a2agw.security.policy``)
and routing rules naming partners the catalogue does not know.

A gateway with no policy assigned gets ``policy: null`` in its desired state, which a
gateway managing its policy treats as a lockdown (the lone deny ``cp:unconfigured``).

Every write is audited in ``cp_audit`` with ids, versions and hashes only, never a document.
"""

from __future__ import annotations

import asyncio
import difflib
import json
import secrets
from dataclasses import dataclass, field
from typing import Annotated, Any, Literal, cast, get_args

import yaml

from a2agw.control import require_fastapi

require_fastapi()

from fastapi import Depends, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import and_, delete, func, or_, select, tuple_, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection

from a2agw.consult.client import ROUTING_FORBID
from a2agw.consult.netguard import Tier
from a2agw.consult.registry import PartnerRecord
from a2agw.control import channel
from a2agw.control.rbac import Actor, Permission, require, route
from a2agw.control.responses import JSONResponse
from a2agw.control.store import (
    ASSIGNMENTS,
    DAY_S,
    GATEWAY_AUDIT,
    GATEWAYS,
    ID,
    NAME,
    PARTNER_VERSIONS,
    PARTNERS,
    POLICIES,
    POLICY_VERSIONS,
    ControlStore,
)
from a2agw.ops.audit import Action, AuditEvent
from a2agw.security.classify import Classification
from a2agw.security.policy import (
    Policy,
    PolicyEngine,
    PolicyError,
    forbid_rule,
    parse_policy,
    policy_hash,
)
from a2agw.security.principal import Principal

COMMENT_MAX = 1000
DOC_MAX_BYTES = 256 * 1024  # a policy document (as JSON) larger than this is refused
GATEWAY_IDS_MAX = 1000
DRY_RUN_MAX_ROWS = 50_000  # rows read per dry-run, newest first
DRY_RUN_BATCH = 1000  # rows per database read (and per evaluation step off the loop)
DRY_RUN_LIST_MAX = 1000  # entries listed per change kind (the counts are complete)
LONE_DENY = "lone deny rule locks down every agent"
NOT_REPLAYABLE = ["egress content checks"]  # the classifier sees message content only

Editor = Annotated[Actor, Depends(require(Permission.POLICY_EDIT))]
Assigner = Annotated[Actor, Depends(require(Permission.ASSIGN))]

_FORBID = ConfigDict(extra="forbid")
Comment = Annotated[str, Field(max_length=COMMENT_MAX)]


class CreatePolicy(BaseModel):
    model_config = _FORBID
    name: str = Field(min_length=1, max_length=NAME, pattern=r"\S")
    doc: dict[str, Any]
    comment: Comment = ""


class NewVersion(BaseModel):
    model_config = _FORBID
    doc: dict[str, Any]
    comment: Comment = ""


class PolicyAssignment(BaseModel):
    model_config = _FORBID
    policy_id: str = Field(max_length=ID)
    version: int | None = Field(ge=1)  # required, null: follow the latest version


class DryRun(BaseModel):
    model_config = _FORBID
    doc: dict[str, Any]
    gateway_ids: list[Annotated[str, Field(max_length=ID)]] | None = Field(
        default=None, max_length=GATEWAY_IDS_MAX
    )
    days: int = Field(default=7, ge=1, le=30)


# -- documents -----------------------------------------------------------------------------


def _invalid(*fields: tuple[str | int, ...], msg: str = "invalid") -> RequestValidationError:
    return RequestValidationError(
        [{"loc": ("body", *loc), "msg": msg, "type": "value_error"} for loc in fields]
    )


def _validated(doc: dict[str, Any]) -> Policy:
    """The policy of a request's ``doc``; 422 naming ``body.doc.<path>`` when it fails."""
    if len(json.dumps(doc)) > DOC_MAX_BYTES:
        raise _invalid(("doc",), msg="policy document too large")
    try:
        return parse_policy(doc)
    except PolicyError as e:
        paths = [tuple(f.split(".")) if f != "<root>" else () for f in e.fields]
        raise _invalid(*(("doc", *p) for p in paths)) from None


def _normalized(policy: Policy) -> dict[str, Any]:
    return policy.model_dump(mode="json")


def _yaml(doc: Any) -> list[str]:
    text = yaml.safe_dump(doc, sort_keys=True, default_flow_style=False, allow_unicode=True)
    return text.splitlines(keepends=True)


def version_diff(old: Any, new: Any, old_version: int, new_version: int) -> str:
    """A unified diff of two policy documents, over their canonical YAML."""
    return "".join(
        difflib.unified_diff(
            _yaml(old), _yaml(new), fromfile=f"v{old_version}", tofile=f"v{new_version}"
        )
    )


def _rule_name(rule: Any, section: str, i: int) -> str:
    return str(rule.id) if rule.id is not None else f"{section}[{i}]"


def warnings_for(policy: Policy, known_partners: set[str]) -> list[str]:
    """What a reviewer should know before saving ``policy`` (see the module docstring)."""
    out: list[str] = []
    allows = [r for r in policy.authz if r.effect == "allow"]
    denies = [(i, r) for i, r in enumerate(policy.authz) if r.effect == "deny"]
    if denies and not allows:
        out.append(LONE_DENY)
    elif denies and not any(r.agents == "*" for r in allows):
        allowed = {a for r in allows for a in r.agents}
        for i, rule in denies:
            if rule.agents == "*":
                continue
            for agent in rule.agents:
                if agent not in allowed:
                    out.append(
                        f"deny rule {_rule_name(rule, 'authz', i)} locks down agent {agent}: "
                        "no allow rule for it"
                    )
    for i, routing in enumerate(policy.routing):
        for pid in routing.partners:
            if pid not in known_partners:
                out.append(
                    f"routing rule {_rule_name(routing, 'routing', i)} names unknown partner {pid}"
                )
    return list(dict.fromkeys(out))


async def _known_partners(conn: AsyncConnection, policy: Policy) -> set[str]:
    named = sorted({p for r in policy.routing for p in r.partners})
    if not named:
        return set()
    rows = await conn.execute(select(PARTNERS.c.id).where(PARTNERS.c.id.in_(named)))
    return {str(p) for p in rows.scalars()}


# -- reading -------------------------------------------------------------------------------


def _not_found(what: str = "policy") -> HTTPException:
    return HTTPException(404, {"error": "not_found", "detail": f"unknown {what}"})


def _conflict(detail: str) -> HTTPException:
    return HTTPException(409, {"error": "conflict", "detail": detail})


def _loads(raw: str | None) -> Any:
    try:
        return json.loads(raw) if raw else {}
    except ValueError:
        return {}


def _summary(v: Any) -> dict[str, Any]:
    return {
        "version": v.version,
        "doc_hash": v.doc_hash,
        "created_by": v.created_by,
        "created_at": v.created_at,
        "comment": v.comment,
    }


async def _versions(conn: AsyncConnection, policy_id: str) -> list[Any]:
    return list(
        (
            await conn.execute(
                select(POLICY_VERSIONS)
                .where(POLICY_VERSIONS.c.policy_id == policy_id)
                .order_by(POLICY_VERSIONS.c.version)
            )
        ).all()
    )


async def _policy_row(conn: AsyncConnection, policy_id: str) -> Any:
    p = (await conn.execute(select(POLICIES).where(POLICIES.c.id == policy_id))).first()
    if p is None:
        raise _not_found()
    return p


async def _following(conn: AsyncConnection, policy_id: str, *, latest_only: bool) -> list[Any]:
    query = (
        select(ASSIGNMENTS.c.gateway_id, ASSIGNMENTS.c.ref_version)
        .where(ASSIGNMENTS.c.kind == "policy")
        .where(ASSIGNMENTS.c.ref_id == policy_id)
        .order_by(ASSIGNMENTS.c.gateway_id)
    )
    if latest_only:
        query = query.where(ASSIGNMENTS.c.ref_version.is_(None))
    return list((await conn.execute(query)).all())


async def detail(store: ControlStore, policy_id: str) -> dict[str, Any]:
    async with store.engine.connect() as conn:
        p = await _policy_row(conn, policy_id)
        versions = await _versions(conn, policy_id)
        gateways = await _following(conn, policy_id, latest_only=False)
    out_versions = []
    previous: tuple[int, Any] | None = None
    for v in versions:
        doc = _loads(v.doc_json)
        diff = version_diff(previous[1], doc, previous[0], v.version) if previous else ""
        out_versions.append({**_summary(v), "doc": doc, "diff": diff})
        previous = (v.version, doc)
    return {
        "id": p.id,
        "name": p.name,
        "created_at": p.created_at,
        "latest_version": versions[-1].version if versions else 0,
        "versions": out_versions,
        "gateways": [{"gateway_id": g.gateway_id, "version": g.ref_version} for g in gateways],
    }


@route("GET", "/api/v1/policies", Permission.READ)
async def list_policies(request: Request) -> dict[str, Any]:
    store: ControlStore = request.app.state.store
    async with store.engine.connect() as conn:
        policies = (await conn.execute(select(POLICIES).order_by(POLICIES.c.name))).all()
        versions: dict[str, list[dict[str, Any]]] = {}
        for v in (
            await conn.execute(
                select(
                    POLICY_VERSIONS.c.policy_id,
                    POLICY_VERSIONS.c.version,
                    POLICY_VERSIONS.c.doc_hash,
                    POLICY_VERSIONS.c.created_by,
                    POLICY_VERSIONS.c.created_at,
                    POLICY_VERSIONS.c.comment,
                ).order_by(POLICY_VERSIONS.c.policy_id, POLICY_VERSIONS.c.version)
            )
        ).all():
            versions.setdefault(v.policy_id, []).append(_summary(v))
        assigned: dict[str, list[dict[str, Any]]] = {}
        for a in (
            await conn.execute(
                select(ASSIGNMENTS.c.ref_id, ASSIGNMENTS.c.gateway_id, ASSIGNMENTS.c.ref_version)
                .where(ASSIGNMENTS.c.kind == "policy")
                .order_by(ASSIGNMENTS.c.gateway_id)
            )
        ).all():
            assigned.setdefault(a.ref_id, []).append(
                {"gateway_id": a.gateway_id, "version": a.ref_version}
            )
    return {
        "policies": [
            {
                "id": p.id,
                "name": p.name,
                "created_at": p.created_at,
                "latest_version": versions[p.id][-1]["version"] if versions.get(p.id) else 0,
                "versions": versions.get(p.id, []),
                "gateways": assigned.get(p.id, []),
            }
            for p in policies
        ]
    }


@route("GET", "/api/v1/policies/{policy_id}", Permission.READ)
async def get_policy(policy_id: str, request: Request) -> dict[str, Any]:
    return await detail(request.app.state.store, policy_id)


# -- writing -------------------------------------------------------------------------------


async def _audit(
    store: ControlStore, actor: str, action: Action, outcome: str, info: dict[str, Any]
) -> None:
    if store.audit is not None:
        await store.audit.emit(
            AuditEvent(actor=actor, action=action, outcome=outcome, detail=info, ts=store.now())
        )


def _version_values(
    policy_id: str, version: int, policy: Policy, actor: Actor, comment: str, now: float
) -> dict[str, Any]:
    return {
        "policy_id": policy_id,
        "version": version,
        "doc_json": json.dumps(_normalized(policy), sort_keys=True, separators=(",", ":")),
        "doc_hash": policy_hash(policy),
        "created_by": actor.id,
        "created_at": now,
        "comment": comment,
    }


@route("POST", "/api/v1/policies", Permission.POLICY_EDIT, status_code=201)
async def create_policy(body: CreatePolicy, request: Request, actor: Editor) -> JSONResponse:
    store: ControlStore = request.app.state.store
    policy = _validated(body.doc)
    name = body.name.strip()
    policy_id = f"pol-{secrets.token_hex(8)}"
    now = store.now()
    try:
        async with store.engine.begin() as conn:
            taken = await conn.execute(select(POLICIES.c.id).where(POLICIES.c.name == name))
            if taken.first() is not None:
                raise _conflict("a policy with this name already exists")
            await conn.execute(POLICIES.insert().values(id=policy_id, name=name, created_at=now))
            await conn.execute(
                POLICY_VERSIONS.insert().values(
                    **_version_values(policy_id, 1, policy, actor, body.comment, now)
                )
            )
            known = await _known_partners(conn, policy)
    except IntegrityError:  # a concurrent create with the same name won
        raise _conflict("a policy with this name already exists") from None
    await _audit(
        store,
        actor.id,
        "cp.policy.save",
        "created",
        {"policy": policy_id, "version": 1, "hash": policy_hash(policy)},
    )
    out = {**await detail(store, policy_id), "warnings": warnings_for(policy, known)}
    return JSONResponse(out, status_code=201)


@route("POST", "/api/v1/policies/{policy_id}/versions", Permission.POLICY_EDIT, status_code=201)
async def add_version(
    policy_id: str, body: NewVersion, request: Request, actor: Editor
) -> JSONResponse:
    store: ControlStore = request.app.state.store
    policy = _validated(body.doc)
    now = store.now()
    try:
        async with store.engine.begin() as conn:
            await _policy_row(conn, policy_id)
            last = (
                await conn.execute(
                    select(func.max(POLICY_VERSIONS.c.version)).where(
                        POLICY_VERSIONS.c.policy_id == policy_id
                    )
                )
            ).scalar_one_or_none()
            version = int(last or 0) + 1
            await conn.execute(
                POLICY_VERSIONS.insert().values(
                    **_version_values(policy_id, version, policy, actor, body.comment, now)
                )
            )
            following = [g.gateway_id for g in await _following(conn, policy_id, latest_only=True)]
            known = await _known_partners(conn, policy)
            await channel.mark_dirty(store, following, conn=conn)
    except IntegrityError:  # a concurrent save took this version number
        raise _conflict("policy changed while the version was saved") from None
    await _audit(
        store,
        actor.id,
        "cp.policy.save",
        "created",
        {"policy": policy_id, "version": version, "hash": policy_hash(policy)},
    )
    out = {**await detail(store, policy_id), "warnings": warnings_for(policy, known)}
    return JSONResponse(out, status_code=201)


async def replace_assignment(
    conn: AsyncConnection, gateway_id: str, policy_id: str, version: int | None
) -> None:
    """Make ``policy_id`` (``version``, None: the latest) the gateway's one policy, in the
    caller's transaction. 404 for an unknown gateway, 422 for an unknown policy or
    version.

    The gateway row is written first (a no-op update, as ``compute_desired`` does): that
    locks it on PostgreSQL (and takes the write lock on sqlite) until the transaction
    ends, so assignments to one gateway are serialized and exactly one policy row
    remains, the one committed last. Without it, two concurrent assignments of different
    policies under READ COMMITTED could each delete nothing new and insert their own."""
    locked = await conn.execute(
        update(GATEWAYS)
        .where(GATEWAYS.c.id == gateway_id)
        .values(desired_gen=GATEWAYS.c.desired_gen)
    )
    if locked.rowcount != 1:
        raise _not_found("gateway")
    known_policy = await conn.execute(select(POLICIES.c.id).where(POLICIES.c.id == policy_id))
    if known_policy.first() is None:
        raise _invalid(("policy_id",), msg="unknown policy")
    if version is not None:
        known_version = await conn.execute(
            select(POLICY_VERSIONS.c.version)
            .where(POLICY_VERSIONS.c.policy_id == policy_id)
            .where(POLICY_VERSIONS.c.version == version)
        )
        if known_version.first() is None:
            raise _invalid(("version",), msg="unknown version")
    await conn.execute(
        delete(ASSIGNMENTS)
        .where(ASSIGNMENTS.c.gateway_id == gateway_id)
        .where(ASSIGNMENTS.c.kind == "policy")
    )
    await conn.execute(
        ASSIGNMENTS.insert().values(
            gateway_id=gateway_id, kind="policy", ref_id=policy_id, ref_version=version
        )
    )


@route("PUT", "/api/v1/gateways/{gateway_id}/policy", Permission.ASSIGN)
async def assign_policy(
    gateway_id: str, body: PolicyAssignment, request: Request, actor: Assigner
) -> dict[str, Any]:
    store: ControlStore = request.app.state.store
    async with store.engine.begin() as conn:
        await replace_assignment(conn, gateway_id, body.policy_id, body.version)
        await channel.mark_dirty(store, [gateway_id], conn=conn)
    await _audit(
        store,
        actor.id,
        "cp.assign",
        "assigned",
        {"gateway": gateway_id, "policy": body.policy_id, "version": body.version},
    )
    return {"gateway_id": gateway_id, "policy_id": body.policy_id, "version": body.version}


# -- dry-run -------------------------------------------------------------------------------

_ADMIT_ACTIONS = ("inbound.admit", "authz.deny", "inbound.reject")
_CALL_ACTIONS = ("partner.call", "egress.deny")
REPLAYED_ACTIONS = (*_ADMIT_ACTIONS, *_CALL_ACTIONS)
# the reasons of a policy (not an AgentAccess) refusal, in authz.deny rows
_POLICY_DENIALS = frozenset({"denied by rule", "no matching allow rule", "policy evaluation error"})
_POLICY_REJECT = "policy: "  # an executor refusal (inbound.reject) by the policy
_KINDS = frozenset({"api_key", "jwt", "anonymous", "system"})
TIERS = frozenset(get_args(Tier))

Change = Literal["blocked", "allowed"]


@dataclass(frozen=True)
class _Partner:
    tier: Tier | None
    record: PartnerRecord | None  # tags and the approved card, for routing matches


@dataclass
class Replay:
    """The outcome of a dry-run, accumulated batch by batch."""

    list_max: int
    evaluated: int = 0
    skipped: int = 0
    read: int = 0
    newly_blocked: list[dict[str, Any]] = field(default_factory=list)
    newly_allowed: list[dict[str, Any]] = field(default_factory=list)
    blocked_count: int = 0
    allowed_count: int = 0

    def add(self, change: Change, entry: dict[str, Any]) -> None:
        if change == "blocked":
            self.blocked_count += 1
            if len(self.newly_blocked) < self.list_max:
                self.newly_blocked.append(entry)
        else:
            self.allowed_count += 1
            if len(self.newly_allowed) < self.list_max:
                self.newly_allowed.append(entry)


def _actor_kind(row: dict[str, Any]) -> str:
    """The kind of caller of a row (never its id): the row's ``principal_kind``, else the
    kind implied by the id's prefix."""
    detail = row.get("detail")
    kind = detail.get("principal_kind") if isinstance(detail, dict) else None
    if isinstance(kind, str) and kind in _KINDS:
        return kind
    actor = row.get("actor")
    if actor == "system":
        return "system"
    return Principal.from_id(actor).kind if isinstance(actor, str) else "anonymous"


def _str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _tier(value: Any) -> Tier | None:
    return cast(Tier, value) if value in TIERS else None


def _classification(value: Any) -> Classification | None:
    if not isinstance(value, str):
        return None
    try:
        return Classification.parse(value)
    except ValueError:
        return None


def _undecidable_match(policy: Policy, agent_id: str, partner_id: str) -> bool:
    """Whether a forbid rule for this agent and partner depends on tags or skills."""
    return any(
        r.mode == "forbid"
        and r.agent == agent_id
        and partner_id in r.partners
        and r.match is not None
        and (r.match.tags_any or r.match.skills_any)
        for r in policy.routing
    )


def _replay_admit(
    engine: PolicyEngine, row: dict[str, Any], action: str, agent_id: str
) -> tuple[bool, bool, str] | None:
    """``(allowed before, allowed now, rule)`` of an inbound row, or None to skip it."""
    detail = row.get("detail") if isinstance(row.get("detail"), dict) else {}
    reason = detail.get("reason") if isinstance(detail, dict) else None
    policy_refusal = (action == "authz.deny" and reason in _POLICY_DENIALS) or (
        action == "inbound.reject" and isinstance(reason, str) and reason.startswith(_POLICY_REJECT)
    )
    if action == "inbound.admit":
        before = True
    elif policy_refusal:
        before = False
    else:  # an AgentAccess refusal, a bad call context...: not the policy's decision
        return None
    actor = row.get("actor")
    if not isinstance(actor, str):
        return None
    decision = engine.authorize(Principal.from_id(actor), agent_id, None)
    return before, decision.allowed, decision.rule or decision.reason


def _replay_call(
    engine: PolicyEngine,
    row: dict[str, Any],
    action: str,
    agent_id: str,
    partners: dict[str, _Partner],
) -> tuple[bool, bool, str] | None:
    """``(allowed before, allowed now, rule)`` of a partner call, or None to skip it."""
    policy = engine.policy
    partner_id = _str(row.get("partner_id"))
    if partner_id is None:
        return None
    classification = _classification(row.get("classification"))
    raw_detail = row.get("detail")
    detail: dict[str, Any] = raw_detail if isinstance(raw_detail, dict) else {}
    # a routing-forbid refusal says so (gateways since this release); its row records
    # the caller's label, so no classification there means no label
    forbidden_then = action == "partner.call" and detail.get("reason") == ROUTING_FORBID
    if forbidden_then:
        if detail.get("classification") == "invalid":
            return None  # the label did not parse: egress would refuse it anyway, unknown
        before = False
    elif action == "partner.call":
        # an older row: "unavailable" without a classification may have been a routing
        # forbid, the row does not say why the call was unavailable
        if row.get("outcome") == "unavailable" and classification is None:
            return None
        before = True
    else:
        before = False
    known = partners.get(partner_id)
    tier = _tier(detail.get("tier"))
    tier = tier or (known.tier if known is not None else None)
    rec = known.record if known is not None else None
    if rec is None:
        if _undecidable_match(policy, agent_id, partner_id):
            return None  # the partner's tags and skills are unknown here
        rec = PartnerRecord(id=partner_id, card={}, card_hash="", tier=tier or "public")
    elif tier is not None and tier != rec.tier:
        rec = rec.model_copy(update={"tier": tier})
    forbid = forbid_rule(policy, agent_id, rec)
    if forbid is not None:
        return before, False, forbid
    if classification is None and not forbidden_then:
        return None
    if tier is None and partner_id not in policy.egress.partner_ceilings:
        return None
    decision = engine.egress(agent_id, rec, classification, "", None)
    return before, decision.allowed, decision.rule or decision.reason


Batch = list[tuple[str, int, float, Any]]  # (gateway id, seq, ts, the parsed row)


def _parse_batch(rows: list[tuple[str, int, float, str]]) -> Batch:
    out: Batch = []
    for gateway_id, seq, ts, raw in rows:
        try:
            row = json.loads(raw)
        except ValueError:
            row = None
        out.append((gateway_id, seq, ts, row))
    return out


def _replay_batch(
    engine: PolicyEngine, batch: Batch, partners: dict[str, _Partner], out: Replay
) -> None:
    """Replay one batch (CPU only: run off the event loop)."""
    for gateway_id, seq, ts, row in batch:
        out.read += 1
        action = row.get("action") if isinstance(row, dict) else None
        agent_id = _str(row.get("agent_id")) if isinstance(row, dict) else None
        result = None
        if isinstance(row, dict) and agent_id is not None:
            if action in _ADMIT_ACTIONS:
                result = _replay_admit(engine, row, action, agent_id)
            elif action in _CALL_ACTIONS:
                result = _replay_call(engine, row, action, agent_id, partners)
        if result is None or not isinstance(row, dict):
            out.skipped += 1
            continue
        out.evaluated += 1
        before, now, rule = result
        if before == now:
            continue
        out.add(
            "allowed" if now else "blocked",
            {
                "gateway_id": gateway_id,
                "seq": seq,
                "ts": ts,
                "actor_kind": _actor_kind(row),
                "agent_id": agent_id,
                "partner_id": _str(row.get("partner_id")),
                "action": action,
                "rule": rule,
            },
        )


def _action_filter() -> Any:
    # rows are stored as sorted compact JSON: the action is this exact substring (the
    # parsed row is checked again)
    return or_(*(GATEWAY_AUDIT.c.row_json.like(f'%"action":"{a}"%') for a in REPLAYED_ACTIONS))


async def _partners(conn: AsyncConnection, ids: set[str], cache: dict[str, _Partner]) -> None:
    """Load the catalogue's tier, tags and approved card of ``ids`` not yet in ``cache``."""
    wanted = sorted(ids - cache.keys())
    if not wanted:
        return
    rows = await conn.execute(
        select(PARTNERS, PARTNER_VERSIONS.c.card_json)
        .outerjoin(
            PARTNER_VERSIONS,
            and_(
                PARTNER_VERSIONS.c.partner_id == PARTNERS.c.id,
                PARTNER_VERSIONS.c.version == PARTNERS.c.current_version,
            ),
        )
        .where(PARTNERS.c.id.in_(wanted))
    )
    for p in rows.all():
        tier = _tier(p.tier)
        if tier is None:
            continue
        tags = _loads(p.tags_json)
        card = _loads(p.card_json)
        record = PartnerRecord(
            id=p.id,
            card=card if isinstance(card, dict) else {},
            card_hash="",
            tier=tier,
            tags=[t for t in tags if isinstance(t, str)] if isinstance(tags, list) else [],
        )
        cache[p.id] = _Partner(tier, record)
    for pid in wanted:
        cache.setdefault(pid, _Partner(None, None))


def _partner_ids(batch: Batch) -> set[str]:
    rows = (row for _gid, _seq, _ts, row in batch if isinstance(row, dict))
    return {pid for row in rows if (pid := _str(row.get("partner_id"))) is not None}


async def replay(
    store: ControlStore, policy: Policy, gateway_ids: list[str] | None, days: int
) -> tuple[Replay, bool]:
    """Replay the gateways' audit rows of the last ``days`` against ``policy``, newest
    first, ``DRY_RUN_MAX_ROWS`` at most; returns the outcome and whether rows were left
    out. Rows are read ``DRY_RUN_BATCH`` at a time (keyset on ``(ts, gateway_id,
    generation, seq)``)
    and each batch is evaluated in a worker thread, so the loop is never held and at most
    one batch of rows is in memory."""
    engine = PolicyEngine(policy)  # no classifier: content checks are not replayed
    out = Replay(list_max=DRY_RUN_LIST_MAX)
    since = store.now() - days * DAY_S
    base = (
        select(
            GATEWAY_AUDIT.c.gateway_id,
            GATEWAY_AUDIT.c.seq,
            GATEWAY_AUDIT.c.ts,
            GATEWAY_AUDIT.c.row_json,
            GATEWAY_AUDIT.c.generation,
        )
        .where(GATEWAY_AUDIT.c.ts >= since)
        .where(_action_filter())
    )
    if gateway_ids is not None:
        base = base.where(GATEWAY_AUDIT.c.gateway_id.in_(sorted(set(gateway_ids))))
    order = (
        GATEWAY_AUDIT.c.ts.desc(),
        GATEWAY_AUDIT.c.gateway_id.desc(),
        GATEWAY_AUDIT.c.generation.desc(),
        GATEWAY_AUDIT.c.seq.desc(),
    )
    key = tuple_(
        GATEWAY_AUDIT.c.ts,
        GATEWAY_AUDIT.c.gateway_id,
        GATEWAY_AUDIT.c.generation,
        GATEWAY_AUDIT.c.seq,
    )
    cache: dict[str, _Partner] = {}
    after: tuple[float, str, int, int] | None = None
    while out.read < DRY_RUN_MAX_ROWS:
        limit = min(DRY_RUN_BATCH, DRY_RUN_MAX_ROWS - out.read)
        query = base.order_by(*order).limit(limit)
        if after is not None:
            query = query.where(key < tuple_(*after))
        async with store.engine.connect() as conn:
            read = list(await conn.execute(query))
        rows = [(str(r[0]), int(r[1]), float(r[2]), str(r[3])) for r in read]
        if rows:
            batch = await asyncio.to_thread(_parse_batch, rows)
            ids = _partner_ids(batch)
            if ids - cache.keys():
                async with store.engine.connect() as conn:
                    await _partners(conn, ids, cache)
            await asyncio.to_thread(_replay_batch, engine, batch, cache, out)
            last = read[-1]
            after = (float(last[2]), str(last[0]), int(last[4]), int(last[1]))
        if len(rows) < limit:
            return out, False
    # the cap is reached: is there anything older?
    query = base.limit(1)
    if after is not None:
        query = query.where(key < tuple_(*after))
    async with store.engine.connect() as conn:
        more = (await conn.execute(query)).first() is not None
    return out, more


@route("POST", "/api/v1/policies/dry-run", Permission.POLICY_EDIT)
async def dry_run(body: DryRun, request: Request, actor: Editor) -> dict[str, Any]:
    store: ControlStore = request.app.state.store
    policy = _validated(body.doc)
    out, truncated = await replay(store, policy, body.gateway_ids, body.days)
    await _audit(
        store,
        actor.id,
        "cp.policy.dryrun",
        "truncated" if truncated else "complete",
        {"count": out.evaluated, "hash": policy_hash(policy)},
    )
    return {
        "evaluated": out.evaluated,
        "newly_blocked": out.newly_blocked,
        "newly_allowed": out.newly_allowed,
        "truncated": truncated,
        "not_replayable": list(NOT_REPLAYABLE),
        "counts": {
            "newly_blocked": out.blocked_count,
            "newly_allowed": out.allowed_count,
            "skipped": out.skipped,
        },
    }
