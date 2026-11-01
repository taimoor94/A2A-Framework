"""Console API: the partner catalogue (the central registry, spec §7.8).

A partner is a record (``cp_partners``: tier, credential and TLS reference names, tags,
status) with numbered card versions (``cp_partner_versions``). Its status is ``pending``
(registered, nothing approved yet), ``approved``, ``quarantined`` or ``rejected``; only an
approved partner is in a gateway's desired state, as its approved version
(``current_version``). A newer unapproved version is the partner's pending card
(``pending: true``) until it is approved.

- ``POST /api/v1/partners`` (``partners.register``): fetch the card (SSRF-guarded for the
  tier), validate and verify it, store version 1 as ``pending``.
- ``GET /api/v1/partners`` (``read``): the list; filters ``tier``, ``status`` (default
  ``approved``: other partners appear only when asked for), ``gateway_id``, and ``q``, the
  skill search.
- ``GET /api/v1/partners/{id}`` (``read``): record, approved card, pending card, their
  diff, the versions, and what each gateway reported.
- ``POST .../approve`` (``partners.trust``) ``{version, expected_hash}``: hash-pinned; a
  gateway that reported the partner quarantined with that pending hash also gets a
  ``partner.approve`` command.
- ``POST .../reject``, ``POST .../quarantine`` (``partners.trust``): the partner leaves
  every desired state.
- ``POST .../refresh`` (``partners.register``): fetch the card again; a significant change
  is a new pending version, a cosmetic one a new approved version.
- ``PUT .../settings`` (``partners.trust``): tier, credential_ref, tls_ref, tags. A new tier
  re-checks the approved card for it (signature, interface URLs).
- ``PUT /api/v1/gateways/{gid}/partners`` (``assign``): the gateway's partners.

Every write that changes what a gateway runs marks the assigned gateways dirty
(``channel.mark_dirty``), and every write is audited in ``cp_audit``. Cards are fetched with
the gateway's own code (``a2agw.consult.cardfetch``); a card sent by a gateway is never
taken (a report carries only the pending card's hash). The control plane holds no partner
secret: ``credential_ref`` and ``tls_ref`` are names each gateway resolves itself.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Annotated, Any, Literal

import httpx

from a2agw.control import require_fastapi

require_fastapi()

from fastapi import Depends, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import case, delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection

from a2agw.consult import cardfetch
from a2agw.consult.carddiff import card_diff
from a2agw.consult.cardfetch import (
    MAX_CARD_BYTES,
    CardFetchError,
    CardSignatureInvalid,
    InvalidCard,
    card_hash,
)
from a2agw.consult.netguard import Tier
from a2agw.control import channel
from a2agw.control.rbac import Actor, Permission, require, route
from a2agw.control.store import (
    ASSIGNMENTS,
    GATEWAYS,
    ID,
    PARTNER_STATES,
    PARTNER_VERSIONS,
    PARTNERS,
    ControlStore,
)
from a2agw.ops.audit import Action, AuditEvent
from a2agw.security.cardsign import CardSignatureError, CardVerifier

PARTNER_ID = r"^[a-z0-9][a-z0-9-]{0,62}$"  # the gateway's partner id rule
REF_NAME = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$"  # credential_ref / tls_ref: names only
URL_MAX = 2048
TAG_MAX = 64
TAGS_MAX = 32
ASSIGN_MAX = 1000
SEARCH_TERMS_MAX = 16
Status = Literal["pending", "approved", "quarantined", "rejected"]

Registrar = Annotated[Actor, Depends(require(Permission.PARTNERS_REGISTER))]
Trustee = Annotated[Actor, Depends(require(Permission.PARTNERS_TRUST))]
Assigner = Annotated[Actor, Depends(require(Permission.ASSIGN))]

_FORBID = ConfigDict(extra="forbid")
Tag = Annotated[str, Field(min_length=1, max_length=TAG_MAX)]
RefName = Annotated[str, Field(pattern=REF_NAME)]
PartnerId = Annotated[str, Field(pattern=PARTNER_ID)]


class RegisterPartner(BaseModel):
    model_config = _FORBID
    id: PartnerId
    card_url: str | None = Field(default=None, min_length=1, max_length=URL_MAX)
    card: dict[str, Any] | None = None
    tier: Tier
    credential_ref: RefName | None = None
    tls_ref: RefName | None = None
    tags: list[Tag] = Field(default_factory=list, max_length=TAGS_MAX)

    @model_validator(mode="after")
    def _one_source(self) -> RegisterPartner:
        if (self.card_url is None) == (self.card is None):
            raise ValueError("give exactly one of card_url and card")
        return self


class Approve(BaseModel):
    model_config = _FORBID
    version: int = Field(ge=1)
    expected_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class PartnerSettings(BaseModel):
    """Only the fields given change; ``null`` clears a reference."""

    model_config = _FORBID
    tier: Tier | None = None
    credential_ref: RefName | None = None
    tls_ref: RefName | None = None
    tags: list[Tag] | None = Field(default=None, max_length=TAGS_MAX)

    @model_validator(mode="after")
    def _tier_and_tags_not_null(self) -> PartnerSettings:
        for name in ("tier", "tags"):
            if name in self.model_fields_set and getattr(self, name) is None:
                raise ValueError(f"{name} cannot be null")
        return self


class Assignment(BaseModel):
    model_config = _FORBID
    partner_ids: list[PartnerId] = Field(max_length=ASSIGN_MAX)


# -- checking cards ------------------------------------------------------------------------


@dataclass(frozen=True)
class CheckedCard:
    card: dict[str, Any]  # normalized
    hash: str
    key_id: str | None  # the verified signing key, for tiers that require signed cards


@dataclass(frozen=True)
class CardChecker:
    """How the catalogue fetches and checks cards (``app.state.cards``): the gateway's
    ``cardfetch`` path, the control plane's ``CardVerifier`` (from ``trust``) and the tiers
    that require signed cards. ``http`` is the test seam: when None each fetch uses a
    guarded client for the partner's tier."""

    http: httpx.AsyncClient | None = None
    verifier: CardVerifier | None = None
    require_signed: frozenset[Tier] = frozenset()

    async def fetch(self, card_url: str, tier: Tier) -> dict[str, Any]:
        return await cardfetch.fetch_card(card_url, tier, http=self.http)

    async def check(self, raw: dict[str, Any], tier: Tier) -> CheckedCard:
        """Normalize, verify (for a signed tier) and SSRF-check the interfaces of a card."""
        if len(json.dumps(raw)) > MAX_CARD_BYTES:
            raise InvalidCard("agent card is too large")
        card, proto = cardfetch.normalize_card(raw)
        try:
            key_id = await cardfetch.verify_signature(
                proto, tier, verifier=self.verifier, require_signed=self.require_signed
            )
        except CardSignatureError:
            raise CardSignatureInvalid("card signature invalid") from None
        await cardfetch.check_endpoints(proto, tier)
        return CheckedCard(card, card_hash(card), key_id)


def _card_error(exc: CardFetchError) -> HTTPException:
    """422 naming the kind of failure (the class), never the message (URLs, hosts)."""
    return HTTPException(422, {"error": "card", "detail": type(exc).__name__})


def _not_found(what: str = "partner") -> HTTPException:
    return HTTPException(404, {"error": "not_found", "detail": f"unknown {what}"})


def _conflict(detail: str) -> HTTPException:
    return HTTPException(409, {"error": "conflict", "detail": detail})


# -- reading -------------------------------------------------------------------------------


def _loads(raw: str | None, default: Any) -> Any:
    try:
        return json.loads(raw) if raw else default
    except ValueError:
        return default


def _dumps(card: dict[str, Any]) -> str:
    return json.dumps(card, sort_keys=True, separators=(",", ":"))


def _tags(raw: str | None) -> list[str]:
    tags = _loads(raw, [])
    return [t for t in tags if isinstance(t, str)] if isinstance(tags, list) else []


async def _partner(conn: AsyncConnection, partner_id: str) -> Any:
    row = (await conn.execute(select(PARTNERS).where(PARTNERS.c.id == partner_id))).first()
    if row is None:
        raise _not_found()
    return row


async def _versions(conn: AsyncConnection, partner_id: str) -> list[Any]:
    return list(
        (
            await conn.execute(
                select(PARTNER_VERSIONS)
                .where(PARTNER_VERSIONS.c.partner_id == partner_id)
                .order_by(PARTNER_VERSIONS.c.version)
            )
        ).all()
    )


async def _assigned(conn: AsyncConnection, partner_id: str) -> list[str]:
    rows = await conn.execute(
        select(ASSIGNMENTS.c.gateway_id)
        .where(ASSIGNMENTS.c.kind == "partner")
        .where(ASSIGNMENTS.c.ref_id == partner_id)
        .order_by(ASSIGNMENTS.c.gateway_id)
    )
    return [str(g) for g in rows.scalars()]


def _pending_row(partner: Any, versions: list[Any]) -> Any:
    """The latest version, when it is newer than the approved one and not approved."""
    if versions and versions[-1].version > partner.current_version:
        last = versions[-1]
        return last if last.approved_at is None else None
    return None


def _approved_row(partner: Any, versions: list[Any]) -> Any:
    return next((v for v in versions if v.version == partner.current_version), None)


def _version_summary(v: Any) -> dict[str, Any]:
    return {
        "version": v.version,
        "card_hash": v.card_hash,
        "signed_key_id": v.signed_key_id,
        "fetched_at": v.fetched_at,
        "approved_by": v.approved_by,
        "approved_at": v.approved_at,
    }


def _with_card(v: Any) -> dict[str, Any]:
    return {**_version_summary(v), "card": _loads(v.card_json, {})}


async def _detail(conn: AsyncConnection, partner_id: str) -> dict[str, Any]:
    p = await _partner(conn, partner_id)
    versions = await _versions(conn, partner_id)
    approved, pending = _approved_row(p, versions), _pending_row(p, versions)
    approved_card = _loads(approved.card_json, {}) if approved is not None else {}
    diff = (
        [c.as_dict() for c in card_diff(approved_card, _loads(pending.card_json, {}))]
        if pending is not None
        else []
    )
    assigned = set(await _assigned(conn, partner_id))
    reported = {
        r.gateway_id: r
        for r in (
            await conn.execute(
                select(PARTNER_STATES).where(PARTNER_STATES.c.partner_id == partner_id)
            )
        ).all()
    }
    gateways = []
    for gid in sorted(assigned | set(reported)):
        r = reported.get(gid)
        gateways.append(
            {
                "gateway_id": gid,
                "assigned": gid in assigned,
                "status": r.status if r is not None else None,
                "pending_hash": r.pending_hash if r is not None else None,
                "event": r.event if r is not None else None,
                "reported_at": r.ts if r is not None else None,
            }
        )
    return {
        "id": p.id,
        "card_url": p.card_url,
        "tier": p.tier,
        "status": p.status,
        "credential_ref": p.credential_ref,
        "tls_ref": p.tls_ref,
        "tags": _tags(p.tags_json),
        "current_version": p.current_version,
        "pending": pending is not None,
        "created_at": p.created_at,
        "updated_at": p.updated_at,
        "approved": _with_card(approved) if approved is not None else None,
        "pending_version": _with_card(pending) if pending is not None else None,
        "diff": diff,
        "versions": [_version_summary(v) for v in versions],
        "gateways": gateways,
    }


async def detail(store: ControlStore, partner_id: str) -> dict[str, Any]:
    async with store.engine.connect() as conn:
        return await _detail(conn, partner_id)


def _terms(q: str) -> list[str]:
    return list(dict.fromkeys(t for t in q.lower().split() if t))[:SEARCH_TERMS_MAX]


def _text(value: Any) -> str:
    return value.lower() if isinstance(value, str) else ""


def search_score(card: dict[str, Any], tags: list[str], terms: list[str]) -> tuple[int, list[str]]:
    """``(score, matched skill ids)`` of a card for the search terms: each term found in a
    skill name counts 2, one found elsewhere (card name and description, skill
    descriptions and tags, the partner's tags) counts 1. Case-insensitive substring
    matches."""
    skills = [s for s in card.get("skills") or [] if isinstance(s, dict)]

    def skill_tags(s: dict[str, Any]) -> list[str]:
        raw = s.get("tags")
        return [_text(t) for t in raw] if isinstance(raw, list) else []

    others = [_text(card.get("name")), _text(card.get("description")), *map(_text, tags)]
    for s in skills:
        others += [_text(s.get("description")), *skill_tags(s)]
    score = 0
    for term in terms:
        if any(term in _text(s.get("name")) for s in skills):
            score += 2
        elif any(term in text for text in others):
            score += 1
    matched = []
    for s in skills:
        fields = [_text(s.get("name")), _text(s.get("description")), *skill_tags(s)]
        if isinstance(s.get("id"), str) and any(t in f for t in terms for f in fields):
            matched.append(s["id"])
    return score, matched


@route("GET", "/api/v1/partners", Permission.READ)
async def list_partners(
    request: Request,
    tier: Tier | None = None,
    status: Status | None = None,
    gateway_id: str | None = Query(None, max_length=ID),
    q: str | None = Query(None, max_length=256),
) -> dict[str, Any]:
    store: ControlStore = request.app.state.store
    query = select(PARTNERS).order_by(PARTNERS.c.id)
    if tier is not None:
        query = query.where(PARTNERS.c.tier == tier)
    # without a status filter only approved partners are listed (and searched): pending,
    # quarantined or rejected partners never surface by default
    query = query.where(PARTNERS.c.status == (status or "approved"))
    if gateway_id is not None:
        query = query.where(
            PARTNERS.c.id.in_(
                select(ASSIGNMENTS.c.ref_id)
                .where(ASSIGNMENTS.c.kind == "partner")
                .where(ASSIGNMENTS.c.gateway_id == gateway_id)
            )
        )
    latest = (
        select(PARTNER_VERSIONS.c.partner_id, func.max(PARTNER_VERSIONS.c.version).label("v"))
        .group_by(PARTNER_VERSIONS.c.partner_id)
        .subquery()
    )
    # the card shown: the approved version, else the latest one
    shown = case((PARTNERS.c.current_version > 0, PARTNERS.c.current_version), else_=latest.c.v)
    query = (
        query.add_columns(
            latest.c.v.label("latest_version"),
            PARTNER_VERSIONS.c.card_json,
            PARTNER_VERSIONS.c.card_hash,
        )
        .outerjoin(latest, latest.c.partner_id == PARTNERS.c.id)
        .outerjoin(
            PARTNER_VERSIONS,
            (PARTNER_VERSIONS.c.partner_id == PARTNERS.c.id)
            & (PARTNER_VERSIONS.c.version == shown),
        )
    )
    async with store.engine.connect() as conn:
        partners = (await conn.execute(query)).all()
        assigned: dict[str, list[str]] = {}
        for a in (
            await conn.execute(
                select(ASSIGNMENTS.c.ref_id, ASSIGNMENTS.c.gateway_id)
                .where(ASSIGNMENTS.c.kind == "partner")
                .order_by(ASSIGNMENTS.c.gateway_id)
            )
        ).all():
            assigned.setdefault(a.ref_id, []).append(a.gateway_id)
        quarantined: dict[str, list[str]] = {}
        for s in (
            await conn.execute(
                select(PARTNER_STATES.c.partner_id, PARTNER_STATES.c.gateway_id)
                .where(PARTNER_STATES.c.status == "quarantined")
                .order_by(PARTNER_STATES.c.gateway_id)
            )
        ).all():
            quarantined.setdefault(s.partner_id, []).append(s.gateway_id)
    terms = _terms(q) if q is not None else []  # a blank q searches nothing: the full list
    ranked: list[tuple[int, dict[str, Any]]] = []
    for p in partners:
        card = _loads(p.card_json, {})
        tags = _tags(p.tags_json)
        item: dict[str, Any] = {
            "id": p.id,
            "tier": p.tier,
            "status": p.status,
            "current_version": p.current_version,
            "pending": (p.latest_version or 0) > p.current_version,
            "card_hash": p.card_hash,
            "name": card.get("name") if isinstance(card.get("name"), str) else None,
            "skills_count": len(card.get("skills") or []),
            "tags": tags,
            "gateways": assigned.get(p.id, []),
            "quarantined_on": quarantined.get(p.id, []),
        }
        if terms:
            if not p.current_version:  # only approved cards are searched
                continue
            score, matched = search_score(card, tags, terms)
            if score == 0:
                continue
            item["matched_skills"] = matched
            ranked.append((score, item))
        else:
            ranked.append((0, item))
    ranked.sort(key=lambda si: (-si[0], si[1]["id"]))
    return {"partners": [item for _, item in ranked]}


@route("GET", "/api/v1/partners/{partner_id}", Permission.READ)
async def get_partner(partner_id: str, request: Request) -> dict[str, Any]:
    return await detail(request.app.state.store, partner_id)


# -- writing -------------------------------------------------------------------------------


async def _audit(
    store: ControlStore,
    actor: str,
    action: Action,
    outcome: str,
    partner_id: str | None,
    info: dict[str, Any],
) -> None:
    if store.audit is not None:
        await store.audit.emit(
            AuditEvent(
                actor=actor,
                action=action,
                partner_id=partner_id,
                outcome=outcome,
                detail=info,
                ts=store.now(),
            )
        )


async def _assigned_ids(store: ControlStore, partner_id: str) -> list[str]:
    async with store.engine.connect() as conn:
        return await _assigned(conn, partner_id)


@route("POST", "/api/v1/partners", Permission.PARTNERS_REGISTER, status_code=201)
async def register_partner(
    body: RegisterPartner, request: Request, actor: Registrar
) -> JSONResponse:
    state = request.app.state
    store: ControlStore = state.store
    cards: CardChecker = state.cards
    async with store.engine.connect() as conn:
        taken = await conn.execute(select(PARTNERS.c.id).where(PARTNERS.c.id == body.id))
        if taken.first() is not None:
            raise _conflict("a partner with this id already exists")
    try:
        raw = (
            body.card
            if body.card is not None
            else await cards.fetch(body.card_url or "", body.tier)
        )
        checked = await cards.check(raw, body.tier)
    except CardFetchError as e:
        raise _card_error(e) from None
    now = store.now()
    try:
        async with store.engine.begin() as conn:
            await conn.execute(
                PARTNERS.insert().values(
                    id=body.id,
                    card_url=body.card_url,
                    tier=body.tier,
                    credential_ref=body.credential_ref,
                    tls_ref=body.tls_ref,
                    tags_json=json.dumps(body.tags),
                    status="pending",
                    current_version=0,
                    created_at=now,
                    updated_at=now,
                )
            )
            await conn.execute(
                PARTNER_VERSIONS.insert().values(
                    partner_id=body.id,
                    version=1,
                    card_json=_dumps(checked.card),
                    card_hash=checked.hash,
                    signed_key_id=checked.key_id,
                    fetched_at=now,
                )
            )
    except IntegrityError:  # a concurrent registration with the same id won
        raise _conflict("a partner with this id already exists") from None
    await _audit(
        store,
        actor.id,
        "cp.partner.register",
        "pending",
        body.id,
        {"tier": body.tier, "version": 1, "hash": checked.hash},
    )
    return JSONResponse(await detail(store, body.id), status_code=201)


@route("POST", "/api/v1/partners/{partner_id}/approve", Permission.PARTNERS_TRUST)
async def approve_partner(
    partner_id: str, body: Approve, request: Request, actor: Trustee
) -> dict[str, Any]:
    state = request.app.state
    store: ControlStore = state.store
    cards: CardChecker = state.cards
    now = store.now()
    async with store.engine.begin() as conn:
        p = await _partner(conn, partner_id)
        v = (
            await conn.execute(
                select(PARTNER_VERSIONS)
                .where(PARTNER_VERSIONS.c.partner_id == partner_id)
                .where(PARTNER_VERSIONS.c.version == body.version)
            )
        ).first()
        if v is None:
            raise _not_found("version")
        if v.card_hash != body.expected_hash:
            raise _conflict("card changed since it was reviewed")
        if p.tier in cards.require_signed and v.signed_key_id is None:
            raise _conflict("the tier requires a signed card; refresh to verify one")
        if v.approved_at is None:
            await conn.execute(
                update(PARTNER_VERSIONS)
                .where(PARTNER_VERSIONS.c.partner_id == partner_id)
                .where(PARTNER_VERSIONS.c.version == body.version)
                .values(approved_by=actor.id, approved_at=now)
            )
        await conn.execute(
            update(PARTNERS)
            .where(PARTNERS.c.id == partner_id)
            .values(status="approved", current_version=body.version, updated_at=now)
        )
        assigned = await _assigned(conn, partner_id)
        holding = (
            await conn.execute(
                select(PARTNER_STATES.c.gateway_id)
                .where(PARTNER_STATES.c.partner_id == partner_id)
                .where(PARTNER_STATES.c.status == "quarantined")
                .where(PARTNER_STATES.c.pending_hash == body.expected_hash)
                .order_by(PARTNER_STATES.c.gateway_id)
            )
        ).scalars()
        quarantined_with_it = [str(g) for g in holding]
    await channel.mark_dirty(store, assigned)
    commands = []
    for gid in quarantined_with_it:
        args = {"id": partner_id, "expected_hash": body.expected_hash}
        try:
            command_id = await channel.enqueue_command(
                store, gid, "partner.approve", args, actor.id
            )
        except (KeyError, ValueError):  # deleted or revoked meanwhile
            continue
        commands.append({"gateway_id": gid, "command_id": command_id})
    await _audit(
        store,
        actor.id,
        "cp.partner.approve",
        "approved",
        partner_id,
        {
            "tier": p.tier,
            "version": body.version,
            "hash": body.expected_hash,
            "count": len(commands),
        },
    )
    return {**await detail(store, partner_id), "commands": commands}


async def _set_status(
    request: Request, partner_id: str, actor: Actor, status: Status, action: Action
) -> dict[str, Any]:
    store: ControlStore = request.app.state.store
    async with store.engine.begin() as conn:
        p = await _partner(conn, partner_id)
        await conn.execute(
            update(PARTNERS)
            .where(PARTNERS.c.id == partner_id)
            .values(status=status, updated_at=store.now())
        )
        assigned = await _assigned(conn, partner_id)
    await channel.mark_dirty(store, assigned)
    await _audit(
        store,
        actor.id,
        action,
        status,
        partner_id,
        {"tier": p.tier, "version": p.current_version, "state": p.status},
    )
    return await detail(store, partner_id)


@route("POST", "/api/v1/partners/{partner_id}/reject", Permission.PARTNERS_TRUST)
async def reject_partner(partner_id: str, request: Request, actor: Trustee) -> dict[str, Any]:
    return await _set_status(request, partner_id, actor, "rejected", "cp.partner.reject")


@route("POST", "/api/v1/partners/{partner_id}/quarantine", Permission.PARTNERS_TRUST)
async def quarantine_partner(partner_id: str, request: Request, actor: Trustee) -> dict[str, Any]:
    return await _set_status(request, partner_id, actor, "quarantined", "cp.partner.quarantine")


def _significant(old: dict[str, Any], new: dict[str, Any]) -> bool:
    return any(c.significant for c in card_diff(old, new))


@route("POST", "/api/v1/partners/{partner_id}/refresh", Permission.PARTNERS_REGISTER)
async def refresh_partner(partner_id: str, request: Request, actor: Registrar) -> dict[str, Any]:
    state = request.app.state
    store: ControlStore = state.store
    cards: CardChecker = state.cards
    async with store.engine.connect() as conn:
        p = await _partner(conn, partner_id)
        versions = await _versions(conn, partner_id)
    if not p.card_url:
        raise _conflict("partner has no card URL to refresh from")
    try:
        checked = await cards.check(await cards.fetch(p.card_url, p.tier), p.tier)
    except CardFetchError as e:
        raise _card_error(e) from None
    last = versions[-1] if versions else None
    approved = _approved_row(p, versions)
    if last is not None and last.card_hash == checked.hash:
        outcome, version = "unchanged", last.version
    else:
        cosmetic = (
            p.status == "approved"
            and approved is not None
            and not (p.tier in cards.require_signed and checked.key_id != approved.signed_key_id)
            and not _significant(_loads(approved.card_json, {}), checked.card)
        )
        outcome = "applied" if cosmetic else "pending"
        version = (last.version if last is not None else 0) + 1
        now = store.now()
        try:
            async with store.engine.begin() as conn:
                await conn.execute(
                    PARTNER_VERSIONS.insert().values(
                        partner_id=partner_id,
                        version=version,
                        card_json=_dumps(checked.card),
                        card_hash=checked.hash,
                        signed_key_id=checked.key_id,
                        fetched_at=now,
                        approved_by=actor.id if cosmetic else None,
                        approved_at=now if cosmetic else None,
                    )
                )
                changes: dict[str, Any] = {"updated_at": now}
                if cosmetic:
                    changes["current_version"] = version
                moved = await conn.execute(
                    update(PARTNERS)
                    .where(PARTNERS.c.id == partner_id)
                    .where(PARTNERS.c.current_version == p.current_version)
                    .where(PARTNERS.c.status == p.status)
                    .values(**changes)
                )
                if moved.rowcount != 1:
                    raise _conflict("partner changed while it was refreshed")
        except IntegrityError:  # a concurrent refresh added this version
            raise _conflict("partner changed while it was refreshed") from None
        if cosmetic:
            await channel.mark_dirty(store, await _assigned_ids(store, partner_id))
    await _audit(
        store,
        actor.id,
        "cp.partner.refresh",
        outcome,
        partner_id,
        {"tier": p.tier, "version": version, "hash": checked.hash},
    )
    return {**await detail(store, partner_id), "outcome": outcome}


@route("PUT", "/api/v1/partners/{partner_id}/settings", Permission.PARTNERS_TRUST)
async def partner_settings(
    partner_id: str, body: PartnerSettings, request: Request, actor: Trustee
) -> dict[str, Any]:
    state = request.app.state
    store: ControlStore = state.store
    cards: CardChecker = state.cards
    async with store.engine.connect() as conn:
        p = await _partner(conn, partner_id)
        versions = await _versions(conn, partner_id)
    current: dict[str, Any] = {
        "tier": p.tier,
        "credential_ref": p.credential_ref,
        "tls_ref": p.tls_ref,
        "tags": _tags(p.tags_json),
    }
    wanted = {name: getattr(body, name) for name in body.model_fields_set}
    changed = sorted(name for name, value in wanted.items() if current[name] != value)
    if not changed:
        return await detail(store, partner_id)
    tier: Tier = wanted.get("tier", p.tier)
    rechecked: list[tuple[int, str | None]] = []
    if "tier" in changed:
        # the cards a gateway may get must pass its checks for the new tier
        # the approved card and the pending one (what an approval would send)
        for v in filter(None, (_approved_row(p, versions), _pending_row(p, versions))):
            try:
                checked = await cards.check(_loads(v.card_json, {}), tier)
            except CardFetchError as e:
                raise _card_error(e) from None
            rechecked.append((v.version, checked.key_id))
    values: dict[str, Any] = {name: wanted[name] for name in changed if name != "tags"}
    if "tags" in changed:
        values["tags_json"] = json.dumps(wanted["tags"])
    async with store.engine.begin() as conn:
        await conn.execute(
            update(PARTNERS)
            .where(PARTNERS.c.id == partner_id)
            .values(**values, updated_at=store.now())
        )
        for version, key_id in rechecked:
            await conn.execute(
                update(PARTNER_VERSIONS)
                .where(PARTNER_VERSIONS.c.partner_id == partner_id)
                .where(PARTNER_VERSIONS.c.version == version)
                .values(signed_key_id=key_id)
            )
        assigned = await _assigned(conn, partner_id)
    await channel.mark_dirty(store, assigned)
    audit_detail: dict[str, Any] = {"fields": ",".join(changed), "tier": tier}
    if "tier" in changed:
        audit_detail["reason"] = "trust"  # a tier change is a trust change
    await _audit(store, actor.id, "cp.partner.update", "updated", partner_id, audit_detail)
    return await detail(store, partner_id)


@route("PUT", "/api/v1/gateways/{gateway_id}/partners", Permission.ASSIGN)
async def assign_partners(
    gateway_id: str, body: Assignment, request: Request, actor: Assigner
) -> dict[str, Any]:
    store: ControlStore = request.app.state.store
    wanted = list(dict.fromkeys(body.partner_ids))
    async with store.engine.begin() as conn:
        known_gateway = await conn.execute(select(GATEWAYS.c.id).where(GATEWAYS.c.id == gateway_id))
        if known_gateway.first() is None:
            raise _not_found("gateway")
        known = set(
            (await conn.execute(select(PARTNERS.c.id).where(PARTNERS.c.id.in_(wanted)))).scalars()
        )
        unknown = [i for i, pid in enumerate(body.partner_ids) if pid not in known]
        if unknown:
            raise _unknown_partners(unknown)
        await conn.execute(
            delete(ASSIGNMENTS)
            .where(ASSIGNMENTS.c.gateway_id == gateway_id)
            .where(ASSIGNMENTS.c.kind == "partner")
        )
        if wanted:
            await conn.execute(
                ASSIGNMENTS.insert(),
                [
                    {
                        "gateway_id": gateway_id,
                        "kind": "partner",
                        "ref_id": pid,
                        "ref_version": None,
                    }
                    for pid in wanted
                ],
            )
    await channel.mark_dirty(store, [gateway_id])
    await _audit(
        store,
        actor.id,
        "cp.assign",
        "assigned",
        None,
        {"gateway": gateway_id, "count": len(wanted)},
    )
    return {"gateway_id": gateway_id, "partner_ids": sorted(wanted)}


def _unknown_partners(indexes: Iterable[int]) -> RequestValidationError:
    """422 in the validation shape: ``fields`` names each unknown id's position."""
    return RequestValidationError(
        [
            {"loc": ("body", "partner_ids", i), "msg": "unknown partner", "type": "value_error"}
            for i in indexes
        ]
    )
