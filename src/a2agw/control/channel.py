"""The gateway channel, control-plane side: gateway tokens, ``/cp/v1/stream``, ``/cp/v1/report``,
desired state and the commands queue.

Gateways connect out to the control plane and authenticate with ``Authorization: Bearer
<gateway token>`` only (``gateway_auth``, set as ``app.state.gateway_auth``): the token's
digest must be in ``cp_gateway_tokens``, not revoked, for a gateway whose status is
``active``. A gateway's identity comes from its token alone; a gateway id in a query or a
body is ignored.

``GET /cp/v1/stream`` (server-sent events): ``hello`` first, then ``state`` whenever the
desired ``(epoch, version)`` differs from what the gateway has (``epoch`` and ``applied``
in the query, then what this stream sent; a missing or other epoch, after a database reset,
counts as behind), ``command`` for each pending, unexpired command (marked ``delivered`` as
it is sent: at most once), and a ``: keepalive`` comment every ``stream_keepalive_s``. The
handler polls the database every ``POLL_S`` (so any replica can serve any gateway), holds
no connection between polls, and ends at the first poll after its token is revoked. Each
poll is a few indexed lookups (token and gateway by primary key, desired state by primary
key, pending commands by ``(gateway_id, status, expires_at)``); ``last_seen_at`` is written
at most every ``SEEN_EVERY_S`` (``SeenWriter``). A poll's database work is shielded from
the client's disconnect (``Background``).

``POST /cp/v1/report``: events, audit rows, health, metrics, command results, the applied
version and gateway info. The body is capped at ``report_max_bytes`` (413) and each list at
``report_max_items``; anything cut, malformed or not allowed is counted in ``dropped``.
Events keep only their kind's allowlisted ``data`` keys and scalar values, strings cut to
``STRING_MAX``; the ``state`` of ``task.state`` and ``partner.call`` events and a call's
``duration_ms`` are also stored as columns (the Console's aggregations). Audit rows are
stored verbatim, keyed on ``(gateway_id, seq)``, so a report sent again changes nothing.
``partner.state`` events also update ``cp_partner_states``, the gateway's last reported
status of each partner and the hash of a pending card it holds (the partner catalogue shows
where a partner is quarantined; no card is taken from it).

Desired state (``compute_desired``): the approved partners and the policy assigned to the
gateway. Its hash is the SHA-256 of its canonical JSON, and its version grows only when the
hash changes. ``mark_dirty`` flags gateways whose assignments changed; the maintenance pass
(``recompute_dirty``) and the gateway's own stream recompute them.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import re
import secrets
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable
from dataclasses import dataclass
from typing import Any, Literal

from a2agw.control import require_fastapi

require_fastapi()

from fastapi import Depends, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import func, select, update
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects import sqlite as sqlite_dialect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection

from a2agw.control.rbac import gateway_route, require_gateway
from a2agw.control.store import (
    ASSIGNMENTS,
    COMMANDS,
    DESIRED,
    EVENTS,
    GATEWAY_AUDIT,
    GATEWAY_TOKENS,
    GATEWAYS,
    HEALTH,
    ID,
    PARTNER_STATES,
    PARTNER_VERSIONS,
    PARTNERS,
    POLICY_VERSIONS,
    ControlStore,
    token_digest,
)
from a2agw.ops.audit import AuditEvent, canonical_json

log = logging.getLogger(__name__)

POLL_S = 0.5  # how often a stream looks at the database
SEEN_EVERY_S = 5.0  # last_seen_at is written at most this often per gateway (per process)
STRING_MAX = 256  # strings in events (and other short fields) are cut to this
TRACE_ID_MAX = 64
URL_MAX = 2048
AUDIT_ROW_MAX_BYTES = 8192  # a gateway audit row larger than this (as JSON) is dropped
RESULT_MAX_BYTES = 8192  # a larger command result is stored as {"truncated": true}
TASK_GET_RESULT_MAX_BYTES = 65536  # task.get answers the gateway's compact task detail
SKILLS_MAX = 64  # skill ids kept per reported agent
TS_PAST_S = 86400.0  # event timestamps are clamped to [now - 1 day, now + 5 minutes]
TS_FUTURE_S = 300.0
INT_MAX_EXACT = 2**53  # larger ints are not kept as numbers
SEQ_MAX = 2**31 - 1  # cp_gateway_audit.seq is a 32-bit integer
COMMAND_TTL_S = 60.0
COMMANDS_PER_POLL = 100
WAIT_POLL_S = 0.25
DRAIN_TIMEOUT_S = 10.0  # shutdown waits this long for stream polls, then cancels them
CANCEL_WAIT_S = 1.0
_COMPUTE_TRIES = 5

# Event kinds and the ``data`` keys kept for each (see a2agw.ops.bus).
EVENT_KEYS: dict[str, frozenset[str]] = {
    "task.state": frozenset({"task_id", "context_id", "state", "trace_id"}),
    "partner.call": frozenset({"partner_id", "task_id", "state", "duration_ms", "trace_id"}),
    "partner.state": frozenset({"partner_id", "status", "event", "pending_hash"}),
    "security.denied": frozenset({"reason", "rule", "principal_kind"}),
}
FINISHED = frozenset({"done", "failed", "expired"})
_STATEFUL = frozenset({"task.state", "partner.call"})  # their ``state`` is a column too
STATE_MAX = 64

Sleep = Callable[[float], Awaitable[None]]

_UNSAFE = re.compile("[\ud800-\udfff\x00]")  # not storable in PostgreSQL text / UTF-8


def _clean(value: str, limit: int = STRING_MAX) -> str:
    return _UNSAFE.sub("�", value[:limit])


def _json(obj: Any) -> str:
    """Compact, sorted, ASCII-only JSON (anything a gateway sent is storable as is)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _number(value: Any) -> float | None:
    """A finite JSON number as a float; None for anything else (booleans included)."""
    return float(value) if _finite_number(value) else None


def _finite_number(value: Any) -> bool:
    """A JSON number usable as a float: a finite float, or an int within +-2**53 (exactly
    representable; a 400-digit int would raise OverflowError in ``math.isfinite``)."""
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return abs(value) < INT_MAX_EXACT
    return isinstance(value, float) and math.isfinite(value)


async def _emit(store: ControlStore, event: AuditEvent, coalesce: str | None = None) -> None:
    if store.audit is None:
        return
    if coalesce is None:
        await store.audit.emit(event)
    else:
        await store.audit.emit_coalesced(event, coalesce)


def _insert(store: ControlStore) -> Any:
    """The dialect's INSERT (for ON CONFLICT)."""
    return sqlite_dialect.insert if store.engine.dialect.name == "sqlite" else postgresql.insert


# -- gateway tokens ------------------------------------------------------------------------


def _live_token_query(digest: str) -> Any:
    return (
        select(GATEWAYS.c.id)
        .select_from(GATEWAY_TOKENS.join(GATEWAYS, GATEWAYS.c.id == GATEWAY_TOKENS.c.gateway_id))
        .where(GATEWAY_TOKENS.c.digest == digest)
        .where(GATEWAY_TOKENS.c.revoked_at.is_(None))
        .where(GATEWAYS.c.status == "active")
    )


async def gateway_auth(request: Request) -> str | None:
    """The gateway calling ``request`` (``app.state.gateway_auth``): ``Authorization: Bearer
    <gateway token>`` for a live token of an active gateway, else None. Nothing else (a
    session cookie, an API key) is looked at. The token's digest is kept on
    ``request.state`` so the stream can see it being revoked."""
    header = request.headers.get("authorization")
    if header is None:
        return None
    scheme, _, token = header.partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token:
        return None
    digest = token_digest(token)
    store: ControlStore = request.app.state.store
    async with store.engine.connect() as conn:
        gateway_id = (await conn.execute(_live_token_query(digest))).scalar_one_or_none()
    if gateway_id is None:
        return None
    request.state.cp_gateway_token = digest
    return str(gateway_id)


class SeenWriter:
    """Writes ``cp_gateways.last_seen_at`` at most once per ``every_s`` per gateway (stream
    polls and reports alike; ``app.state.seen``). The time of the last write is kept in
    memory, per process: each replica writes at most that often for the gateways it
    serves. ``connected`` (seen within two keepalive intervals) stays accurate as long as
    ``every_s`` is below that window."""

    def __init__(self, every_s: float = SEEN_EVERY_S) -> None:
        self.every_s = every_s
        self._written: dict[str, float] = {}

    async def seen(self, store: ControlStore, gateway_id: str, now: float) -> bool:
        """Record that the gateway was seen ``now``; returns whether it was written."""
        last = self._written.get(gateway_id)
        if last is not None and 0 <= now - last < self.every_s:
            return False
        self._written[gateway_id] = now
        async with store.engine.begin() as conn:
            await conn.execute(
                update(GATEWAYS).where(GATEWAYS.c.id == gateway_id).values(last_seen_at=now)
            )
        return True


async def _still_live(store: ControlStore, digest: str, gateway_id: str) -> bool:
    """Whether the stream's token still works (one primary-key lookup on each table)."""
    async with store.engine.connect() as conn:
        live = (await conn.execute(_live_token_query(digest))).scalar_one_or_none()
    return live == gateway_id


# -- desired state -------------------------------------------------------------------------


@dataclass(frozen=True)
class DesiredState:
    gateway_id: str
    epoch: str  # the store's epoch: versions count within it
    version: int
    hash: str
    partners: list[dict[str, Any]]
    policy: dict[str, Any] | None

    def frame(self) -> dict[str, Any]:
        """The ``state`` frame's data."""
        return {
            "epoch": self.epoch,
            "version": self.version,
            "hash": self.hash,
            "partners": self.partners,
            "policy": self.policy,
        }


def desired_hash(doc: dict[str, Any]) -> str:
    """SHA-256 (hex) of the canonical JSON (sorted keys, compact) of a desired document."""
    return hashlib.sha256(canonical_json(doc).encode()).hexdigest()


def _loads(raw: str | None, default: Any) -> Any:
    try:
        return json.loads(raw) if raw else default
    except ValueError:
        return default


async def _render(conn: AsyncConnection, gateway_id: str) -> dict[str, Any]:
    """The desired document of a gateway: ``{"partners": [...], "policy": dict | None}``."""
    assigned = (
        await conn.execute(
            select(ASSIGNMENTS)
            .where(ASSIGNMENTS.c.gateway_id == gateway_id)
            .order_by(ASSIGNMENTS.c.kind, ASSIGNMENTS.c.ref_id)
        )
    ).all()
    partners: list[dict[str, Any]] = []
    policy: dict[str, Any] | None = None
    for a in assigned:
        if a.kind == "partner":
            rendered = await _render_partner(conn, a.ref_id, a.ref_version)
            if rendered is not None:
                partners.append(rendered)
        elif a.kind == "policy" and policy is None:  # one policy per gateway
            policy = await _render_policy(conn, a.ref_id, a.ref_version)
    return {"partners": partners, "policy": policy}


async def _render_partner(
    conn: AsyncConnection, partner_id: str, pinned: int | None
) -> dict[str, Any] | None:
    """An approved partner as its approved version: the pinned one if it is approved, else
    the latest approved version up to the current one. None when there is none."""
    p = (
        await conn.execute(
            select(PARTNERS)
            .where(PARTNERS.c.id == partner_id)
            .where(PARTNERS.c.status == "approved")
        )
    ).first()
    if p is None:
        return None
    query = (
        select(PARTNER_VERSIONS)
        .where(PARTNER_VERSIONS.c.partner_id == partner_id)
        .where(PARTNER_VERSIONS.c.approved_at.is_not(None))
    )
    if pinned is not None:
        query = query.where(PARTNER_VERSIONS.c.version == pinned)
    else:
        query = query.where(PARTNER_VERSIONS.c.version <= p.current_version)
    v = (await conn.execute(query.order_by(PARTNER_VERSIONS.c.version.desc()).limit(1))).first()
    if v is None:
        return None
    tags = _loads(p.tags_json, [])
    return {
        "id": p.id,
        "card": _loads(v.card_json, {}),
        "card_hash": v.card_hash,
        "tier": p.tier,
        "credential_ref": p.credential_ref,
        "tls_ref": p.tls_ref,
        "tags": tags if isinstance(tags, list) else [],
        "card_url": p.card_url,
    }


async def _render_policy(
    conn: AsyncConnection, policy_id: str, pinned: int | None
) -> dict[str, Any] | None:
    query = select(POLICY_VERSIONS.c.doc_json).where(POLICY_VERSIONS.c.policy_id == policy_id)
    if pinned is not None:
        query = query.where(POLICY_VERSIONS.c.version == pinned)
    raw = (
        await conn.execute(query.order_by(POLICY_VERSIONS.c.version.desc()).limit(1))
    ).scalar_one_or_none()
    if raw is None:
        return None
    doc = _loads(raw, None)
    return doc if isinstance(doc, dict) else None


async def compute_desired(store: ControlStore, gateway_id: str) -> DesiredState:
    """Render the desired state of ``gateway_id`` and store it in ``cp_desired``. The version
    starts at 1 and grows by one only when the hash changes. ``KeyError`` for an unknown
    gateway.

    The gateway row is written first (a no-op update), which serializes computations for
    one gateway: on PostgreSQL it locks the row, on sqlite it takes the write lock before
    anything is read. The version update is also conditional on the version read, so a
    lost race is retried."""
    for _ in range(_COMPUTE_TRIES):
        try:
            state = await _compute_once(store, gateway_id)
        except IntegrityError:  # a concurrent first computation inserted the row
            continue
        if state is not None:
            return state
    raise RuntimeError("desired state kept changing while it was computed")


async def _compute_once(store: ControlStore, gateway_id: str) -> DesiredState | None:
    now = store.now()
    async with store.engine.begin() as conn:
        locked = await conn.execute(
            update(GATEWAYS)
            .where(GATEWAYS.c.id == gateway_id)
            .values(desired_gen=GATEWAYS.c.desired_gen)
        )
        if not locked.rowcount:
            raise KeyError(f"unknown gateway {gateway_id}")
        gen = (
            await conn.execute(select(GATEWAYS.c.desired_gen).where(GATEWAYS.c.id == gateway_id))
        ).scalar_one()
        doc = await _render(conn, gateway_id)
        digest = desired_hash(doc)
        current = (
            await conn.execute(select(DESIRED).where(DESIRED.c.gateway_id == gateway_id))
        ).first()
        if current is None:
            version = 1
            await conn.execute(
                DESIRED.insert().values(
                    gateway_id=gateway_id,
                    version=version,
                    doc_json=canonical_json(doc),
                    doc_hash=digest,
                    computed_at=now,
                    source_gen=gen,
                )
            )
        elif current.doc_hash == digest:
            version = current.version
            if current.source_gen < gen:
                await conn.execute(
                    update(DESIRED)
                    .where(DESIRED.c.gateway_id == gateway_id)
                    .where(DESIRED.c.source_gen < gen)
                    .values(source_gen=gen)
                )
        else:
            version = current.version + 1
            moved = await conn.execute(
                update(DESIRED)
                .where(DESIRED.c.gateway_id == gateway_id)
                .where(DESIRED.c.version == current.version)
                .values(
                    version=version,
                    doc_json=canonical_json(doc),
                    doc_hash=digest,
                    computed_at=now,
                    source_gen=max(gen, current.source_gen),
                )
            )
            if moved.rowcount != 1:
                return None
    return DesiredState(gateway_id, store.epoch, version, digest, doc["partners"], doc["policy"])


async def load_desired(store: ControlStore, gateway_id: str) -> DesiredState | None:
    """The stored desired state (as last computed), or None."""
    async with store.engine.connect() as conn:
        row = (
            await conn.execute(select(DESIRED).where(DESIRED.c.gateway_id == gateway_id))
        ).first()
    if row is None:
        return None
    doc = _loads(row.doc_json, {})
    return DesiredState(
        gateway_id,
        store.epoch,
        row.version,
        row.doc_hash,
        doc.get("partners", []),
        doc.get("policy"),
    )


async def mark_dirty(store: ControlStore, gateway_ids: Iterable[str]) -> None:
    """Flag gateways whose desired state may have changed (an assignment, an approved
    partner version, a new policy version): it is recomputed by the maintenance pass and
    by the gateway's open stream at its next poll. Unknown ids are ignored."""
    ids = sorted(set(gateway_ids))
    if not ids:
        return
    async with store.engine.begin() as conn:
        await conn.execute(
            update(GATEWAYS)
            .where(GATEWAYS.c.id.in_(ids))
            .values(desired_gen=GATEWAYS.c.desired_gen + 1)
        )


def _dirty() -> Any:
    return DESIRED.c.gateway_id.is_(None) | (GATEWAYS.c.desired_gen > DESIRED.c.source_gen)


async def dirty_gateways(store: ControlStore) -> list[str]:
    """Active gateways whose desired state is missing or flagged by ``mark_dirty``."""
    query = (
        select(GATEWAYS.c.id)
        .select_from(GATEWAYS.outerjoin(DESIRED, DESIRED.c.gateway_id == GATEWAYS.c.id))
        .where(GATEWAYS.c.status == "active")
        .where(_dirty())
        .order_by(GATEWAYS.c.id)
    )
    async with store.engine.connect() as conn:
        return [str(g) for g in (await conn.execute(query)).scalars()]


async def recompute_dirty(store: ControlStore) -> int:
    """Recompute every dirty gateway's desired state (the maintenance hook); returns how
    many were recomputed."""
    count = 0
    for gateway_id in await dirty_gateways(store):
        try:
            await compute_desired(store, gateway_id)
        except KeyError:  # deleted in between
            continue
        count += 1
    return count


async def _clean_version(store: ControlStore, gateway_id: str) -> int | None:
    """The stored desired version, or None when it must be (re)computed."""
    query = (
        select(DESIRED.c.version, _dirty().label("dirty"))
        .select_from(GATEWAYS.outerjoin(DESIRED, DESIRED.c.gateway_id == GATEWAYS.c.id))
        .where(GATEWAYS.c.id == gateway_id)
    )
    async with store.engine.connect() as conn:
        row = (await conn.execute(query)).first()
    if row is None or row.version is None or row.dirty:
        return None
    return int(row.version)


# -- commands ------------------------------------------------------------------------------


@dataclass(frozen=True)
class CommandRow:
    id: str
    gateway_id: str
    kind: str
    args: dict[str, Any]
    status: str  # pending | delivered | done | failed | expired
    result: Any
    actor: str
    created_at: float
    delivered_at: float | None
    finished_at: float | None
    expires_at: float

    def frame(self) -> dict[str, Any]:
        """The ``command`` frame's data. ``actor`` (who queued it) is what the gateway runs
        it as: ``cp:<actor>``, so the gateway's own audit trail names the operator."""
        return {
            "id": self.id,
            "kind": self.kind,
            "args": self.args,
            "expires_at": self.expires_at,
            "actor": self.actor,
        }


def _command(row: Any) -> CommandRow:
    args = _loads(row.args_json, {})
    return CommandRow(
        id=row.id,
        gateway_id=row.gateway_id,
        kind=row.kind,
        args=args if isinstance(args, dict) else {},
        status=row.status,
        result=_loads(row.result_json, None),
        actor=row.actor,
        created_at=row.created_at,
        delivered_at=row.delivered_at,
        finished_at=row.finished_at,
        expires_at=row.expires_at,
    )


async def enqueue_command(
    store: ControlStore,
    gateway_id: str,
    kind: str,
    args: dict[str, Any],
    actor: str,
    ttl_s: float = COMMAND_TTL_S,
) -> str:
    """Queue a command for a gateway; it is delivered on the gateway's stream (at most
    once) until ``ttl_s`` from now. Returns its id. ``KeyError`` for an unknown gateway,
    ``ValueError`` for a revoked one or a bad kind or ttl, ``TypeError`` for args that
    are not a dict."""
    if not kind or len(kind) > 64:
        raise ValueError("command kind must be 1 to 64 characters")
    if not isinstance(args, dict):
        raise TypeError("command args must be an object")
    if not (ttl_s > 0 and math.isfinite(ttl_s)):
        raise ValueError("ttl_s must be a positive number")
    args_json = _json(args)
    command_id = f"cmd-{secrets.token_hex(8)}"
    now = store.now()
    async with store.engine.begin() as conn:
        status = (
            await conn.execute(select(GATEWAYS.c.status).where(GATEWAYS.c.id == gateway_id))
        ).scalar_one_or_none()
        if status is None:
            raise KeyError(f"unknown gateway {gateway_id}")
        if status != "active":
            raise ValueError("gateway is revoked")
        await conn.execute(
            COMMANDS.insert().values(
                id=command_id,
                gateway_id=gateway_id,
                kind=kind,
                args_json=args_json,
                status="pending",
                actor=actor,
                created_at=now,
                expires_at=now + ttl_s,
            )
        )
    await _emit(
        store,
        AuditEvent(
            actor=actor,
            action="cp.command",
            outcome="queued",
            detail={"gateway": gateway_id, "command": kind},
            ts=now,
        ),
    )
    return command_id


async def find_command(
    store: ControlStore,
    gateway_id: str,
    kind: str,
    args: dict[str, Any],
    *,
    now: float,
    done_within_s: float,
) -> str | None:
    """The newest command of ``kind`` with exactly ``args`` for the gateway that is still
    open (pending or delivered, unexpired) or finished ``done`` within ``done_within_s``,
    so a caller can share it instead of queueing the same command again; else None."""
    open_ = COMMANDS.c.status.in_(("pending", "delivered")) & (COMMANDS.c.expires_at > now)
    fresh = (COMMANDS.c.status == "done") & (COMMANDS.c.finished_at >= now - done_within_s)
    query = (
        select(COMMANDS.c.id)
        .where(COMMANDS.c.gateway_id == gateway_id)
        .where(COMMANDS.c.kind == kind)
        .where(COMMANDS.c.args_json == _json(args))
        .where(open_ | fresh)
        .order_by(COMMANDS.c.created_at.desc(), COMMANDS.c.id.desc())
        .limit(1)
    )
    async with store.engine.connect() as conn:
        found = (await conn.execute(query)).scalar_one_or_none()
    return str(found) if found is not None else None


async def get_command(store: ControlStore, command_id: str) -> CommandRow:
    """``KeyError`` for an unknown (or purged) command."""
    async with store.engine.connect() as conn:
        row = (await conn.execute(select(COMMANDS).where(COMMANDS.c.id == command_id))).first()
    if row is None:
        raise KeyError(f"unknown command {command_id}")
    return _command(row)


async def wait_command(
    store: ControlStore,
    command_id: str,
    timeout_s: float,
    *,
    sleep: Sleep = asyncio.sleep,
    interval_s: float = WAIT_POLL_S,
) -> CommandRow:
    """The command once it is finished (done, failed or expired), or as it is after
    ``timeout_s`` (still pending or delivered). It polls every ``interval_s``; the timeout
    counts the time slept, so a fake ``sleep`` makes it deterministic."""
    waited = 0.0
    while True:
        row = await get_command(store, command_id)
        if row.status in FINISHED or waited >= timeout_s:
            return row
        step = min(interval_s, timeout_s - waited)
        await sleep(step)
        waited += step


async def take_commands(
    store: ControlStore, gateway_id: str, now: float, *, digest: str | None = None
) -> list[CommandRow]:
    """The gateway's pending, unexpired commands, oldest first, marked ``delivered``. A
    command another stream (or replica) took first is not returned.

    The marking UPDATE itself requires the gateway to be active and, with ``digest`` (the
    stream's token), that token to be live: a revoke or rotation landing between a poll's
    liveness check and this delivers nothing."""
    live = (
        select(GATEWAYS.c.id)
        .where(GATEWAYS.c.id == gateway_id)
        .where(GATEWAYS.c.status == "active")
    )
    if digest is not None:
        live = live.where(
            select(GATEWAY_TOKENS.c.digest)
            .where(GATEWAY_TOKENS.c.digest == digest)
            .where(GATEWAY_TOKENS.c.gateway_id == gateway_id)
            .where(GATEWAY_TOKENS.c.revoked_at.is_(None))
            .exists()
        )
    async with store.engine.begin() as conn:
        pending = (
            await conn.execute(
                select(COMMANDS)
                .where(COMMANDS.c.gateway_id == gateway_id)
                .where(COMMANDS.c.status == "pending")
                .where(COMMANDS.c.expires_at > now)
                .order_by(COMMANDS.c.created_at, COMMANDS.c.id)
                .limit(COMMANDS_PER_POLL)
            )
        ).all()
        taken: list[CommandRow] = []
        for row in pending:
            marked = await conn.execute(
                update(COMMANDS)
                .where(COMMANDS.c.id == row.id)
                .where(COMMANDS.c.status == "pending")
                .where(COMMANDS.c.expires_at > now)  # expiry is final, even mid-poll
                .where(live.exists())
                .values(status="delivered", delivered_at=now)
            )
            if marked.rowcount == 1:
                taken.append(_command(row))
    return taken


def result_cap(kind: str) -> int:
    """The largest result (as JSON) kept for a command of ``kind``: 64 KiB for ``task.get``
    (the gateway's compact task detail), 8 KiB for every other kind."""
    return TASK_GET_RESULT_MAX_BYTES if kind == "task.get" else RESULT_MAX_BYTES


async def finish_command(
    store: ControlStore,
    gateway_id: str,
    command_id: str,
    status: Literal["done", "failed"],
    result: Any,
    *,
    now: float,
) -> bool:
    """Record a gateway's result for one of its delivered commands; one larger than
    ``result_cap`` is stored as ``{"truncated": true}``. False (nothing changes) for a
    command of another gateway, or one not in ``delivered``."""
    result_json = _json(result)
    async with store.engine.begin() as conn:
        kind = (
            await conn.execute(
                select(COMMANDS.c.kind)
                .where(COMMANDS.c.id == command_id)
                .where(COMMANDS.c.gateway_id == gateway_id)
                .where(COMMANDS.c.status == "delivered")
            )
        ).scalar_one_or_none()
        if kind is None:
            return False
        if len(result_json) > result_cap(kind):
            result_json = _json({"truncated": True})
        done = await conn.execute(
            update(COMMANDS)
            .where(COMMANDS.c.id == command_id)
            .where(COMMANDS.c.status == "delivered")
            .values(status=status, result_json=result_json, finished_at=now)
        )
        if done.rowcount != 1:
            return False
    await _emit(
        store,
        AuditEvent(
            actor=gateway_id,
            action="cp.command",
            outcome=status,
            detail={"gateway": gateway_id, "command": kind},
            ts=now,
        ),
    )
    return True


# -- the stream ----------------------------------------------------------------------------


def _frame(event: str, data: Any) -> str:
    return f"event: {event}\ndata: {_json(data)}\n\n"


class Background:
    """Database work of streams, run as tasks the client's disconnect cannot cancel.

    Starlette cancels a streaming response's generator when the client goes away. A
    cancellation that lands inside a database call can leave the connection half-closed
    (aiosqlite's terminate never completes under it). So each poll's database work runs in
    its own task, awaited through ``asyncio.shield``: a disconnect cancels the generator at
    that await, and the poll finishes on its own and returns its connections. The
    lifespan awaits ``drain`` before it disposes the engine (``app.state.background``)."""

    def __init__(self, drain_timeout_s: float = DRAIN_TIMEOUT_S) -> None:
        self.drain_timeout_s = drain_timeout_s
        self._tasks: set[asyncio.Task[Any]] = set()

    @property
    def pending(self) -> int:
        return len(self._tasks)

    async def run(self, work: Awaitable[Any]) -> Any:
        task = asyncio.ensure_future(work)
        self._tasks.add(task)
        task.add_done_callback(self._done)
        return await asyncio.shield(task)

    def _done(self, task: asyncio.Task[Any]) -> None:
        self._tasks.discard(task)
        if not task.cancelled():
            task.exception()  # retrieved: a poll nobody awaits any more may fail quietly

    async def drain(self) -> None:
        """Wait for the running polls, ``drain_timeout_s`` at most; the ones still running
        then (a stuck database call) are cancelled and logged by name, so shutdown always
        finishes."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.drain_timeout_s
        while self._tasks and (left := deadline - loop.time()) > 0:
            await asyncio.wait(list(self._tasks), timeout=left)
        stragglers = list(self._tasks)
        if not stragglers:
            return
        names = sorted({_task_name(t) for t in stragglers})
        log.warning(
            "control-plane shutdown: cancelling %d stream poll(s) still running after %.1fs: %s",
            len(stragglers),
            self.drain_timeout_s,
            ", ".join(names),
        )
        for t in stragglers:
            t.cancel()
        await asyncio.wait(stragglers, timeout=CANCEL_WAIT_S)
        self._tasks.difference_update(stragglers)


def _task_name(task: asyncio.Task[Any]) -> str:
    coro = task.get_coro()
    return str(getattr(coro, "__qualname__", type(coro).__name__))


@dataclass
class _Poll:
    """One stream's state between polls: what the gateway has, (epoch, version), from the
    query and then from what this stream sent. Any difference from the desired (epoch,
    version) means behind, a version number of another epoch (a reset or replaced
    database) included."""

    store: ControlStore
    seen: SeenWriter
    gateway_id: str
    digest: str
    sent: tuple[str | None, int]

    async def once(self, now: float) -> list[str] | None:
        """The frames of one poll, or None when the token no longer works."""
        store, gateway_id = self.store, self.gateway_id
        if not await _still_live(store, self.digest, gateway_id):
            return None
        await self.seen.seen(store, gateway_id, now)
        out: list[str] = []
        desired: DesiredState | None = None
        version = await _clean_version(store, gateway_id)
        if version is None:
            desired = await compute_desired(store, gateway_id)
            version = desired.version
        if (store.epoch, version) != self.sent:
            desired = desired or await load_desired(store, gateway_id)
            if desired is not None:
                out.append(_frame("state", desired.frame()))
                self.sent = (desired.epoch, desired.version)
        taken = await take_commands(store, gateway_id, now, digest=self.digest)
        out += [_frame("command", c.frame()) for c in taken]
        return out


async def _frames(
    request: Request, gateway_id: str, digest: str, applied: tuple[str | None, int]
) -> AsyncIterator[str]:
    state = request.app.state
    store: ControlStore = state.store
    clock: Callable[[], float] = state.clock
    sleep: Sleep = state.sleep
    background: Background = state.background
    keepalive = state.settings.limits.stream_keepalive_s
    now = clock()
    connected = AuditEvent(
        actor=gateway_id,
        action="cp.connect",
        outcome="connected",
        detail={"gateway": gateway_id},
        ts=now,
    )
    await background.run(_emit(store, connected, coalesce=gateway_id))
    yield _frame("hello", {"gateway_id": gateway_id, "server_time": now})
    poll = _Poll(store, state.seen, gateway_id, digest, applied)
    last_beat = now
    while True:
        now = clock()
        frames = await background.run(poll.once(now))
        if frames is None:
            return  # revoked (or rotated away): the stream ends
        for frame in frames:
            yield frame
        if now - last_beat >= keepalive:
            yield ": keepalive\n\n"
            last_beat = now
        await sleep(POLL_S)


@gateway_route("GET", "/cp/v1/stream")
async def stream(
    request: Request,
    applied: int = Query(0, ge=0),
    epoch: str | None = Query(None, max_length=64),
    me: str = Depends(require_gateway),
) -> StreamingResponse:
    """The gateway's event stream (server-sent events). ``applied`` and ``epoch``: the
    desired state the gateway has (no epoch, or another one: it is sent the state)."""
    digest: str = request.state.cp_gateway_token
    return StreamingResponse(
        _frames(request, me, digest, (epoch or None, applied)),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


# -- reports -------------------------------------------------------------------------------

_FORBID = ConfigDict(extra="forbid")


class Applied(BaseModel):
    model_config = _FORBID
    epoch: str = Field(max_length=64)
    version: int = Field(ge=0, le=SEQ_MAX)
    hash: str = Field(max_length=128)
    status: Literal["applied", "rejected"]
    reason: str | None = None


class ReportedAgent(BaseModel):
    """A hosted agent as gateway info describes it (gateways before this sent bare ids)."""

    model_config = _FORBID
    id: str
    name: str | None = None
    version: str | None = None
    skills: list[Any] | None = None  # skill ids; anything else is dropped
    card_url: str | None = None


class GatewayInfo(BaseModel):
    model_config = _FORBID
    version: str
    agents: list[str | ReportedAgent]
    base_url: str


class Report(BaseModel):
    """The body of ``/cp/v1/report``. Lists are validated item by item (a bad item is
    dropped and counted, not a reason to refuse the report)."""

    model_config = _FORBID
    events: list[Any] = Field(default_factory=list)
    audit: list[Any] = Field(default_factory=list)
    health: dict[str, Any] | None = None
    metrics: dict[str, Any] | None = None
    results: list[Any] = Field(default_factory=list)
    applied: Applied | None = None
    info: GatewayInfo | None = None
    gateway_id: Any = None  # accepted and ignored: the gateway is the one of the token


def _too_large(limit: int) -> HTTPException:
    return HTTPException(
        413, {"error": "too_large", "detail": f"report body exceeds {limit} bytes"}
    )


async def _read_capped(request: Request, limit: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > limit:
        raise _too_large(limit)
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > limit:
            raise _too_large(limit)
    return bytes(body)


def _no_constants(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def _parse_report(raw: bytes) -> Report:
    try:
        data = json.loads(raw, parse_constant=_no_constants)
    except ValueError:
        raise RequestValidationError(
            [{"loc": ("body",), "msg": "invalid JSON", "type": "json_invalid"}]
        ) from None
    try:
        return Report.model_validate(data)
    except ValidationError as e:
        raise RequestValidationError(
            [
                {"loc": ("body", *err["loc"]), "msg": err["msg"], "type": err["type"]}
                for err in e.errors()
            ]
        ) from None


def _scalar(value: Any) -> tuple[bool, Any]:
    """``(keep, value)``: strings cut and cleaned, finite numbers, booleans and null kept;
    anything else (objects, lists) dropped."""
    if isinstance(value, str):
        return True, _clean(value)
    if value is None or isinstance(value, bool) or _finite_number(value):
        return True, value
    return False, None


def _clamp_ts(value: Any, now: float) -> float:
    """A reported timestamp within [now - 1 day, now + 5 minutes]; ``now`` when it is not
    a usable number."""
    sent = _number(value)
    return now if sent is None else min(max(sent, now - TS_PAST_S), now + TS_FUTURE_S)


def _seq_order(item: Any) -> tuple[int, int]:
    seq = item.get("seq") if isinstance(item, dict) else None
    if type(seq) is int and 0 <= seq <= SEQ_MAX:
        return (0, seq)
    return (1, 0)


def _event_row(item: Any, gateway_id: str, now: float) -> dict[str, Any] | None:
    """The ``cp_events`` row of one reported event, or None to drop it."""
    if not isinstance(item, dict):
        return None
    kind = item.get("kind")
    keys = EVENT_KEYS.get(kind) if isinstance(kind, str) else None
    agent_id = item.get("agent_id")
    raw = item.get("data", {})
    if keys is None or not isinstance(agent_id, str) or not isinstance(raw, dict):
        return None
    data: dict[str, Any] = {}
    for key in sorted(keys & raw.keys()):
        keep, value = _scalar(raw[key])
        if keep:
            data[key] = value
    ts = _clamp_ts(item.get("ts"), now)

    def column(key: str, limit: int = STRING_MAX) -> str | None:
        value = data.get(key)
        return _clean(value, limit) if isinstance(value, str) else None

    return {
        "gateway_id": gateway_id,
        "ts": ts,
        "kind": kind,
        "agent_id": _clean(agent_id),
        "partner_id": column("partner_id"),
        "task_id": column("task_id"),
        "trace_id": column("trace_id", TRACE_ID_MAX),
        "data_json": _json(data),
        "state": column("state", STATE_MAX) if kind in _STATEFUL else None,
        "duration_ms": _number(data.get("duration_ms")) if kind == "partner.call" else None,
    }


def _partner_state(row: dict[str, Any]) -> dict[str, Any] | None:
    """The ``cp_partner_states`` values of a stored ``partner.state`` event row, or None
    when it lacks a partner id or status. A ``removed`` event has status None (the row is
    deleted)."""
    if row["kind"] != "partner.state":
        return None
    data = _loads(row["data_json"], {})
    partner_id, status, event = data.get("partner_id"), data.get("status"), data.get("event")
    if not isinstance(partner_id, str) or not partner_id or not isinstance(status, str):
        return None
    pending = data.get("pending_hash")
    return {
        "gateway_id": row["gateway_id"],
        "partner_id": _clean(partner_id, ID),
        "status": None if event == "removed" else _clean(status, 16),
        "pending_hash": _clean(pending, ID) if isinstance(pending, str) else None,
        "event": _clean(event, 32) if isinstance(event, str) else "",
        "ts": row["ts"],
    }


async def _record_partner_states(
    store: ControlStore, conn: AsyncConnection, rows: list[dict[str, Any]]
) -> None:
    """Keep each gateway's last reported state of each partner (where the partner list
    shows it quarantined, and the pending hash an approval is matched against)."""
    for state in sorted(filter(None, map(_partner_state, rows)), key=lambda r: r["ts"]):
        key = (PARTNER_STATES.c.gateway_id == state["gateway_id"]) & (
            PARTNER_STATES.c.partner_id == state["partner_id"]
        )
        if state["status"] is None:
            await conn.execute(PARTNER_STATES.delete().where(key))
            continue
        stmt = _insert(store)(PARTNER_STATES).values(**state)
        changes = {k: state[k] for k in ("status", "pending_hash", "event", "ts")}
        await conn.execute(
            stmt.on_conflict_do_update(
                index_elements=["gateway_id", "partner_id"],
                set_=changes,
                where=PARTNER_STATES.c.ts <= state["ts"],
            )
        )


def _agent(agent: str | ReportedAgent) -> dict[str, Any]:
    """A reported agent as stored: ``{id, name, version, skills, card_url}``, strings cut,
    at most ``SKILLS_MAX`` skill ids (a bare id has the other fields null)."""
    if isinstance(agent, str):
        agent = ReportedAgent(id=agent)

    def text(value: str | None, limit: int = STRING_MAX) -> str | None:
        return _clean(value, limit) if value is not None else None

    skills = None
    if agent.skills is not None:
        skills = [_clean(s) for s in agent.skills if isinstance(s, str)][:SKILLS_MAX]
    return {
        "id": _clean(agent.id),
        "name": text(agent.name),
        "version": text(agent.version),
        "skills": skills,
        "card_url": text(agent.card_url, URL_MAX),
    }


@dataclass
class _Ingest:
    store: ControlStore
    gateway_id: str
    now: float
    max_items: int
    dropped: int = 0

    def cap(self, items: list[Any]) -> list[Any]:
        if len(items) > self.max_items:
            self.dropped += len(items) - self.max_items
            return items[: self.max_items]
        return items

    async def events(self, items: list[Any]) -> int:
        rows = []
        for item in self.cap(items):
            row = _event_row(item, self.gateway_id, self.now)
            if row is None:
                self.dropped += 1
            else:
                rows.append(row)
        if rows:
            async with self.store.engine.begin() as conn:
                await conn.execute(EVENTS.insert(), rows)
                await _record_partner_states(self.store, conn, rows)
        return len(rows)

    async def audit(self, items: list[Any]) -> int:
        """Store the gateway's audit rows; returns the seq the gateway may forget up to."""
        rows = []
        acked = 0
        # by seq (rows without a usable seq last), so the cap cuts the highest seqs: a row
        # cut here is never acked, and is sent again
        for item in self.cap(sorted(items, key=_seq_order)):
            seq = item.get("seq") if isinstance(item, dict) else None
            if type(seq) is not int or not 0 <= seq <= SEQ_MAX:
                self.dropped += 1
                continue
            acked = max(acked, seq)  # handled: stored, already stored, or too large
            row_json = _json(item)
            if len(row_json) > AUDIT_ROW_MAX_BYTES:
                self.dropped += 1
                continue
            rows.append(
                {
                    "gateway_id": self.gateway_id,
                    "seq": seq,
                    "row_json": row_json,  # verbatim, its own ts included
                    "ts": _clamp_ts(item.get("ts"), self.now),  # ordering and retention
                }
            )
        async with self.store.engine.begin() as conn:
            if rows:
                stmt = _insert(self.store)(GATEWAY_AUDIT).on_conflict_do_nothing()
                await conn.execute(stmt, rows)
            stored = (
                await conn.execute(
                    select(func.max(GATEWAY_AUDIT.c.seq)).where(
                        GATEWAY_AUDIT.c.gateway_id == self.gateway_id
                    )
                )
            ).scalar_one_or_none()
        return max(acked, int(stored or 0))

    async def health(self, health: dict[str, Any] | None, metrics: dict[str, Any] | None) -> None:
        if health is None and metrics is None:
            return
        values: dict[str, Any] = {"ts": self.now}
        if health is not None:
            values["health_json"] = _json(health)
        if metrics is not None:
            values["metrics_json"] = _json(metrics)
        stmt = _insert(self.store)(HEALTH).values(
            gateway_id=self.gateway_id,
            ts=self.now,
            health_json=values.get("health_json", "{}"),
            metrics_json=values.get("metrics_json", "{}"),
        )
        stmt = stmt.on_conflict_do_update(index_elements=["gateway_id"], set_=values)
        async with self.store.engine.begin() as conn:
            await conn.execute(stmt)

    async def results(self, items: list[Any]) -> None:
        for item in self.cap(items):
            ok = (
                isinstance(item, dict)
                and isinstance(item.get("id"), str)
                and item.get("status") in ("done", "failed")
                and await finish_command(
                    self.store,
                    self.gateway_id,
                    item["id"],
                    item["status"],
                    item.get("result"),
                    now=self.now,
                )
            )
            if not ok:
                self.dropped += 1

    async def applied(self, applied: Applied) -> None:
        gateway_id, now = self.gateway_id, self.now
        detail: dict[str, Any] = {
            "gateway": gateway_id,
            "version": applied.version,
            "hash": _clean(applied.hash),
        }
        epoch = _clean(applied.epoch, TRACE_ID_MAX)
        if applied.status == "applied":
            async with self.store.engine.begin() as conn:
                changed = await conn.execute(
                    update(GATEWAYS)
                    .where(GATEWAYS.c.id == gateway_id)
                    .where(
                        (GATEWAYS.c.last_version_applied != applied.version)
                        | GATEWAYS.c.epoch_applied.is_distinct_from(epoch)
                    )
                    .values(last_version_applied=applied.version, epoch_applied=epoch)
                )
            if changed.rowcount:
                event = AuditEvent(
                    actor=gateway_id, action="cp.apply", outcome="applied", detail=detail, ts=now
                )
                await _emit(self.store, event)
            return
        reason = _clean(applied.reason or "")
        rejection = {
            "epoch": epoch,
            "version": applied.version,
            "hash": _clean(applied.hash),
            "reason": reason,
            "at": now,
        }
        await self._update_info(lambda info: {**info, "last_rejection": rejection})
        event = AuditEvent(
            actor=gateway_id,
            action="cp.apply",
            outcome="rejected",
            detail={**detail, "reason": reason},
            ts=now,
        )
        await _emit(
            self.store, event, coalesce=f"{gateway_id}:{epoch}:{applied.version}:{applied.hash}"
        )

    async def info(self, info: GatewayInfo) -> None:
        agents = [_agent(a) for a in self.cap(info.agents)]
        reported = {
            "version": _clean(info.version),
            "agents": agents,
            "base_url": _clean(info.base_url, URL_MAX),
        }
        await self._update_info(lambda stored: {**stored, **reported})

    async def _update_info(self, change: Callable[[dict[str, Any]], dict[str, Any]]) -> None:
        async with self.store.engine.begin() as conn:
            raw = (
                await conn.execute(
                    select(GATEWAYS.c.info_json).where(GATEWAYS.c.id == self.gateway_id)
                )
            ).scalar_one_or_none()
            stored = _loads(raw, {})
            updated = change(stored if isinstance(stored, dict) else {})
            await conn.execute(
                update(GATEWAYS)
                .where(GATEWAYS.c.id == self.gateway_id)
                .values(info_json=_json(updated))
            )


@gateway_route("POST", "/cp/v1/report")
async def report(request: Request, me: str = Depends(require_gateway)) -> dict[str, int]:
    """Ingest a gateway's report; returns what was taken."""
    state = request.app.state
    limits = state.settings.limits
    body = _parse_report(await _read_capped(request, limits.report_max_bytes))
    store: ControlStore = state.store
    now = state.clock()
    await state.seen.seen(store, me, now)
    ingest = _Ingest(store, me, now, limits.report_max_items)
    accepted = await ingest.events(body.events)
    acked = await ingest.audit(body.audit)
    await ingest.health(body.health, body.metrics)
    await ingest.results(body.results)
    if body.applied is not None:
        await ingest.applied(body.applied)
    if body.info is not None:
        await ingest.info(body.info)
    return {"acked_audit_seq": acked, "accepted_events": accepted, "dropped": ingest.dropped}
