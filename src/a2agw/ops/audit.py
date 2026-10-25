"""Tamper-evident audit log: an append-only, hash-chained table of security decisions.

Each row stores ``hash = sha256(prev_hash + canonical_json(row))`` where the row is every
column except ``seq`` (assigned by the database) and ``hash`` itself, ``prev_hash``
included. The first row links to ``GENESIS_HASH`` (64 zeros). ``verify_chain`` recomputes
the chain and returns the ``seq`` of the first row that does not match: an edited row
fails its own hash, a deleted row breaks the link of the row after it. Removing rows from
the *end* of the table cannot be detected from the table alone; export the log (``a2agw
audit export``) to keep an external copy of the head.

What is stored: ids (principal, agent, partner, task), the action, its outcome, a
classification name and a small ``detail`` dict restricted to ``DETAIL_KEYS`` with string
values cut to ``DETAIL_MAX_CHARS``. Never message text, artifact contents or secrets.

Concurrency: appends are serialized by an ``asyncio.Lock`` per ``AuditLog`` (read the last
hash, insert, in one transaction). Phase 2 assumes a single writer process per database;
two processes appending to the same table could fork the chain.

Availability: ``emit``/``submit`` never raise. An audit failure is logged (exception class
only) and counted in ``audit_errors`` (reported by admin ``/healthz``); the request that
caused it proceeds (fail-open for availability, by design).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal, get_args

from sqlalchemy import Column, Float, Integer, MetaData, String, Table, Text, select
from sqlalchemy.ext.asyncio import AsyncEngine

log = logging.getLogger(__name__)

Action = Literal[
    "inbound.admit",
    "inbound.reject",
    "authz.deny",
    "partner.call",
    "egress.deny",
    "partner.add",
    "partner.quarantine",
    "partner.approve",
    "partner.disable",
    "partner.enable",
    "partner.update",
    "admin.read",
]
ACTIONS: frozenset[str] = frozenset(get_args(Action))
DETAIL_KEYS = frozenset(
    {
        "reason",
        "rule",
        "state",
        "tier",
        "principal_kind",
        "skill_id",
        "classification",
        "key_id",
        "count",
    }
)
DETAIL_MAX_CHARS = 256
FIELD_MAX_CHARS = 256
GENESIS_HASH = "0" * 64
_BATCH = 500

_metadata = MetaData()
AUDIT_TABLE = Table(
    "a2agw_audit",
    _metadata,
    Column("seq", Integer, primary_key=True, autoincrement=True),
    Column("ts", Float, nullable=False, index=True),
    Column("actor", String(256), nullable=False),
    Column("action", String(64), nullable=False, index=True),
    Column("agent_id", String(256), nullable=True, index=True),
    Column("partner_id", String(256), nullable=True, index=True),
    Column("task_id", String(256), nullable=True),
    Column("classification", String(32), nullable=True),
    Column("outcome", String(256), nullable=False),
    Column("detail_json", Text, nullable=False),
    Column("prev_hash", String(64), nullable=False),
    Column("hash", String(64), nullable=False),
    # sqlite: never reuse the seq of a deleted last row.
    sqlite_autoincrement=True,
)
_HASHED = (
    "ts",
    "actor",
    "action",
    "agent_id",
    "partner_id",
    "task_id",
    "classification",
    "outcome",
    "detail_json",
    "prev_hash",
)


@dataclass(frozen=True, kw_only=True)
class AuditEvent:
    actor: str  # principal id, "system" or "anonymous"
    action: Action
    agent_id: str | None = None
    partner_id: str | None = None
    task_id: str | None = None
    classification: str | None = None
    outcome: str = ""
    detail: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _cut(value: str | None, limit: int = FIELD_MAX_CHARS) -> str | None:
    return value[:limit] if isinstance(value, str) else None


def _finite(value: Any) -> bool:
    return isinstance(value, float) and math.isfinite(value)


def sanitize_detail(detail: dict[str, Any] | None) -> dict[str, Any]:
    """Allowlisted keys only; strings cut to ``DETAIL_MAX_CHARS``; non-scalars dropped."""
    out: dict[str, Any] = {}
    for key, value in (detail or {}).items():
        if key not in DETAIL_KEYS:
            continue
        if isinstance(value, str):
            out[key] = value[:DETAIL_MAX_CHARS]
        elif value is None or isinstance(value, bool | int) or _finite(value):
            out[key] = value
    return out


def _classification(value: Any) -> str | None:
    if value is None:
        return None
    name = getattr(value, "name", None)
    if isinstance(name, str):  # a Classification
        return name.lower()
    return _cut(str(value), 32)


def _digest(row: dict[str, Any]) -> str:
    body = {k: row[k] for k in _HASHED}
    return hashlib.sha256((row["prev_hash"] + canonical_json(body)).encode()).hexdigest()


def parse_since(value: str) -> float:
    """An ISO 8601 timestamp (naive means UTC) or epoch seconds -> epoch seconds."""
    try:
        number = float(value)
    except ValueError:
        pass
    else:
        if not math.isfinite(number):
            raise ValueError("since must be a finite timestamp")
        return number
    try:
        dt = datetime.fromisoformat(value.strip())
    except ValueError:
        raise ValueError("since must be an ISO 8601 timestamp") from None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.timestamp()


def _public(row: dict[str, Any]) -> dict[str, Any]:
    out = {k: v for k, v in row.items() if k != "detail_json"}
    try:
        out["detail"] = json.loads(row["detail_json"])
    except (TypeError, ValueError):
        out["detail"] = {}
    return out


class AuditLog:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        self._lock = asyncio.Lock()
        self._pending: set[asyncio.Task[None]] = set()
        self.audit_errors = 0  # failed emits since start (admin /healthz)

    async def initialize(self) -> None:
        async with self._engine.begin() as conn:
            await conn.run_sync(_metadata.create_all)

    # -- writing ---------------------------------------------------------------------------

    async def append(self, ev: AuditEvent) -> int:
        if ev.action not in ACTIONS:
            raise ValueError("unknown audit action")
        row: dict[str, Any] = {
            "ts": float(ev.ts),
            "actor": _cut(ev.actor) or "system",
            "action": ev.action,
            "agent_id": _cut(ev.agent_id),
            "partner_id": _cut(ev.partner_id),
            "task_id": _cut(ev.task_id),
            "classification": _classification(ev.classification),
            "outcome": _cut(ev.outcome) or "",
            "detail_json": canonical_json(sanitize_detail(ev.detail)),
        }
        t = AUDIT_TABLE
        async with self._lock, self._engine.begin() as conn:
            last = (
                await conn.execute(select(t.c.hash).order_by(t.c.seq.desc()).limit(1))
            ).scalar_one_or_none()
            row["prev_hash"] = last or GENESIS_HASH
            row["hash"] = _digest(row)
            result = await conn.execute(t.insert().values(**row))
            return int(result.inserted_primary_key[0])

    async def emit(self, ev: AuditEvent) -> None:
        """Append, never raising: failures are logged and counted (fail-open)."""
        try:
            await self.append(ev)
        except Exception as exc:  # noqa: BLE001 - audit must not break the request
            self.audit_errors += 1
            log.warning("audit append failed for %s: %s", ev.action, type(exc).__name__)

    def submit(self, ev: AuditEvent) -> None:
        """Fire-and-forget ``emit`` from sync code running on the event loop."""
        try:
            task = asyncio.get_running_loop().create_task(self.emit(ev))
        except RuntimeError:
            self.audit_errors += 1
            log.warning("audit append failed for %s: no running event loop", ev.action)
            return
        self._pending.add(task)
        task.add_done_callback(self._pending.discard)

    async def drain(self) -> None:
        """Wait for every submitted event to be written (or to fail)."""
        while self._pending:
            await asyncio.gather(*list(self._pending), return_exceptions=True)

    # -- reading ---------------------------------------------------------------------------

    async def query(
        self,
        filters: dict[str, Any],
        limit: int = 100,
        cursor: str | None = None,
        *,
        ascending: bool = False,
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Rows matching ``filters`` (``action``, ``agent``, ``partner``, ``since`` epoch
        seconds), newest first unless ``ascending``. ``cursor`` is the opaque value returned
        as the second item; ``ValueError`` if it is malformed."""
        t = AUDIT_TABLE
        stmt = select(t)
        if filters.get("action"):
            stmt = stmt.where(t.c.action == filters["action"])
        if filters.get("agent"):
            stmt = stmt.where(t.c.agent_id == filters["agent"])
        if filters.get("partner"):
            stmt = stmt.where(t.c.partner_id == filters["partner"])
        if filters.get("since") is not None:
            stmt = stmt.where(t.c.ts >= float(filters["since"]))
        if cursor:
            if not cursor.isdigit() or len(cursor) > 18:
                raise ValueError("invalid cursor")
            after = int(cursor)
            stmt = stmt.where(t.c.seq > after if ascending else t.c.seq < after)
        order = t.c.seq.asc() if ascending else t.c.seq.desc()
        stmt = stmt.order_by(order).limit(limit + 1)
        async with self._engine.connect() as conn:
            rows = [dict(r._mapping) for r in (await conn.execute(stmt)).all()]
        next_cursor = None
        if len(rows) > limit:
            rows = rows[:limit]
            next_cursor = str(rows[-1]["seq"])
        return [_public(r) for r in rows], next_cursor

    async def verify_chain(self) -> int | None:
        """The seq of the first row whose link or hash does not match, or None."""
        t = AUDIT_TABLE
        prev, after = GENESIS_HASH, None
        async with self._engine.connect() as conn:
            while True:
                stmt = select(t).order_by(t.c.seq.asc()).limit(_BATCH)
                if after is not None:
                    stmt = stmt.where(t.c.seq > after)
                batch = [dict(r._mapping) for r in (await conn.execute(stmt)).all()]
                if not batch:
                    return None
                for row in batch:
                    if row["prev_hash"] != prev or _digest(row) != row["hash"]:
                        return int(row["seq"])
                    prev, after = row["hash"], row["seq"]
