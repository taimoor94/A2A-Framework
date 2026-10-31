"""Durable per-agent A2A task storage, a cross-owner task index and restart recovery."""

from __future__ import annotations

import asyncio
import base64
import binascii
import builtins
import logging
import re
import time
import warnings
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from a2a.server.context import ServerCallContext
from a2a.server.models import create_task_model
from a2a.server.tasks import DatabaseTaskStore, TaskStore
from a2a.types import Message, Part, Role, Task, TaskState
from sqlalchemy import (
    Column,
    Float,
    MetaData,
    String,
    Table,
    and_,
    delete,
    event,
    func,
    inspect,
    or_,
    select,
    text,
    update,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects import sqlite as sqlite_dialect
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine

from a2agw._ddl import retry_ddl
from a2agw.consult.handles import OUTBOUND_TABLE
from a2agw.security.principal import Principal, PrincipalUser

_metadata = MetaData()
_index_table = Table(
    "a2agw_task_index",
    _metadata,
    Column("task_id", String, primary_key=True),
    Column("agent_id", String, nullable=False, index=True),
    Column("owner", String, nullable=False),
    Column("context_id", String, nullable=False),
    Column("state", String, nullable=False, index=True),
    Column("updated_at", Float, nullable=False),
    Column("origin", String, nullable=True),
    # The trace (32 lowercase hex digits) of the first traced turn of the task: its inbound
    # span (``a2agw.inbound``). None until that span starts, and for untraced tasks.
    Column("trace_id", String, nullable=True),
)
# Index columns added after Phase 3, with their DDL type (ALTER TABLE ... ADD COLUMN).
_ADDED_COLUMNS = {"trace_id": "VARCHAR"}

INDEX_TABLE = _index_table  # joined by the outbound TTL scoping (consult.handles)

# Inbound message ids already acted on (spec 8.5): a re-sent message is answered with the task
# the first one created instead of running the agent again. One row per (agent, tenant,
# owner, messageId); ``task_id`` is NULL while the first send is still setting up.
_ledger_table = Table(
    "a2agw_inbound_messages",
    _metadata,
    Column("agent_id", String, primary_key=True),
    Column("tenant", String, primary_key=True),
    Column("owner", String, primary_key=True),
    Column("message_id", String, primary_key=True),
    Column("task_id", String, nullable=True),
    # SHA-256 of the whole request: only an identical re-send is a duplicate.
    Column("fingerprint", String, nullable=False, default=""),
    Column("created_at", Float, nullable=False, index=True),
)

_RESUMABLE_STATES = {
    TaskState.Name(TaskState.TASK_STATE_INPUT_REQUIRED),
    TaskState.Name(TaskState.TASK_STATE_AUTH_REQUIRED),
}
_ACTIVE_STATES = {
    TaskState.Name(TaskState.TASK_STATE_SUBMITTED),
    TaskState.Name(TaskState.TASK_STATE_WORKING),
} | _RESUMABLE_STATES
_TERMINAL_STATES = {
    TaskState.Name(s)
    for s in (
        TaskState.TASK_STATE_COMPLETED,
        TaskState.TASK_STATE_FAILED,
        TaskState.TASK_STATE_CANCELED,
        TaskState.TASK_STATE_REJECTED,
    )
}
_AGENT_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_MODELS: dict[str, tuple[str, type]] = {}
logger = logging.getLogger(__name__)


SQLITE_BUSY_TIMEOUT_MS = 5000


def _is_file_sqlite(url: URL) -> bool:
    db = url.database or ""
    in_memory = db in ("", ":memory:") or "mode=memory" in db or url.query.get("mode") == "memory"
    return url.get_backend_name() == "sqlite" and not in_memory


def _sqlite_pragmas(dbapi_conn: Any, _record: Any) -> None:
    """WAL lets readers run alongside the writer; busy_timeout waits out a held lock
    instead of failing with "database is locked"."""
    cur = dbapi_conn.cursor()
    try:
        # busy_timeout first: switching to WAL itself needs a lock that other starting
        # gateways may hold.
        cur.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
        cur.execute("PRAGMA journal_mode=WAL")
    finally:
        cur.close()


async def create_engine(url: str = "sqlite+aiosqlite:///a2agw.db") -> AsyncEngine:
    if make_url(url).get_backend_name() == "postgresql":
        # pre_ping replaces connections the server or a proxy dropped; recycle keeps them
        # younger than typical idle timeouts.
        engine = create_async_engine(
            url, pool_pre_ping=True, pool_size=10, max_overflow=10, pool_recycle=1800
        )
    else:
        engine = create_async_engine(url)
    if _is_file_sqlite(engine.url):
        event.listen(engine.sync_engine, "connect", _sqlite_pragmas)
    return engine


def task_store_for(engine: AsyncEngine, agent_id: str) -> DatabaseTaskStore:
    """A task store backed by this agent's own table.

    The SDK registers generated models on a process-global MetaData, so each per-agent model
    is built once per process (cached by table name) and reused by every store, on any engine.
    Each call returns a new store.
    """
    if not _AGENT_ID_RE.fullmatch(agent_id):
        raise ValueError(f"invalid agent_id for table name: {agent_id!r}")
    table_name = f"tasks_{agent_id.replace('-', '_')}"
    cached = _MODELS.get(table_name)
    if cached is not None and cached[0] != agent_id:
        raise ValueError(
            f"agent ids {cached[0]!r} and {agent_id!r} map to the same table {table_name!r}"
        )
    if cached is None:
        # The SDK names every generated model class "TaskModel", which makes SQLAlchemy warn
        # once per extra table. The tables are distinct, so the warning is noise.
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore", message="This declarative base already contains a class"
            )
            model = create_task_model(table_name)
        cached = _MODELS[table_name] = (agent_id, model)
    # Default table name makes the SDK reuse its built-in model; we then swap in ours.
    store = DatabaseTaskStore(engine, create_table=True, table_name="tasks")
    store.task_model = cached[1]
    return store


def _encode_cursor(updated_at: float, task_id: str) -> str:
    return base64.urlsafe_b64encode(f"{updated_at!r}:{task_id}".encode()).decode()


def _decode_cursor(cursor: str) -> tuple[float, str]:
    try:
        raw = base64.urlsafe_b64decode(cursor.encode()).decode()
        ts, sep, task_id = raw.partition(":")
        if not sep:
            raise ValueError("missing separator")
        return float(ts), task_id
    except (binascii.Error, ValueError, UnicodeError) as exc:
        raise ValueError("invalid cursor") from exc


class TaskIndex:
    """Cross-owner index of tasks, queried by the admin API and by recovery."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def initialize(self) -> None:
        async def create() -> None:
            async with self._engine.begin() as conn:
                await conn.run_sync(_metadata.create_all, checkfirst=True)
                # The re-entry query joins the outbound handles, so make sure the table exists.
                await conn.run_sync(OUTBOUND_TABLE.create, checkfirst=True)
                # Tables made before a column existed gain it (sqlite and postgres alike).
                columns = await conn.run_sync(_index_columns)
                for name in _ADDED_COLUMNS:
                    if name not in columns:
                        await _add_index_column(conn, name)

        await retry_ddl(create)

    async def upsert(
        self,
        task_id: str,
        agent_id: str,
        owner: str,
        context_id: str,
        state: str,
        origin: str | None,
        *,
        trace_id: str | None = None,
    ) -> None:
        """Insert or update a row. ``origin=None`` keeps the row's existing origin; a row's
        ``trace_id`` is the first one recorded for it (later turns keep it)."""
        insert = (
            sqlite_dialect.insert if self._engine.dialect.name == "sqlite" else postgresql.insert
        )
        values = {
            "task_id": task_id,
            "agent_id": agent_id,
            "owner": owner,
            "context_id": context_id,
            "state": state,
            "updated_at": time.time(),
            "origin": origin,
            "trace_id": trace_id,
        }
        stmt = insert(_index_table).values(**values)
        set_: dict[str, Any] = {k: v for k, v in values.items() if k != "task_id"}
        # origin=None never erases a known origin (e.g. a resumed turn has none of its own).
        set_["origin"] = func.coalesce(stmt.excluded.origin, _index_table.c.origin)
        set_["trace_id"] = func.coalesce(_index_table.c.trace_id, stmt.excluded.trace_id)
        stmt = stmt.on_conflict_do_update(index_elements=["task_id"], set_=set_)
        async with self._engine.begin() as conn:
            await conn.execute(stmt)

    async def get(self, agent_id: str, task_id: str) -> dict[str, Any] | None:
        """One row, by agent and task id (one query whether or not it exists)."""
        t = _index_table
        stmt = select(t).where(t.c.task_id == task_id, t.c.agent_id == agent_id)
        async with self._engine.connect() as conn:
            row = (await conn.execute(stmt)).first()
        return dict(row._mapping) if row is not None else None

    async def list(
        self,
        agent_id: str | None = None,
        state: str | None = None,
        limit: int = 100,
        cursor: str | None = None,
    ) -> tuple[list[dict[str, Any]], str | None]:
        t = _index_table
        stmt = select(t)
        conds = []
        if agent_id is not None:
            conds.append(t.c.agent_id == agent_id)
        if state is not None:
            conds.append(t.c.state == state)
        if cursor:
            ts, tid = _decode_cursor(cursor)
            conds.append(or_(t.c.updated_at < ts, and_(t.c.updated_at == ts, t.c.task_id > tid)))
        if conds:
            stmt = stmt.where(and_(*conds))
        stmt = stmt.order_by(t.c.updated_at.desc(), t.c.task_id).limit(limit + 1)
        async with self._engine.connect() as conn:
            rows = [dict(r._mapping) for r in (await conn.execute(stmt)).all()]
        next_cursor = None
        if len(rows) > limit:
            rows = rows[:limit]
            last = rows[-1]
            next_cursor = _encode_cursor(last["updated_at"], last["task_id"])
        return rows, next_cursor

    # ``builtins.list``: the ``list`` method above shadows the builtin in this class body.
    async def by_state(self, states: set[str]) -> builtins.list[dict[str, Any]]:
        stmt = select(_index_table).where(_index_table.c.state.in_(sorted(states)))
        async with self._engine.connect() as conn:
            return [dict(r._mapping) for r in (await conn.execute(stmt)).all()]

    async def count_active_outside(self, agent_ids: set[str]) -> int:
        """Non-terminal rows of agents not in ``agent_ids`` (served by another gateway, or
        orphaned by a removed agent)."""
        return sum(1 for r in await self.by_state(_ACTIVE_STATES) if r["agent_id"] not in agent_ids)

    async def blocked_downstream(self, agent_id: str, origin: str, exclude_task_id: str) -> bool:
        """Whether ``agent_id`` has a non-terminal task in ``origin``, other than
        ``exclude_task_id``, that is waiting on at least one non-terminal outbound partner task.

        Such an agent is being re-entered from inside its own call chain."""
        t, o = _index_table, OUTBOUND_TABLE
        terminal = sorted(_TERMINAL_STATES)
        stmt = (
            select(t.c.task_id)
            .join(o, o.c.inbound_task_id == t.c.task_id)
            .where(
                t.c.agent_id == agent_id,
                t.c.origin == origin,
                t.c.task_id != exclude_task_id,
                t.c.state.not_in(terminal),
                o.c.state.not_in(terminal),
            )
            .limit(1)
        )
        async with self._engine.connect() as conn:
            return (await conn.execute(stmt)).first() is not None

    async def set_state(self, task_id: str, state: str) -> None:
        stmt = (
            update(_index_table)
            .where(_index_table.c.task_id == task_id)
            .values(state=state, updated_at=time.time())
        )
        async with self._engine.begin() as conn:
            await conn.execute(stmt)

    async def delete(self, task_id: str) -> None:
        """Remove a row (a direct-reply turn that ended without creating a task)."""
        async with self._engine.begin() as conn:
            await conn.execute(delete(_index_table).where(_index_table.c.task_id == task_id))


def _index_columns(sync: Any) -> set[str]:
    return {c["name"] for c in inspect(sync).get_columns(_index_table.name)}


async def _add_index_column(conn: AsyncConnection, name: str) -> None:
    # postgres: IF NOT EXISTS tolerates a concurrent startup doing the same. sqlite has no
    # such clause: a concurrent startup shows up as a "duplicate column" error.
    guard = "IF NOT EXISTS " if conn.dialect.name == "postgresql" else ""
    ddl = _ADDED_COLUMNS[name]
    try:
        await conn.execute(text(f"ALTER TABLE {_index_table.name} ADD COLUMN {guard}{name} {ddl}"))
    except OperationalError as e:
        if "duplicate column" not in str(e).lower():
            raise
        if name not in await conn.run_sync(_index_columns):
            raise


class OutboundHandleStore(Protocol):
    async def by_inbound(self, inbound_task_id: str) -> list[dict[str, Any]]: ...


@dataclass
class RecoveryReport:
    failed: list[str] = field(default_factory=list)
    kept: list[str] = field(default_factory=list)
    outbound_cancelled: int = 0
    cancel_errors: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _context_for(owner: str) -> ServerCallContext:
    kind: Literal["api_key", "jwt", "anonymous"]
    if owner.startswith("key:"):
        kind = "api_key"
    elif owner.startswith("jwt:"):
        kind = "jwt"
    else:
        kind = "anonymous"
    return ServerCallContext(user=PrincipalUser(Principal(id=owner, kind=kind, scopes=frozenset())))


async def recover_on_startup(
    index: TaskIndex,
    stores: dict[str, TaskStore],
    durable: dict[str, bool],
    handles: OutboundHandleStore | None,
    cancel_outbound: Callable[..., Awaitable[object]] | None,
    *,
    cancel_timeout_s: float = 60.0,
    on_failed: OnFailed | None = None,
) -> RecoveryReport:
    """Spec 11a item 5: fail orphaned in-flight tasks, keep durable input-required ones.

    Only the tasks of agents in ``stores`` are touched: gateways sharing one database each
    recover their own agents. ``on_failed(agent_id, task)`` is awaited for each task saved
    FAILED (the host queues its push notification); its errors are logged, never raised.

    The non-terminal outbound handles of every failed task are then cancelled concurrently,
    within ``cancel_timeout_s`` overall. A cancel that raises or times out is reported in
    ``cancel_errors``; every other one counts in ``outbound_cancelled``.
    """
    report = RecoveryReport()
    to_cancel: list[tuple[str, dict[str, Any]]] = []
    failed_state = TaskState.Name(TaskState.TASK_STATE_FAILED)
    for row in await index.by_state(_ACTIVE_STATES):
        task_id, agent_id, owner = row["task_id"], row["agent_id"], row["owner"]
        if agent_id not in stores:
            continue  # another gateway sharing this database serves that agent
        if row["state"] in _RESUMABLE_STATES and durable.get(agent_id, False):
            report.kept.append(task_id)
            continue
        try:
            store = stores.get(agent_id)
            if store is not None:
                await _fail_stored(store, agent_id, task_id, owner, "gateway restarted", on_failed)
            if handles is not None and cancel_outbound is not None:
                for handle in await handles.by_inbound(task_id):
                    if handle.get("state") not in _TERMINAL_STATES:
                        to_cancel.append((task_id, handle))
            await index.set_state(task_id, failed_state)
            report.failed.append(task_id)
        except Exception:
            logger.exception("recovery failed for task %s", task_id)
            report.errors.append(task_id)
    if to_cancel and cancel_outbound is not None:
        await _cancel_all(to_cancel, cancel_outbound, cancel_timeout_s, report)
    return report


OnFailed = Callable[[str, Task], Awaitable[object]]


async def _fail_stored(
    store: TaskStore,
    agent_id: str,
    task_id: str,
    owner: str,
    reason: str,
    on_failed: OnFailed | None,
) -> None:
    """Mark the SDK's stored task FAILED with ``reason`` (if it is stored), then report it."""
    ctx = _context_for(owner)
    task = await store.get(task_id, ctx)
    if task is None:
        return
    task.status.state = TaskState.TASK_STATE_FAILED
    task.status.message.CopyFrom(
        Message(message_id=f"recovery-{task_id}", role=Role.ROLE_AGENT, parts=[Part(text=reason)])
    )
    await store.save(task, ctx)
    if on_failed is not None:
        try:
            await on_failed(agent_id, task)
        except Exception:
            logger.exception("failed-task notification for task %s raised", task_id)


async def _cancel_all(
    to_cancel: list[tuple[str, dict[str, Any]]],
    cancel_outbound: Callable[..., Awaitable[object]],
    timeout_s: float,
    report: RecoveryReport,
) -> None:
    async def one(handle: dict[str, Any]) -> None:
        await cancel_outbound(handle)

    tasks = [asyncio.create_task(one(h)) for _, h in to_cancel]
    try:
        await asyncio.wait(tasks, timeout=timeout_s)
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    for (task_id, handle), t in zip(to_cancel, tasks, strict=True):
        if t.cancelled() or t.exception() is not None:
            if not t.cancelled():
                logger.error("outbound cancel failed during recovery", exc_info=t.exception())
            else:
                logger.warning("outbound cancel timed out during recovery")
            report.cancel_errors.append(f"{task_id}:{handle.get('partner_id')}")
        else:
            report.outbound_cancelled += 1


async def reap_tasks(
    index: TaskIndex,
    handles: OutboundHandleStore | None,
    cancel_outbound: Callable[..., Awaitable[object]] | None,
    agent_id: str,
    *,
    cancel_timeout_s: float = 60.0,
    store: TaskStore | None = None,
    on_failed: OnFailed | None = None,
) -> RecoveryReport:
    """Mark every non-terminal index row of ``agent_id`` FAILED and cancel their non-terminal
    outbound handles. For agents no gateway serves any more (nobody recovers their tasks).
    The caller must make sure no gateway is serving the agent.

    With ``store`` (the agent's SDK task store) the stored task is marked FAILED too
    ("agent no longer served"), and ``on_failed(agent_id, task)`` is awaited for it."""
    report = RecoveryReport()
    to_cancel: list[tuple[str, dict[str, Any]]] = []
    failed_state = TaskState.Name(TaskState.TASK_STATE_FAILED)
    for row in await index.by_state(_ACTIVE_STATES):
        if row["agent_id"] != agent_id:
            continue
        task_id = row["task_id"]
        try:
            if store is not None:
                await _fail_stored(store, agent_id, task_id, row["owner"], REAPED_REASON, on_failed)
            if handles is not None and cancel_outbound is not None:
                for handle in await handles.by_inbound(task_id):
                    if handle.get("state") not in _TERMINAL_STATES:
                        to_cancel.append((task_id, handle))
            await index.set_state(task_id, failed_state)
            report.failed.append(task_id)
        except Exception:
            logger.exception("reaping failed for task %s", task_id)
            report.errors.append(task_id)
    if to_cancel and cancel_outbound is not None:
        await _cancel_all(to_cancel, cancel_outbound, cancel_timeout_s, report)
    return report


REAPED_REASON = "agent no longer served"
MESSAGE_RETENTION_S = 24 * 3600.0  # a message id is a duplicate for this long
RESERVATION_STALE_S = 60.0  # a reservation never given a task (crashed send) is taken over


@dataclass(frozen=True)
class MessageKey:
    agent_id: str
    tenant: str
    owner: str
    message_id: str

    def where(self) -> Any:
        t = _ledger_table.c
        return and_(
            t.agent_id == self.agent_id,
            t.tenant == self.tenant,
            t.owner == self.owner,
            t.message_id == self.message_id,
        )


class MessageLedger:
    """Inbound message ids (spec 8.5), persisted so duplicates are recognised across restarts
    and across gateways sharing the database. Rows older than ``retention_s`` no longer count
    and are deleted by ``purge`` (the host's maintenance loop)."""

    def __init__(self, engine: AsyncEngine, *, retention_s: float = MESSAGE_RETENTION_S) -> None:
        self._engine = engine
        self.retention_s = retention_s

    async def initialize(self) -> None:
        async def create() -> None:
            async with self._engine.begin() as conn:
                await conn.run_sync(_ledger_table.create, checkfirst=True)

        await retry_ddl(create)

    async def reserve(
        self, key: MessageKey, now: float | None = None, *, fingerprint: str = ""
    ) -> dict[str, Any] | None:
        """Claim ``key`` for a new send. Returns None when the caller now owns it, else the
        existing row (a duplicate: its ``task_id`` may still be NULL while the first send is
        setting up). A row with another ``fingerprint`` (the id re-used for a different
        request), an expired row, or a reservation that never got a task within
        ``RESERVATION_STALE_S`` is taken over with a compare-and-set."""
        now = time.time() if now is None else now
        insert = (
            sqlite_dialect.insert if self._engine.dialect.name == "sqlite" else postgresql.insert
        )
        stmt = (
            insert(_ledger_table)
            .values(
                agent_id=key.agent_id,
                tenant=key.tenant,
                owner=key.owner,
                message_id=key.message_id,
                task_id=None,
                fingerprint=fingerprint,
                created_at=now,
            )
            .on_conflict_do_nothing()
        )
        async with self._engine.begin() as conn:
            if (await conn.execute(stmt)).rowcount == 1:
                return None
            row = (await conn.execute(select(_ledger_table).where(key.where()))).first()
        if row is None:  # deleted in between: try once more
            return await self.reserve(key, now, fingerprint=fingerprint)
        existing = dict(row._mapping)
        expired = now - existing["created_at"] >= self.retention_s
        stale = existing["task_id"] is None and now - existing["created_at"] >= RESERVATION_STALE_S
        other = existing["fingerprint"] != fingerprint
        if expired or stale or other:
            take = (
                update(_ledger_table)
                .where(
                    key.where(),
                    _ledger_table.c.created_at == existing["created_at"],
                    _ledger_table.c.fingerprint == existing["fingerprint"],
                )
                .values(task_id=None, created_at=now, fingerprint=fingerprint)
            )
            async with self._engine.begin() as conn:
                if (await conn.execute(take)).rowcount == 1:
                    return None
            return await self.get(key) or existing
        return existing

    async def fill(self, key: MessageKey, task_id: str, *, fingerprint: str | None = None) -> None:
        """Record the task of the send holding ``key`` (only while it still holds it)."""
        cond = and_(key.where(), _ledger_table.c.task_id.is_(None))
        if fingerprint is not None:
            cond = and_(cond, _ledger_table.c.fingerprint == fingerprint)
        stmt = update(_ledger_table).where(cond).values(task_id=task_id)
        async with self._engine.begin() as conn:
            await conn.execute(stmt)

    async def get(self, key: MessageKey) -> dict[str, Any] | None:
        async with self._engine.connect() as conn:
            row = (await conn.execute(select(_ledger_table).where(key.where()))).first()
        return dict(row._mapping) if row is not None else None

    async def supersede(
        self, key: MessageKey, task_id: str, fingerprint: str, now: float | None = None
    ) -> bool:
        """Compare-and-set takeover of a key whose task has ended (or vanished): only if the
        row still points at ``task_id`` with ``fingerprint``. Of several concurrent re-sends
        exactly one wins (True) and runs; the others re-read and find the winner's send."""
        stmt = (
            update(_ledger_table)
            .where(
                key.where(),
                _ledger_table.c.task_id == task_id,
                _ledger_table.c.fingerprint == fingerprint,
            )
            .values(task_id=None, created_at=time.time() if now is None else now)
        )
        async with self._engine.begin() as conn:
            return (await conn.execute(stmt)).rowcount == 1

    async def release(
        self, key: MessageKey, *, only_unfilled: bool = True, fingerprint: str | None = None
    ) -> None:
        """Forget ``key`` (a send that created no task, or answered with a bare Message);
        with ``fingerprint``, only while the row is still that request's."""
        cond = key.where()
        if only_unfilled:
            cond = and_(cond, _ledger_table.c.task_id.is_(None))
        if fingerprint is not None:
            cond = and_(cond, _ledger_table.c.fingerprint == fingerprint)
        async with self._engine.begin() as conn:
            await conn.execute(delete(_ledger_table).where(cond))

    async def purge(self, now: float | None = None) -> int:
        """Delete rows past the retention window; returns how many."""
        cutoff = (time.time() if now is None else now) - self.retention_s
        stmt = delete(_ledger_table).where(_ledger_table.c.created_at < cutoff)
        async with self._engine.begin() as conn:
            return int((await conn.execute(stmt)).rowcount or 0)
