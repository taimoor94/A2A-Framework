"""Durable per-agent A2A task storage, a cross-owner task index and restart recovery."""

from __future__ import annotations

import base64
import time
import warnings
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from a2a.server.context import ServerCallContext
from a2a.server.tasks import DatabaseTaskStore, TaskStore
from a2a.types import Message, Part, Role, TaskState
from sqlalchemy import Column, Float, MetaData, String, Table, and_, or_, select, update
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects import sqlite as sqlite_dialect
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

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
)

_ACTIVE_STATES = {
    "TASK_STATE_SUBMITTED",
    "TASK_STATE_WORKING",
    "TASK_STATE_INPUT_REQUIRED",
    "TASK_STATE_AUTH_REQUIRED",
}
_RESUMABLE_STATES = {"TASK_STATE_INPUT_REQUIRED", "TASK_STATE_AUTH_REQUIRED"}


async def create_engine(url: str = "sqlite+aiosqlite:///a2agw.db") -> AsyncEngine:
    return create_async_engine(url)


def task_store_for(engine: AsyncEngine, agent_id: str) -> DatabaseTaskStore:
    """One table per agent; call once per agent_id per process."""
    # The SDK names every generated model class "TaskModel", which makes SQLAlchemy warn
    # once per extra table. The tables are distinct, so the warning is noise.
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="This declarative base already contains a class")
        return DatabaseTaskStore(
            engine, create_table=True, table_name=f"tasks_{agent_id.replace('-', '_')}"
        )


def _encode_cursor(updated_at: float, task_id: str) -> str:
    return base64.urlsafe_b64encode(f"{updated_at!r}:{task_id}".encode()).decode()


def _decode_cursor(cursor: str) -> tuple[float, str]:
    raw = base64.urlsafe_b64decode(cursor.encode()).decode()
    ts, _, task_id = raw.partition(":")
    return float(ts), task_id


class TaskIndex:
    """Cross-owner index of tasks, queried by the admin API and by recovery."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def initialize(self) -> None:
        async with self._engine.begin() as conn:
            await conn.run_sync(_metadata.create_all)

    async def upsert(
        self,
        task_id: str,
        agent_id: str,
        owner: str,
        context_id: str,
        state: str,
        origin: str | None,
    ) -> None:
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
        }
        stmt = insert(_index_table).values(**values)
        stmt = stmt.on_conflict_do_update(
            index_elements=["task_id"],
            set_={k: v for k, v in values.items() if k != "task_id"},
        )
        async with self._engine.begin() as conn:
            await conn.execute(stmt)

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

    async def by_state(self, states: set[str]) -> list[dict[str, Any]]:
        stmt = select(_index_table).where(_index_table.c.state.in_(sorted(states)))
        async with self._engine.connect() as conn:
            return [dict(r._mapping) for r in (await conn.execute(stmt)).all()]

    async def set_state(self, task_id: str, state: str) -> None:
        stmt = (
            update(_index_table)
            .where(_index_table.c.task_id == task_id)
            .values(state=state, updated_at=time.time())
        )
        async with self._engine.begin() as conn:
            await conn.execute(stmt)


class OutboundHandleStore(Protocol):
    async def by_inbound(self, inbound_task_id: str) -> list[dict[str, Any]]: ...


@dataclass
class RecoveryReport:
    failed: list[str] = field(default_factory=list)
    kept: list[str] = field(default_factory=list)
    outbound_cancelled: int = 0


def _context_for(owner: str) -> ServerCallContext:
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
    cancel_outbound: Callable[[dict[str, Any]], Awaitable[None]] | None,
) -> RecoveryReport:
    """Spec 11a item 5: fail orphaned in-flight tasks, keep durable input-required ones."""
    report = RecoveryReport()
    failed_state = TaskState.Name(TaskState.TASK_STATE_FAILED)
    for row in await index.by_state(_ACTIVE_STATES):
        task_id, agent_id, owner = row["task_id"], row["agent_id"], row["owner"]
        if row["state"] in _RESUMABLE_STATES and durable.get(agent_id, False):
            report.kept.append(task_id)
            continue
        store = stores.get(agent_id)
        if store is not None:
            ctx = _context_for(owner)
            task = await store.get(task_id, ctx)
            if task is not None:
                task.status.state = TaskState.TASK_STATE_FAILED
                task.status.message.CopyFrom(
                    Message(
                        message_id=f"recovery-{task_id}",
                        role=Role.ROLE_AGENT,
                        parts=[Part(text="gateway restarted")],
                    )
                )
                await store.save(task, ctx)
        await index.set_state(task_id, failed_state)
        report.failed.append(task_id)
        if handles is not None and cancel_outbound is not None:
            for handle in await handles.by_inbound(task_id):
                await cancel_outbound(handle)
                report.outbound_cancelled += 1
    return report
