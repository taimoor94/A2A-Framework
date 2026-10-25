"""Durable record of outbound partner tasks (handles), linked to the inbound task that made them.

Task ids are chosen by partners, so a handle is keyed by ``(partner_id, task_id)``: one partner
can never overwrite another partner's handle by reusing its task id.
"""

from __future__ import annotations

import time
from typing import Any

from sqlalchemy import (
    Column,
    Float,
    MetaData,
    String,
    Table,
    func,
    inspect,
    select,
    text,
    update,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects import sqlite as sqlite_dialect
from sqlalchemy.ext.asyncio import AsyncEngine

_metadata = MetaData()
_outbound = Table(
    "a2agw_outbound",
    _metadata,
    Column("partner_id", String, primary_key=True),
    Column("task_id", String, primary_key=True),
    Column("context_id", String, nullable=True),
    Column("inbound_task_id", String, nullable=True, index=True),
    Column("origin", String, nullable=True, index=True),
    Column("state", String, nullable=False),  # TaskState NAME, e.g. "TASK_STATE_WORKING"
    Column("created_at", Float, nullable=False),
    # The prefixed id of the inbound caller the partner task was started for (``key:...``,
    # ``jwt:...``), so cascade and recovery cancels are made with that caller's credentials.
    Column("caller_id", String, nullable=True),
)
OUTBOUND_TABLE = _outbound  # read by the inbound side's re-entry check (serve.store)


class OutboundHandleStore:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def initialize(self) -> None:
        async with self._engine.begin() as conn:
            await conn.run_sync(_metadata.create_all)
            # Phase 1 tables lack caller_id: add it (works on sqlite and postgres alike).
            columns = await conn.run_sync(
                lambda sync: {c["name"] for c in inspect(sync).get_columns(_outbound.name)}
            )
            if "caller_id" not in columns:
                # postgres: IF NOT EXISTS tolerates a concurrent startup doing the same.
                guard = "IF NOT EXISTS " if conn.dialect.name == "postgresql" else ""
                await conn.execute(
                    text(f"ALTER TABLE a2agw_outbound ADD COLUMN {guard}caller_id VARCHAR")
                )

    async def record(
        self,
        task_id: str,
        partner_id: str,
        context_id: str | None,
        inbound_task_id: str | None,
        origin: str | None,
        state: str,
        *,
        caller_id: str | None = None,
    ) -> None:
        """Insert a handle, or update its state. Known links (inbound task, origin, caller)
        are kept."""
        insert = (
            sqlite_dialect.insert if self._engine.dialect.name == "sqlite" else postgresql.insert
        )
        stmt = insert(_outbound).values(
            task_id=task_id,
            partner_id=partner_id,
            context_id=context_id,
            inbound_task_id=inbound_task_id,
            origin=origin,
            state=state,
            created_at=time.time(),
            caller_id=caller_id,
        )
        ex, t = stmt.excluded, _outbound.c
        stmt = stmt.on_conflict_do_update(
            index_elements=["partner_id", "task_id"],
            set_={
                "state": ex.state,
                "context_id": func.coalesce(ex.context_id, t.context_id),
                "inbound_task_id": func.coalesce(t.inbound_task_id, ex.inbound_task_id),
                "origin": func.coalesce(t.origin, ex.origin),
                "caller_id": func.coalesce(t.caller_id, ex.caller_id),
            },
        )
        async with self._engine.begin() as conn:
            await conn.execute(stmt)

    async def update_state(self, partner_id: str, task_id: str, state: str) -> None:
        stmt = (
            update(_outbound)
            .where(_outbound.c.partner_id == partner_id, _outbound.c.task_id == task_id)
            .values(state=state)
        )
        async with self._engine.begin() as conn:
            await conn.execute(stmt)

    async def get(self, partner_id: str, task_id: str) -> dict[str, Any] | None:
        stmt = select(_outbound).where(
            _outbound.c.partner_id == partner_id, _outbound.c.task_id == task_id
        )
        async with self._engine.connect() as conn:
            row = (await conn.execute(stmt)).first()
        return dict(row._mapping) if row is not None else None

    async def by_inbound(self, inbound_task_id: str) -> list[dict[str, Any]]:
        stmt = (
            select(_outbound)
            .where(_outbound.c.inbound_task_id == inbound_task_id)
            .order_by(_outbound.c.created_at)
        )
        async with self._engine.connect() as conn:
            return [dict(r._mapping) for r in (await conn.execute(stmt)).all()]

    async def seen_origin(self, origin: str) -> bool:
        stmt = select(_outbound.c.task_id).where(_outbound.c.origin == origin).limit(1)
        async with self._engine.connect() as conn:
            return (await conn.execute(stmt)).first() is not None
