"""Durable record of outbound partner tasks (handles), linked to the inbound task that made them."""

from __future__ import annotations

import time
from typing import Any

from sqlalchemy import Column, Float, MetaData, String, Table, func, select, update
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects import sqlite as sqlite_dialect
from sqlalchemy.ext.asyncio import AsyncEngine

_metadata = MetaData()
_outbound = Table(
    "a2agw_outbound",
    _metadata,
    Column("task_id", String, primary_key=True),
    Column("partner_id", String, nullable=False),
    Column("context_id", String, nullable=True),
    Column("inbound_task_id", String, nullable=True, index=True),
    Column("origin", String, nullable=True, index=True),
    Column("state", String, nullable=False),  # TaskState NAME, e.g. "TASK_STATE_WORKING"
    Column("created_at", Float, nullable=False),
)


class OutboundHandleStore:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def initialize(self) -> None:
        async with self._engine.begin() as conn:
            await conn.run_sync(_metadata.create_all)

    async def record(
        self,
        task_id: str,
        partner_id: str,
        context_id: str | None,
        inbound_task_id: str | None,
        origin: str | None,
        state: str,
    ) -> None:
        """Insert a handle, or update its state. Known links (inbound task, origin) are kept."""
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
        )
        ex, t = stmt.excluded, _outbound.c
        stmt = stmt.on_conflict_do_update(
            index_elements=["task_id"],
            set_={
                "state": ex.state,
                "context_id": func.coalesce(ex.context_id, t.context_id),
                "inbound_task_id": func.coalesce(t.inbound_task_id, ex.inbound_task_id),
                "origin": func.coalesce(t.origin, ex.origin),
            },
        )
        async with self._engine.begin() as conn:
            await conn.execute(stmt)

    async def update_state(self, task_id: str, state: str) -> None:
        stmt = update(_outbound).where(_outbound.c.task_id == task_id).values(state=state)
        async with self._engine.begin() as conn:
            await conn.execute(stmt)

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
