"""Durable record of outbound partner tasks (handles), linked to the inbound task that made them.

Task ids are chosen by partners, so a handle is keyed by ``(partner_id, task_id)``: one partner
can never overwrite another partner's handle by reusing its task id.
"""

from __future__ import annotations

import time
from collections.abc import Collection
from typing import Any

from sqlalchemy import (
    Column,
    Float,
    Integer,
    MetaData,
    String,
    Table,
    and_,
    case,
    func,
    inspect,
    or_,
    select,
    text,
    update,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects import sqlite as sqlite_dialect
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from a2agw._ddl import retry_ddl

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
    # Why a2agw itself ended the handle (e.g. "ttl expired"); None for partner-reported states.
    Column("end_reason", String, nullable=True),
    # TTL expiry: partner cancels attempted so far (a failed one is retried, up to a cap).
    Column("cancel_attempts", Integer, nullable=False, server_default="0"),
    # Who started a partner task that has no inbound task: ``sidecar:<agent id>`` for a
    # standalone sidecar call (``AgentHost.sidecar_owner``), so that host's TTL expiry
    # covers it. None for calls linked to an inbound task.
    Column("owner", String, nullable=True),
)
# Columns added after Phase 1, with their DDL type (ALTER TABLE ... ADD COLUMN).
_ADDED_COLUMNS = {
    "caller_id": "VARCHAR",
    "end_reason": "VARCHAR",
    "cancel_attempts": "INTEGER NOT NULL DEFAULT 0",
    "owner": "VARCHAR",
}
OUTBOUND_TABLE = _outbound  # read by the inbound side's re-entry check (serve.store)


class OutboundHandleStore:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def initialize(self) -> None:
        async def migrate() -> None:
            async with self._engine.begin() as conn:
                await conn.run_sync(_metadata.create_all, checkfirst=True)
                # Phase 1 tables lack caller_id: add it (works on sqlite and postgres alike).
                columns = await conn.run_sync(
                    lambda sync: {c["name"] for c in inspect(sync).get_columns(_outbound.name)}
                )
                for name in _ADDED_COLUMNS:  # added after Phase 1
                    if name not in columns:
                        await self._add_column(conn, name)

        await retry_ddl(migrate)

    @staticmethod
    async def _add_caller_id(conn: AsyncConnection) -> None:
        await OutboundHandleStore._add_column(conn, "caller_id")

    @staticmethod
    async def _add_column(conn: AsyncConnection, name: str) -> None:
        # postgres: IF NOT EXISTS tolerates a concurrent startup doing the same. sqlite has
        # no such clause: a concurrent startup shows up as a "duplicate column" error.
        guard = "IF NOT EXISTS " if conn.dialect.name == "postgresql" else ""
        try:
            ddl = _ADDED_COLUMNS[name]
            await conn.execute(text(f"ALTER TABLE a2agw_outbound ADD COLUMN {guard}{name} {ddl}"))
        except OperationalError as e:
            if "duplicate column" not in str(e).lower():
                raise
            columns = await conn.run_sync(
                lambda sync: {c["name"] for c in inspect(sync).get_columns(_outbound.name)}
            )
            if name not in columns:
                raise

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
        owner: str | None = None,
    ) -> None:
        """Insert a handle, or update its state. Known links (inbound task, origin, caller,
        owner) are kept."""
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
            owner=owner,
        )
        ex, t = stmt.excluded, _outbound.c
        stmt = stmt.on_conflict_do_update(
            index_elements=["partner_id", "task_id"],
            set_={
                # A handle a2agw ended itself (end_reason set) keeps its state.
                "state": case((t.end_reason.is_(None), ex.state), else_=t.state),
                "context_id": func.coalesce(ex.context_id, t.context_id),
                "inbound_task_id": func.coalesce(t.inbound_task_id, ex.inbound_task_id),
                "origin": func.coalesce(t.origin, ex.origin),
                "caller_id": func.coalesce(t.caller_id, ex.caller_id),
                "owner": func.coalesce(t.owner, ex.owner),
            },
        )
        async with self._engine.begin() as conn:
            await conn.execute(stmt)

    async def update_state(self, partner_id: str, task_id: str, state: str) -> None:
        """Record a state the partner reported. A handle a2agw itself ended (``end_reason``
        set, e.g. TTL expiry) keeps its state."""
        stmt = (
            update(_outbound)
            .where(
                _outbound.c.partner_id == partner_id,
                _outbound.c.task_id == task_id,
                _outbound.c.end_reason.is_(None),
            )
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

    async def count_open(self, partner_ids: list[str]) -> dict[str, int]:
        """Non-terminal handles per partner, for the given partners (absent: none)."""
        if not partner_ids:
            return {}
        from a2agw.consult.results import TERMINAL_NAMES

        stmt = (
            select(_outbound.c.partner_id, func.count())
            .where(
                _outbound.c.partner_id.in_(partner_ids),
                _outbound.c.state.notin_(sorted(TERMINAL_NAMES)),
            )
            .group_by(_outbound.c.partner_id)
        )
        async with self._engine.connect() as conn:
            return {str(pid): int(n) for pid, n in (await conn.execute(stmt)).all()}

    async def seen_origin(self, origin: str) -> bool:
        stmt = select(_outbound.c.task_id).where(_outbound.c.origin == origin).limit(1)
        async with self._engine.connect() as conn:
            return (await conn.execute(stmt)).first() is not None

    async def older_than(
        self,
        cutoff: float,
        *,
        limit: int = 100,
        partner_ids: Collection[str] | None = None,
        agent_ids: Collection[str] | None = None,
        retry_reason: str | None = None,
        max_attempts: int | None = None,
        owners: Collection[str] = (),
    ) -> list[dict[str, Any]]:
        """Non-terminal handles created before ``cutoff`` (epoch seconds), oldest first.

        Scoping, for gateways sharing one database: ``partner_ids`` keeps only handles of
        those partners; ``agent_ids`` keeps only handles whose inbound task is indexed
        (``a2agw_task_index``) under one of those agents, plus handles with no inbound task
        whose ``owner`` is one of ``owners`` (other handles with no inbound task are then
        excluded). With ``retry_reason`` and ``max_attempts``, handles that a2agw ended
        with that ``end_reason`` and fewer than ``max_attempts`` cancel attempts are
        selected too (whatever their age: they already passed the TTL)."""
        from a2agw.consult.results import TERMINAL_NAMES
        from a2agw.serve.store import INDEX_TABLE

        o = _outbound
        due = and_(o.c.created_at < cutoff, o.c.state.notin_(sorted(TERMINAL_NAMES)))
        if retry_reason is not None and max_attempts is not None:
            due = or_(due, and_(o.c.end_reason == retry_reason, o.c.cancel_attempts < max_attempts))
        conds = [due]
        if partner_ids is not None:
            conds.append(o.c.partner_id.in_(sorted(partner_ids)))
        stmt = select(o)
        if agent_ids is not None:
            t = INDEX_TABLE
            stmt = stmt.select_from(o.outerjoin(t, t.c.task_id == o.c.inbound_task_id))
            mine = t.c.agent_id.in_(sorted(agent_ids))
            if owners:
                unlinked = and_(o.c.inbound_task_id.is_(None), o.c.owner.in_(sorted(owners)))
                mine = or_(mine, unlinked)
            conds.append(mine)
        stmt = stmt.where(*conds).order_by(o.c.created_at).limit(limit)
        async with self._engine.connect() as conn:
            return [dict(r._mapping) for r in (await conn.execute(stmt)).all()]

    async def claim_end(
        self,
        partner_id: str,
        task_id: str,
        seen_state: str,
        state: str,
        reason: str,
        *,
        seen_reason: str | None = None,
        seen_attempts: int | None = None,
    ) -> bool:
        """Compare-and-set: end the handle (``state``, ``end_reason``) only if it is still in
        ``seen_state`` (and, when given, still has ``seen_reason`` / ``seen_attempts``;
        a claim with ``seen_attempts`` also counts one more cancel attempt). Exactly one of
        several gateways sharing the database wins a claim, on sqlite and on Postgres alike
        (one conditional UPDATE)."""
        o = _outbound
        conds = [o.c.partner_id == partner_id, o.c.task_id == task_id, o.c.state == seen_state]
        values: dict[str, Any] = {"state": state, "end_reason": reason}
        if seen_reason is not None:
            conds.append(o.c.end_reason == seen_reason)
        if seen_attempts is not None:
            conds.append(o.c.cancel_attempts == seen_attempts)
            values["cancel_attempts"] = seen_attempts + 1
        stmt = update(o).where(*conds).values(**values)
        async with self._engine.begin() as conn:
            return (await conn.execute(stmt)).rowcount == 1

    async def mark_end_reason(
        self, partner_id: str, task_id: str, seen_reason: str, reason: str, attempts: int
    ) -> bool:
        """Compare-and-set the ``end_reason`` of a handle a2agw ended (after a cancel
        attempt): only while it still has ``seen_reason`` and ``attempts`` attempts."""
        o = _outbound
        stmt = (
            update(o)
            .where(
                o.c.partner_id == partner_id,
                o.c.task_id == task_id,
                o.c.end_reason == seen_reason,
                o.c.cancel_attempts == attempts,
            )
            .values(end_reason=reason)
        )
        async with self._engine.begin() as conn:
            return (await conn.execute(stmt)).rowcount == 1
