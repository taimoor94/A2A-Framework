"""Durable record of Verified System Change jobs, their plan steps and their receipts."""

from __future__ import annotations

import json
import time
from typing import Any, Literal

from sqlalchemy import (
    Column,
    Float,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    func,
    inspect,
    select,
    text,
    update,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects import sqlite as sqlite_dialect
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from a2agw._ddl import retry_ddl
from a2agw.vsc.spec import ExecutableSpec, spec_hash

JobState = Literal[
    "submitted",
    "planning",
    "awaiting_spec",
    "running",
    "awaiting_approval",
    "verifying",
    "accepted",
    "failed",
    "cancelled",
]
StepState = Literal["pending", "running", "verifying", "passed", "failed", "skipped"]

# Jobs a restarted gateway picks up again.
RESUMABLE_STATES = ("submitted", "planning", "running", "verifying", "awaiting_approval")

_metadata = MetaData()
_jobs = Table(
    "vsc_jobs",
    _metadata,
    Column("job_id", String, primary_key=True),
    Column("state", String, nullable=False, index=True),
    Column("request", Text, nullable=False),
    Column("spec_json", Text, nullable=True),
    Column("spec_hash", String, nullable=True),
    Column("plan_json", Text, nullable=True),
    Column("plan_hash", String, nullable=True),
    Column("owner", String, nullable=False),
    Column("created_at", Float, nullable=False),
    Column("updated_at", Float, nullable=False),
    Column("reason", String, nullable=True),
    Column("tokens_in", Integer, nullable=False, server_default="0"),
    Column("tokens_out", Integer, nullable=False, server_default="0"),
    Column("cost", Float, nullable=False, server_default="0"),
    Column("attempts", Integer, nullable=False, server_default="0"),
    Column("current_task_id", String, nullable=True),
    # Seconds spent in active states (planning, running, verifying): what the deadline bounds.
    Column("active_s", Float, nullable=False, server_default="0"),
    # Every whole-system check passed on the job's current commits.
    Column("whole_passed", Integer, nullable=False, server_default="0"),
    # The A2A context the job was submitted in (the ``deliver`` agent's), if any.
    Column("context_id", String, nullable=True, index=True),
)
_steps = Table(
    "vsc_steps",
    _metadata,
    Column("job_id", String, primary_key=True),
    Column("step_id", String, primary_key=True),
    Column("attempt", Integer, primary_key=True, autoincrement=False),
    Column("seq", Integer, nullable=False),
    Column("system", String, nullable=False),
    Column("kind", String, nullable=False),
    Column("state", String, nullable=False),
    Column("worker", String, nullable=True),
    Column("workspace", String, nullable=True),
    Column("result_json", Text, nullable=True),
    Column("usage_json", Text, nullable=True),
    Column("started_at", Float, nullable=True),
    Column("ended_at", Float, nullable=True),
)
_receipts = Table(
    "vsc_receipts",
    _metadata,
    Column("job_id", String, primary_key=True),
    Column("receipt_json", Text, nullable=False),
    Column("receipt_hash", String, nullable=False),
    Column("audit_seq", Integer, nullable=True),
    Column("created_at", Float, nullable=False),
)
# Columns added after the first release, per table, with their DDL type
# (ALTER TABLE ... ADD COLUMN).
_ADDED_COLUMNS: dict[str, dict[str, str]] = {
    "vsc_jobs": {
        "active_s": "FLOAT NOT NULL DEFAULT 0",
        "whole_passed": "INTEGER NOT NULL DEFAULT 0",
        "context_id": "VARCHAR",
    },
}


def _upsert(engine: AsyncEngine):
    return sqlite_dialect.insert if engine.dialect.name == "sqlite" else postgresql.insert


class VscStore:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def initialize(self) -> None:
        async def migrate() -> None:
            async with self._engine.begin() as conn:
                await conn.run_sync(_metadata.create_all, checkfirst=True)
                for table in (_jobs, _steps, _receipts):
                    added = _ADDED_COLUMNS.get(table.name, {})
                    columns = await conn.run_sync(
                        lambda sync, t=table: {c["name"] for c in inspect(sync).get_columns(t.name)}
                    )
                    for name in added:
                        if name not in columns:
                            await self._add_column(conn, table, name, added[name])

        await retry_ddl(migrate)

    @staticmethod
    async def _add_column(conn: AsyncConnection, table: Table, name: str, ddl: str) -> None:
        guard = "IF NOT EXISTS " if conn.dialect.name == "postgresql" else ""
        try:
            await conn.execute(text(f"ALTER TABLE {table.name} ADD COLUMN {guard}{name} {ddl}"))
        except OperationalError as e:
            if "duplicate column" not in str(e).lower():
                raise
            columns = await conn.run_sync(
                lambda sync: {c["name"] for c in inspect(sync).get_columns(table.name)}
            )
            if name not in columns:
                raise

    # -- jobs ----------------------------------------------------------------------------

    async def create_job(
        self, job_id: str, request: str, owner: str, *, context_id: str | None = None
    ) -> None:
        now = time.time()
        stmt = _upsert(self._engine)(_jobs).values(
            job_id=job_id,
            state="submitted",
            request=request,
            owner=owner,
            created_at=now,
            updated_at=now,
            tokens_in=0,
            tokens_out=0,
            cost=0.0,
            attempts=0,
            context_id=context_id,
        )
        async with self._engine.begin() as conn:
            await conn.execute(stmt.on_conflict_do_nothing(index_elements=["job_id"]))

    async def _update_job(self, job_id: str, **values: Any) -> None:
        stmt = (
            update(_jobs).where(_jobs.c.job_id == job_id).values(updated_at=time.time(), **values)
        )
        async with self._engine.begin() as conn:
            await conn.execute(stmt)

    async def get_job(self, job_id: str) -> dict[str, Any] | None:
        async with self._engine.connect() as conn:
            row = (await conn.execute(select(_jobs).where(_jobs.c.job_id == job_id))).first()
        return dict(row._mapping) if row is not None else None

    async def job_for_context(self, context_id: str) -> dict[str, Any] | None:
        """The job submitted in this A2A context (the earliest, should there be several)."""
        stmt = (
            select(_jobs)
            .where(_jobs.c.context_id == context_id)
            .order_by(_jobs.c.created_at, _jobs.c.job_id)
            .limit(1)
        )
        async with self._engine.connect() as conn:
            row = (await conn.execute(stmt)).first()
        return dict(row._mapping) if row is not None else None

    async def set_state(
        self, job_id: str, state: JobState, *, reason: str | None = None, active_s: float = 0.0
    ) -> None:
        """Set the state; ``active_s`` is added to the job's active time in the same write."""
        await self._update_job(
            job_id, state=state, reason=reason, active_s=_jobs.c.active_s + active_s
        )

    async def add_active(self, job_id: str, seconds: float) -> None:
        await self._update_job(job_id, active_s=_jobs.c.active_s + seconds)

    async def set_whole_passed(self, job_id: str, passed: bool) -> None:
        await self._update_job(job_id, whole_passed=int(passed))

    async def set_spec(self, job_id: str, spec: ExecutableSpec) -> None:
        await self._update_job(job_id, spec_json=spec.model_dump_json(), spec_hash=spec_hash(spec))

    async def set_plan(self, job_id: str, plan_json: dict[str, Any], plan_hash: str) -> None:
        await self._update_job(
            job_id, plan_json=json.dumps(plan_json, sort_keys=True), plan_hash=plan_hash
        )

    async def set_task(self, job_id: str, task_id: str | None) -> None:
        await self._update_job(job_id, current_task_id=task_id)

    async def add_usage(self, job_id: str, tokens_in: int, tokens_out: int, cost: float) -> None:
        await self._update_job(
            job_id,
            tokens_in=_jobs.c.tokens_in + tokens_in,
            tokens_out=_jobs.c.tokens_out + tokens_out,
            cost=_jobs.c.cost + cost,
        )

    async def add_attempt(self, job_id: str) -> None:
        """Count one more worker attempt against the job."""
        await self._update_job(job_id, attempts=_jobs.c.attempts + 1)

    async def list_jobs(
        self, *, state: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        stmt = select(_jobs).order_by(_jobs.c.created_at.desc(), _jobs.c.job_id).limit(limit)
        if state is not None:
            stmt = stmt.where(_jobs.c.state == state)
        async with self._engine.connect() as conn:
            return [dict(r._mapping) for r in (await conn.execute(stmt)).all()]

    async def resumable(self) -> list[str]:
        stmt = select(_jobs.c.job_id).where(_jobs.c.state.in_(RESUMABLE_STATES))
        async with self._engine.connect() as conn:
            return [r[0] for r in (await conn.execute(stmt)).all()]

    # -- steps ---------------------------------------------------------------------------

    async def add_step(self, job_id: str, step: dict[str, Any], seq: int) -> None:
        """Record a planned step (attempt 0, pending); a repeat is ignored."""
        stmt = _upsert(self._engine)(_steps).values(
            job_id=job_id,
            step_id=step["id"],
            attempt=0,
            seq=seq,
            system=step["system"],
            kind=step["kind"],
            state="pending",
        )
        async with self._engine.begin() as conn:
            await conn.execute(
                stmt.on_conflict_do_nothing(index_elements=["job_id", "step_id", "attempt"])
            )

    async def start_attempt(
        self, job_id: str, step_id: str, attempt: int, worker: str, workspace: str
    ) -> None:
        """Mark ``attempt`` running. A new attempt number gets its own row (copying the
        step's seq, system and kind); the earlier attempts stay as history."""
        t = _steps.c
        now = time.time()
        async with self._engine.begin() as conn:
            res = await conn.execute(
                update(_steps)
                .where(t.job_id == job_id, t.step_id == step_id, t.attempt == attempt)
                .values(
                    state="running",
                    worker=worker,
                    workspace=workspace,
                    started_at=now,
                    ended_at=None,
                )
            )
            if res.rowcount:
                return
            base = (
                await conn.execute(
                    select(_steps)
                    .where(t.job_id == job_id, t.step_id == step_id)
                    .order_by(t.attempt.desc())
                    .limit(1)
                )
            ).first()
            if base is None:
                raise KeyError(f"unknown step {job_id}/{step_id}")
            await conn.execute(
                _steps.insert().values(
                    job_id=job_id,
                    step_id=step_id,
                    attempt=attempt,
                    seq=base.seq,
                    system=base.system,
                    kind=base.kind,
                    state="running",
                    worker=worker,
                    workspace=workspace,
                    started_at=now,
                )
            )

    async def end_attempt(
        self,
        job_id: str,
        step_id: str,
        attempt: int,
        state: StepState,
        result: dict[str, Any],
        usage: dict[str, Any],
    ) -> None:
        t = _steps.c
        stmt = (
            update(_steps)
            .where(t.job_id == job_id, t.step_id == step_id, t.attempt == attempt)
            .values(
                state=state,
                result_json=json.dumps(result, sort_keys=True),
                usage_json=json.dumps(usage, sort_keys=True),
                ended_at=time.time(),
            )
        )
        async with self._engine.begin() as conn:
            await conn.execute(stmt)

    async def steps(self, job_id: str) -> list[dict[str, Any]]:
        """The latest attempt of every step, in plan order."""
        t = _steps.c
        latest = (
            select(t.step_id, func.max(t.attempt).label("a"))
            .where(t.job_id == job_id)
            .group_by(t.step_id)
            .subquery()
        )
        stmt = (
            select(_steps)
            .join(latest, (t.step_id == latest.c.step_id) & (t.attempt == latest.c.a))
            .where(t.job_id == job_id)
            .order_by(t.seq, t.step_id)
        )
        async with self._engine.connect() as conn:
            return [dict(r._mapping) for r in (await conn.execute(stmt)).all()]

    async def attempts(self, job_id: str) -> list[dict[str, Any]]:
        """Every attempt row of every step (attempt 0 is the planned placeholder), in plan
        order, then attempt order."""
        t = _steps.c
        stmt = select(_steps).where(t.job_id == job_id).order_by(t.seq, t.step_id, t.attempt)
        async with self._engine.connect() as conn:
            return [dict(r._mapping) for r in (await conn.execute(stmt)).all()]

    # -- receipts ------------------------------------------------------------------------

    async def put_receipt(
        self, job_id: str, receipt: dict[str, Any], receipt_hash: str, audit_seq: int | None
    ) -> None:
        """Store the job's receipt; written once, a repeat keeps the first."""
        stmt = _upsert(self._engine)(_receipts).values(
            job_id=job_id,
            receipt_json=json.dumps(receipt, sort_keys=True),
            receipt_hash=receipt_hash,
            audit_seq=audit_seq,
            created_at=time.time(),
        )
        async with self._engine.begin() as conn:
            await conn.execute(stmt.on_conflict_do_nothing(index_elements=["job_id"]))

    async def get_receipt(self, job_id: str) -> dict[str, Any] | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(select(_receipts).where(_receipts.c.job_id == job_id))
            ).first()
        if row is None:
            return None
        out = dict(row._mapping)
        out["receipt"] = json.loads(out.pop("receipt_json"))
        return out
