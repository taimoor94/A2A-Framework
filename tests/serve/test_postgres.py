"""Both database backends: dialect regressions, shared databases and concurrent startup.

Tests taking ``db_url`` run on sqlite and on a throwaway PostgreSQL (skipped when its
binaries are missing, see ``tests/postgres_support.py``); tests taking ``pg_url`` are
Postgres only.
"""

from __future__ import annotations

import asyncio
import types
import uuid

import httpx
import pytest
from a2a.client import ClientConfig, ClientFactory
from a2a.types import GetTaskRequest, Message, Part, Role, SendMessageRequest, TaskState
from a2a.utils.errors import TaskNotFoundError
from sqlalchemy import text

from a2agw.consult.handles import OutboundHandleStore
from a2agw.core.events import Done
from a2agw.ops.audit import AuditEvent, AuditLog
from a2agw.serve.agent import AgentSpec, SkillSpec
from a2agw.serve.host import AgentHost
from a2agw.serve.push import PushSettings
from a2agw.serve.store import TaskIndex, create_engine, recover_on_startup, task_store_for

W = "TASK_STATE_WORKING"
FAILED = "TASK_STATE_FAILED"


class Echo:
    durable_sessions = False

    async def run(self, ctx):
        yield Done(text=f"echo: {ctx.text}")


def spec(agent_id: str) -> AgentSpec:
    return AgentSpec(
        id=agent_id,
        name=agent_id.title(),
        description="Test agent",
        skills=[SkillSpec(id="s", name="S", description="d")],
        adapter=Echo(),
    )


def msg() -> Message:
    return Message(message_id=uuid.uuid4().hex, role=Role.ROLE_USER, parts=[Part(text="hi")])


async def send_one(client, message: Message):
    return [ev async for ev in client.send_message(SendMessageRequest(message=message))]


def task_id_of(events) -> str:
    return events[0].task.id


class Env:
    """One AgentHost on ``db_url`` plus the HTTP clients driving it."""

    def __init__(self, tmp_path, *, db_url: str, **host_kwargs) -> None:
        self.host = AgentHost("http://t", db_url=db_url, **host_kwargs)
        self._clients: list[httpx.AsyncClient] = []

    async def start(self) -> None:
        await self.host.startup()

    def client(self, agent_id: str):
        hc = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.host.app()), base_url="http://t"
        )
        self._clients.append(hc)
        return ClientFactory(ClientConfig(httpx_client=hc, streaming=False)).create(
            self.host.cards[agent_id]
        )

    async def stop(self) -> None:
        for hc in self._clients:
            await hc.aclose()
        await self.host.shutdown()


def _ev(**kw) -> AuditEvent:
    return AuditEvent(actor="key:alice", action="inbound.admit", outcome="ok", **kw)


# -- engine ----------------------------------------------------------------------------


@pytest.mark.postgres
async def test_postgres_engine_pool_settings(pg_url):
    eng = await create_engine(pg_url)
    try:
        pool = eng.sync_engine.pool
        assert pool.size() == 10 and pool._max_overflow == 10  # type: ignore[attr-defined]
        assert pool._pre_ping is True  # type: ignore[attr-defined]
        assert pool._recycle == 1800  # type: ignore[attr-defined]
        async with eng.connect() as conn:
            assert (await conn.execute(text("SELECT 1"))).scalar_one() == 1
    finally:
        await eng.dispose()


# -- dialect regressions (each runs on both backends) ----------------------------------


async def test_cursor_roundtrips_full_precision_timestamps(db_url, monkeypatch):
    """updated_at must be stored as a double: a float4 column would collapse these and
    make the cursor skip or repeat rows."""
    stamps = iter([1_700_000_000.123456 + i * 1e-6 for i in range(7)])
    monkeypatch.setattr("a2agw.serve.store.time", types.SimpleNamespace(time=lambda: next(stamps)))
    eng = await create_engine(db_url)
    try:
        index = TaskIndex(eng)
        await index.initialize()
        for i in range(7):
            await index.upsert(f"t{i}", "ag", "key:x", "c", W, None)
        seen, cur = [], None
        while True:
            rows, cur = await index.list("ag", None, limit=3, cursor=cur)
            seen += [r["task_id"] for r in rows]
            if not cur:
                break
        assert seen == [f"t{i}" for i in reversed(range(7))]
        [first, *_] = (await index.list("ag", None, limit=1))[0]
        assert first["updated_at"] == 1_700_000_000.123456 + 6e-6
    finally:
        await eng.dispose()


async def test_audit_timestamps_survive_roundtrip_and_chain_verifies(db_url):
    eng = await create_engine(db_url)
    try:
        log = AuditLog(eng)
        await log.initialize()
        ts = 1_700_000_000.123456789
        await log.append(_ev(ts=ts))
        await log.append(_ev(ts=int(ts)))  # an int timestamp binds as a float, not an int
        rows, _ = await log.query({"since": 1_700_000_000}, 10, None, ascending=True)
        assert rows[0]["ts"] == ts and rows[1]["ts"] == float(int(ts))
        assert await log.verify_chain() is None
    finally:
        await eng.dispose()


async def test_audit_seq_is_monotonic_after_deleting_last_row(db_url):
    eng = await create_engine(db_url)
    try:
        log = AuditLog(eng)
        await log.initialize()
        s1, s2 = await log.append(_ev()), await log.append(_ev())
        async with eng.begin() as conn:
            await conn.execute(text("DELETE FROM a2agw_audit WHERE seq = :s"), {"s": s2})
        s3 = await log.append(_ev())
        assert s1 < s2 < s3  # a deleted seq is never reused
    finally:
        await eng.dispose()


async def test_handle_upsert_keeps_first_links_and_partner_scoped_keys(db_url):
    eng = await create_engine(db_url)
    try:
        h = OutboundHandleStore(eng)
        await h.initialize()
        await h.record("t", "p1", None, "in-1", "o1", W, caller_id="key:a")
        await h.record("t", "p2", "ctx", "in-2", None, W)  # same task id, other partner
        await h.record("t", "p1", "ctx", "in-X", "oX", "TASK_STATE_COMPLETED", caller_id="key:b")
        r1, r2 = await h.get("p1", "t"), await h.get("p2", "t")
        assert (r1["inbound_task_id"], r1["origin"], r1["caller_id"]) == ("in-1", "o1", "key:a")
        assert (r1["context_id"], r1["state"]) == ("ctx", "TASK_STATE_COMPLETED")
        assert r2["inbound_task_id"] == "in-2" and r2["state"] == W
        assert await h.seen_origin("o1") and not await h.seen_origin("nope")
    finally:
        await eng.dispose()


async def test_recovery_leaves_other_hosts_agents_alone(db_url):
    """On a shared database a starting host must only fail the tasks of its own agents."""
    eng = await create_engine(db_url)
    try:
        index = TaskIndex(eng)
        await index.initialize()
        store = task_store_for(eng, "mine")
        await store.initialize()
        await index.upsert("mine-1", "mine", "key:a", "c", W, None)
        await index.upsert("theirs-1", "theirs", "key:a", "c", W, None)
        report = await recover_on_startup(index, {"mine": store}, {}, None, None)
        assert report.failed == ["mine-1"]
        states = {r["task_id"]: r["state"] for r in (await index.list())[0]}
        assert states == {"mine-1": FAILED, "theirs-1": W}
    finally:
        await eng.dispose()


# -- audit chain across processes ------------------------------------------------------


@pytest.mark.postgres
async def test_two_writers_on_one_postgres_keep_one_chain(pg_url):
    """The in-process lock cannot serialize two hosts; the database must."""
    e1, e2 = await create_engine(pg_url), await create_engine(pg_url)
    try:
        a, b = AuditLog(e1), AuditLog(e2)
        await a.initialize()
        await b.initialize()
        await asyncio.gather(
            *(a.append(_ev(task_id=f"a{i}")) for i in range(15)),
            *(b.append(_ev(task_id=f"b{i}")) for i in range(15)),
        )
        assert await a.verify_chain() is None
        rows, _ = await a.query({}, 100, None)
        assert len(rows) == 30
    finally:
        await e1.dispose()
        await e2.dispose()


# -- concurrent startup ----------------------------------------------------------------


async def test_concurrent_startup_does_not_crash(tmp_path, db_url):
    """Several hosts starting at once on one empty database all create the same tables."""
    envs = []
    for _ in range(4):
        e = Env(tmp_path, db_url=db_url, audit=True, push=PushSettings(allow_private=True))
        e.host.add(spec("alpha"))
        e.host.add(spec("beta"))
        envs.append(e)
    try:
        results = await asyncio.gather(*(e.start() for e in envs), return_exceptions=True)
        assert [r for r in results if r is not None] == []
    finally:
        await asyncio.gather(*(e.stop() for e in envs), return_exceptions=True)


async def test_concurrent_handle_migration_does_not_crash(db_url):
    eng = await create_engine(db_url)
    try:
        async with eng.begin() as conn:  # the Phase 1 schema
            await conn.exec_driver_sql(
                "CREATE TABLE a2agw_outbound (partner_id VARCHAR NOT NULL, task_id VARCHAR NOT "
                "NULL, context_id VARCHAR, inbound_task_id VARCHAR, origin VARCHAR, state "
                "VARCHAR NOT NULL, created_at FLOAT NOT NULL, PRIMARY KEY (partner_id, task_id))"
            )
        stores = [OutboundHandleStore(eng) for _ in range(5)]
        await asyncio.gather(*(s.initialize() for s in stores))
        await stores[0].record("t", "p", None, None, None, W, caller_id="key:a")
        assert (await stores[1].get("p", "t"))["caller_id"] == "key:a"
    finally:
        await eng.dispose()


# -- two hosts, one database -----------------------------------------------------------


@pytest.mark.postgres
async def test_two_hosts_share_postgres(tmp_path, pg_url):
    ea = Env(tmp_path, db_url=pg_url, audit=True)
    eb = Env(tmp_path, db_url=pg_url, audit=True)
    ea.host.add(spec("alpha"))
    eb.host.add(spec("beta"))
    await ea.start()
    try:
        await eb.start()
        try:
            ta = task_id_of(await send_one(ea.client("alpha"), msg()))
            tb = task_id_of(await send_one(eb.client("beta"), msg()))
            # One shared index, partitioned by agent.
            for host in (ea.host, eb.host):
                rows, _ = await host.index.list()
                assert {(r["task_id"], r["agent_id"]) for r in rows} == {
                    (ta, "alpha"),
                    (tb, "beta"),
                }
            assert [r["task_id"] for r in (await ea.host.index.list("alpha"))[0]] == [ta]
            assert [r["task_id"] for r in (await eb.host.index.list("beta"))[0]] == [tb]
            # A task is only reachable through the host (and table) of its own agent.
            got = await ea.client("alpha").get_task(GetTaskRequest(id=ta))
            assert got.status.state == TaskState.TASK_STATE_COMPLETED
            with pytest.raises(TaskNotFoundError):
                await eb.client("beta").get_task(GetTaskRequest(id=ta))
            with pytest.raises(TaskNotFoundError):
                await ea.client("alpha").get_task(GetTaskRequest(id=tb))
            # One audit chain, each host's rows tagged with its own agent only.
            await ea.host.audit.drain()
            await eb.host.audit.drain()
            assert await ea.host.audit.verify_chain() is None
            rows, _ = await ea.host.audit.query({"action": "inbound.admit"}, 100)
            assert {(r["agent_id"], r["task_id"]) for r in rows} == {("alpha", ta), ("beta", tb)}
        finally:
            await eb.stop()
    finally:
        await ea.stop()


async def test_recovery_cancels_real_outbound_handles(db_url):
    eng = await create_engine(db_url)
    try:
        index, handles = TaskIndex(eng), OutboundHandleStore(eng)
        await index.initialize()
        await handles.initialize()
        store = task_store_for(eng, "rec")
        await store.initialize()
        await index.upsert("in-1", "rec", "key:a", "c", W, "o")
        await handles.record("p1", "px", None, "in-1", "o", W, caller_id="key:a")
        await handles.record("p2", "px", None, "in-1", "o", "TASK_STATE_COMPLETED")
        cancelled: list[dict] = []

        async def cancel(handle):
            cancelled.append(handle)

        report = await recover_on_startup(index, {"rec": store}, {}, handles, cancel)
        assert [(h["task_id"], h["caller_id"]) for h in cancelled] == [("p1", "key:a")]
        assert report.failed == ["in-1"] and report.outbound_cancelled == 1
    finally:
        await eng.dispose()
