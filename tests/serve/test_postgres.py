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
from a2a.utils.errors import InvalidParamsError, TaskNotFoundError
from sqlalchemy import text

from a2agw.consult.handles import OutboundHandleStore
from a2agw.core.events import Done
from a2agw.ops.audit import AuditEvent, AuditLog
from a2agw.serve.agent import AgentSpec, SkillSpec
from a2agw.serve.host import AgentHost
from a2agw.serve.push import PushSettings
from a2agw.serve.store import (
    TaskIndex,
    create_engine,
    reap_tasks,
    recover_on_startup,
    task_store_for,
)

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
async def test_postgres_engine_survives_dropped_connections_and_allows_overflow(pg_url):
    eng, admin = await create_engine(pg_url), await create_engine(pg_url)
    try:
        async with eng.connect() as conn:
            pid = (await conn.execute(text("SELECT pg_backend_pid()"))).scalar_one()
        async with admin.begin() as conn:  # the server drops the pooled connection
            await conn.execute(text("SELECT pg_terminate_backend(:p)"), {"p": pid})
        async with eng.connect() as conn:  # pool_pre_ping replaces it
            assert (await conn.execute(text("SELECT 1"))).scalar_one() == 1

        # pool_size 10 + max_overflow 10: twenty connections at once (the default is 15).
        async def hold() -> int:
            async with eng.connect() as conn:
                await conn.execute(text("SELECT pg_sleep(0.3)"))
                return 1

        assert sum(await asyncio.gather(*(hold() for _ in range(20)))) == 20
        # No public accessor for the recycle time; this reads the pool's private setting.
        assert eng.sync_engine.pool._recycle == 1800  # type: ignore[attr-defined]
    finally:
        await eng.dispose()
        await admin.dispose()


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


# -- NUL bytes, generic internal errors -------------------------------------------------


def _msg(*, context_id: str = "", text: str = "hi secretword") -> Message:
    return Message(
        message_id=uuid.uuid4().hex,
        role=Role.ROLE_USER,
        parts=[Part(text=text)],
        context_id=context_id,
    )


@pytest.mark.parametrize("where", ["context_id", "text", "message_id"])
async def test_nul_is_invalid_params_without_leaking(tmp_path, db_url, where):
    e = Env(tmp_path, db_url=db_url, audit=True)
    e.host.add(spec("alpha"))
    await e.start()
    try:
        if where == "context_id":
            message = _msg(context_id="c\x00x")
        elif where == "text":
            message = _msg(text="a\x00b secretword")
        else:
            message = _msg()
            message.message_id = "m\x00"
        with pytest.raises(InvalidParamsError) as exc:
            await send_one(e.client("alpha"), message)
        shown = str(exc.value)
        assert "invalid characters" in shown
        for leak in ("INSERT", "SELECT", "secretword", "parameters"):
            assert leak not in shown
        assert (await e.host.index.list())[0] == []
        # The host is still healthy.
        assert await send_one(e.client("alpha"), _msg())
    finally:
        await e.stop()


async def test_database_error_is_a_generic_internal_error(tmp_path, db_url, monkeypatch, caplog):
    e = Env(tmp_path, db_url=db_url)
    e.host.add(spec("alpha"))
    await e.start()
    try:
        tid = task_id_of(await send_one(e.client("alpha"), _msg()))
        store = e.host.handlers["alpha"].task_store

        async def boom(*args, **kwargs):
            raise RuntimeError("SELECT secret_column FROM tasks WHERE password = 'hunter2'")

        monkeypatch.setattr(store, "get", boom)
        with caplog.at_level("ERROR"), pytest.raises(Exception) as exc:
            await e.client("alpha").get_task(GetTaskRequest(id=tid))
        shown = str(exc.value)
        assert "internal error" in shown.lower()
        for leak in ("secret_column", "hunter2", "SELECT"):
            assert leak not in shown
        assert "RuntimeError" in caplog.text and "hunter2" not in caplog.text
    finally:
        await e.stop()


async def test_nul_in_audit_fields_is_replaced(db_url):
    eng = await create_engine(db_url)
    try:
        log = AuditLog(eng)
        await log.initialize()
        await log.append(
            AuditEvent(
                actor="jwt:a\x00b",
                action="inbound.admit",
                outcome="o\x00k",
                detail={"reason": "r\x00r"},
            )
        )
        [row], _ = await log.query({}, 5)
        assert row["actor"] == "jwt:a�b" and row["detail"]["reason"] == "r�r"
        assert await log.verify_chain() is None
    finally:
        await eng.dispose()


# -- bounded cross-process audit lock ----------------------------------------------------


@pytest.mark.postgres
async def test_advisory_lock_wait_is_bounded(pg_url, monkeypatch):
    from a2agw.ops import audit as audit_mod

    monkeypatch.setattr(audit_mod, "LOCK_TIMEOUT_S", 0.5)
    eng, holder = await create_engine(pg_url), await create_engine(pg_url)
    try:
        log = AuditLog(eng)
        await log.initialize()
        async with holder.connect() as conn:
            tx = await conn.begin()
            await conn.execute(
                text("SELECT pg_advisory_xact_lock(:k)"), {"k": audit_mod._ADVISORY_KEY}
            )
            started = asyncio.get_running_loop().time()
            await log.emit(_ev())  # never raises; counts the failure
            elapsed = asyncio.get_running_loop().time() - started
            await tx.rollback()
        assert elapsed < 10 and log.audit_errors == 1  # bounded by the 0.5 s lock timeout
        await log.emit(_ev())  # the lock is free again
        assert log.audit_errors == 1
        assert len((await log.query({}, 10))[0]) == 1
    finally:
        await eng.dispose()
        await holder.dispose()


# -- reaping tasks of agents nobody serves ---------------------------------------------


async def _seed_orphans(eng):
    index, handles = TaskIndex(eng), OutboundHandleStore(eng)
    await index.initialize()
    await handles.initialize()
    await index.upsert("gone-1", "gone", "key:a", "c", W, None)
    await index.upsert("gone-2", "gone", "key:a", "c", "TASK_STATE_COMPLETED", None)
    await index.upsert("other-1", "other", "key:a", "c", W, None)
    await handles.record("p1", "px", None, "gone-1", None, W, caller_id="key:a")
    return index, handles


async def test_reap_tasks_fails_open_tasks_and_cancels_handles(db_url):
    eng = await create_engine(db_url)
    try:
        index, handles = await _seed_orphans(eng)
        cancelled: list[str] = []

        async def cancel(h):
            cancelled.append(h["task_id"])

        report = await reap_tasks(index, handles, cancel, "gone")
        assert report.failed == ["gone-1"] and cancelled == ["p1"]
        states = {r["task_id"]: r["state"] for r in (await index.list())[0]}
        assert states == {
            "gone-1": FAILED,
            "gone-2": "TASK_STATE_COMPLETED",
            "other-1": W,
        }
        assert await index.count_active_outside({"other"}) == 0
    finally:
        await eng.dispose()


async def _age(eng, seconds: float = 3600.0) -> None:
    async with eng.begin() as conn:
        await conn.execute(
            text("UPDATE a2agw_task_index SET updated_at = updated_at - :s"), {"s": seconds}
        )


async def _states(eng) -> dict[str, str]:
    return {r["task_id"]: r["state"] for r in (await TaskIndex(eng).list())[0]}


async def _reap_audit(host):
    await host.audit.drain()
    rows, _ = await host.audit.query({"action": "task.reap"}, 50, None, ascending=True)
    return [
        (r["agent_id"], r["outcome"], r["detail"].get("reason"), r["detail"]["count"]) for r in rows
    ]


async def test_host_warns_about_foreign_open_tasks(tmp_path, db_url, caplog):
    eng = await create_engine(db_url)
    await _seed_orphans(eng)
    await eng.dispose()
    e = Env(tmp_path, db_url=db_url)
    e.host.add(spec("alpha"))
    with caplog.at_level("WARNING"):
        await e.start()
    try:
        assert "2 non-terminal task(s)" in caplog.text and "a2agw tasks reap" in caplog.text
        assert await e.host.index.count_active_outside({"alpha"}) == 2  # recovery skipped them
    finally:
        await e.stop()


async def test_admin_reap_is_dry_run_idle_guarded_confirmed_and_audited(tmp_path, db_url):
    eng = await create_engine(db_url)
    await _seed_orphans(eng)
    e = Env(tmp_path, db_url=db_url, audit=True, admin_without_auth=True)
    e.host.add(spec("alpha"))
    await e.start()
    try:
        hc = httpx.AsyncClient(transport=httpx.ASGITransport(app=e.host.app()), base_url="http://t")
        url = "/a2agw/admin/tasks/reap"
        async with hc:
            assert (await hc.post(url)).status_code == 400  # agent is required
            assert (
                await hc.post(url, params={"agent": "gone", "confirm": "yes"})
            ).status_code == 400
            assert (
                await hc.post(url, params={"agent": "alpha", "confirm": "true"})
            ).status_code == 409
            assert (await hc.get(url, params={"agent": "gone"})).status_code != 200
            # No confirm: a dry run that changes nothing.
            r = await hc.post(url, params={"agent": "gone"})
            assert r.status_code == 200
            assert r.json() == {"dry_run": True, "tasks": 1, "handles": 1, "recent": 1}
            assert (await _states(eng))["gone-1"] == W
            # Confirmed but the rows are recent: refused with the count.
            r = await hc.post(url, params={"agent": "gone", "confirm": "true"})
            assert r.status_code == 409 and r.json()["recent"] == 1
            assert (await _states(eng))["gone-1"] == W
            # force reaps recent rows; idle rows need no force.
            r = await hc.post(url, params={"agent": "gone", "confirm": "true", "force": "true"})
            assert r.status_code == 200 and r.json()["reaped"] == 1
            await eng.dispose()
        eng = await create_engine(db_url)
        states = await _states(eng)
        assert states["gone-1"] == FAILED and states["other-1"] == W
        await _age(eng)
        await TaskIndex(eng).upsert("gone-3", "gone", "key:a", "c", W, None)
        await _age(eng)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=e.host.app()), base_url="http://t"
        ) as hc:
            r = await hc.post(url, params={"agent": "gone", "confirm": "true"})
            assert r.status_code == 200 and r.json()["reaped"] == 1
        # Exactly one audit row per attempt, none from the route itself.
        assert await _reap_audit(e.host) == [
            ("alpha", "refused", "served", 0),
            ("gone", "refused", "not_confirmed", 1),
            ("gone", "refused", "recent", 1),
            ("gone", "reaped", None, 1),
            ("gone", "reaped", None, 1),
        ]
    finally:
        await eng.dispose()
        await e.stop()


async def test_failed_reap_is_audited(tmp_path, db_url, monkeypatch):
    e = Env(tmp_path, db_url=db_url, audit=True)
    e.host.add(spec("alpha"))
    await e.start()
    try:

        async def boom(*args, **kwargs):
            raise RuntimeError("db down")

        monkeypatch.setattr("a2agw.serve.reap.reap_tasks", boom)
        with pytest.raises(RuntimeError):
            await e.host.reap("gone", confirm=True, force=True)
        assert await _reap_audit(e.host) == [("gone", "failed", None, 0)]
    finally:
        await e.stop()


async def test_admin_reap_needs_the_admin_scope(tmp_path, db_url):
    e = Env(tmp_path, db_url=db_url)  # no auth, no admin_without_auth: admin fails closed
    e.host.add(spec("alpha"))
    await e.start()
    try:
        hc = httpx.AsyncClient(transport=httpx.ASGITransport(app=e.host.app()), base_url="http://t")
        async with hc:
            r = await hc.post(
                "/a2agw/admin/tasks/reap", params={"agent": "gone", "confirm": "true"}
            )
        assert r.status_code == 403
    finally:
        await e.stop()


def _cli(tmp_path, url, *args, agents="[]"):
    from typer.testing import CliRunner

    from a2agw import cli

    cfg = tmp_path / "a2agw.yaml"
    cfg.write_text(f"base_url: http://localhost\ndb_url: {url}\nagents: {agents}\n")
    return CliRunner().invoke(cli.app, ["tasks", "reap", "-c", str(cfg), *args])


async def test_cli_tasks_reap(tmp_path, db_url, caplog):
    eng = await create_engine(db_url)
    await _seed_orphans(eng)
    try:
        loop = asyncio.get_running_loop()

        async def run(*args, **kw):  # the CLI runs its own event loop: use a thread
            return await loop.run_in_executor(None, lambda: _cli(tmp_path, db_url, *args, **kw))

        r = await run("--agent", "gone")
        assert r.exit_code == 0 and "dry run: 1 open task(s), 1 partner task(s)" in r.output
        assert (await _states(eng))["gone-1"] == W
        r = await run("--agent", "gone", "--yes")  # recent
        assert r.exit_code == 1 and "1 task(s) changed in the last 10 minutes" in r.output
        assert (await _states(eng))["gone-1"] == W
        await _age(eng)
        with caplog.at_level("WARNING"):
            r = await run("--agent", "gone", "--yes")
        assert r.exit_code == 0 and "reaped 1 task(s)" in r.output
        assert "non-terminal" not in caplog.text  # no host, no foreign-task warning
        states = await _states(eng)
        assert states["gone-1"] == FAILED and states["other-1"] == W
        r = await run("--agent", "other", "--yes", "--force")
        assert r.exit_code == 0 and (await _states(eng))["other-1"] == FAILED
        log = AuditLog(eng)
        rows, _ = await log.query({"action": "task.reap"}, 20, None, ascending=True)
        assert [(r["agent_id"], r["outcome"], r["detail"].get("reason")) for r in rows] == [
            ("gone", "refused", "not_confirmed"),
            ("gone", "refused", "recent"),
            ("gone", "reaped", None),
            ("other", "reaped", None),
        ]
    finally:
        await eng.dispose()


async def test_cli_refuses_to_reap_a_served_agent(tmp_path, monkeypatch):
    import sys
    import textwrap

    (tmp_path / "served_agent.py").write_text(
        textwrap.dedent(
            """
            from a2agw.core.events import Done
            from a2agw.serve.agent import AgentSpec, SkillSpec

            class A:
                durable_sessions = False
                async def run(self, ctx):
                    yield Done(text="x")

            spec = AgentSpec(id="mine", name="M", description="d",
                             skills=[SkillSpec(id="s", name="S", description="d")], adapter=A())
            """
        )
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    url = f"sqlite+aiosqlite:///{tmp_path / 'gw.db'}"
    loop = asyncio.get_running_loop()
    r = await loop.run_in_executor(
        None,
        lambda: _cli(
            tmp_path,
            url,
            "--agent",
            "mine",
            "--yes",
            "--force",
            agents="[{spec: 'served_agent:spec'}]",
        ),
    )
    sys.modules.pop("served_agent", None)
    assert r.exit_code == 1 and "served by this gateway" in r.output


# -- agent output with NUL ---------------------------------------------------------------


async def test_agent_output_with_nul_is_stored(tmp_path, db_url):
    from a2agw.core.events import ArtifactChunk, Status

    class Nul:
        durable_sessions = False

        async def run(self, ctx):
            yield Status("work\x00ing")
            yield ArtifactChunk(
                artifact_id="a\x00", parts=[Part(text="par\x00t", filename="f\x00")], name="n\x00"
            )
            yield Done(text="done\x00!")

    sp = spec("alpha")
    sp.adapter = Nul()
    e = Env(tmp_path, db_url=db_url)
    e.host.add(sp)
    await e.start()
    try:
        events = await send_one(e.client("alpha"), _msg())
        task = events[-1].task
        assert task.status.state == TaskState.TASK_STATE_COMPLETED
        texts = [p.text for a in task.artifacts for p in a.parts]
        assert "par\ufffdt" in texts and "done\ufffd!" in texts
        assert {a.name for a in task.artifacts} == {"n\ufffd", "result"}
        [row] = (await e.host.index.list("alpha"))[0]
        assert row["state"] == "TASK_STATE_COMPLETED"
    finally:
        await e.stop()


async def test_reap_marks_the_sdk_task_store_failed(tmp_path, db_url):
    """M2: reaping fails the agent's stored A2A task too, not only its index row (host and
    CLI paths)."""
    from a2a.server.context import ServerCallContext
    from a2a.types import Task, TaskStatus

    from a2agw.security.principal import Principal, PrincipalUser

    eng = await create_engine(db_url)
    try:
        await _seed_orphans(eng)
        store = task_store_for(eng, "gone")
        await store.initialize()
        owner = ServerCallContext(
            user=PrincipalUser(Principal(id="key:a", kind="api_key", scopes=frozenset()))
        )
        await store.save(
            Task(
                id="gone-1", context_id="c", status=TaskStatus(state=TaskState.TASK_STATE_WORKING)
            ),
            owner,
        )
        await _age(eng)
        r = await asyncio.get_running_loop().run_in_executor(
            None, lambda: _cli(tmp_path, db_url, "--agent", "gone", "--yes")
        )
        assert r.exit_code == 0, r.output
        task = await task_store_for(eng, "gone").get("gone-1", owner)
        assert task is not None and task.status.state == TaskState.TASK_STATE_FAILED
        assert task.status.message.parts[0].text == "agent no longer served"
    finally:
        await eng.dispose()
