import asyncio

import pytest
from a2a.server.context import ServerCallContext
from a2a.types import Role, Task, TaskState, TaskStatus

from a2agw.consult.handles import OutboundHandleStore
from a2agw.security.principal import Principal, PrincipalUser
from a2agw.serve.store import (
    TaskIndex,
    create_engine,
    recover_on_startup,
    task_store_for,
)

W = "TASK_STATE_WORKING"
S = "TASK_STATE_SUBMITTED"
IR = "TASK_STATE_INPUT_REQUIRED"
FAILED = "TASK_STATE_FAILED"


def _ctx(owner: str) -> ServerCallContext:
    kind = "api_key" if owner.startswith("key:") else "anonymous"
    return ServerCallContext(user=PrincipalUser(Principal(id=owner, kind=kind, scopes=frozenset())))


@pytest.fixture
async def engine(db_url):
    eng = await create_engine(db_url)
    yield eng
    await eng.dispose()


@pytest.fixture
async def index(engine):
    idx = TaskIndex(engine)
    await idx.initialize()
    return idx


async def _seed(index, store, agent, task_id, state, owner="key:alice"):
    task = Task(
        id=task_id,
        context_id="c1",
        status=TaskStatus(state=getattr(TaskState, state)),
    )
    await store.save(task, _ctx(owner))
    await index.upsert(task_id, agent, owner, "c1", state, None)


async def test_index_upsert_and_list_pagination(index):
    for i in range(5):
        await index.upsert(f"t{i}", "a1", "key:x", "c", W, None)
    await index.upsert("o1", "a2", "key:x", "c", S, "origin")
    # upsert on conflict updates in place
    await index.upsert("t0", "a1", "key:x", "c", "TASK_STATE_COMPLETED", None)

    rows, cur = await index.list("a1", None, limit=2, cursor=None)
    assert len(rows) == 2 and cur is not None
    seen = [r["task_id"] for r in rows]
    while cur:
        rows, cur = await index.list("a1", None, limit=2, cursor=cur)
        seen += [r["task_id"] for r in rows]
    assert sorted(seen) == [f"t{i}" for i in range(5)]
    assert len(set(seen)) == 5

    rows, cur = await index.list(None, S, limit=10, cursor=None)
    assert [r["task_id"] for r in rows] == ["o1"] and cur is None
    assert rows[0]["origin"] == "origin"
    done, _ = await index.list("a1", "TASK_STATE_COMPLETED", limit=10, cursor=None)
    assert [r["task_id"] for r in done] == ["t0"]


async def test_two_agent_stores_share_engine(engine):
    s1 = task_store_for(engine, "agent-one")
    s2 = task_store_for(engine, "agent-two")
    await s1.initialize()
    await s2.initialize()
    await s1.save(
        Task(id="x", context_id="c", status=TaskStatus(state=TaskState.TASK_STATE_WORKING)),
        _ctx("key:a"),
    )
    assert await s1.get("x", _ctx("key:a")) is not None
    assert await s2.get("x", _ctx("key:a")) is None


class _Handles:
    def __init__(self, rows):
        self.rows = rows

    async def by_inbound(self, inbound_task_id):
        return self.rows.get(inbound_task_id, [])


async def test_recovery_fails_working_tasks(engine, index):
    store = task_store_for(engine, "rec-work")
    await store.initialize()
    await _seed(index, store, "rec-work", "w1", W)
    await _seed(index, store, "rec-work", "s1", S, owner="anonymous")
    report = await recover_on_startup(index, {"rec-work": store}, {"rec-work": True}, None, None)
    assert sorted(report.failed) == ["s1", "w1"]
    got = await store.get("w1", _ctx("key:alice"))
    assert got.status.state == TaskState.TASK_STATE_FAILED
    assert got.status.message.role == Role.ROLE_AGENT
    assert got.status.message.parts[0].text == "gateway restarted"
    assert (await store.get("s1", _ctx("anonymous"))).status.state == TaskState.TASK_STATE_FAILED
    rows, _ = await index.list("rec-work", FAILED, limit=10, cursor=None)
    assert len(rows) == 2


async def test_recovery_keeps_input_required_when_durable(engine, index):
    store = task_store_for(engine, "rec-keep")
    await store.initialize()
    await _seed(index, store, "rec-keep", "i1", IR)
    report = await recover_on_startup(index, {"rec-keep": store}, {"rec-keep": True}, None, None)
    assert report.kept == ["i1"] and report.failed == []
    got = await store.get("i1", _ctx("key:alice"))
    assert got.status.state == TaskState.TASK_STATE_INPUT_REQUIRED


async def test_recovery_fails_input_required_when_not_durable(engine, index):
    store = task_store_for(engine, "rec-nd")
    await store.initialize()
    await _seed(index, store, "rec-nd", "i1", IR)
    report = await recover_on_startup(index, {"rec-nd": store}, {"rec-nd": False}, None, None)
    assert report.failed == ["i1"] and report.kept == []
    got = await store.get("i1", _ctx("key:alice"))
    assert got.status.state == TaskState.TASK_STATE_FAILED


async def test_recovery_cancels_outbound_handles(engine, index):
    store = task_store_for(engine, "rec-out")
    await store.initialize()
    await _seed(index, store, "rec-out", "w1", W)
    await _seed(index, store, "rec-out", "w2", W)
    handles = _Handles(
        {"w1": [{"task_id": "p1", "partner_id": "px"}, {"task_id": "p2", "partner_id": "py"}]}
    )
    calls = []

    async def cancel(h):
        calls.append(h)

    report = await recover_on_startup(
        index, {"rec-out": store}, {"rec-out": False}, handles, cancel
    )
    assert [c["task_id"] for c in calls] == ["p1", "p2"]
    assert report.outbound_cancelled == 2
    assert sorted(report.failed) == ["w1", "w2"]


async def test_recovery_index_only_when_task_missing(engine, index):
    store = task_store_for(engine, "rec-miss")
    await store.initialize()
    await index.upsert("ghost", "rec-miss", "key:alice", "c", W, None)
    report = await recover_on_startup(index, {"rec-miss": store}, {"rec-miss": False}, None, None)
    assert report.failed == ["ghost"]
    rows, _ = await index.list("rec-miss", FAILED, limit=10, cursor=None)
    assert [r["task_id"] for r in rows] == ["ghost"]


async def test_recovery_continues_when_cancel_raises(engine, index):
    store = task_store_for(engine, "rec-cx")
    await store.initialize()
    await _seed(index, store, "rec-cx", "a1", W)
    await _seed(index, store, "rec-cx", "a2", W)
    handles = _Handles(
        {"a1": [{"task_id": "p1", "partner_id": "px"}, {"task_id": "p2", "partner_id": "py"}]}
    )
    calls = []

    async def cancel(h):
        calls.append(h["task_id"])
        if h["task_id"] == "p1":
            raise RuntimeError("boom")

    report = await recover_on_startup(index, {"rec-cx": store}, {}, handles, cancel)
    assert sorted(report.failed) == ["a1", "a2"]
    assert calls == ["p1", "p2"]
    assert report.cancel_errors == ["a1:px"]
    assert report.outbound_cancelled == 1 and report.errors == []
    rows, _ = await index.list("rec-cx", FAILED, limit=10, cursor=None)
    assert len(rows) == 2


class _FlakyStore:
    def __init__(self, inner):
        self.inner = inner

    async def get(self, task_id, ctx):
        if task_id == "bad":
            raise RuntimeError("db down")
        return await self.inner.get(task_id, ctx)

    async def save(self, task, ctx):
        await self.inner.save(task, ctx)


async def test_recovery_continues_when_store_get_raises(engine, index):
    inner = task_store_for(engine, "rec-sg")
    await inner.initialize()
    await _seed(index, inner, "rec-sg", "bad", W)
    await _seed(index, inner, "rec-sg", "good", W)
    report = await recover_on_startup(index, {"rec-sg": _FlakyStore(inner)}, {}, None, None)
    assert report.errors == ["bad"] and report.failed == ["good"]
    assert (await inner.get("good", _ctx("key:alice"))).status.state == TaskState.TASK_STATE_FAILED


async def test_task_store_for_is_idempotent(engine):
    s1 = task_store_for(engine, "idem-a")
    s2 = task_store_for(engine, "idem-a")
    await s1.initialize()
    await s2.initialize()
    await s1.save(
        Task(id="x", context_id="c", status=TaskStatus(state=TaskState.TASK_STATE_WORKING)),
        _ctx("key:a"),
    )
    assert await s2.get("x", _ctx("key:a")) is not None
    task_store_for(engine, "idem-b-c")
    with pytest.raises(ValueError, match="same table"):
        task_store_for(engine, "idem_b-c")
    with pytest.raises(ValueError, match="invalid agent_id"):
        task_store_for(engine, "bad name; drop")


async def test_two_engines_same_agent_id(db_factory):
    e1 = await create_engine(db_factory())
    e2 = await create_engine(db_factory())
    try:
        s1, s2 = task_store_for(e1, "a"), task_store_for(e2, "a")
        await s1.initialize()
        await s2.initialize()
        working = TaskStatus(state=TaskState.TASK_STATE_WORKING)
        await s1.save(Task(id="t1", context_id="c", status=working), _ctx("key:a"))
        await s2.save(Task(id="t2", context_id="c", status=working), _ctx("key:a"))
        assert (await s1.get("t1", _ctx("key:a"))).id == "t1"
        assert await s1.get("t2", _ctx("key:a")) is None
        assert (await s2.get("t2", _ctx("key:a"))).id == "t2"
        assert await s2.get("t1", _ctx("key:a")) is None
    finally:
        await e1.dispose()
        await e2.dispose()


async def test_list_rejects_malformed_cursor(index):
    for bad in ("!!!notbase64", "bm9zZXA="):
        with pytest.raises(ValueError, match="invalid cursor"):
            await index.list(None, None, limit=5, cursor=bad)


async def test_pagination_with_equal_timestamps(index, monkeypatch):
    monkeypatch.setattr("a2agw.serve.store.time.time", lambda: 1000.0)
    for tid in ["d", "b", "e", "a", "c"]:
        await index.upsert(tid, "ag", "key:x", "c", W, None)
    seen, cur = [], None
    while True:
        rows, cur = await index.list("ag", None, limit=2, cursor=cur)
        seen += [r["task_id"] for r in rows]
        if not cur:
            break
    assert seen == ["a", "b", "c", "d", "e"]


async def test_upsert_none_origin_keeps_existing(index):
    await index.upsert("t1", "a1", "key:x", "c", S, "orig-1")
    await index.upsert("t1", "a1", "key:x", "c", W, None)
    [row] = await index.by_state({W})
    assert row["origin"] == "orig-1"
    await index.upsert("t1", "a1", "key:x", "c", W, "orig-2")
    [row] = await index.by_state({W})
    assert row["origin"] == "orig-2"


async def test_blocked_downstream_needs_other_live_task_with_live_outbound_handle(engine, index):
    handles = OutboundHandleStore(engine)
    await handles.initialize()
    done = "TASK_STATE_COMPLETED"
    await index.upsert("t1", "a1", "key:x", "c", W, "o1")  # waiting on a live partner task
    await handles.record("p1", "px", "pc", "t1", "o1", W)
    await index.upsert("t2", "a1", "key:x", "c", W, "o2")  # live, but no outbound handle
    await index.upsert("t3", "a1", "key:x", "c", W, "o3")  # its partner task has finished
    await handles.record("p3", "px", "pc", "t3", "o3", done)
    await index.upsert("t4", "a1", "key:x", "c", done, "o4")  # finished itself
    await handles.record("p4", "px", "pc", "t4", "o4", W)
    await index.upsert("t5", "a2", "key:x", "c", IR, "o5")  # input-required counts as live
    await handles.record("p5", "px", "pc", "t5", "o5", IR)

    assert await index.blocked_downstream("a1", "o1", "t9")
    assert not await index.blocked_downstream("a1", "o1", "t1")  # the task itself never counts
    assert not await index.blocked_downstream("a1", "o2", "t9")
    assert not await index.blocked_downstream("a1", "o3", "t9")
    assert not await index.blocked_downstream("a1", "o4", "t9")
    assert not await index.blocked_downstream("a2", "o1", "t9")  # other agent
    assert await index.blocked_downstream("a2", "o5", "t9")
    assert not await index.blocked_downstream("a1", "nope", "t9")


async def test_recovery_skips_terminal_handles(engine, index):
    store = task_store_for(engine, "rec-term")
    await store.initialize()
    await _seed(index, store, "rec-term", "w1", W)
    handles = _Handles(
        {
            "w1": [
                {"task_id": "p1", "partner_id": "px", "state": "TASK_STATE_COMPLETED"},
                {"task_id": "p2", "partner_id": "py", "state": W},
            ]
        }
    )
    calls = []

    async def cancel(h):
        calls.append(h["task_id"])

    report = await recover_on_startup(index, {"rec-term": store}, {}, handles, cancel)
    assert calls == ["p2"]
    assert report.outbound_cancelled == 1 and report.cancel_errors == []


async def test_recovery_cancels_run_concurrently_within_bound(engine, index):
    store = task_store_for(engine, "rec-slow")
    await store.initialize()
    await _seed(index, store, "rec-slow", "w1", W)
    await _seed(index, store, "rec-slow", "w2", W)
    handles = _Handles(
        {
            "w1": [{"task_id": "p1", "partner_id": "hang"}],
            "w2": [{"task_id": "p2", "partner_id": "ok"}],
        }
    )
    started = []

    async def cancel(h):
        started.append(h["task_id"])
        if h["partner_id"] == "hang":
            await asyncio.Event().wait()

    async with asyncio.timeout(2):
        report = await recover_on_startup(
            index, {"rec-slow": store}, {}, handles, cancel, cancel_timeout_s=0.1
        )
    assert sorted(started) == ["p1", "p2"]
    assert report.outbound_cancelled == 1
    assert report.cancel_errors == ["w1:hang"]
    assert sorted(report.failed) == ["w1", "w2"]


async def test_delete_removes_only_that_row(index):
    await index.upsert("t1", "a1", "key:x", "c", S, "o1")
    await index.upsert("t2", "a1", "key:x", "c", S, "o1")
    await index.delete("t1")
    await index.delete("missing")  # deleting an unknown id is a no-op
    rows, _ = await index.list(agent_id="a1")
    assert [r["task_id"] for r in rows] == ["t2"]


async def test_file_sqlite_engine_uses_wal_and_busy_timeout(tmp_path):
    """Finding 6: concurrent readers and a writer must not fail with "database is locked"."""
    from sqlalchemy import text

    eng = await create_engine(f"sqlite+aiosqlite:///{tmp_path / 'wal.db'}")
    try:
        async with eng.connect() as conn:
            assert (await conn.execute(text("PRAGMA journal_mode"))).scalar() == "wal"
            assert (await conn.execute(text("PRAGMA busy_timeout"))).scalar() == 5000
    finally:
        await eng.dispose()


async def test_in_memory_sqlite_engine_skips_pragmas():
    from sqlalchemy import text

    eng = await create_engine("sqlite+aiosqlite:///:memory:")
    try:
        async with eng.connect() as conn:
            assert (await conn.execute(text("PRAGMA journal_mode"))).scalar() == "memory"
    finally:
        await eng.dispose()


# -- inbound message ledger (spec 8.5) ----------------------------------------------------


async def test_message_ledger_reserve_fill_and_duplicate(engine):
    from a2agw.serve.store import MessageKey, MessageLedger

    ledger = MessageLedger(engine)
    await ledger.initialize()
    key = MessageKey("alpha", "", "key:a", "m1")
    assert await ledger.reserve(key) is None  # first send owns it
    dup = await ledger.reserve(key)
    assert dup is not None and dup["task_id"] is None  # still being set up
    await ledger.fill(key, "t1")
    assert (await ledger.reserve(key))["task_id"] == "t1"
    # The same id for a different request takes the key over; the old send can no longer
    # fill it.
    assert await ledger.reserve(key, fingerprint="other") is None
    await ledger.fill(key, "t-old", fingerprint="")
    assert (await ledger.get(key))["task_id"] is None
    await ledger.fill(key, "t2", fingerprint="other")
    assert (await ledger.reserve(key, fingerprint="other"))["task_id"] == "t2"
    # Another owner, tenant or agent is a different key.
    for other in (
        MessageKey("alpha", "", "key:b", "m1"),
        MessageKey("alpha", "acme", "key:a", "m1"),
        MessageKey("beta", "", "key:a", "m1"),
    ):
        assert await ledger.reserve(other) is None


async def test_message_ledger_retention_and_purge(engine):
    import time

    from a2agw.serve.store import RESERVATION_STALE_S, MessageKey, MessageLedger

    ledger = MessageLedger(engine, retention_s=100)
    await ledger.initialize()
    key = MessageKey("alpha", "", "anonymous", "m1")
    now = time.time()
    assert await ledger.reserve(key, now) is None
    await ledger.fill(key, "t1")
    assert (await ledger.reserve(key, now + 99))["task_id"] == "t1"
    assert await ledger.reserve(key, now + 101) is None  # expired: a new message again
    # A reservation that never got a task (crashed send) is taken over.
    stale = MessageKey("alpha", "", "anonymous", "m2")
    assert await ledger.reserve(stale, now) is None
    assert await ledger.reserve(stale, now + RESERVATION_STALE_S + 1) is None
    assert await ledger.purge(now + 1000) == 2
    assert await ledger.get(key) is None
