import pytest
from a2a.server.context import ServerCallContext
from a2a.types import Role, Task, TaskState, TaskStatus

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
async def engine(tmp_path):
    eng = await create_engine(f"sqlite+aiosqlite:///{tmp_path / 't.db'}")
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
