"""I1: TTL expiry is scoped to the gateway, retries failed cancels, and runs them bounded.

``AgentHost.maintain`` only expires handles whose partner its registry knows and whose
inbound task belongs to one of its agents; a failed partner cancel is retried (at most
``CANCEL_MAX_ATTEMPTS`` in all); cancels run concurrently (``CANCEL_CONCURRENCY``) within a
pass deadline.
"""

from __future__ import annotations

import asyncio
import time

import pytest
from sqlalchemy import text

from a2agw.consult.handles import OutboundHandleStore
from a2agw.ops.audit import AuditLog
from a2agw.serve import reap as reap_mod
from a2agw.serve.agent import AgentSpec, SkillSpec
from a2agw.serve.host import AgentHost
from a2agw.serve.reap import CANCEL_FAILED_REASON, TTL_REASON, expire_outbound
from a2agw.serve.store import TaskIndex, create_engine

W = "TASK_STATE_WORKING"
CANCELED = "TASK_STATE_CANCELED"
FAR = time.time() + 10 * 86400

CARD = {
    "name": "P",
    "description": "d",
    "version": "1",
    "supportedInterfaces": [
        {"url": "https://1.1.1.1/rpc", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
    ],
    "capabilities": {},
    "defaultInputModes": ["text/plain"],
    "defaultOutputModes": ["text/plain"],
    "skills": [{"id": "s", "name": "s", "description": "d", "tags": []}],
}


class Echo:
    durable_sessions = False

    async def run(self, ctx):  # pragma: no cover - never called here
        if False:
            yield None


def spec(agent_id: str) -> AgentSpec:
    return AgentSpec(
        id=agent_id,
        name=agent_id,
        description="d",
        skills=[SkillSpec(id="s", name="s", description="d")],
        adapter=Echo(),
    )


async def _host(db_url: str, agent: str, partner: str) -> tuple[AgentHost, list[dict]]:
    host = AgentHost("http://localhost", db_url=db_url)
    host.add(spec(agent))
    await host.partners.add_from_card(partner, CARD, "public")
    await host.startup()
    calls: list[dict] = []

    async def cancel(handle):
        calls.append(handle)

    host._cancel_outbound = cancel  # type: ignore[method-assign]
    return host, calls


async def test_gateways_sharing_a_database_only_expire_their_own_handles(db_url):
    a, a_calls = await _host(db_url, "alpha", "pa")
    try:
        b, b_calls = await _host(db_url, "beta", "pb")
        try:
            idx = a.index
            await idx.upsert("in-a", "alpha", "key:x", "c", W, "o")
            await idx.upsert("in-b", "beta", "key:x", "c", W, "o")
            h = a.handles
            await h.record("ha", "pa", "c", "in-a", "o", W)  # A's partner, A's task
            await h.record("hb", "pb", "c", "in-b", "o", W)  # B's partner, B's task
            await h.record("hx", "zz", "c", "in-a", "o", W)  # unknown partner
            await h.record("hy", "pa", "c", "in-b", "o", W)  # A's partner, B's task
            await h.record("hz", "pa", "c", None, "o", W)  # no inbound task
            report = await a.maintain(now=FAR)
            assert [c["task_id"] for c in a_calls] == ["ha"]
            assert report.expired == 1
            for tid, pid in (("hb", "pb"), ("hx", "zz"), ("hy", "pa"), ("hz", "pa")):
                row = await h.get(pid, tid)
                assert (row["state"], row["end_reason"]) == (W, None), tid
            await b.maintain(now=FAR)
            assert [c["task_id"] for c in b_calls] == ["hb"]
            assert (await h.get("pa", "hy"))["state"] == W  # B does not know partner "pa"
        finally:
            await b.shutdown()
    finally:
        await a.shutdown()


@pytest.fixture
async def store(db_url):
    eng = await create_engine(db_url)
    handles = OutboundHandleStore(eng)
    await handles.initialize()
    index = TaskIndex(eng)
    await index.initialize()
    audit = AuditLog(eng)
    await audit.initialize()
    yield eng, handles, audit
    await eng.dispose()


async def _old(eng, handles, *ids: str, partner: str = "p") -> None:
    for tid in ids:
        await handles.record(tid, partner, "c", "in-1", "o", W)
    async with eng.begin() as conn:
        await conn.execute(text("UPDATE a2agw_outbound SET created_at = created_at - 172800"))


async def _rows(audit):
    await audit.drain()
    rows, _ = await audit.query({"action": "outbound.expire"}, 50, None, ascending=True)
    return [(r["task_id"], r["outcome"], r["detail"].get("attempt")) for r in rows]


async def test_failed_cancel_is_retried_until_it_succeeds(store):
    eng, handles, audit = store
    await _old(eng, handles, "t1")
    attempts: list[str] = []

    async def flaky(h):
        attempts.append(h["task_id"])
        if len(attempts) == 1:
            raise RuntimeError("partner down")

    r1 = await expire_outbound(handles, flaky, audit, ttl_s=86400)
    assert (r1.expired, r1.cancel_failed) == (1, 1)
    row = await handles.get("p", "t1")
    assert (row["state"], row["end_reason"], row["cancel_attempts"]) == (
        CANCELED,
        CANCEL_FAILED_REASON,
        1,
    )
    r2 = await expire_outbound(handles, flaky, audit, ttl_s=86400)
    assert (r2.expired, r2.cancel_failed) == (1, 0)
    row = await handles.get("p", "t1")
    assert (row["end_reason"], row["cancel_attempts"]) == (TTL_REASON, 2)
    assert await _rows(audit) == [("t1", "cancel_failed", 1), ("t1", "canceled", 2)]
    # Done: never selected again.
    assert (await expire_outbound(handles, flaky, audit, ttl_s=86400)).expired == 0
    assert attempts == ["t1", "t1"]


async def test_cancel_attempts_are_capped(store):
    eng, handles, audit = store
    await _old(eng, handles, "t1")
    calls: list[str] = []

    async def down(h):
        calls.append(h["task_id"])
        raise RuntimeError("partner down")

    for _ in range(5):
        await expire_outbound(handles, down, audit, ttl_s=86400)
    assert len(calls) == reap_mod.CANCEL_MAX_ATTEMPTS == 3
    row = await handles.get("p", "t1")
    assert (row["end_reason"], row["cancel_attempts"]) == (CANCEL_FAILED_REASON, 3)
    assert [r[2] for r in await _rows(audit)] == [1, 2, 3]


async def test_cancels_run_concurrently_and_bounded(store):
    eng, handles, _audit = store
    ids = [f"t{i:02d}" for i in range(20)]
    await _old(eng, handles, *ids)
    running = peak = 0

    async def slow(h):
        nonlocal running, peak
        running += 1
        peak = max(peak, running)
        await asyncio.sleep(0.05)
        running -= 1

    started = time.monotonic()
    report = await expire_outbound(handles, slow, None, ttl_s=86400)
    assert report.expired == 20
    assert peak == reap_mod.CANCEL_CONCURRENCY == 8
    assert time.monotonic() - started < 20 * 0.05  # not sequential


async def test_pass_deadline_leaves_unstarted_handles_for_the_next_pass(store):
    eng, handles, _audit = store
    ids = [f"t{i:02d}" for i in range(12)]
    await _old(eng, handles, *ids)

    async def slow(h):
        await asyncio.sleep(0.3)

    report = await expire_outbound(handles, slow, None, ttl_s=86400, pass_deadline_s=0.1)
    assert report.expired == 8  # the first wave was claimed; the rest was not started
    left = [tid for tid in ids if (await handles.get("p", tid))["state"] == W]
    assert len(left) == 4
    # The timed-out cancels count as failed attempts and stay eligible.
    assert report.cancel_failed == 8
    again = await expire_outbound(handles, None, None, ttl_s=86400)
    assert again.expired == 12


@pytest.mark.parametrize("phase", [1, 2])
async def test_older_databases_gain_the_attempts_column(db_url, phase):
    eng = await create_engine(db_url)
    try:
        extra = ", caller_id VARCHAR, end_reason VARCHAR" if phase == 2 else ""
        async with eng.begin() as conn:
            await conn.exec_driver_sql(
                "CREATE TABLE a2agw_outbound (partner_id VARCHAR NOT NULL, task_id VARCHAR NOT "
                "NULL, context_id VARCHAR, inbound_task_id VARCHAR, origin VARCHAR, state "
                f"VARCHAR NOT NULL, created_at FLOAT NOT NULL{extra}, "
                "PRIMARY KEY (partner_id, task_id))"
            )
            await conn.exec_driver_sql(
                "INSERT INTO a2agw_outbound (partner_id, task_id, inbound_task_id, state, "
                "created_at) VALUES ('p', 'old', 'in-1', 'TASK_STATE_WORKING', 1.0)"
            )
        stores = [OutboundHandleStore(eng) for _ in range(3)]
        await asyncio.gather(*(s.initialize() for s in stores))
        assert (await stores[0].get("p", "old"))["cancel_attempts"] == 0

        async def down(h):
            raise RuntimeError("partner down")

        report = await expire_outbound(stores[0], down, None, ttl_s=60)
        assert (report.expired, report.cancel_failed) == (1, 1)
        assert (await stores[1].get("p", "old"))["cancel_attempts"] == 1
    finally:
        await eng.dispose()
