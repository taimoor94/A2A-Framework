"""Outbound TTL (spec 8.2): ``expire_outbound`` ends handles left open too long, once."""

from __future__ import annotations

import asyncio
import time

import pytest
from sqlalchemy import text

from a2agw.consult.handles import OutboundHandleStore
from a2agw.ops.audit import AuditLog
from a2agw.serve.reap import TTL_REASON, expire_outbound
from a2agw.serve.store import create_engine

W = "TASK_STATE_WORKING"
CANCELED = "TASK_STATE_CANCELED"
COMPLETED = "TASK_STATE_COMPLETED"


@pytest.fixture
async def env(db_url):
    eng = await create_engine(db_url)
    handles = OutboundHandleStore(eng)
    await handles.initialize()
    audit = AuditLog(eng)
    await audit.initialize()
    yield eng, handles, audit
    await eng.dispose()


async def _seed(eng, handles: OutboundHandleStore) -> None:
    await handles.record("old", "p", "c1", "in-1", "o", W, caller_id="key:a")
    await handles.record("done", "p", "c2", "in-1", "o", COMPLETED)
    await handles.record("young", "p", "c3", "in-2", "o", W)
    async with eng.begin() as conn:  # "old" and "done" were created two days ago
        await conn.execute(
            text(
                "UPDATE a2agw_outbound SET created_at = created_at - 172800 "
                "WHERE task_id IN ('old', 'done')"
            )
        )


async def _expire_rows(audit: AuditLog):
    await audit.drain()
    rows, _ = await audit.query({"action": "outbound.expire"}, 50, None, ascending=True)
    return [(r["partner_id"], r["task_id"], r["outcome"], r["detail"]) for r in rows]


async def test_ttl_expiry_cancels_partner_and_marks_handle(env):
    eng, handles, audit = env
    await _seed(eng, handles)
    cancelled: list[dict] = []

    async def cancel(h):
        cancelled.append(h)

    report = await expire_outbound(handles, cancel, audit, ttl_s=86400)
    assert (report.expired, report.cancel_failed) == (1, 0)
    assert [(h["task_id"], h["caller_id"]) for h in cancelled] == [("old", "key:a")]
    old = await handles.get("p", "old")
    assert old["state"] == CANCELED and old["end_reason"] == TTL_REASON
    # Already terminal, or younger than the TTL: untouched.
    done, young = await handles.get("p", "done"), await handles.get("p", "young")
    assert (done["state"], done["end_reason"]) == (COMPLETED, None)
    assert (young["state"], young["end_reason"]) == (W, None)
    assert await _expire_rows(audit) == [("p", "old", "canceled", {"reason": TTL_REASON})]
    # A second pass finds nothing left to do.
    assert (await expire_outbound(handles, cancel, audit, ttl_s=86400)).expired == 0
    assert len(cancelled) == 1


async def test_failed_partner_cancel_still_ends_handle_and_is_audited(env):
    eng, handles, audit = env
    await _seed(eng, handles)

    async def cancel(h):
        raise RuntimeError("partner unreachable")

    report = await expire_outbound(handles, cancel, audit, ttl_s=86400)
    assert (report.expired, report.cancel_failed) == (1, 1)
    assert (await handles.get("p", "old"))["state"] == CANCELED
    assert [r[2] for r in await _expire_rows(audit)] == ["cancel_failed"]


async def test_gateways_sharing_a_database_expire_a_handle_once(env, db_url):
    eng, handles, audit = env
    await _seed(eng, handles)
    other_eng = await create_engine(db_url)  # a second gateway on the same database
    try:
        other = OutboundHandleStore(other_eng)
        calls: list[str] = []

        async def cancel(h):
            calls.append(h["task_id"])
            await asyncio.sleep(0.05)

        reports = await asyncio.gather(
            expire_outbound(handles, cancel, audit, ttl_s=86400),
            expire_outbound(other, cancel, None, ttl_s=86400),
        )
        assert sum(r.expired for r in reports) == 1 and calls == ["old"]
    finally:
        await other_eng.dispose()


async def test_ttl_is_measured_from_creation(env):
    _, handles, _ = env
    await handles.record("t1", "p", "c", "in", "o", W)
    calls: list[str] = []

    async def cancel(h):
        calls.append(h["task_id"])

    assert (await expire_outbound(handles, cancel, None, ttl_s=60)).expired == 0
    later = time.time() + 61
    assert (await expire_outbound(handles, cancel, None, ttl_s=60, now=later)).expired == 1
    assert calls == ["t1"]


async def test_partner_updates_never_reopen_an_ended_handle(env):
    eng, handles, audit = env
    await _seed(eng, handles)

    async def cancel(h):
        pass

    await expire_outbound(handles, cancel, audit, ttl_s=86400)
    # A late partner report (check, wait, a fresh consult response) does not overwrite it.
    await handles.update_state("p", "old", COMPLETED)
    await handles.record("old", "p", "c1", "in-1", "o", W)
    old = await handles.get("p", "old")
    assert (old["state"], old["end_reason"]) == (CANCELED, TTL_REASON)
    await handles.update_state("p", "young", COMPLETED)  # handles not ended still update
    assert (await handles.get("p", "young"))["state"] == COMPLETED
