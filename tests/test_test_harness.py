"""The test harness itself: the database-leak guard and the in-process ASGI transport."""

from __future__ import annotations

import asyncio

import db_leak_guard
import httpx
import pytest
from sqlalchemy import text
from streaming_asgi import StreamingASGITransport

from a2agw.serve.store import create_engine


async def test_guard_reports_an_engine_disposed_under_a_checked_out_connection(tmp_path, request):
    engine = await create_engine(f"sqlite+aiosqlite:///{tmp_path / 'g.db'}")
    conn = await engine.connect()
    try:
        await conn.execute(text("SELECT 1"))
        await engine.dispose()
        found = db_leak_guard._problems.pop(request.node.nodeid, [])
        assert len(found) == 1
        assert "disposed with 1 connection(s) still checked out" in found[0]
        assert "held by: task " in found[0]  # names the task holding it
    finally:
        # Returned now, it would sit in the disposed pool until the GC finds it: close it.
        await conn.invalidate()
        await conn.close()
        await engine.dispose()


async def test_guard_tracks_checkouts_until_checkin(tmp_path, request):
    engine = await create_engine(f"sqlite+aiosqlite:///{tmp_path / 'g.db'}")
    try:
        conn = await engine.connect()
        owners = [owner for _, owner, _ in db_leak_guard._open.values()]
        assert request.node.nodeid in owners
        await conn.close()
        owners = [owner for _, owner, _ in db_leak_guard._open.values()]
        assert request.node.nodeid not in owners
    finally:
        await engine.dispose()


def _app(gate: asyncio.Event, finished: list[str]):
    async def app(scope, receive, send):
        try:
            await gate.wait()
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})
            finished.append("done")
        except asyncio.CancelledError:
            finished.append("cancelled")
            raise

    return app


async def test_a_request_whose_client_gave_up_runs_on_until_it_ends():
    gate, finished = asyncio.Event(), []
    transport = StreamingASGITransport({"t": _app(gate, finished)})
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as hc:
        with pytest.raises(TimeoutError):
            async with asyncio.timeout(0.05):
                await hc.get("/")
        gate.set()
        for _ in range(100):
            if finished:
                break
            await asyncio.sleep(0.01)
        assert finished == ["done"]


async def test_stop_serving_ends_running_requests_and_refuses_new_ones():
    gate, finished = asyncio.Event(), []
    transport = StreamingASGITransport({"t": _app(gate, finished)})
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as hc:
        with pytest.raises(TimeoutError):
            async with asyncio.timeout(0.05):
                await hc.get("/")
        await transport.stop_serving()
        assert finished == ["cancelled"]  # ended and waited for, not left behind
        with pytest.raises(httpx.ConnectError):
            await hc.get("/")
