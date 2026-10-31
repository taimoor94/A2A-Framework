"""The test harness itself: the in-process ASGI transport."""

from __future__ import annotations

import asyncio

import httpx
import pytest
from streaming_asgi import StreamingASGITransport


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
