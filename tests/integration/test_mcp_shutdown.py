"""A gateway with an open MCP session (its standalone notification stream never ends by
itself) shuts down promptly and cleanly: on an exit signal, and on ``end_streams`` before a
programmatic stop."""

from __future__ import annotations

import asyncio
import logging
import signal
import socket
import time

import httpx2
import pytest
import uvicorn
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from sse_starlette.sse import AppStatus

from a2agw.core.events import Done
from a2agw.serve.agent import AgentSpec, SkillSpec
from a2agw.serve.host import AgentHost

GRACEFUL_S = 8.0


class Echo:
    durable_sessions = False

    async def run(self, ctx):
        yield Done(text="x")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _until(predicate, timeout: float = 5.0) -> None:
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(0.02)


@pytest.fixture
async def gateway(tmp_path):
    """A served host with an open MCP session whose notification stream is connected."""
    port = _free_port()
    host = AgentHost(
        f"http://127.0.0.1:{port}",
        db_url=f"sqlite+aiosqlite:///{tmp_path}/g.db",
        mcp_agents=["a"],
    )
    host.add(
        AgentSpec(
            id="a",
            name="A",
            description="d",
            skills=[SkillSpec(id="s", name="S", description="d")],
            adapter=Echo(),
        )
    )
    config = uvicorn.Config(
        host.app(),
        host="127.0.0.1",
        port=port,
        log_level="error",
        timeout_graceful_shutdown=GRACEFUL_S,
    )
    server = uvicorn.Server(config)
    # uvicorn re-raises a captured exit signal once it stops: keep that from ending pytest.
    previous = signal.signal(signal.SIGTERM, lambda sig, frame: None)
    served = asyncio.create_task(server.serve())
    await _until(lambda: server.started)
    token = host.consult_tokens.issue("a", "T1", None, None).token
    done = asyncio.Event()

    async def client() -> None:
        headers = {"Authorization": f"Bearer {token}"}
        async with (
            httpx2.AsyncClient(headers=headers) as hc,
            streamable_http_client(f"http://127.0.0.1:{port}/a2agw/mcp/a", http_client=hc) as (
                read,
                write,
            ),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            await session.list_tools()
            await done.wait()

    session = asyncio.create_task(client())
    # The standalone GET stream is open once the session has a request in flight at rest.
    await _until(lambda: any(s.active for s in host._mcp._sessions.values()))
    try:
        yield host, server, served
    finally:
        done.set()
        session.cancel()
        await asyncio.gather(session, return_exceptions=True)
        if not served.done():
            server.should_exit = True
            await asyncio.wait_for(served, 30)
        signal.signal(signal.SIGTERM, previous)
        # sse_starlette records an exit signal process-wide (it patches uvicorn's
        # handle_exit): reset it, or every later SSE response ends at once.
        AppStatus.should_exit = False


def _errors(caplog) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name.startswith(("uvicorn", "a2agw", "mcp.server"))
        and (r.levelno >= logging.ERROR or r.exc_info)
    ]


async def test_exit_signal_ends_open_sessions(gateway, caplog):
    _host, _server, served = gateway
    caplog.set_level(logging.WARNING)
    start = time.monotonic()
    signal.raise_signal(signal.SIGTERM)
    await asyncio.wait_for(served, 30)
    assert time.monotonic() - start < GRACEFUL_S / 4
    assert _errors(caplog) == []


async def test_end_streams_before_programmatic_stop(gateway, caplog):
    host, server, served = gateway
    caplog.set_level(logging.WARNING)
    start = time.monotonic()
    await host.end_streams()
    server.should_exit = True
    await asyncio.wait_for(served, 30)
    assert time.monotonic() - start < GRACEFUL_S / 4
    assert _errors(caplog) == []
