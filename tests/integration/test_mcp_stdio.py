"""``a2agw mcp``: an MCP client spawns the gateway's stdio MCP server and consults a partner
served by a real (loopback) gateway."""

from __future__ import annotations

import asyncio
import socket
import sys
from pathlib import Path

import pytest
import uvicorn
from mcp import StdioServerParameters
from mcp.client.session import ClientSession
from mcp.client.stdio import stdio_client

from a2agw.core.events import Done
from a2agw.serve.agent import AgentSpec, SkillSpec
from a2agw.serve.host import AgentHost


class Echo:
    durable_sessions = False

    async def run(self, ctx):
        yield Done(text=f"echo: {ctx.text}")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
async def partner(tmp_path):
    """A gateway serving the agent ``researcher`` on a loopback port: its base URL."""
    port = _free_port()
    host = AgentHost(f"http://127.0.0.1:{port}", db_url=f"sqlite+aiosqlite:///{tmp_path}/p.db")
    host.add(
        AgentSpec(
            id="researcher",
            name="Researcher",
            description="Finds things",
            skills=[SkillSpec(id="find", name="Find", description="Finds things")],
            adapter=Echo(),
        )
    )
    server = uvicorn.Server(
        uvicorn.Config(host.app(), host="127.0.0.1", port=port, log_level="error")
    )
    task = asyncio.create_task(server.serve())
    for _ in range(500):
        if server.started:
            break
        await asyncio.sleep(0.01)
    assert server.started
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    await asyncio.wait_for(task, 10)


async def test_stdio_mcp_session_consults_partner(tmp_path, partner):
    config = tmp_path / "a2agw.yaml"
    config.write_text(
        "base_url: http://127.0.0.1:1\n"
        f"db_url: sqlite+aiosqlite:///{tmp_path / 'gw.db'}\n"
        f"partners_file: {tmp_path / 'partners.yaml'}\n"
        "partners:\n"
        f"  - {{id: researcher, url: '{partner}/agents/researcher', tier: internal}}\n"
        "sidecar:\n"
        "  mcp: {agents: [coder]}\n"
    )
    cli = Path(sys.executable).parent / "a2agw"
    params = StdioServerParameters(
        command=str(cli), args=["mcp", "-c", str(config), "--agent", "coder"], cwd=str(tmp_path)
    )
    async with (
        asyncio.timeout(60),
        stdio_client(params) as (read, write),
        ClientSession(read, write) as session,
    ):
        init = await session.initialize()
        assert init.server_info.name == "a2agw-coder"
        tools = {t.name for t in (await session.list_tools()).tools}
        assert tools == {"ask_researcher", "a2a_check_task", "a2a_cancel_task", "a2a_wait"}
        result = await session.call_tool("ask_researcher", {"message": "hi"})
    assert result.is_error is False
    body = result.structured_content
    assert (body["partner"], body["state"], body["text"]) == ("researcher", "completed", "echo: hi")
