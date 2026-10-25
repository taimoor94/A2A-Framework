"""Pinned: an SDK stream may be driven from several tasks, over real sockets.

``PartnerClient`` awaits a partner stream's first event in a helper task (so an interrupted
send can still be cleaned up), reads the rest in the calling task, and may close it from yet
another task (cancellation cleanup). httpx/anyio scopes entered in one task and exited in
another fail loudly, so an a2a-sdk or httpx upgrade that ties a stream to the task that
opened it breaks this test first.
"""

from __future__ import annotations

import asyncio
import socket
import uuid

import pytest
import uvicorn
from a2a.client import ClientConfig, ClientFactory
from a2a.types import Message, Part, Role, SendMessageRequest

from a2agw.consult.guarded_net import fixed_tier, guarded_async_client
from a2agw.core.events import ArtifactChunk, Done, Status
from a2agw.serve.agent import AgentSpec, SkillSpec
from a2agw.serve.host import AgentHost


class Ticker:
    """Streams a status and three chunks, then waits for ``gate`` before finishing."""

    durable_sessions = False

    def __init__(self) -> None:
        self.gate = asyncio.Event()

    async def run(self, ctx):
        yield Status("working")
        for i in range(3):
            yield ArtifactChunk([Part(text=f"chunk{i}")])
            await asyncio.sleep(0.01)
        await self.gate.wait()
        yield Done(text="done")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
async def served(tmp_path):
    port = _free_port()
    ticker = Ticker()
    host = AgentHost(f"http://127.0.0.1:{port}", db_url=f"sqlite+aiosqlite:///{tmp_path}/a.db")
    host.add(
        AgentSpec(
            id="tick",
            name="Tick",
            description="streams",
            skills=[SkillSpec(id="s", name="S", description="d")],
            adapter=ticker,
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
    yield host, ticker
    ticker.gate.set()
    server.should_exit = True
    await asyncio.wait_for(task, 10)


async def test_stream_cross_task_affinity(served):
    host, ticker = served
    async with guarded_async_client(fixed_tier("internal"), timeout=10) as hc:
        client = ClientFactory(ClientConfig(httpx_client=hc, streaming=True)).create(
            host.cards["tick"]
        )
        msg = Message(message_id=uuid.uuid4().hex, role=Role.ROLE_USER, parts=[Part(text="go")])
        agen = client.send_message(SendMessageRequest(message=msg))

        # 1. The first event, read in a helper task (as PartnerClient._drive does).
        first = await asyncio.create_task(agen.__anext__())
        assert first.HasField("task") or first.HasField("status_update")

        # 2. The rest, read in this (the calling) task, while the agent is still running.
        texts: list[str] = []
        async with asyncio.timeout(5):
            async for ev in agen:
                if ev.HasField("artifact_update"):
                    texts += [p.text for p in ev.artifact_update.artifact.parts]
                if len(texts) == 3:
                    break
        assert texts == ["chunk0", "chunk1", "chunk2"]

        # 3. Closed from a third task while the server is still streaming.
        await asyncio.wait_for(asyncio.create_task(agen.aclose()), 5)
        assert not ticker.gate.is_set()  # the agent was still running: closed mid-stream

        # The connection pool is still usable afterwards.
        r = await hc.get(f"{host.base_url}/agents/tick/.well-known/agent-card.json")
        assert r.status_code == 200
