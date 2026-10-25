"""Keeps the A2A TCK system under test (examples/tck_sut) working without running the TCK."""

from __future__ import annotations

import uuid

import httpx
from a2a.client import ClientConfig, ClientFactory
from a2a.types import Message, Part, Role, SendMessageRequest, TaskState

from examples.tck_sut.sut_agent import build_host


async def _send(client, prefix: str):
    msg = Message(
        message_id=f"{prefix}-{uuid.uuid4().hex}", role=Role.ROLE_USER, parts=[Part(text="hi")]
    )
    return [ev async for ev in client.send_message(SendMessageRequest(message=msg))]


async def test_sut_completes_and_replies_in_process(tmp_path):
    host = build_host("http://t", db_url=f"sqlite+aiosqlite:///{tmp_path / 'tck.db'}")
    await host.startup()
    hc = httpx.AsyncClient(transport=httpx.ASGITransport(app=host.app()), base_url="http://t")
    try:
        card = (await hc.get("/.well-known/agent-card.json")).json()
        assert card["supportedInterfaces"][0]["url"] == "http://t/agents/tck/"
        client = ClientFactory(ClientConfig(httpx_client=hc, streaming=False)).create(
            host.cards["tck"]
        )

        [ev] = await _send(client, "tck-complete-task")
        assert ev.task.status.state == TaskState.TASK_STATE_COMPLETED
        assert [p.text for a in ev.task.artifacts for p in a.parts] == ["Hello from TCK"]

        [ev] = await _send(client, "tck-message-response")
        assert ev.WhichOneof("payload") == "message"
        assert [p.text for p in ev.message.parts] == ["Direct message response"]
    finally:
        await hc.aclose()
        await host.shutdown()
