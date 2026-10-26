"""An external webhook agent served by AgentHost: A2A in, ``a2agw.invoke/1`` out."""

from __future__ import annotations

import asyncio
import json
import uuid

import httpx
import pytest
from a2a.client import ClientConfig, ClientFactory
from a2a.types import (
    CancelTaskRequest,
    GetTaskRequest,
    Message,
    Part,
    Role,
    SendMessageConfiguration,
    SendMessageRequest,
    TaskState,
)
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response, StreamingResponse
from starlette.routing import Route
from streaming_asgi import StreamingASGITransport

from a2agw.adapters.webhook import WebhookAdapter
from a2agw.gateway.protocol import PROTOCOL, sign
from a2agw.serve.agent import AgentSpec, SkillSpec
from a2agw.serve.host import AgentHost

NDJSON = "application/x-ndjson"


class WebhookAgent:
    """A fake external agent: echoes the text, or streams a status and then blocks."""

    def __init__(self) -> None:
        self.invokes: list[dict] = []
        self.signatures_ok: list[bool] = []
        self.started = asyncio.Event()
        self.gone = asyncio.Event()

        async def invoke(request: Request) -> Response:
            body = await request.body()
            ts = request.headers["x-a2agw-timestamp"]
            self.signatures_ok.append(request.headers["x-a2agw-signature"] == sign("k", ts, body))
            inv = json.loads(body)
            self.invokes.append(inv)
            if inv["text"] == "block":
                return StreamingResponse(self._block(), media_type=NDJSON)
            lines = [
                {"type": "status", "text": "on it"},
                {"type": "done", "text": f"agent says: {inv['text']}"},
            ]
            return Response("".join(json.dumps(x) + "\n" for x in lines), media_type=NDJSON)

        self.app = Starlette(routes=[Route("/a2agw/invoke", invoke, methods=["POST"])])

    async def _block(self):
        try:
            yield b'{"type":"status","text":"working"}\n'
            self.started.set()
            await asyncio.Event().wait()
        finally:
            self.gone.set()


@pytest.fixture
async def env(tmp_path):
    fake = WebhookAgent()
    agent_http = httpx.AsyncClient(transport=StreamingASGITransport({"coder": fake.app}))
    host = AgentHost("http://gw", db_url=f"sqlite+aiosqlite:///{tmp_path / 'gw.db'}")
    host.add(
        AgentSpec(
            id="coder",
            name="Coder",
            description="An external agent",
            skills=[SkillSpec(id="code", name="Code", description="Writes code")],
            adapter=WebhookAdapter("http://coder/a2agw/invoke", secret="k", http=agent_http),
        )
    )
    await host.startup()
    a2a_http = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=host.app()), base_url="http://gw"
    )
    client = ClientFactory(ClientConfig(httpx_client=a2a_http, streaming=False)).create(
        host.cards["coder"]
    )
    try:
        yield fake, client
    finally:
        await a2a_http.aclose()
        await host.shutdown()
        await agent_http.aclose()


def msg(text: str) -> Message:
    return Message(message_id=uuid.uuid4().hex, role=Role.ROLE_USER, parts=[Part(text=text)])


async def send(client, text: str, **config):
    req = SendMessageRequest(message=msg(text))
    if config:
        req.configuration.CopyFrom(SendMessageConfiguration(**config))
    return [ev async for ev in client.send_message(req)]


async def test_a2a_call_reaches_webhook_agent(env):
    fake, client = env
    [ev] = await send(client, "write fizzbuzz")
    task = ev.task
    assert task.status.state == TaskState.TASK_STATE_COMPLETED
    [artifact] = task.artifacts
    assert [p.text for p in artifact.parts] == ["agent says: write fizzbuzz"]
    [inv] = fake.invokes
    assert inv["protocol"] == PROTOCOL and inv["agent_id"] == "coder"
    assert inv["task_id"] == task.id and inv["context_id"] == task.context_id
    assert inv["caller"] == {"id": "anonymous", "kind": "anonymous"}
    assert fake.signatures_ok == [True]


async def test_a2a_cancel_closes_webhook_stream(env):
    fake, client = env
    [ev] = await send(client, "block", return_immediately=True)
    task_id = ev.task.id
    await asyncio.wait_for(fake.started.wait(), 2.0)
    assert not fake.gone.is_set()
    cancelled = await client.cancel_task(CancelTaskRequest(id=task_id))
    assert cancelled.status.state == TaskState.TASK_STATE_CANCELED
    await asyncio.wait_for(fake.gone.wait(), 2.0)  # the agent saw the connection close
    task = await client.get_task(GetTaskRequest(id=task_id))
    assert task.status.state == TaskState.TASK_STATE_CANCELED
