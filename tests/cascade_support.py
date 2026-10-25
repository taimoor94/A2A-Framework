"""Shared two-agents-on-one-host wiring (used by the cascade and telemetry tests)."""

from __future__ import annotations

import uuid
from typing import Any

import httpx
from a2a.client import ClientConfig, ClientFactory
from a2a.types import Message, Part, Role, SendMessageConfiguration, SendMessageRequest
from google.protobuf.json_format import MessageToDict
from streaming_asgi import StreamingASGITransport

from a2agw.serve.agent import AgentSpec, SkillSpec
from a2agw.serve.host import AgentHost


class Fn:
    """Adapter whose behaviour is a test-supplied async generator function of the context."""

    durable_sessions = False

    def __init__(self, fn) -> None:
        self.fn = fn

    def run(self, ctx):
        return self.fn(ctx)


def spec(agent_id: str, adapter, **kw) -> AgentSpec:
    return AgentSpec(
        id=agent_id,
        name=agent_id.title(),
        description=f"Test agent {agent_id}",
        skills=[SkillSpec(id="s", name="S", description="d")],
        adapter=adapter,
        **kw,
    )


def msg(text: str) -> Message:
    return Message(message_id=uuid.uuid4().hex, role=Role.ROLE_USER, parts=[Part(text=text)])


class Env:
    def __init__(self, host: AgentHost, partner_hc: httpx.AsyncClient):
        self.host = host
        self.partner_hc = partner_hc  # the host's outbound client
        self.hc = httpx.AsyncClient(  # inbound callers of this host
            transport=StreamingASGITransport({"t": host.app()}), base_url="http://t"
        )

    def client(self, agent_id: str, *, streaming: bool = False):
        card = self.host.cards[agent_id]
        return ClientFactory(ClientConfig(httpx_client=self.hc, streaming=streaming)).create(card)

    async def register(self, *ids: str) -> None:
        for i in ids:
            await self.host.partners.add_from_card(i, MessageToDict(self.host.cards[i]), "internal")

    async def send(self, agent_id: str, text: str, **config: Any):
        req = SendMessageRequest(message=msg(text))
        if config:
            req.configuration.CopyFrom(SendMessageConfiguration(**config))
        return [ev async for ev in self.client(agent_id).send_message(req)]
