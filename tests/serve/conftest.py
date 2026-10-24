"""Shared fixtures: an in-process A2A server around AdapterExecutor, driven by the SDK client."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx
import pytest
from a2a.client import Client, ClientConfig, ClientFactory
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore
from starlette.applications import Starlette

from a2agw.ops.bus import EventBus
from a2agw.serve.agent import AgentSpec, SkillSpec, build_card
from a2agw.serve.executor import AdapterExecutor
from a2agw.serve.store import TaskIndex, create_engine


@dataclass
class Harness:
    executor: AdapterExecutor
    index: TaskIndex
    bus: EventBus
    spec: AgentSpec
    hc: httpx.AsyncClient
    card: Any

    def client(self, *, streaming: bool) -> Client:
        config = ClientConfig(httpx_client=self.hc, streaming=streaming)
        return ClientFactory(config).create(self.card)


@pytest.fixture
async def make_server(tmp_path):
    engine = await create_engine(f"sqlite+aiosqlite:///{tmp_path / 'idx.db'}")
    index = TaskIndex(engine)
    await index.initialize()
    cleanup: list[Any] = []

    async def _make(adapter, *, context_builder=None, **spec_kwargs) -> Harness:
        spec = AgentSpec(
            id=spec_kwargs.pop("id", "echo"),
            name="Echo",
            description="Test agent",
            skills=[SkillSpec(id="echo", name="Echo", description="Echoes")],
            adapter=adapter,
            **spec_kwargs,
        )
        bus = EventBus()
        executor = AdapterExecutor(spec, index, bus)
        card = build_card(spec, "http://t", security=None)
        handler = DefaultRequestHandler(
            agent_executor=executor, task_store=InMemoryTaskStore(), agent_card=card
        )
        app = Starlette(
            routes=create_agent_card_routes(card)
            + create_jsonrpc_routes(
                handler, rpc_url=f"/agents/{spec.id}/", context_builder=context_builder
            )
        )
        hc = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")
        cleanup.append((handler, hc))
        return Harness(executor, index, bus, spec, hc, card)

    yield _make
    for handler, hc in cleanup:
        await handler.aclose()
        await hc.aclose()
    await engine.dispose()
