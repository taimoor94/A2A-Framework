"""PartnerClient end to end against real in-process AgentHost partners."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import re

import httpx
import pytest
import respx
from a2a.helpers import new_text_message
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentInterface,
    Part,
    Role,
    StreamResponse,
    Task,
    TaskState,
)
from google.protobuf.json_format import MessageToDict
from starlette.applications import Starlette
from streaming_asgi import StreamingASGITransport

from a2agw.consult import client as client_mod
from a2agw.consult import netguard
from a2agw.consult import results as results_mod
from a2agw.consult.client import PartnerClient, ToolResult
from a2agw.consult.credentials import ChainCredentials, StaticCredentials
from a2agw.consult.handles import OutboundHandleStore
from a2agw.consult.oauth import OAuthClientCredentials, OAuthTokenExchange
from a2agw.consult.registry import PartnerRegistry
from a2agw.consult.resilience import CircuitBreaker
from a2agw.context.call_context import EXTENSION_URI, CallContext, use_call, use_inbound
from a2agw.core.events import ArtifactChunk, Done, NeedInput, Status
from a2agw.ops.bus import EventBus
from a2agw.security.auth import ApiKeyEntry, AuthConfig
from a2agw.security.principal import Principal
from a2agw.serve.agent import AgentSpec, SkillSpec
from a2agw.serve.host import AgentHost
from a2agw.serve.store import create_engine


def rpc_methods(transport: StreamingASGITransport) -> list[str]:
    out = []
    for _, _, body in transport.requests:
        try:
            out.append(json.loads(body)["method"])
        except (ValueError, KeyError, TypeError):
            continue
    return out


# -- partner adapters -----------------------------------------------------------------


class Echo:
    durable_sessions = False

    async def run(self, ctx):
        yield Done(text=f"echo: {ctx.text}")


class Asker:
    durable_sessions = False

    async def run(self, ctx):
        if not ctx.resumed:
            yield NeedInput(question="which city?")
            return
        yield Done(text=f"weather in {ctx.text}: sunny")


class Gated:
    durable_sessions = False

    def __init__(self) -> None:
        self.gate = asyncio.Event()
        self.started = asyncio.Event()

    async def run(self, ctx):
        yield Status(text="thinking")
        self.started.set()
        await self.gate.wait()
        yield Done(text="finally")


class Recorder:
    durable_sessions = False

    def __init__(self) -> None:
        self.calls: list[CallContext | None] = []

    async def run(self, ctx):
        self.calls.append(ctx.call)
        yield Done(text="ok")


def spec(agent_id: str, adapter, **kw) -> AgentSpec:
    return AgentSpec(
        id=agent_id,
        name=agent_id.title(),
        description="Test partner",
        skills=[SkillSpec(id="s", name="S", description="d")],
        adapter=adapter,
        **kw,
    )


class DirectExecutor(AgentExecutor):
    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        await event_queue.enqueue_event(
            new_text_message("direct hello", context_id=context.context_id, role=Role.ROLE_AGENT)
        )

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        return None


def direct_app() -> tuple[Starlette, AgentCard, DefaultRequestHandler]:
    card = AgentCard(
        name="Direct",
        description="Replies with a message",
        version="1",
        supported_interfaces=[
            AgentInterface(url="http://d/", protocol_binding="JSONRPC", protocol_version="1.0")
        ],
        capabilities=AgentCapabilities(streaming=True),
        default_input_modes=["text/plain"],
        default_output_modes=["text/plain"],
    )
    handler = DefaultRequestHandler(
        agent_executor=DirectExecutor(), task_store=InMemoryTaskStore(), agent_card=card
    )
    app = Starlette(routes=create_agent_card_routes(card) + create_jsonrpc_routes(handler, "/"))
    return app, card, handler


# -- fixture --------------------------------------------------------------------------


class Env:
    def __init__(self, host, transport, hc, registry, handles, bus, client, engine):
        self.host = host
        self.transport = transport
        self.hc = hc
        self.registry = registry
        self.handles = handles
        self.bus = bus
        self.client = client
        self.engine = engine

    def card(self, agent_id: str) -> dict:
        return MessageToDict(self.host.cards[agent_id])


@pytest.fixture
async def env(tmp_path, monkeypatch):
    monkeypatch.setenv("A2AGW_DEV", "1")
    monkeypatch.setattr(client_mod, "POLL_MIN_S", 0.02)
    monkeypatch.setattr(client_mod, "POLL_MAX_S", 0.05)
    monkeypatch.setattr(client_mod, "WAIT_ANY_INTERVAL_S", 0.05)
    monkeypatch.setattr(client_mod, "RETRY_BASE_S", 0.001)
    monkeypatch.setattr(client_mod, "RETRY_CAP_S", 0.002)
    made: list[Env] = []

    async def _make(
        *specs: AgentSpec, register: bool = True, apps: dict | None = None, auth=None
    ) -> Env:
        host = AgentHost(
            "http://t", db_url=f"sqlite+aiosqlite:///{tmp_path / 'host.db'}", auth=auth
        )
        for s in specs:
            host.add(s)
        await host.startup()
        transport = StreamingASGITransport({"t": host.app(), **(apps or {})})
        hc = httpx.AsyncClient(transport=transport)
        registry = PartnerRegistry(http=hc)
        engine = await create_engine(f"sqlite+aiosqlite:///{tmp_path / 'out.db'}")
        handles = OutboundHandleStore(engine)
        await handles.initialize()
        bus = EventBus()
        client = PartnerClient(
            registry, credentials=None, handles=handles, bus=bus, http=hc, agent_id="me"
        )
        e = Env(host, transport, hc, registry, handles, bus, client, engine)
        if register:
            for s in specs:
                await registry.add_from_card(s.id, e.card(s.id), "internal")
        made.append(e)
        return e

    yield _make
    for e in made:
        await e.client.aclose()
        await e.hc.aclose()
        await e.host.shutdown()
        await e.engine.dispose()


# -- tests ----------------------------------------------------------------------------


@pytest.mark.parametrize("streaming", [True, False])
async def test_consult_completed_text(env, streaming):
    e = await env(spec("alpha", Echo(), streaming=streaming))
    res = await e.client.consult("alpha", "hello", wait_seconds=5)
    assert isinstance(res, ToolResult)
    assert res.state == "completed"
    assert res.text == "echo: hello"
    assert res.task_id and res.context_id
    assert res.artifacts[0]["parts"] == [{"kind": "text", "text": "echo: hello"}]
    rec = e.registry.get("alpha")
    assert res.provenance == {
        "partner": "alpha",
        "tier": "internal",
        "card_hash": rec.card_hash,
        "untrusted": True,
    }
    expected = "SendStreamingMessage" if streaming else "SendMessage"
    assert rpc_methods(e.transport)[0] == expected
    ev = e.bus.recent()[-1]
    assert ev.kind == "partner.call" and ev.agent_id == "me"
    assert set(ev.data) == {"partner_id", "task_id", "state", "duration_ms"}
    assert ev.data["partner_id"] == "alpha" and ev.data["state"] == "completed"
    rows = await e.handles.by_inbound("none")
    assert rows == []


async def test_service_parameters_sent(env):
    e = await env(spec("alpha", Echo()))
    seen: list[httpx.Headers] = []

    async def hook(request: httpx.Request) -> None:
        seen.append(request.headers)

    e.hc.event_hooks["request"].append(hook)
    res = await e.client.consult("alpha", "x", wait_seconds=5)
    assert res.state == "completed"
    assert seen[0]["A2A-Version"] == "1.0"
    assert EXTENSION_URI in seen[0]["A2A-Extensions"]


@pytest.mark.parametrize("streaming", [True, False])
async def test_consult_input_required_then_reply_same_task(env, streaming):
    e = await env(spec("asker", Asker(), streaming=streaming))
    first = await e.client.consult("asker", "weather?", wait_seconds=5)
    assert first.state == "input_required"
    assert first.question == "which city?"
    assert first.task_id
    second = await e.client.consult(
        "asker", "Paris", task_id=first.task_id, context_id=first.context_id, wait_seconds=5
    )
    assert second.state == "completed"
    assert second.task_id == first.task_id
    assert "weather in Paris: sunny" in second.text
    assert second.question is None


async def test_long_task_returns_working_handle_then_check_completes(env):
    gated = Gated()
    e = await env(spec("slow", gated))
    res = await e.client.consult("slow", "go", wait_seconds=0.3, inbound_task_id="in-1")
    assert res.state == "working"
    assert res.task_id
    rows = await e.handles.by_inbound("in-1")
    assert [(r["task_id"], r["partner_id"]) for r in rows] == [(res.task_id, "slow")]
    assert rows[0]["state"] == "TASK_STATE_WORKING"
    still = await e.client.check("slow", res.task_id)
    assert still.state == "working"
    gated.gate.set()
    [done] = await e.client.wait_any([("slow", res.task_id)], 5)
    assert done.state == "completed" and done.text == "finally"
    rows = await e.handles.by_inbound("in-1")
    assert rows[0]["state"] == "TASK_STATE_COMPLETED"


async def test_wait_any_returns_first_completed(env):
    a, b = Gated(), Gated()
    e = await env(spec("pa", a), spec("pb", b))
    ra = await e.client.consult("pa", "go", wait_seconds=0.2)
    rb = await e.client.consult("pb", "go", wait_seconds=0.2)
    assert ra.state == rb.state == "working"
    b.gate.set()
    results = await e.client.wait_any([("pa", ra.task_id), ("pb", rb.task_id)], 5)
    assert [r.partner for r in results] == ["pa", "pb"]
    assert results[0].state == "working"
    assert results[1].state == "completed"
    a.gate.set()


async def test_wait_any_times_out_with_current_results(env):
    a = Gated()
    e = await env(spec("pa", a))
    ra = await e.client.consult("pa", "go", wait_seconds=0.1)
    loop = asyncio.get_running_loop()
    t0 = loop.time()
    [r] = await e.client.wait_any([("pa", ra.task_id)], 0.3)
    assert r.state == "working"
    assert 0.25 <= loop.time() - t0 < 2
    a.gate.set()


async def test_direct_message_reply(env):
    app, card, handler = direct_app()
    e = await env(register=False, apps={"d": app})
    await e.registry.add_from_card("direct", MessageToDict(card), "internal")
    res = await e.client.consult("direct", "hi", wait_seconds=5)
    assert res.state == "completed"
    assert res.task_id is None
    assert res.text == "direct hello"
    await handler.aclose()


async def test_cancelled_consult_answered_by_direct_message_skips_lookup(env):
    """A cancelled call whose first response turns out to be a direct message has no partner
    task to cancel: the cleanup ends at once instead of polling the context."""
    app, card, handler = direct_app()

    async def slow(scope, receive, send):
        async def send_later(message):
            if message["type"] == "http.response.start" and scope["method"] == "POST":
                await asyncio.sleep(0.2)
            await send(message)

        await app(scope, receive, send_later)

    e = await env(register=False, apps={"d": slow})
    await e.registry.add_from_card("direct", MessageToDict(card), "internal")
    t = asyncio.create_task(e.client.consult("direct", "hi", wait_seconds=5))
    await asyncio.sleep(0.05)
    started = asyncio.get_running_loop().time()
    t.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await t
    assert asyncio.get_running_loop().time() - started < 1.0
    assert "ListTasks" not in rpc_methods(e.transport)
    await handler.aclose()


async def test_rest_only_partner(env):
    e = await env(spec("alpha", Echo()), register=False)
    card = e.card("alpha")
    card["supportedInterfaces"] = [
        i for i in card["supportedInterfaces"] if i["protocolBinding"] == "HTTP+JSON"
    ]
    await e.registry.add_from_card("alpha", card, "internal")
    res = await e.client.consult("alpha", "rest please", wait_seconds=5)
    assert res.state == "completed"
    assert res.text == "echo: rest please"
    assert all("/rest" in path for _, path, _ in e.transport.requests)


async def test_unsupported_binding_unavailable(env):
    e = await env(spec("alpha", Echo()), register=False)
    card = e.card("alpha")
    card["supportedInterfaces"] = [
        {"url": "http://t/grpc", "protocolBinding": "GRPC", "protocolVersion": "1.0"}
    ]
    await e.registry.add_from_card("alpha", card, "internal")
    res = await e.client.consult("alpha", "x", wait_seconds=5)
    assert res.state == "unavailable"
    assert res.reason == "no supported binding"
    assert e.transport.requests == []


async def test_call_context_propagates_hop(env):
    rec = Recorder()
    e = await env(spec("rec", rec))
    caller = CallContext.new("caller").child("caller")
    with use_call(caller):
        res = await e.client.consult("rec", "x", wait_seconds=5)
    assert res.state == "completed"
    seen = rec.calls[0]
    assert seen is not None
    assert seen.path[-2] == caller.path[-1]
    assert seen.path[-1] == "rec"
    assert seen.hop == caller.hop + 1
    assert seen.origin == caller.origin
    assert await e.handles.seen_origin(caller.origin)
    assert not await e.handles.seen_origin("nope")


async def test_no_current_call_starts_from_client_id(env):
    rec = Recorder()
    e = await env(spec("rec", rec))
    res = await e.client.consult("rec", "x", wait_seconds=5)
    assert res.state == "completed"
    seen = rec.calls[0]
    assert seen.path == ("me", "rec")
    assert seen.hop == 1


async def test_breaker_open_returns_unavailable(env):
    e = await env(spec("alpha", Echo()))

    class Refuse(httpx.AsyncBaseTransport):
        def __init__(self) -> None:
            self.calls = 0

        async def handle_async_request(self, request):
            self.calls += 1
            raise httpx.ConnectError("refused", request=request)

    refuse = Refuse()
    e.hc._transport = refuse
    for _ in range(5):
        res = await e.client.consult("alpha", "x", wait_seconds=5)
        assert res.state == "unavailable"
        assert res.reason == "partner unreachable"
    assert refuse.calls == 15  # three attempts each
    res = await e.client.consult("alpha", "x", wait_seconds=5)
    assert res.state == "unavailable" and res.reason == "circuit open"
    assert refuse.calls == 15


async def test_quarantined_partner_unavailable(env):
    e = await env(spec("alpha", Echo()))
    e.registry.get("alpha").status = "quarantined"
    res = await e.client.consult("alpha", "x", wait_seconds=5)
    assert res.state == "unavailable"
    assert res.reason == "partner quarantined"
    unknown = await e.client.consult("ghost", "x", wait_seconds=5)
    assert unknown.state == "unavailable" and unknown.reason == "unknown partner"
    assert e.transport.requests == []


async def test_cancel_for_inbound_cancels_partner_task(env):
    gated = Gated()
    e = await env(spec("slow", gated), spec("alpha", Echo()))
    res = await e.client.consult("slow", "go", wait_seconds=0.2, inbound_task_id="in-9")
    done = await e.client.consult("alpha", "x", wait_seconds=5, inbound_task_id="in-9")
    assert res.state == "working" and done.state == "completed"
    assert await e.client.cancel_for_inbound("in-9") == 1
    after = await e.client.check("slow", res.task_id)
    assert after.state == "canceled"
    rows = {r["task_id"]: r["state"] for r in await e.handles.by_inbound("in-9")}
    assert rows[res.task_id] == "TASK_STATE_CANCELED"
    assert await e.client.cancel_for_inbound("in-9") == 0


async def test_stream_drop_falls_back_to_subscribe(env):
    gated = Gated()
    e = await env(spec("slow", gated))
    inner = e.transport

    class DropOnce(httpx.AsyncBaseTransport):
        def __init__(self) -> None:
            self.dropped = False

        async def handle_async_request(self, request):
            resp = await inner.handle_async_request(request)
            method = rpc_methods(inner)[-1] if rpc_methods(inner) else ""
            if method == "SubscribeToTask":
                gated.gate.set()
            if method != "SendStreamingMessage" or self.dropped:
                return resp
            self.dropped = True
            original = resp.stream

            class Breaking(httpx.AsyncByteStream):
                async def __aiter__(self):
                    async for chunk in original:  # type: ignore[union-attr]
                        yield chunk
                        raise httpx.ReadError("connection reset")

                async def aclose(self):
                    await original.aclose()  # type: ignore[union-attr]

            return httpx.Response(
                resp.status_code, headers=resp.headers, stream=Breaking(), request=request
            )

    e.hc._transport = DropOnce()
    res = await e.client.consult("slow", "go", wait_seconds=5)
    assert res.state == "completed"
    assert res.text == "finally"
    methods = rpc_methods(inner)
    assert methods.count("SendStreamingMessage") == 1  # never re-sent
    assert "SubscribeToTask" in methods
    assert "GetTask" not in methods  # completion arrived over the subscription


async def test_ambiguous_failure_finds_task_by_context(env):
    gated = Gated()
    e = await env(spec("slow", gated))
    inner = e.transport

    class LoseResponse(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            resp = await inner.handle_async_request(request)
            if rpc_methods(inner)[-1] == "SendStreamingMessage":
                await resp.aclose()
                raise httpx.ReadError("lost", request=request)
            return resp

    e.hc._transport = LoseResponse()
    await asyncio.sleep(0)
    res = await e.client.consult("slow", "go", wait_seconds=0.5)
    assert res.state == "working"
    assert res.task_id
    methods = rpc_methods(inner)
    assert methods.count("SendStreamingMessage") == 1
    assert "ListTasks" in methods
    gated.gate.set()


async def test_ambiguous_failure_without_task_is_delivery_unknown(env):
    e = await env(spec("alpha", Echo()))

    class Lost(httpx.AsyncBaseTransport):
        def __init__(self) -> None:
            self.sends = 0

        async def handle_async_request(self, request):
            if b"SendStreamingMessage" in request.content:
                self.sends += 1
                raise httpx.ReadError("lost", request=request)
            return await e.transport.handle_async_request(request)

    lost = Lost()
    e.hc._transport = lost
    res = await e.client.consult("alpha", "x", wait_seconds=5)
    assert res.state == "unavailable"
    assert res.reason == "delivery unknown"
    assert lost.sends == 1


async def test_credentials_for_caller_sent(env):
    e = await env(spec("alpha", Echo()), register=False)
    await e.registry.add_from_card("alpha", e.card("alpha"), "internal", credential_ref="ref")
    callers: list = []

    class Creds:
        async def headers(self, partner, caller):
            callers.append(caller)
            return {"X-Partner-Key": "k1"}

    seen: list[httpx.Headers] = []

    async def hook(request: httpx.Request) -> None:
        seen.append(request.headers)

    e.hc.event_hooks["request"].append(hook)
    client = PartnerClient(e.registry, credentials=Creds(), http=e.hc)
    who = Principal(id="key:bob", kind="api_key", scopes=frozenset())
    res = await client.consult("alpha", "x", wait_seconds=5, caller=who)
    assert res.state == "completed"
    assert seen[0]["X-Partner-Key"] == "k1"
    assert callers[0] == who
    await client.aclose()


async def test_bulkhead_full_returns_busy(env, monkeypatch):
    monkeypatch.setattr(client_mod, "BULKHEAD_WAIT_S", 0.01)
    e = await env(spec("alpha", Echo()))
    bulkhead = e.client._bulkhead("alpha")
    async with contextlib.AsyncExitStack() as stack:
        for _ in range(bulkhead.max_concurrent):
            await stack.enter_async_context(bulkhead.acquire(1))
        res = await e.client.consult("alpha", "x", wait_seconds=5)
    assert res.state == "unavailable" and res.reason == "busy"
    assert e.transport.requests == []


def test_reply_ignores_stale_interrupted_status():
    track = results_mod.Track("t1", "c1")
    old = Task(id="t1", context_id="c1")
    old.status.state = TaskState.TASK_STATE_INPUT_REQUIRED
    old.status.message.message_id = "q1"
    track.apply(StreamResponse(task=old))
    track.mark_stale()
    assert not track.settled
    upd = StreamResponse()
    upd.status_update.task_id = "t1"
    upd.status_update.status.state = TaskState.TASK_STATE_INPUT_REQUIRED
    upd.status_update.status.message.message_id = "q2"
    track.apply(upd)
    assert track.settled


async def test_reply_to_unknown_task_is_failed_protocol_error(env):
    e = await env(spec("alpha", Echo()))
    res = await e.client.consult("alpha", "x", task_id="nope", context_id="c", wait_seconds=5)
    assert res.state == "failed"
    assert res.reason is not None and res.reason.startswith("partner error:")
    assert await e.handles.by_inbound("none") == []
    assert e.client._breaker("alpha").state == "closed"


# -- review round 1 regressions -------------------------------------------------------


class Big:
    durable_sessions = False

    async def run(self, ctx):
        yield Done(text="x" * 200_000)


class Firehose:
    """Streams far more than the per-call byte budget, then completes."""

    durable_sessions = False

    async def run(self, ctx):
        for i in range(40):
            yield ArtifactChunk(
                parts=[Part(text="y" * 65536)], artifact_id="big", append=i > 0, last=False
            )
        yield Done(text="end")


class FakeClock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def half_open_breaker(e, partner_id: str) -> CircuitBreaker:
    clk = FakeClock()
    breaker = CircuitBreaker(clock=clk)
    for _ in range(5):
        breaker.record_failure()
    clk.t += 30
    assert breaker.state == "half_open"
    e.client._breakers[partner_id] = breaker
    return breaker


@pytest.mark.parametrize("streaming", [True, False])
async def test_big_reply_text_is_capped(env, streaming):
    e = await env(spec("big", Big(), streaming=streaming))
    res = await e.client.consult("big", "go", wait_seconds=5)
    assert res.state == "completed"
    assert res.truncated is True
    assert len(res.text.encode()) <= 65536
    assert res.text == "x" * 65536
    # The artifact copy does not fit in what is left of the shared budget.
    assert res.artifacts[0]["parts"] == [{"kind": "text", "truncated": True, "size": 200_000}]


def test_text_cap_cuts_on_character_boundary():
    text, cut = results_mod.cut_utf8("é" * 40_000, 65536)  # 2 bytes each
    assert cut and len(text.encode()) <= 65536 and text == "é" * 32768
    text, cut = results_mod.cut_utf8("a" + "€" * 30_000, 65536)  # 3 bytes each
    assert cut and len(text.encode()) <= 65536 and text.endswith("€")


async def test_huge_stream_stops_at_byte_budget(env):
    e = await env(spec("hose", Firehose()))
    loop = asyncio.get_running_loop()
    t0 = loop.time()
    res = await e.client.consult("hose", "go", wait_seconds=5)
    assert loop.time() - t0 < 4
    assert res.truncated is True
    assert res.state == "working"  # stopped before the partner's completion arrived
    assert len(res.text.encode()) <= 65536


@pytest.mark.parametrize("streaming", [True, False])
async def test_reply_with_task_id_only(env, streaming):
    e = await env(spec("asker", Asker(), streaming=streaming))
    first = await e.client.consult("asker", "weather?", wait_seconds=5)
    assert first.state == "input_required"
    second = await e.client.consult("asker", "Paris", task_id=first.task_id, wait_seconds=5)
    assert second.state == "completed", second.reason
    assert second.task_id == first.task_id
    assert second.context_id == first.context_id
    assert "weather in Paris: sunny" in second.text


async def test_reply_with_task_id_only_without_handle_sends_no_context(env):
    e = await env(spec("asker", Asker()))
    first = await e.client.consult("asker", "weather?", wait_seconds=5)
    bare = PartnerClient(e.registry, http=e.hc)  # no handle store: no stored context
    second = await bare.consult("asker", "Paris", task_id=first.task_id, wait_seconds=5)
    assert second.state == "completed", second.reason
    body = json.loads(e.transport.requests[-1][2])
    assert "contextId" not in body["params"]["message"]
    await bare.aclose()


async def test_handles_are_partner_scoped(env):
    e = await env()
    await e.handles.record("same", "pa", "ca", "in-1", "o", "TASK_STATE_WORKING")
    await e.handles.record("same", "pb", "cb", "in-2", "o", "TASK_STATE_WORKING")
    await e.handles.update_state("pb", "same", "TASK_STATE_COMPLETED")
    a = await e.handles.get("pa", "same")
    b = await e.handles.get("pb", "same")
    assert a["state"] == "TASK_STATE_WORKING" and a["context_id"] == "ca"
    assert b["state"] == "TASK_STATE_COMPLETED" and b["context_id"] == "cb"
    assert [r["partner_id"] for r in await e.handles.by_inbound("in-1")] == ["pa"]


def test_track_rejects_foreign_task_id():
    track = results_mod.Track("t1", "c1")
    with pytest.raises(results_mod.ProtocolViolation):
        track.apply(StreamResponse(task=Task(id="t2", context_id="c1")))
    upd = StreamResponse()
    upd.status_update.task_id = "t9"
    upd.status_update.context_id = "c1"
    with pytest.raises(results_mod.ProtocolViolation):
        track.apply(upd)
    with pytest.raises(results_mod.ProtocolViolation):
        track.set_task(Task(id="t1", context_id="c2"))


async def test_mismatched_context_from_partner_is_protocol_error(env):
    e = await env(spec("alpha", Echo()))
    inner = e.transport

    class Forge(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            resp = await inner.handle_async_request(request)
            original = resp.stream

            class Rewritten(httpx.AsyncByteStream):
                async def __aiter__(self):
                    async for chunk in original:  # type: ignore[union-attr]
                        yield re.sub(rb'"contextId":\s*"[^"]*"', b'"contextId":"forged"', chunk)

                async def aclose(self):
                    await original.aclose()  # type: ignore[union-attr]

            headers = [(k, v) for k, v in resp.headers.items() if k != "content-length"]
            return httpx.Response(
                resp.status_code, headers=headers, stream=Rewritten(), request=request
            )

    e.hc._transport = Forge()
    res = await e.client.consult("alpha", "x", wait_seconds=5, inbound_task_id="in-f")
    assert res.state == "failed"
    assert res.reason == "partner protocol error"
    assert await e.handles.by_inbound("in-f") == []


async def test_hung_partner_opens_breaker_after_timeouts(env, monkeypatch):
    monkeypatch.setattr(client_mod, "LOOKUP_FLOOR_S", 0.02)
    e = await env(spec("alpha", Echo()))

    class Hang(httpx.AsyncBaseTransport):
        def __init__(self) -> None:
            self.calls = 0

        async def handle_async_request(self, request):
            self.calls += 1
            await asyncio.Event().wait()

    hang = Hang()
    e.hc._transport = hang
    for _ in range(5):
        res = await e.client.consult("alpha", "x", wait_seconds=0.05)
        assert res.state == "unavailable" and res.reason == "delivery unknown"
    calls = hang.calls
    res = await e.client.consult("alpha", "x", wait_seconds=0.05)
    assert res.reason == "circuit open"
    assert hang.calls == calls
    assert e.client._bulkhead("alpha").in_use == 0


async def test_busy_does_not_consume_half_open_probe(env, monkeypatch):
    monkeypatch.setattr(client_mod, "BULKHEAD_WAIT_S", 0.01)
    e = await env(spec("alpha", Echo()))
    breaker = half_open_breaker(e, "alpha")
    bulkhead = e.client._bulkhead("alpha")
    async with contextlib.AsyncExitStack() as stack:
        for _ in range(bulkhead.max_concurrent):
            await stack.enter_async_context(bulkhead.acquire(1))
        res = await e.client.consult("alpha", "x", wait_seconds=5)
        assert res.reason == "busy"
    res = await e.client.consult("alpha", "x", wait_seconds=5)
    assert res.state == "completed"  # the probe was still available
    assert breaker.state == "closed"


async def test_cancelled_consult_releases_probe_and_slot(env):
    gated = Gated()
    e = await env(spec("slow", gated))
    breaker = half_open_breaker(e, "slow")
    t = asyncio.create_task(e.client.consult("slow", "go", wait_seconds=5))
    await asyncio.wait_for(gated.started.wait(), 5)
    t.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await t
    assert e.client._bulkhead("slow").in_use == 0
    assert breaker.allow()  # the abandoned probe was given back
    gated.gate.set()


class LateDelivery(httpx.AsyncBaseTransport):
    """Delivers the streaming send to the partner only after ``delay`` seconds and never
    answers it; every other request passes straight through."""

    def __init__(self, inner: httpx.AsyncBaseTransport, delay: float) -> None:
        self.inner = inner
        self.delay = delay
        self.responses: list[httpx.Response] = []
        self.forwarders: list[asyncio.Task] = []

    async def handle_async_request(self, request):
        body = await request.aread()
        if b"SendStreamingMessage" not in body:
            return await self.inner.handle_async_request(request)

        async def forward() -> None:
            await asyncio.sleep(self.delay)
            copy = httpx.Request(request.method, request.url, headers=request.headers, content=body)
            self.responses.append(await self.inner.handle_async_request(copy))

        self.forwarders.append(asyncio.create_task(forward()))
        await asyncio.Event().wait()  # the caller never hears back
        raise AssertionError("unreachable")

    async def close(self) -> None:
        await asyncio.gather(*self.forwarders, return_exceptions=True)
        for r in self.responses:
            await r.aclose()


async def test_cancelled_consult_retries_context_lookup_until_task_appears(env, monkeypatch):
    """Finding 1 fallback: no first event ever arrives and the partner creates its task only
    after the first lookups came back empty; the lookup is retried and the task cancelled."""
    monkeypatch.setattr(client_mod, "CANCEL_CLEANUP_S", 2.0)  # waits 1 s for a first event
    gated = Gated()
    e = await env(spec("slow", gated))
    late = LateDelivery(e.transport, delay=1.3)
    e.hc._transport = late
    t = asyncio.create_task(e.client.consult("slow", "go", wait_seconds=5, inbound_task_id="in-l"))
    await asyncio.sleep(0.1)  # the send is in flight
    t.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await t
    assert gated.started.is_set()  # the partner only received the message meanwhile
    methods = rpc_methods(e.transport)
    assert methods.count("ListTasks") >= 2  # first lookups were empty and retried
    [row] = await e.handles.by_inbound("in-l")
    assert row["state"] == "TASK_STATE_CANCELED"
    assert (await e.client.check("slow", row["task_id"])).state == "canceled"
    await late.close()


async def test_aclose_drains_cleanup_tasks(env):
    """Finding 2: a cleanup still running in the background when the client closes runs to
    completion before the HTTP clients go away."""
    gated = Gated()
    e = await env(spec("slow", gated))
    res = await e.client.consult("slow", "go", wait_seconds=0.2, inbound_task_id="in-d")
    assert res.state == "working"
    real_fetch = e.client._fetch

    async def slow_fetch(*args, **kwargs):
        await asyncio.sleep(0.3)
        return await real_fetch(*args, **kwargs)

    e.client._fetch = slow_fetch  # type: ignore[method-assign]
    _, sdk_client, _ = await e.client._prepare("slow")
    track = results_mod.Track(res.task_id, res.context_id)
    waiter = asyncio.create_task(
        e.client._cleanup_cancelled("slow", sdk_client, track, False, "in-d", None, [])
    )
    await asyncio.sleep(0.05)
    waiter.cancel()  # the cancelled consult stops waiting; its cleanup carries on
    await waiter
    assert len(e.client._cleanups) == 1
    await e.client.aclose()
    assert not e.client._cleanups
    [row] = await e.handles.by_inbound("in-d")
    assert row["state"] == "TASK_STATE_CANCELED"
    assert (await e.client.check("slow", res.task_id)).state == "canceled"


async def test_503_before_any_event_looks_task_up(env):
    e = await env(spec("alpha", Echo()))
    inner = e.transport

    class Proxy503(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            resp = await inner.handle_async_request(request)
            if rpc_methods(inner)[-1] == "SendStreamingMessage":
                await resp.aread()  # the partner accepted; the proxy answers 503
                return httpx.Response(503, request=request)
            return resp

    e.hc._transport = Proxy503()
    res = await e.client.consult("alpha", "x", wait_seconds=5)
    assert res.state == "completed"
    assert res.text == "echo: x"
    methods = rpc_methods(inner)
    assert methods.count("SendStreamingMessage") == 1 and "ListTasks" in methods


async def test_internal_error_is_raised_not_blamed_on_partner(env, monkeypatch):
    e = await env(spec("alpha", Echo()))
    breaker = half_open_breaker(e, "alpha")

    def boom(self, ev):
        raise RuntimeError("bug")

    monkeypatch.setattr(results_mod.Track, "apply", boom)
    with pytest.raises(RuntimeError, match="bug"):
        await e.client.consult("alpha", "x", wait_seconds=5)
    assert breaker.state == "closed"  # the send itself got a response
    assert e.client._bulkhead("alpha").in_use == 0


async def test_cancel_for_inbound_runs_concurrently_within_bound(env):
    a, b = Gated(), Gated()
    e = await env(spec("pa", a), spec("pb", b))
    ra = await e.client.consult("pa", "go", wait_seconds=0.2, inbound_task_id="in-c")
    rb = await e.client.consult("pb", "go", wait_seconds=0.2, inbound_task_id="in-c")
    assert ra.state == rb.state == "working"
    started: list[str] = []
    real_cancel = e.client.cancel

    async def slow_cancel(partner_id, task_id, **kw):
        started.append(partner_id)
        if partner_id == "pa":
            await asyncio.Event().wait()  # never finishes: cut off by the bound
        return await real_cancel(partner_id, task_id, **kw)

    e.client.cancel = slow_cancel  # type: ignore[method-assign]
    e.client.default_deadline_s = 0.3
    assert await e.client.cancel_for_inbound("in-c") == 1
    assert sorted(started) == ["pa", "pb"]
    a.gate.set()


# -- review round 2: malformed partner responses are contained ----------------------

GARBAGE = [
    (b"data: not-json\n\n", "text/event-stream"),
    (b'data: {"jsonrpc":"2.0","id":"1"}\n\n', "text/event-stream"),
    (b'data: ["x"]\n\n', "text/event-stream"),
    (b'["x"]', "application/json"),
    (b'{"jsonrpc":"2.0","id":"1","result":null}', "application/json"),
]


def garbage_for(inner: StreamingASGITransport, methods: set[str], body: bytes, ct: str):
    class Garbage(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            try:
                method = json.loads(request.content)["method"]
            except (ValueError, KeyError, TypeError):
                method = None
            if method in methods:
                headers = {"content-type": ct}
                return httpx.Response(200, content=body, headers=headers, request=request)
            return await inner.handle_async_request(request)

    return Garbage()


@pytest.mark.parametrize(("body", "ct"), GARBAGE)
async def test_garbage_send_response_is_protocol_error(env, body, ct):
    e = await env(spec("alpha", Echo()))
    breaker = half_open_breaker(e, "alpha")
    e.hc._transport = garbage_for(e.transport, {"SendStreamingMessage"}, body, ct)
    res = await e.client.consult("alpha", "x", wait_seconds=3)
    assert res.state == "failed"
    assert res.reason == "partner protocol error"
    assert breaker.state == "closed"  # the partner responded: success
    assert e.client._bulkhead("alpha").in_use == 0


@pytest.mark.parametrize(("body", "ct"), [GARBAGE[3], GARBAGE[4]])
async def test_garbage_check_and_cancel_are_protocol_errors(env, body, ct):
    gated = Gated()
    e = await env(spec("slow", gated))
    res = await e.client.consult("slow", "go", wait_seconds=0.2)
    assert res.state == "working"
    e.hc._transport = garbage_for(e.transport, {"GetTask", "CancelTask"}, body, ct)
    checked = await e.client.check("slow", res.task_id)
    assert checked.state == "failed" and checked.reason == "partner protocol error"
    cancelled = await e.client.cancel("slow", res.task_id)
    assert cancelled.state == "failed" and cancelled.reason == "partner protocol error"
    assert e.client._breaker("slow").state == "closed"
    gated.gate.set()


async def test_wait_any_survives_one_garbage_partner(env):
    a, b = Gated(), Gated()
    e = await env(spec("pa", a), spec("pb", b))
    ra = await e.client.consult("pa", "go", wait_seconds=0.2)
    rb = await e.client.consult("pb", "go", wait_seconds=0.2)
    b.gate.set()
    inner = e.transport

    class GarbageForPa(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            if request.url.path.startswith("/agents/pa/"):
                return httpx.Response(200, content=b'["x"]', request=request)
            return await inner.handle_async_request(request)

    e.hc._transport = GarbageForPa()
    results = await e.client.wait_any([("pa", ra.task_id), ("pb", rb.task_id)], 5)
    assert results[0].state == "failed" and results[0].reason == "partner protocol error"
    assert results[1].partner == "pb" and results[1].state in ("working", "completed")
    a.gate.set()


# -- Phase 2: OAuth 401 resend and caller-scoped cascades ----------------------------

TOKEN_URL = "https://auth.example.com/token"


def _sha(k: str) -> str:
    return hashlib.sha256(k.encode()).hexdigest()


@pytest.fixture
def oauth_env(monkeypatch):
    async def fake(host: str) -> list[str]:
        return ["93.184.216.34"]

    monkeypatch.setattr(netguard, "_resolve", fake)
    monkeypatch.setenv("OAUTH_SECRET", "client-secret")


def _token(tok: str) -> httpx.Response:
    return httpx.Response(
        200, json={"access_token": tok, "token_type": "Bearer", "expires_in": 600}
    )


class SendLog(httpx.AsyncBaseTransport):
    """Records (messageId, Authorization) of every send that reaches the partner host."""

    def __init__(self, inner: StreamingASGITransport) -> None:
        self.inner = inner
        self.sends: list[tuple[str, str]] = []

    async def handle_async_request(self, request):
        try:
            body = json.loads(request.content)
        except ValueError:
            body = {}
        if body.get("method") in ("SendMessage", "SendStreamingMessage"):
            mid = body["params"]["message"]["messageId"]
            self.sends.append((mid, request.headers.get("authorization", "")))
        return await self.inner.handle_async_request(request)


async def test_401_before_accept_refreshes_and_resends_once(env, oauth_env):
    partner_auth = AuthConfig(api_keys={_sha("tok-good"): ApiKeyEntry(principal_id="gw")})
    e = await env(spec("alpha", Echo()), register=False, auth=partner_auth)
    await e.registry.add_from_card("alpha", e.card("alpha"), "internal", credential_ref="o")
    log = SendLog(e.transport)
    e.hc._transport = log
    creds = OAuthClientCredentials(TOKEN_URL, "gw", "OAUTH_SECRET", refs={"o"})
    client = PartnerClient(e.registry, credentials=creds, handles=e.handles, http=e.hc)
    breaker = half_open_breaker(e, "alpha")
    client._breakers["alpha"] = breaker
    try:
        with respx.mock as rx:
            route = rx.post(TOKEN_URL).mock(side_effect=[_token("tok-stale"), _token("tok-good")])
            res = await client.consult("alpha", "x", wait_seconds=5)
        assert res.state == "completed", res
        assert res.text == "echo: x"
        assert route.call_count == 2
        assert len(log.sends) == 2
        (mid1, auth1), (mid2, auth2) = log.sends
        assert mid1 == mid2
        assert auth1 == "Bearer tok-stale" and auth2 == "Bearer tok-good"
        assert breaker.state == "closed"
    finally:
        await client.aclose()


async def test_401_twice_gives_auth_required_result(env, oauth_env):
    partner_auth = AuthConfig(api_keys={_sha("tok-good"): ApiKeyEntry(principal_id="gw")})
    e = await env(spec("alpha", Echo()), register=False, auth=partner_auth)
    await e.registry.add_from_card("alpha", e.card("alpha"), "internal", credential_ref="o")
    log = SendLog(e.transport)
    e.hc._transport = log
    creds = OAuthClientCredentials(TOKEN_URL, "gw", "OAUTH_SECRET")
    client = PartnerClient(e.registry, credentials=creds, http=e.hc)
    breaker = half_open_breaker(e, "alpha")
    client._breakers["alpha"] = breaker
    try:
        with respx.mock as rx:
            route = rx.post(TOKEN_URL).mock(side_effect=[_token("bad-1"), _token("bad-2")])
            res = await client.consult("alpha", "x", wait_seconds=5)
        assert res.state == "auth_required"
        assert res.reason == "partner rejected credentials"
        assert route.call_count == 2
        assert len(log.sends) == 2  # one resend, never more
        assert breaker.state == "closed"  # the partner did answer
    finally:
        await client.aclose()


async def test_401_without_invalidate_is_not_resent(env):
    partner_auth = AuthConfig(api_keys={_sha("tok-good"): ApiKeyEntry(principal_id="gw")})
    e = await env(spec("alpha", Echo()), register=False, auth=partner_auth)
    await e.registry.add_from_card("alpha", e.card("alpha"), "internal", credential_ref="o")
    log = SendLog(e.transport)
    e.hc._transport = log
    creds = StaticCredentials({"o": {"Authorization": "Bearer nope"}})
    client = PartnerClient(e.registry, credentials=ChainCredentials(creds), http=e.hc)
    try:
        res = await client.consult("alpha", "x", wait_seconds=5)
        assert res.state == "auth_required"
        assert len(log.sends) == 1
    finally:
        await client.aclose()


async def test_cascade_cancel_uses_original_caller(env):
    gated = Gated()
    e = await env(spec("slow", gated), register=False)
    await e.registry.add_from_card("slow", e.card("slow"), "internal", credential_ref="r")
    callers: list[Principal | None] = []

    class Creds:
        async def headers(self, partner, caller):
            callers.append(caller)
            return {"X-Partner-Key": "k"}

    client = PartnerClient(e.registry, credentials=Creds(), handles=e.handles, http=e.hc)
    alice = Principal(id="jwt:alice", kind="jwt", scopes=frozenset({"a"}))
    try:
        res = await client.consult(
            "slow", "go", wait_seconds=0.2, inbound_task_id="in-a", caller=alice
        )
        assert res.state == "working"
        [row] = await e.handles.by_inbound("in-a")
        assert row["caller_id"] == "jwt:alice"
        callers.clear()
        other = Principal(id="key:mallory", kind="api_key", scopes=frozenset())
        with use_inbound("in-other", other):
            assert await client.cancel_for_inbound("in-a") == 1
        assert callers and all(
            c is not None and (c.id, c.kind, c.scopes) == ("jwt:alice", "jwt", frozenset())
            for c in callers
        )

        # Restart recovery rebuilds the caller the same way.
        seen: list = []

        async def spy(partner_id, task_id, *, caller=None):
            seen.append(caller)
            return ToolResult(partner=partner_id, task_id=task_id, state="canceled")

        e.host.client.cancel = spy  # type: ignore[method-assign]
        await e.host._cancel_outbound(
            {"partner_id": "slow", "task_id": "t1", "caller_id": "key:bob"}
        )
        await e.host._cancel_outbound({"partner_id": "slow", "task_id": "t2", "caller_id": None})
        assert seen[0] == Principal(id="key:bob", kind="api_key", scopes=frozenset())
        assert seen[1] is None
    finally:
        gated.gate.set()
        await client.aclose()


async def test_handles_migration_adds_caller_id(db_url):
    await _check_caller_id_migration(db_url)


async def _check_caller_id_migration(url: str) -> None:
    engine = await create_engine(url)
    try:
        async with engine.begin() as conn:  # the Phase 1 schema, with one row
            await conn.exec_driver_sql(
                "CREATE TABLE a2agw_outbound (partner_id VARCHAR NOT NULL, task_id VARCHAR NOT "
                "NULL, context_id VARCHAR, inbound_task_id VARCHAR, origin VARCHAR, state "
                "VARCHAR NOT NULL, created_at FLOAT NOT NULL, PRIMARY KEY (partner_id, task_id))"
            )
            await conn.exec_driver_sql(
                "INSERT INTO a2agw_outbound VALUES ('p', 't', NULL, 'in-1', NULL, "
                "'TASK_STATE_WORKING', 1.0)"
            )
        store = OutboundHandleStore(engine)
        await store.initialize()
        await store.initialize()  # idempotent
        [old] = await store.by_inbound("in-1")
        assert old["caller_id"] is None
        await store.record("t2", "p", None, "in-1", None, "TASK_STATE_WORKING", caller_id="jwt:x")
        await store.record("t2", "p", None, "in-1", None, "TASK_STATE_COMPLETED", caller_id="jwt:y")
        row = await store.get("p", "t2")
        assert row is not None and row["caller_id"] == "jwt:x"  # the first caller is kept
        assert row["state"] == "TASK_STATE_COMPLETED"
    finally:
        await engine.dispose()


async def test_migration_tolerates_column_added_concurrently(tmp_path):
    engine = await create_engine(f"sqlite+aiosqlite:///{tmp_path / 'race.db'}")
    try:
        store = OutboundHandleStore(engine)
        await store.initialize()  # the column exists now
        async with engine.begin() as conn:  # a second startup that inspected before the first
            await OutboundHandleStore._add_caller_id(conn)  # "duplicate column": tolerated
    finally:
        await engine.dispose()


async def test_401_on_check_and_cancel_resends_once(env, oauth_env):
    gated = Gated()
    partner_auth = AuthConfig(api_keys={_sha("tok-good"): ApiKeyEntry(principal_id="gw")})
    e = await env(spec("slow", gated), register=False, auth=partner_auth)
    await e.registry.add_from_card("slow", e.card("slow"), "internal", credential_ref="o")
    creds = OAuthClientCredentials(TOKEN_URL, "gw", "OAUTH_SECRET", refs={"o"})
    client = PartnerClient(e.registry, credentials=creds, handles=e.handles, http=e.hc)
    try:
        with respx.mock as rx:
            route = rx.post(TOKEN_URL).mock(return_value=_token("tok-good"))
            res = await client.consult("slow", "go", wait_seconds=0.2)
            assert res.state == "working"
            # The token is rotated: the cached one is now rejected.
            partner_auth.api_keys.clear()
            partner_auth.api_keys[_sha("tok-new")] = ApiKeyEntry(principal_id="gw")
            route.mock(side_effect=[_token("tok-new"), _token("tok-newer")])
            checked = await client.check("slow", res.task_id)
            assert checked.state == "working" and route.call_count == 2
            partner_auth.api_keys.clear()
            partner_auth.api_keys[_sha("tok-newer")] = ApiKeyEntry(principal_id="gw")
            cancelled = await client.cancel("slow", res.task_id)
            assert cancelled.state == "canceled" and route.call_count == 3
            partner_auth.api_keys.clear()  # nothing is accepted any more
            route.mock(return_value=_token("tok-x"))
            again = await client.check("slow", res.task_id)
            assert again.state == "auth_required"
            assert again.reason == "partner rejected credentials"
    finally:
        gated.gate.set()
        await client.aclose()


async def test_token_error_is_credential_error_and_spares_breaker(env, oauth_env, caplog):
    e = await env(spec("alpha", Echo()), register=False)
    await e.registry.add_from_card("alpha", e.card("alpha"), "internal", credential_ref="o")
    creds = OAuthClientCredentials(TOKEN_URL, "gw", "OAUTH_SECRET", refs={"o"})
    client = PartnerClient(e.registry, credentials=creds, http=e.hc)
    breaker = half_open_breaker(e, "alpha")
    client._breakers["alpha"] = breaker
    try:
        with respx.mock as rx, caplog.at_level("WARNING", logger="a2agw.consult.client"):
            rx.post(TOKEN_URL).mock(return_value=httpx.Response(500, text="client-secret"))
            res = await client.consult("alpha", "x", wait_seconds=5)
        assert res.state == "unavailable" and res.reason == "credential error"
        assert breaker.state == "half_open"  # neither success nor failure was recorded
        assert any(
            "token endpoint" in r.getMessage() and "'o'" in r.getMessage() for r in caplog.records
        )
        assert "client-secret" not in caplog.text
        assert all(b"SendStreamingMessage" not in body for _, _, body in e.transport.requests)
    finally:
        await client.aclose()


async def test_recovery_cancel_uses_exchange_fallback(env, oauth_env):
    gated = Gated()
    e = await env(spec("slow", gated))
    res = await e.client.consult("slow", "go", wait_seconds=0.2, inbound_task_id="in-r")
    assert res.state == "working"
    calls: list = []

    class Service:
        async def headers(self, partner, caller):
            calls.append(caller)
            return {"X-Service": "gw"}

    exchange = OAuthTokenExchange(
        TOKEN_URL, "gw", "OAUTH_SECRET", "aud", refs={"r"}, fallback=Service()
    )
    host = e.host
    assert host.client is not None
    await host.partners.add_from_card("slow", e.card("slow"), "internal", credential_ref="r")
    host.client.credentials = exchange
    host.client.http = e.hc  # reach the partner over the in-process transport
    host.client._clients.clear()
    try:
        # An ordinary call with no inbound token is refused.
        checked = await host.client.check("slow", res.task_id)
        assert checked.state == "unavailable" and checked.reason == "credential error"
        assert calls == []
        # Restart recovery is a maintenance call: the service fallback is used.
        await host._cancel_outbound(
            {"partner_id": "slow", "task_id": res.task_id, "caller_id": "jwt:alice"}
        )
        assert calls and calls[0] == Principal.from_id("jwt:alice")
        assert (await e.client.check("slow", res.task_id)).state == "canceled"
    finally:
        gated.gate.set()


async def test_circuit_open_result_carries_retry_after(env):
    """Spec 8.1: an open breaker answers ``unavailable`` with the seconds until the partner
    is tried again, so the agent can pick an alternative or come back later."""
    e = await env(spec("alpha", Echo()))
    clk = FakeClock()
    breaker = CircuitBreaker(clock=clk, reset_after_s=30)
    for _ in range(5):
        breaker.record_failure()
    clk.t += 12
    e.client._breakers["alpha"] = breaker
    res = await e.client.consult("alpha", "x", wait_seconds=5)
    assert res.state == "unavailable" and res.reason == "circuit open"
    assert res.retry_after_s == 18
    assert e.transport.requests == []
    # Results that are not a breaker refusal carry none.
    clk.t += 18
    ok = await e.client.consult("alpha", "x", wait_seconds=5)
    assert ok.state == "completed" and ok.retry_after_s is None


@pytest.mark.parametrize("version", ["0.2", "abc"])
async def test_partner_without_supported_protocol_version_is_unavailable(env, version):
    """Spec 8.6: no interface at a protocol version we speak gives an explicit result, not
    an exception and not a call."""
    e = await env(spec("alpha", Echo()), register=False)
    card = e.card("alpha")
    for iface in card["supportedInterfaces"]:
        iface["protocolVersion"] = version
    await e.registry.add_from_card("alpha", card, "internal")
    res = await e.client.consult("alpha", "x", wait_seconds=5)
    assert res.state == "unavailable"
    assert res.reason == "no supported protocol version"
    assert e.transport.requests == []


async def test_binding_with_supported_version_preferred(env):
    """JSON-RPC at an unsupported version, REST at 1.0: the REST interface is used."""
    e = await env(spec("alpha", Echo()), register=False)
    card = e.card("alpha")
    for iface in card["supportedInterfaces"]:
        if iface["protocolBinding"] == "JSONRPC":
            iface["protocolVersion"] = "0.2"
    await e.registry.add_from_card("alpha", card, "internal")
    res = await e.client.consult("alpha", "x", wait_seconds=5)
    assert res.state == "completed" and res.text == "echo: x"
    assert all("/rest/" in path for _, path, _ in e.transport.requests)


async def test_v03_partner_gets_its_own_protocol_version_header(env):
    """Spec 8.13: a 0.3-only partner is called through the SDK's compatibility transport, and
    the request declares 0.3 (a fixed ``A2A-Version: 1.0`` would make a version-checking 0.3
    server reject every call)."""
    e = await env(spec("alpha", Echo(), streaming=False), register=False)
    card = {
        "name": "Legacy",
        "description": "0.3 only",
        "version": "1.0",
        "url": "http://t/agents/alpha/",
        "preferredTransport": "JSONRPC",
        "protocolVersion": "0.3.0",
        "capabilities": {"streaming": False},
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [{"id": "s", "name": "S", "description": "d", "tags": ["s"]}],
    }
    await e.registry.add_from_card("legacy", card, "internal")
    seen: list[list[str]] = []

    async def hook(request: httpx.Request) -> None:
        seen.append(request.headers.get_list("a2a-version"))

    e.hc.event_hooks["request"].append(hook)
    res = await e.client.consult("legacy", "hello", wait_seconds=5)
    assert res.state == "completed" and res.text == "echo: hello"
    assert seen and all(v == ["0.3"] for v in seen)
    assert rpc_methods(e.transport)[0] == "message/send"
