"""PartnerClient end to end against real in-process AgentHost partners."""

from __future__ import annotations

import asyncio
import contextlib
import json
from typing import Any

import httpx
import pytest
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
    Role,
    StreamResponse,
    Task,
    TaskState,
)
from google.protobuf.json_format import MessageToDict
from starlette.applications import Starlette

from a2agw.consult import client as client_mod
from a2agw.consult.client import PartnerClient, ToolResult
from a2agw.consult.handles import OutboundHandleStore
from a2agw.consult.registry import PartnerRegistry
from a2agw.context.call_context import EXTENSION_URI, CallContext, use_call
from a2agw.core.events import Done, NeedInput, Status
from a2agw.ops.bus import EventBus
from a2agw.security.principal import Principal
from a2agw.serve.agent import AgentSpec, SkillSpec
from a2agw.serve.host import AgentHost
from a2agw.serve.store import create_engine

# -- an ASGI transport that really streams (httpx.ASGITransport buffers whole bodies) ----


class _Body(httpx.AsyncByteStream):
    def __init__(self, queue: asyncio.Queue, task: asyncio.Task, disconnected: asyncio.Event):
        self._queue = queue
        self._task = task
        self._disconnected = disconnected

    async def __aiter__(self):
        while True:
            chunk = await self._queue.get()
            if chunk is None:
                return
            if chunk:
                yield chunk

    async def aclose(self) -> None:
        self._disconnected.set()
        if not self._task.done():
            try:
                await asyncio.wait_for(asyncio.shield(self._task), 1.0)
            except (TimeoutError, Exception):  # noqa: BLE001
                self._task.cancel()


class StreamingASGITransport(httpx.AsyncBaseTransport):
    """Routes by host to ASGI apps; response bodies are streamed chunk by chunk."""

    def __init__(self, apps: dict[str, Any]):
        self.apps = apps
        self.requests: list[tuple[str, str, bytes]] = []  # (host, path, body)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        body = b"".join([c async for c in request.stream])  # type: ignore[union-attr]
        self.requests.append((request.url.host, request.url.path, body))
        app = self.apps[request.url.host]
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": request.method,
            "headers": [(k.lower(), v) for k, v in request.headers.raw],
            "scheme": request.url.scheme,
            "path": request.url.path,
            "raw_path": request.url.raw_path.split(b"?")[0],
            "query_string": request.url.query,
            "server": (request.url.host, request.url.port),
            "client": ("127.0.0.1", 123),
            "root_path": "",
        }
        queue: asyncio.Queue = asyncio.Queue()
        started: asyncio.Future = asyncio.get_running_loop().create_future()
        disconnected = asyncio.Event()
        body_sent = False

        async def receive():
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            await disconnected.wait()
            return {"type": "http.disconnect"}

        async def send(message):
            if message["type"] == "http.response.start":
                started.set_result(message)
            elif message["type"] == "http.response.body":
                if disconnected.is_set():
                    raise OSError("client disconnected")
                queue.put_nowait(message.get("body", b""))
                if not message.get("more_body", False):
                    queue.put_nowait(None)

        async def run():
            try:
                await app(scope, receive, send)
            except BaseException as e:  # noqa: BLE001
                if not started.done():
                    started.set_exception(e if isinstance(e, Exception) else RuntimeError())
            finally:
                queue.put_nowait(None)

        task = asyncio.create_task(run())
        start = await started
        return httpx.Response(
            start["status"],
            headers=start.get("headers", []),
            stream=_Body(queue, task, disconnected),
            request=request,
        )


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

    async def _make(*specs: AgentSpec, register: bool = True, apps: dict | None = None) -> Env:
        host = AgentHost("http://t", db_url=f"sqlite+aiosqlite:///{tmp_path / 'host.db'}")
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
    track = client_mod._Track("t1", "c1")
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
