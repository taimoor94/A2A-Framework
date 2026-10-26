"""WebhookAdapter against a fake external agent (a Starlette app behind an ASGI transport)."""

from __future__ import annotations

import asyncio
import json
import logging
import time
import types
from collections.abc import Awaitable, Callable

import httpcore
import httpx
import pytest
from a2a.types import Message, Part, Role
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route
from streaming_asgi import StreamingASGITransport

from a2agw.adapters import webhook as webhook_mod
from a2agw.adapters.webhook import WebhookAdapter
from a2agw.consult.guarded_net import GuardedBackend
from a2agw.core.events import ArtifactChunk, Done, Failed, NeedInput, Status, Usage
from a2agw.core.spi import InboundContext
from a2agw.gateway.protocol import MAX_LINE_BYTES, PROTOCOL, sign

URL = "http://agent/a2agw/invoke"
NDJSON = "application/x-ndjson"
LOGGER = "a2agw.agent.coder"


class FakeAgent:
    """One POST route; ``handler`` is set per test. Records each request."""

    def __init__(self) -> None:
        self.handler: Callable[[Request], Awaitable[Response]] | None = None
        self.requests: list[tuple[dict[str, str], bytes]] = []

        async def invoke(request: Request) -> Response:
            body = await request.body()
            self.requests.append((dict(request.headers), body))
            assert self.handler is not None
            return await self.handler(request)

        self.app = Starlette(routes=[Route("/a2agw/invoke", invoke, methods=["POST"])])

    def ndjson(self, *events: dict) -> None:
        async def h(_req: Request) -> Response:
            return Response("".join(json.dumps(e) + "\n" for e in events), media_type=NDJSON)

        self.handler = h


@pytest.fixture
async def agent():
    fake = FakeAgent()
    transport = StreamingASGITransport({"agent": fake.app})
    async with httpx.AsyncClient(transport=transport) as hc:
        fake.http = hc  # type: ignore[attr-defined]
        yield fake


def adapter(fake: FakeAgent, **kw) -> WebhookAdapter:
    return WebhookAdapter(URL, http=fake.http, **kw)  # type: ignore[attr-defined]


def ctx(text: str = "hello") -> InboundContext:
    msg = Message(message_id="m1", role=Role.ROLE_USER, parts=[Part(text=text)])
    return InboundContext.from_message("coder", msg, task_id="t1", context_id="c1")


async def collect(a: WebhookAdapter, c: InboundContext | None = None) -> list:
    return [ev async for ev in a.run(c or ctx())]


def chunk(text: str, *, first: bool, last: bool) -> ArtifactChunk:
    return ArtifactChunk(
        [Part(text=text)], name="output", artifact_id="output", append=not first, last=last
    )


async def test_ndjson_stream_maps_to_events(agent):
    agent.ndjson(
        {"type": "status", "text": "thinking"},
        {"type": "text", "text": "Hel"},
        {"type": "text", "text": "lo"},
        {"type": "usage", "tokens_in": 1, "tokens_out": 2, "cost": 0.25},
        {"type": "done", "text": "fin"},
        {"type": "status", "text": "after the end: ignored"},
    )
    events = await collect(adapter(agent))
    assert events == [
        Status("thinking"),
        chunk("Hel", first=True, last=False),
        chunk("lo", first=False, last=False),
        Usage(1, 2, 0.25),
        Done("fin"),
    ]
    _, body = agent.requests[0]
    sent = json.loads(body)
    assert sent["protocol"] == PROTOCOL and sent["text"] == "hello" and sent["task_id"] == "t1"
    assert sent["consult"] is None
    assert sent["deadline"] == pytest.approx(time.time() + 300.0, abs=5)


async def test_text_stream_ends_with_last_chunk(agent):
    agent.ndjson({"type": "text", "text": "a"}, {"type": "text", "text": "b"})
    assert await collect(adapter(agent)) == [
        chunk("a", first=True, last=False),
        chunk("b", first=False, last=True),
        Done(),
    ]


async def test_plain_json_text_completes(agent):
    async def h(_req):
        return JSONResponse({"text": "hi there"})

    agent.handler = h
    assert await collect(adapter(agent)) == [Done("hi there")]


async def test_plain_json_events_list(agent):
    async def h(_req):
        return JSONResponse(
            {"events": [{"type": "status", "text": "s"}, {"type": "need_input", "question": "q"}]}
        )

    agent.handler = h
    events = await collect(adapter(agent))
    assert events == [Status("s"), NeedInput("q")]


async def test_signature_headers_present_and_valid(agent):
    agent.ndjson({"type": "done"})
    before = int(time.time())
    await collect(adapter(agent, secret="shh"))
    headers, body = agent.requests[0]
    ts = headers["x-a2agw-timestamp"]
    assert before - 1 <= int(ts) <= int(time.time()) + 1
    assert headers["x-a2agw-signature"] == sign("shh", ts, body)
    assert headers["x-a2agw-protocol"] == PROTOCOL
    assert headers["content-type"] == "application/json"
    assert headers["accept"] == "application/x-ndjson, application/json"
    assert headers["accept-encoding"] == "identity"
    assert b"shh" not in body

    await collect(adapter(agent))  # no secret: no signature header
    headers, _ = agent.requests[1]
    assert "x-a2agw-signature" not in headers and "x-a2agw-timestamp" in headers


async def test_http_500_fails_without_body(agent, caplog):
    async def h(_req):
        return Response("internal SECRET-MARKER details", status_code=500)

    agent.handler = h
    with caplog.at_level(logging.DEBUG):
        events = await collect(adapter(agent))
    assert events == [Failed("agent returned HTTP 500")]
    assert "SECRET-MARKER" not in repr(events) and "SECRET-MARKER" not in caplog.text


async def test_malformed_line_fails_protocol_error(agent, caplog):
    async def h(_req):
        return Response(
            '{"type":"status","text":"ok"}\n{not json SECRET-MARKER\n', media_type=NDJSON
        )

    agent.handler = h
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        events = await collect(adapter(agent))
    assert events == [Status("ok"), Failed("agent protocol error")]
    records = [r for r in caplog.records if r.name == LOGGER]
    assert records and all(r.levelno == logging.WARNING for r in records)
    assert "SECRET-MARKER" not in caplog.text


@pytest.mark.parametrize(
    "body",
    [
        '{"type":"bogus"}\n',
        '{"type":"artifact","parts":[{"nope":1}]}\n',
        "[1, 2]\n",
    ],
)
async def test_invalid_events_fail_protocol_error(agent, body):
    async def h(_req):
        return Response(body, media_type=NDJSON)

    agent.handler = h
    assert await collect(adapter(agent)) == [Failed("agent protocol error")]


async def test_wrong_content_type_and_bad_json_shapes_fail(agent):
    bodies = [
        Response("hello", media_type="text/plain"),
        JSONResponse({"text": "a", "events": []}),
        JSONResponse({"other": 1}),
        JSONResponse({"text": 5}),
        Response("{broken", media_type="application/json"),
    ]
    for resp in bodies:

        async def h(_req, resp=resp):
            return resp

        agent.handler = h
        assert await collect(adapter(agent)) == [Failed("agent protocol error")]


async def test_oversized_line_fails(agent):
    prefix, suffix = '{"type":"status","text":"', '"}'
    fits = prefix + "a" * (MAX_LINE_BYTES - len(prefix) - len(suffix)) + suffix
    assert len(fits) == MAX_LINE_BYTES

    async def ok(_req):
        return Response(fits + "\n", media_type=NDJSON)

    agent.handler = ok
    events = await collect(adapter(agent))
    assert len(events) == 2 and isinstance(events[0], Status) and events[1] == Done()

    async def too_big(_req):  # one byte over, and no newline ever comes
        async def gen():
            yield b"x" * MAX_LINE_BYTES
            yield b"x"
            await asyncio.Event().wait()

        return StreamingResponse(gen(), media_type=NDJSON)

    agent.handler = too_big
    assert await collect(adapter(agent)) == [Failed("agent protocol error")]


async def test_response_and_event_limits(agent, monkeypatch):
    monkeypatch.setattr(webhook_mod, "MAX_EVENTS", 3)
    agent.ndjson(*[{"type": "status", "text": str(i)} for i in range(4)])
    events = await collect(adapter(agent))
    assert events == [Status("0"), Status("1"), Status("2"), Failed("agent protocol error")]

    monkeypatch.setattr(webhook_mod, "MAX_RESPONSE_BYTES", 100)
    agent.ndjson(*[{"type": "status", "text": "x" * 20} for _ in range(3)])
    events = await collect(adapter(agent))
    assert events[-1] == Failed("agent protocol error") and len(events) < 4

    async def h(_req):
        return JSONResponse({"text": "y" * 200})

    agent.handler = h
    assert await collect(adapter(agent)) == [Failed("agent protocol error")]


async def test_stall_times_out(agent):
    gone = asyncio.Event()

    async def h(_req):
        async def gen():
            try:
                yield b'{"type":"status","text":"started"}\n'
                await asyncio.Event().wait()
            finally:
                gone.set()

        return StreamingResponse(gen(), media_type=NDJSON)

    agent.handler = h
    start = time.monotonic()
    events = await collect(adapter(agent, timeout_s=0.2))
    assert events == [Status("started"), Failed("agent timed out")]
    assert time.monotonic() - start < 2.0
    await asyncio.wait_for(gone.wait(), 2.0)  # the connection was closed


async def test_cancel_closes_stream(agent):
    sent = asyncio.Event()
    gone = asyncio.Event()

    async def h(_req):
        async def gen():
            try:
                yield b'{"type":"status","text":"working"}\n'
                sent.set()
                await asyncio.Event().wait()
            finally:
                gone.set()

        return StreamingResponse(gen(), media_type=NDJSON)

    agent.handler = h
    got: list = []
    first = asyncio.Event()

    async def consume():
        async for ev in adapter(agent).run(ctx()):
            got.append(ev)
            first.set()

    task = asyncio.create_task(consume())
    await asyncio.wait_for(first.wait(), 2.0)
    assert sent.is_set() and not gone.is_set()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.wait_for(gone.wait(), 2.0)
    assert got == [Status("working")]


async def test_aclose_closes_stream(agent):
    gone = asyncio.Event()

    async def h(_req):
        async def gen():
            try:
                yield b'{"type":"text","text":"partial"}\n{"type":"status","text":"s"}\n'
                await asyncio.Event().wait()
            finally:
                gone.set()

        return StreamingResponse(gen(), media_type=NDJSON)

    agent.handler = h
    events = adapter(agent).run(ctx())
    assert await anext(events) == chunk("partial", first=True, last=False)
    await events.aclose()
    await asyncio.wait_for(gone.wait(), 2.0)


async def test_connection_lost_mid_stream(agent):
    async def h(_req):
        async def gen():
            yield b'{"type":"status","text":"s"}\n'
            raise ConnectionError("dropped")

        return StreamingResponse(gen(), media_type=NDJSON)

    agent.handler = h
    assert await collect(adapter(agent)) == [Status("s"), Failed("agent connection lost")]


async def test_unreachable_agent():
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    async with httpx.AsyncClient(transport=httpx.MockTransport(refuse)) as hc:
        events = await collect(WebhookAdapter(URL, http=hc))
    assert events == [Failed("agent unreachable")]


async def test_metadata_ip_refused_on_internal_tier(caplog, monkeypatch):
    vetted: list[str] = []
    connects: list[str] = []
    real_vetted = GuardedBackend._vetted

    async def spy_vetted(self, host, timeout):
        vetted.append(host)
        return await real_vetted(self, host, timeout)

    async def no_connect(self, host, *args, **kw):  # the socket layer must never be reached
        connects.append(host)
        raise AssertionError("connection attempted")

    monkeypatch.setattr(GuardedBackend, "_vetted", spy_vetted)
    monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", no_connect)
    a = WebhookAdapter("http://169.254.169.254/latest/meta-data")  # guarded client, tier internal
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        events = await collect(a)
    assert events == [Failed("agent unreachable")]
    assert vetted == ["169.254.169.254"]  # the guard ran ...
    assert connects == []  # ... and refused before any connection
    assert "unsafe address" in caplog.text and "169.254" not in caplog.text


async def test_undecodable_body_fails_protocol_error(caplog):
    def bad_gzip(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": NDJSON, "content-encoding": "gzip"},
            content=b"not gzip at all",
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(bad_gzip)) as hc:
        with caplog.at_level(logging.WARNING, logger=LOGGER):
            events = await collect(WebhookAdapter(URL, http=hc))
    assert events == [Failed("agent protocol error")]
    assert any(r.name == LOGGER and "DecodingError" in r.getMessage() for r in caplog.records)


async def test_other_request_errors_use_connection_state():
    # A RequestError that is not a TransportError: before the response, the agent was
    # never reached; after it, the connection was lost.
    def broken(_req: httpx.Request) -> httpx.Response:
        raise httpx.TooManyRedirects("loop")

    async with httpx.AsyncClient(transport=httpx.MockTransport(broken)) as hc:
        assert await collect(WebhookAdapter(URL, http=hc)) == [Failed("agent unreachable")]

    class Breaks(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b'{"type":"status","text":"s"}\n'
            raise httpx.RequestError("gone")

    def midway(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": NDJSON}, stream=Breaks())

    async with httpx.AsyncClient(transport=httpx.MockTransport(midway)) as hc:
        events = await collect(WebhookAdapter(URL, http=hc))
    assert events == [Status("s"), Failed("agent connection lost")]


async def test_deadline_sent_is_captured_at_turn_start(agent, monkeypatch):
    from a2agw.adapters import _sidecar

    clock = [1000.0]
    monkeypatch.setattr(_sidecar, "time", types.SimpleNamespace(time=lambda: clock[0]))

    async def slow_grant(_c: InboundContext) -> None:
        clock[0] += 50.0  # the grant takes a while; the turn's deadline does not move

    agent.ndjson({"type": "done"})
    await collect(adapter(agent, consult=slow_grant, timeout_s=300.0))
    assert json.loads(agent.requests[0][1])["deadline"] == 1300.0


async def test_consult_setup_failure_and_timeout(agent, caplog):
    agent.ndjson({"type": "done"})

    async def boom(_c: InboundContext):
        raise RuntimeError("SECRET-MARKER detail")

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        events = await collect(adapter(agent, consult=boom))
    assert events == [Failed("agent consult setup failed")]
    assert "RuntimeError" in caplog.text and "SECRET-MARKER" not in caplog.text
    assert agent.requests == []  # nothing sent

    async def hang(_c: InboundContext):
        await asyncio.Event().wait()

    start = time.monotonic()
    events = await collect(adapter(agent, consult=hang, timeout_s=0.2))
    assert events == [Failed("agent timed out")]
    assert time.monotonic() - start < 2.0 and agent.requests == []


async def test_end_without_terminal_is_done(agent):
    agent.ndjson({"type": "status", "text": "only"})
    assert await collect(adapter(agent)) == [Status("only"), Done()]

    async def empty(_req):
        return Response("", media_type=NDJSON)

    agent.handler = empty
    assert await collect(adapter(agent)) == [Done()]


async def test_consult_grant_is_sent(agent):
    from a2agw.gateway.protocol import ConsultGrant

    seen: list[str] = []

    async def grant(c: InboundContext) -> ConsultGrant:
        seen.append(c.task_id)
        return ConsultGrant(url="http://gw/consult", token="g-tok", expires_at=42.0)

    agent.ndjson({"type": "done"})
    await collect(adapter(agent, consult=grant))
    assert seen == ["t1"]
    sent = json.loads(agent.requests[0][1])
    assert sent["consult"] == {"url": "http://gw/consult", "token": "g-tok", "expires_at": 42.0}


def test_constructor_validates_url_and_options():
    assert WebhookAdapter(URL, durable_sessions=True).durable_sessions is True
    assert WebhookAdapter(URL).durable_sessions is False
    for bad in ("ftp://agent/x", "not a url", "http://user:pw@agent/"):
        with pytest.raises(ValueError):
            WebhookAdapter(bad)
    with pytest.raises(ValueError, match="https"):
        WebhookAdapter("http://agent.example.com/", tier="partner")
    with pytest.raises(ValueError):
        WebhookAdapter(URL, timeout_s=0)
