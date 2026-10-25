"""Spec section 8 boundary conditions that had no test of their own (docs/boundary-conditions.md
maps every condition to its tests). Partners are real AgentHost agents behind a
``faults.FaultInjector``; the consulting side is a real PartnerClient."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import httpx
import pytest
from a2a.types import Part
from faults import (
    FaultInjector,
    close_connection,
    drop_stream_after,
    latency,
    malformed_body,
    status,
)
from google.protobuf.json_format import MessageToDict
from streaming_asgi import StreamingASGITransport

from a2agw.consult import client as client_mod
from a2agw.consult.client import PartnerClient
from a2agw.consult.handles import OutboundHandleStore
from a2agw.consult.registry import PartnerRegistry
from a2agw.core.events import ArtifactChunk, Done, NeedAuth, Status
from a2agw.ops.bus import EventBus
from a2agw.serve.agent import AgentSpec, SkillSpec
from a2agw.serve.host import AgentHost
from a2agw.serve.store import create_engine

# -- partner adapters -----------------------------------------------------------------


class Echo:
    durable_sessions = False

    async def run(self, ctx):
        yield Done(text=f"echo: {ctx.text}")


class Gated:
    """Works until ``gate`` is set; ``chunks`` artifact pieces are streamed before and after."""

    durable_sessions = False

    def __init__(self, chunks: list[str] | None = None) -> None:
        self.gate = asyncio.Event()
        self.started = asyncio.Event()
        self.chunks = chunks or []

    async def run(self, ctx):
        yield Status(text="thinking")
        half = len(self.chunks) // 2
        for i, piece in enumerate(self.chunks[:half]):
            yield ArtifactChunk([Part(text=piece)], artifact_id="a1", append=i > 0, last=False)
        self.started.set()
        await self.gate.wait()
        for j, piece in enumerate(self.chunks[half:], start=half):
            last = j == len(self.chunks) - 1
            yield ArtifactChunk([Part(text=piece)], artifact_id="a1", append=j > 0, last=last)
        yield Done(text="finally")


class AuthNeeded:
    durable_sessions = False

    async def run(self, ctx):
        yield NeedAuth(scheme="oauth2", detail="sign in at the partner first")


def spec(agent_id: str, adapter: Any, **kw: Any) -> AgentSpec:
    return AgentSpec(
        id=agent_id,
        name=agent_id.title(),
        description="Test partner",
        skills=[SkillSpec(id="s", name="S", description="d")],
        adapter=adapter,
        **kw,
    )


def methods(transport: StreamingASGITransport) -> list[str]:
    out = []
    for _, _, body in transport.requests:
        try:
            out.append(json.loads(body)["method"])
        except (ValueError, KeyError, TypeError):
            out.append("")
    return out


# -- fixture --------------------------------------------------------------------------


class Env:
    def __init__(self, host, faults, transport, hc, registry, handles, client, engine):
        self.host = host
        self.faults: FaultInjector = faults
        self.transport: StreamingASGITransport = transport
        self.hc = hc
        self.registry: PartnerRegistry = registry
        self.handles: OutboundHandleStore = handles
        self.client: PartnerClient = client
        self.engine = engine

    def card(self, agent_id: str) -> dict:
        return MessageToDict(self.host.cards[agent_id])

    def new_client(self) -> PartnerClient:
        """A second PartnerClient on the same handle store: the consulting gateway after a
        restart."""
        return PartnerClient(
            self.registry, handles=self.handles, bus=EventBus(), http=self.hc, agent_id="me"
        )


@pytest.fixture
async def env(tmp_path, monkeypatch):
    monkeypatch.setenv("A2AGW_DEV", "1")
    monkeypatch.setattr(client_mod, "POLL_MIN_S", 0.02)
    monkeypatch.setattr(client_mod, "POLL_MAX_S", 0.05)
    monkeypatch.setattr(client_mod, "WAIT_ANY_INTERVAL_S", 0.05)
    monkeypatch.setattr(client_mod, "RETRY_BASE_S", 0.001)
    monkeypatch.setattr(client_mod, "RETRY_CAP_S", 0.002)
    monkeypatch.setattr(client_mod, "LOOKUP_FLOOR_S", 0.02)
    made: list[Env] = []

    async def _make(*specs: AgentSpec, register: bool = True) -> Env:
        host = AgentHost("http://t", db_url=f"sqlite+aiosqlite:///{tmp_path / 'host.db'}")
        for s in specs:
            host.add(s)
        await host.startup()
        faults = FaultInjector(host.app(), {})
        transport = StreamingASGITransport({"t": faults})
        hc = httpx.AsyncClient(transport=transport)
        registry = PartnerRegistry(http=hc)
        engine = await create_engine(f"sqlite+aiosqlite:///{tmp_path / 'out.db'}")
        handles = OutboundHandleStore(engine)
        await handles.initialize()
        client = PartnerClient(registry, handles=handles, bus=EventBus(), http=hc, agent_id="me")
        e = Env(host, faults, transport, hc, registry, handles, client, engine)
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


# -- 1. partner down or slow ----------------------------------------------------------


async def test_partner_down_gives_unavailable_then_opens_breaker(env):
    e = await env(spec("alpha", Echo()))
    e.faults.plan.update(
        {
            "SendStreamingMessage": close_connection(),
            "ListTasks": close_connection(),
        }
    )
    for _ in range(5):
        res = await e.client.consult("alpha", "x", wait_seconds=2)
        assert res.state == "unavailable"
    seen = len(e.transport.requests)
    res = await e.client.consult("alpha", "x", wait_seconds=2)
    assert res.state == "unavailable" and res.reason == "circuit open"
    assert res.retry_after_s is not None and 0 < res.retry_after_s <= 30
    assert len(e.transport.requests) == seen  # the open breaker sent nothing


async def test_partner_5xx_before_accepting_is_unavailable_not_failed(env):
    e = await env(spec("alpha", Echo()))
    e.faults.plan.update({"SendStreamingMessage": status(503), "ListTasks": status(503)})
    res = await e.client.consult("alpha", "x", wait_seconds=2)
    # A 503 may come from a proxy after the partner accepted: the task is looked up (not
    # re-sent), and with none found the delivery is unknown.
    assert res.state == "unavailable" and res.reason == "delivery unknown"
    assert methods(e.transport) == ["SendStreamingMessage", "ListTasks"]


async def test_slow_partner_past_the_deadline_is_unavailable(env):
    e = await env(spec("alpha", Echo()))
    e.faults.plan["SendStreamingMessage"] = latency(3)
    t0 = time.monotonic()
    res = await e.client.consult("alpha", "x", wait_seconds=0.3)
    assert time.monotonic() - t0 < 2.5  # the deadline, not the partner, ended the call
    assert res.state == "unavailable" and res.reason == "delivery unknown"
    assert methods(e.transport) == ["SendStreamingMessage", "ListTasks"]  # never re-sent


async def test_malformed_partner_body_is_a_protocol_failure(env):
    e = await env(spec("alpha", Echo(), streaming=False))
    e.faults.plan["SendMessage"] = malformed_body()
    res = await e.client.consult("alpha", "x", wait_seconds=2)
    assert res.state == "failed" and res.reason == "partner error: A2AClientError"
    assert methods(e.transport) == ["SendMessage"]


# -- 3. stream drops mid-task ---------------------------------------------------------


async def test_stream_and_resubscribe_drop_fall_back_to_polling(env):
    gated = Gated(chunks=["alpha-", "beta-", "gamma-", "delta"])
    e = await env(spec("slow", gated))
    e.faults.plan.update(
        {
            "SendStreamingMessage": drop_stream_after(2, times=1),
            "SubscribeToTask": close_connection(),
        }
    )

    async def release() -> None:
        await gated.started.wait()
        await asyncio.sleep(0.2)
        gated.gate.set()

    releaser = asyncio.create_task(release())
    res = await e.client.consult("slow", "go", wait_seconds=5)
    await asyncio.wait_for(releaser, 5)
    assert res.state == "completed"
    calls = methods(e.transport)
    assert calls.count("SendStreamingMessage") == 1  # never re-sent
    assert "SubscribeToTask" in calls and "GetTask" in calls  # resubscribe, then poll
    # Every chunk exactly once, in order, although events were seen on the dropped stream
    # and the whole task again when polling.
    assert res.text.split("\n") == ["alpha-", "beta-", "gamma-", "delta", "finally"]
    [a1] = [a for a in res.artifacts if a.get("artifact_id", a.get("id")) == "a1"] or [
        res.artifacts[0]
    ]
    assert [p["text"] for p in a1["parts"]] == ["alpha-", "beta-", "gamma-", "delta"]


# -- 4. gateway restarts mid-task: outbound handles resume ----------------------------


async def test_outbound_handle_survives_consulting_gateway_restart(env):
    gated = Gated()
    e = await env(spec("slow", gated))
    res = await e.client.consult("slow", "go", wait_seconds=1.0, inbound_task_id="in-1")
    assert res.state == "working" and res.task_id
    await e.client.aclose()  # the consulting gateway goes away
    restarted = e.new_client()
    try:
        [row] = await e.handles.by_inbound("in-1")
        assert row["task_id"] == res.task_id and row["partner_id"] == "slow"
        gated.gate.set()
        [done] = await restarted.wait_any([(row["partner_id"], row["task_id"])], 5)
        assert done.state == "completed" and done.text == "finally"
        [row] = await e.handles.by_inbound("in-1")
        assert row["state"] == "TASK_STATE_COMPLETED"
    finally:
        await restarted.aclose()


# -- 5. duplicate deliveries: one messageId, one partner task --------------------------


async def test_lost_response_is_looked_up_not_resent(env):
    e = await env(spec("alpha", Echo()))
    e.faults.plan["SendStreamingMessage"] = drop_stream_after(0, times=1)
    res = await e.client.consult("alpha", "x", wait_seconds=5)
    assert res.state == "completed" and res.text == "echo: x"
    calls = methods(e.transport)
    assert calls.count("SendStreamingMessage") == 1
    rows, _ = await e.host.index.list(agent_id="alpha")
    assert len(rows) == 1  # the partner ran the message once


# -- 6. version mismatch --------------------------------------------------------------


async def test_inbound_unsupported_version_is_a_clear_error(env):
    e = await env(spec("alpha", Echo()))
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "SendMessage",
        "params": {"message": {"messageId": "m1", "role": "ROLE_USER", "parts": [{"text": "x"}]}},
    }
    for version in ("2.0", "0.1"):
        r = await e.hc.post("http://t/agents/alpha/", json=body, headers={"A2A-Version": version})
        err = r.json()["error"]
        assert err["code"] == -32009 and version in err["message"]
    rows, _ = await e.host.index.list(agent_id="alpha")
    assert rows == []


async def test_outbound_partner_without_a_version_we_speak_is_explicit(env):
    e = await env(spec("alpha", Echo()), register=False)
    card = e.card("alpha")
    for iface in card["supportedInterfaces"]:
        iface["protocolVersion"] = "0.2"
    await e.registry.add_from_card("old", card, "internal")
    res = await e.client.consult("old", "x", wait_seconds=2)
    assert res.state == "unavailable" and res.reason == "no supported protocol version"
    assert e.transport.requests == []  # no silent fallback to another version


async def test_outbound_partner_rejecting_our_version_is_a_clear_failure(env):
    """A newer partner that refuses A2A-Version 1.0 (VersionNotSupportedError): the call
    fails with that reason and is not retried under another version."""
    e = await env(spec("alpha", Echo()), register=False)

    async def refuse(scope, receive, send):
        body = json.loads((await receive())["body"])
        error = {"code": -32009, "message": "A2A version '1.0' is not supported"}
        payload = json.dumps({"jsonrpc": "2.0", "id": body.get("id"), "error": error})
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": payload.encode()})

    e.transport.apps["v2"] = refuse
    card = e.card("alpha")
    card["supportedInterfaces"] = [
        {"url": "http://v2/rpc", "protocolBinding": "JSONRPC", "protocolVersion": "2.0"}
    ]
    card["capabilities"]["streaming"] = False
    await e.registry.add_from_card("v2", card, "internal")
    res = await e.client.consult("v2", "x", wait_seconds=2)
    assert res.state == "failed" and res.reason
    assert "version" in res.reason.lower()
    assert [h for h, _, _ in e.transport.requests] == ["v2"]


# -- 11. auth expiry mid-task: auth-required is surfaced -------------------------------


async def test_partner_auth_required_is_surfaced(env):
    e = await env(spec("locked", AuthNeeded()))
    res = await e.client.consult("locked", "x", wait_seconds=5)
    assert res.state == "auth_required" and res.task_id
    assert "sign in at the partner first" in (res.question or res.text or "")


# -- 12. multi-tenant partners --------------------------------------------------------


@pytest.mark.parametrize("streaming", [True, False])
async def test_tenant_routed_per_interface(env, streaming):
    e = await env(spec("alpha", Echo(), tenant="acme", streaming=streaming), register=False)
    await e.registry.add_from_card("alpha", e.card("alpha"), "internal")
    res = await e.client.consult("alpha", "x", wait_seconds=5)
    assert res.state == "completed"
    sent = [json.loads(b) for _, _, b in e.transport.requests if b]
    assert sent and all(m["params"].get("tenant") == "acme" for m in sent)


async def test_tenant_routed_for_rest_interface(env):
    e = await env(spec("alpha", Echo(), tenant="acme"), register=False)
    card = e.card("alpha")
    card["supportedInterfaces"] = [
        i for i in card["supportedInterfaces"] if i["protocolBinding"] == "HTTP+JSON"
    ]
    await e.registry.add_from_card("alpha", card, "internal")
    res = await e.client.consult("alpha", "x", wait_seconds=5)
    assert res.state == "completed"
    paths = [p for _, p, _ in e.transport.requests]
    assert paths and all(p.startswith("/agents/alpha/rest/acme/") for p in paths)


# -- 13. 0.3-only partners ------------------------------------------------------------


def _v03_card(url: str) -> dict:
    return {
        "name": "Legacy",
        "description": "A 0.3 partner",
        "version": "1.0",
        "url": url,
        "preferredTransport": "JSONRPC",
        "protocolVersion": "0.3.0",
        "capabilities": {"streaming": False},
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [{"id": "s", "name": "S", "description": "d", "tags": ["s"]}],
    }


async def test_v03_only_partner_consulted_in_compat_mode_and_flagged(env):
    e = await env(spec("alpha", Echo(), streaming=False), register=False)
    rec = await e.registry.add_from_card("legacy", _v03_card("http://t/agents/alpha/"), "internal")
    assert rec.v03_only is True
    res = await e.client.consult("legacy", "hello", wait_seconds=5)
    assert res.state == "completed" and res.text == "echo: hello"
    assert methods(e.transport)[0] == "message/send"  # the 0.3 method name
    current = await e.registry.add_from_card("current", e.card("alpha"), "internal")
    assert current.v03_only is False


async def test_inbound_v03_request_served_by_compat_mode(env):
    e = await env(spec("alpha", Echo()))
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "message/send",
        "params": {
            "message": {
                "messageId": "m1",
                "role": "user",
                "kind": "message",
                "parts": [{"kind": "text", "text": "legacy"}],
            }
        },
    }
    r = await e.hc.post("http://t/agents/alpha/", json=body, headers={"A2A-Version": "0.3"})
    result = r.json()["result"]
    assert result["kind"] == "task" and result["status"]["state"] == "completed"
    assert result["artifacts"][0]["parts"][0]["text"] == "echo: legacy"
