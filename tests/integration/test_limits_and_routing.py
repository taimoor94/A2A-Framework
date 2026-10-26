"""I2 (files raise egress classification), I7 (per-caller and per-task caps), I8 (forbid)."""

from __future__ import annotations

import asyncio
import hashlib
import uuid

import httpx
import pytest
from a2a.client import ClientConfig, ClientFactory
from a2a.types import Message, Part, Role, SendMessageConfiguration, SendMessageRequest
from a2a.utils.errors import InvalidRequestError
from cascade_support import Fn, spec
from streaming_asgi import StreamingASGITransport

from a2agw.context.call_context import current_agent
from a2agw.core.events import Done
from a2agw.security.auth import ApiKeyEntry, AuthConfig
from a2agw.security.classify import Classification, RegexPiiClassifier
from a2agw.security.policy import Policy, PolicyEngine


def engine_for(classifier=None, **doc) -> PolicyEngine:
    return PolicyEngine(Policy.model_validate({"version": 1, **doc}), classifier=classifier)


async def echo(ctx):
    yield Done(text=f"echo: {ctx.text}")


# -- I2: files floor the classification -------------------------------------------------


def test_policy_egress_floors_files_at_confidential_with_a_classifier():
    from a2agw.consult.registry import PartnerRecord

    rec = PartnerRecord(id="pub", card={}, card_hash="x", tier="public")
    with_classifier = engine_for(RegexPiiClassifier())
    d = with_classifier.egress("a", rec, None, "hello", None, has_files=True)
    assert not d.allowed and d.classification == Classification.CONFIDENTIAL
    assert with_classifier.egress("a", rec, None, "hello", None).allowed
    # Without a classifier the operator's labels alone decide (files are not inspected).
    assert engine_for().egress("a", rec, None, "hello", None, has_files=True).allowed


PUBLIC_CARD = {
    "name": "Pub",
    "description": "public partner",
    "version": "1.0",
    "supportedInterfaces": [
        {
            "url": "https://pub.example.com/rpc",
            "protocolBinding": "JSONRPC",
            "protocolVersion": "1.0",
        }
    ],
    "capabilities": {},
    "defaultInputModes": ["text/plain"],
    "defaultOutputModes": ["text/plain"],
    "skills": [{"id": "s1", "name": "S1", "description": "d", "tags": []}],
}


async def test_file_to_public_partner_is_denied_when_a_classifier_is_configured(env, monkeypatch):
    from a2agw.consult import netguard

    async def public(host):
        return ["93.184.216.34"]

    monkeypatch.setattr(netguard, "_resolve", public)
    e = await env(spec("a", Fn(echo)), policy=engine_for(RegexPiiClassifier()))
    await e.host.partners.add_from_card("pub", PUBLIC_CARD, "public")
    sent: list[str] = []
    orig = e.host.client._consult

    async def spy(pid, *a, **kw):
        sent.append(pid)
        return await orig(pid, *a, **kw)

    e.host.client._consult = spy
    res = await e.host.client.consult("pub", "see attached", files=[("a.txt", b"x", "text/plain")])
    assert res.state == "rejected"
    assert res.reason.startswith("egress policy: classification confidential exceeds public")
    assert sent == []
    # Positive control: the same message without a file passes the egress check.
    await e.host.client.consult("pub", "see attached", wait_seconds=0.5)
    assert sent == ["pub"]


# -- I8: routing forbid is enforced ------------------------------------------------------


async def test_consult_refuses_a_partner_forbidden_for_the_current_agent(env):
    policy = engine_for(routing=[{"agent": "a", "partners": ["b"], "mode": "forbid"}])
    e = await env(spec("a", Fn(echo)), spec("b", Fn(echo)), policy=policy)
    await e.register("b")
    calls: list[str] = []
    orig = e.host.client._prepare

    async def spy(pid):
        calls.append(pid)
        return await orig(pid)

    e.host.client._prepare = spy
    token = current_agent.set("a")
    try:
        res = await e.host.client.consult("b", "hi")
    finally:
        current_agent.reset(token)
    assert res.state == "unavailable" and res.reason == "forbidden by policy"
    assert calls == []  # nothing was prepared, let alone sent
    # Another agent (here the host itself) may still consult it.
    assert (await e.host.client.consult("b", "hi")).state == "completed"


def test_readme_and_demo_use_the_policy_filtered_tools():
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    pm = (root / "examples/software_team/pm.py").read_text()
    readme = (root / "README.md").read_text()
    assert "partner_tools(host.partners)" not in pm and "host.partner_tools(" in pm
    assert "partner_tools(host.partners)" not in readme


# -- I7: per-task fan-out cap --------------------------------------------------------------


async def test_fan_out_per_inbound_task_is_capped_and_released(env):
    e = await env(spec("b", Fn(echo)), max_consults_per_task=2)
    await e.register("b")
    c = e.host.client
    for _ in range(2):
        assert (await c.consult("b", "x", inbound_task_id="in-1")).state == "completed"
    res = await c.consult("b", "x", inbound_task_id="in-1")
    assert res.state == "unavailable" and res.reason == "fan-out limit reached for this task"
    # Another inbound task has its own budget.
    assert (await c.consult("b", "x", inbound_task_id="in-2")).state == "completed"
    # Released when the inbound task ends (the executor's end cascade).
    await c.cancel_for_inbound("in-1")
    assert (await c.consult("b", "x", inbound_task_id="in-1")).state == "completed"


async def test_fan_out_cap_applies_inside_a_running_agent(env):
    seen: list[str] = []

    async def fan(ctx):
        for _ in range(4):
            seen.append((await e.host.client.consult("b", "x")).state)
        yield Done(text="ok")

    e = await env(spec("a", Fn(fan)), spec("b", Fn(echo)), max_consults_per_task=3)
    await e.register("b")
    await e.send("a", "go")
    assert seen == ["completed", "completed", "completed", "unavailable"]


# -- I7: per-caller concurrency cap ------------------------------------------------------


def _h(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def _auth() -> AuthConfig:
    return AuthConfig(
        api_keys={
            _h("alice-secret"): ApiKeyEntry(principal_id="alice"),
            _h("bob-secret"): ApiKeyEntry(principal_id="bob"),
        }
    )


def _msg() -> Message:
    return Message(message_id=uuid.uuid4().hex, role=Role.ROLE_USER, parts=[Part(text="go")])


async def test_concurrent_tasks_per_caller_are_capped_isolated_and_released(env):
    gate = asyncio.Event()

    async def wait(ctx):
        await gate.wait()
        yield Done(text="done")

    e = await env(spec("a", Fn(wait)), auth=_auth(), max_concurrent_tasks_per_caller=2)

    def client(secret: str):
        hc = httpx.AsyncClient(
            transport=StreamingASGITransport({"t": e.host.app()}),
            base_url="http://t",
            headers={"X-API-Key": secret},
        )
        return hc, ClientFactory(ClientConfig(httpx_client=hc, streaming=False)).create(
            e.host.cards["a"]
        )

    async def send(c):
        req = SendMessageRequest(
            message=_msg(), configuration=SendMessageConfiguration(return_immediately=True)
        )
        return [ev async for ev in c.send_message(req)]

    hca, alice = client("alice-secret")
    hcb, bob = client("bob-secret")
    try:
        await send(alice)
        await send(alice)
        await asyncio.sleep(0.05)  # both runs have started
        with pytest.raises(InvalidRequestError, match="too many concurrent tasks"):
            await send(alice)
        await send(bob)  # another principal is not affected
        gate.set()
        for _ in range(200):  # the runs end and release their slots
            if e.host.caller_limiter.count("key:alice") == 0:
                break
            await asyncio.sleep(0.01)
        assert e.host.caller_limiter.count("key:alice") == 0
        await send(alice)
    finally:
        gate.set()
        await hca.aclose()
        await hcb.aclose()
    await e.host.audit.drain()
    rows, _ = await e.host.audit.query({"action": "limit.exceeded"}, 10)
    assert [(r["actor"], r["agent_id"], r["detail"].get("limit")) for r in rows] == [
        ("key:alice", "a", "max_concurrent_tasks_per_caller")
    ]


async def test_caller_cap_counts_streaming_sends(env):
    gate = asyncio.Event()
    started = asyncio.Semaphore(0)

    async def wait(ctx):
        started.release()
        await gate.wait()
        yield Done(text="done")

    e = await env(spec("a", Fn(wait)), auth=_auth(), max_concurrent_tasks_per_caller=1)
    hc = httpx.AsyncClient(
        transport=StreamingASGITransport({"t": e.host.app()}),
        base_url="http://t",
        headers={"X-API-Key": "alice-secret"},
    )
    stream = ClientFactory(ClientConfig(httpx_client=hc, streaming=True)).create(e.host.cards["a"])
    try:
        first = asyncio.create_task(_drain(stream.send_message(SendMessageRequest(message=_msg()))))
        await asyncio.wait_for(started.acquire(), 5)
        with pytest.raises(InvalidRequestError):
            await _drain(stream.send_message(SendMessageRequest(message=_msg())))
        gate.set()
        await asyncio.wait_for(first, 5)
        assert e.host.caller_limiter.count("key:alice") == 0
    finally:
        gate.set()
        await hc.aclose()


async def _drain(it):
    return [ev async for ev in it]
