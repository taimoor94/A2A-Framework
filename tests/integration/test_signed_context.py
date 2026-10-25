"""Signed call contexts between gateways: outbound signing, inbound trust, cross-gateway loops."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx
import jwt
import pytest
from a2a.client import ClientConfig, ClientFactory
from a2a.types import SendMessageRequest, TaskState
from cascade_support import Fn, msg, spec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from google.protobuf.json_format import MessageToDict
from streaming_asgi import StreamingASGITransport

from a2agw.consult import client as client_mod
from a2agw.context.call_context import EXTENSION_URI, CallContext, use_call
from a2agw.context.signing import JWS_METADATA_KEY, CallContextSigner, CallContextVerifier
from a2agw.core.events import Done
from a2agw.security.cardsign import load_public_key
from a2agw.serve.host import AgentHost


def _keypair(tmp_path, name: str):
    key = ec.generate_private_key(ec.SECP256R1())
    priv = tmp_path / f"{name}.pem"
    priv.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    pub = tmp_path / f"{name}.pub.pem"
    pub.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return priv, pub


@pytest.fixture
def gw_keys(tmp_path):
    """Signers for gateways A and B, and a verifier that trusts both issuers."""
    a_priv, a_pub = _keypair(tmp_path, "gw-a")
    b_priv, b_pub = _keypair(tmp_path, "gw-b")
    trusted = {
        "gw-a": ("https://a.example", load_public_key(a_pub)),
        "gw-b": ("https://b.example", load_public_key(b_pub)),
    }
    return {
        "a": CallContextSigner(a_priv, "gw-a", "ES256", "https://a.example"),
        "b": CallContextSigner(b_priv, "gw-b", "ES256", "https://b.example"),
        "verifier": CallContextVerifier(trusted),
        "trusts_a": CallContextVerifier({"gw-a": trusted["gw-a"]}),
        "trusts_b": CallContextVerifier({"gw-b": trusted["gw-b"]}),
    }


async def until(predicate, timeout: float = 5.0) -> None:
    async with asyncio.timeout(timeout):
        while not await predicate():
            await asyncio.sleep(0.02)


# -- outbound ---------------------------------------------------------------------------


async def test_outbound_jws_attached_and_verifies(env, gw_keys):
    seen: dict[str, Any] = {}

    async def b_run(ctx):
        seen["md"] = ctx.metadata
        seen["call"] = ctx.call
        yield Done(text="ok")

    e = await env(
        spec("b", Fn(b_run)),
        context_signer=gw_keys["a"],
        context_verifier=gw_keys["verifier"],
    )
    await e.register("b")
    deadline = time.time() + 42.9
    sent = CallContext(origin="o-1", root_agent="a", hop=1, path=("a",), deadline=deadline)
    with use_call(sent):
        res = await e.host.client.consult("b", "hi", wait_seconds=5)
    assert res.state == "completed"
    token = seen["md"][JWS_METADATA_KEY]
    verified = gw_keys["verifier"].verify(token)
    # Signed exactly as sent (R6: current_call unchanged), traceparent included.
    unsigned = CallContext.from_metadata({EXTENSION_URI: seen["md"][EXTENSION_URI]})
    assert verified == unsigned
    assert (verified.origin, verified.path, verified.hop) == ("o-1", ("a",), 1)
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["exp"] <= deadline
    assert claims["iss"] == "https://a.example"
    # B ran under the verified context.
    assert seen["call"].path == ("a", "b") and seen["call"].origin == "o-1"
    rows, _ = await e.host.audit.query({"action": "inbound.admit", "agent": "b"}, 10)
    assert [r["detail"]["context"] for r in rows] == ["signed"]


async def test_no_signer_no_jws(env):
    seen: dict[str, Any] = {}

    async def b_run(ctx):
        seen["md"] = ctx.metadata
        yield Done(text="ok")

    e = await env(spec("b", Fn(b_run)))
    await e.register("b")
    res = await e.host.client.consult("b", "hi", wait_seconds=5)
    assert res.state == "completed"
    assert JWS_METADATA_KEY not in seen["md"]
    assert EXTENSION_URI in seen["md"]


async def test_retries_do_not_resign(env, gw_keys, monkeypatch):
    monkeypatch.setattr(client_mod, "RETRY_BASE_S", 0.001)
    monkeypatch.setattr(client_mod, "RETRY_CAP_S", 0.002)
    seen: list[str] = []

    async def b_run(ctx):
        seen.append(ctx.metadata[JWS_METADATA_KEY])
        yield Done(text="ok")

    signer = gw_keys["a"]
    calls = 0
    real_sign = signer.sign

    def counting(cc):
        nonlocal calls
        calls += 1
        return real_sign(cc)

    monkeypatch.setattr(signer, "sign", counting)
    e = await env(spec("b", Fn(b_run)), context_signer=signer)
    await e.register("b")

    inner = e.partner_hc._transport

    class Flaky(httpx.AsyncBaseTransport):
        failed = 0

        async def handle_async_request(self, request):
            if request.method == "POST" and self.failed < 2:
                self.failed += 1
                raise httpx.ConnectError("refused", request=request)
            return await inner.handle_async_request(request)

    flaky = Flaky()
    e.partner_hc._transport = flaky
    res = await e.host.client.consult("b", "hi", wait_seconds=5)
    assert res.state == "completed"
    assert flaky.failed == 2
    assert calls == 1
    assert len(seen) == 1
    # A second consult signs afresh: nothing is cached across consults.
    res = await e.host.client.consult("b", "again", wait_seconds=5)
    assert calls == 2 and seen[0] != seen[1]


# -- inbound ----------------------------------------------------------------------------


async def test_inbound_tampered_jws_rejected_and_audited(env, gw_keys):
    async def b_run(ctx):
        yield Done(text="never")

    e = await env(spec("b", Fn(b_run)), context_verifier=gw_keys["verifier"])
    cc = CallContext(origin="o-2", root_agent="x", hop=1, path=("x",))
    token = gw_keys["a"].sign(cc)
    head, payload, sig = token.split(".")
    bad = f"{head}.{payload}.{sig[:-2]}{'AA' if sig[-2:] != 'AA' else 'BB'}"
    m = msg("hi")
    m.metadata.update({**cc.to_metadata(), JWS_METADATA_KEY: bad})
    [ev] = [ev async for ev in e.client("b").send_message(SendMessageRequest(message=m))]
    assert ev.task.status.state == TaskState.TASK_STATE_REJECTED
    assert ev.task.status.message.parts[0].text == "invalid call context"
    rows, _ = await e.host.audit.query({"action": "inbound.reject", "agent": "b"}, 10)
    [row] = rows
    assert row["detail"]["reason"] == "invalid call context"
    assert row["detail"]["context"] == "bad signature"
    assert bad not in str(row) and payload not in str(row)


async def test_inbound_jws_ignored_without_verifier(env, gw_keys):
    """A gateway that has not opted into signing keeps Phase 1 behaviour."""

    async def b_run(ctx):
        yield Done(text="ok")

    e = await env(spec("b", Fn(b_run)))
    cc = CallContext(origin="o-3", root_agent="x", hop=1, path=("x",))
    m = msg("hi")
    m.metadata.update({**cc.to_metadata(), JWS_METADATA_KEY: "not-a-token"})
    [ev] = [ev async for ev in e.client("b").send_message(SendMessageRequest(message=m))]
    assert ev.task.status.state == TaskState.TASK_STATE_COMPLETED


# -- two gateways -----------------------------------------------------------------------


@pytest.fixture
async def two_gateways(tmp_path, fast):
    made: list[tuple[AgentHost, httpx.AsyncClient]] = []

    async def _make(a_specs, b_specs, *, a_kw=None, b_kw=None):
        transport = StreamingASGITransport({})
        hcs = []
        hosts = []
        for name, specs, kw in (("a", a_specs, a_kw or {}), ("b", b_specs, b_kw or {})):
            hc = httpx.AsyncClient(transport=transport, base_url=f"http://{name}")
            host = AgentHost(
                f"http://{name}",
                db_url=f"sqlite+aiosqlite:///{tmp_path / f'{name}.db'}",
                partner_http=hc,
                **kw,
            )
            for s in specs:
                host.add(s)
            transport.apps[name] = host.app()
            await host.startup()
            made.append((host, hc))
            hcs.append(hc)
            hosts.append(host)
        return hosts[0], hosts[1], hcs[1]

    yield _make
    for host, hc in made:
        await host.shutdown()
        await hc.aclose()


@pytest.mark.parametrize("signed", [True, False])
async def test_two_gateway_loop(two_gateways, gw_keys, signed):
    """A (gateway A) consults B (gateway B). B forwards the call back to A with the signed
    context exactly as received but the unsigned path stripped and the hop reset. With
    signing, A sees the cycle in the signed path; without, only the re-entry rule catches it."""
    results: dict[str, Any] = {}

    async def a_run(ctx):
        if ctx.text == "start":
            results["a"] = await host_a.client.consult("b", "help", wait_seconds=5)
            yield Done(text="outer done")
        else:
            yield Done(text="nested ok")

    async def b_run(ctx):
        # A real call back takes a network round trip; wait until A has recorded its handle
        # for this task so A is visibly blocked downstream (as in the T15 re-entry test).
        async def recorded() -> bool:
            return await host_a.handles.get("b", ctx.task_id) is not None

        await until(recorded)
        cc = dict(ctx.metadata[EXTENSION_URI])
        cc["path"] = []
        cc["hop"] = 0
        back = msg("nested")
        back.metadata.update({EXTENSION_URI: cc})
        if JWS_METADATA_KEY in ctx.metadata:
            back.metadata.update({JWS_METADATA_KEY: ctx.metadata[JWS_METADATA_KEY]})
        results["forwarded_jws"] = JWS_METADATA_KEY in ctx.metadata
        req = SendMessageRequest(message=back)
        [ev] = [ev async for ev in a_client.send_message(req)]
        results["nested"] = ev.task
        yield Done(text="b done")

    a_kw = b_kw = {}
    if signed:
        # Each gateway trusts only the other's issuer: the host adds its own key itself.
        a_kw = {"context_signer": gw_keys["a"], "context_verifier": gw_keys["trusts_b"]}
        b_kw = {"context_signer": gw_keys["b"], "context_verifier": gw_keys["trusts_a"]}
    host_a, host_b, b_hc = await two_gateways(
        [spec("a", Fn(a_run))], [spec("b", Fn(b_run))], a_kw=a_kw, b_kw=b_kw
    )
    await host_a.partners.add_from_card("b", MessageToDict(host_b.cards["b"]), "internal")
    # B's gateway client calls A (the forwarding partner's call back, and the test's call).
    a_client = ClientFactory(ClientConfig(httpx_client=b_hc, streaming=False)).create(
        host_a.cards["a"]
    )
    [ev] = [ev async for ev in a_client.send_message(SendMessageRequest(message=msg("start")))]
    assert ev.task.status.state == TaskState.TASK_STATE_COMPLETED
    assert results["a"].state == "completed"
    assert results["forwarded_jws"] is signed
    nested = results["nested"]
    assert nested.status.state == TaskState.TASK_STATE_REJECTED
    reason = nested.status.message.parts[0].text
    assert reason == ("cycle detected" if signed else "re-entry")


async def test_signing_failure_fails_closed(env, gw_keys, monkeypatch):
    ran: list[str] = []

    async def b_run(ctx):
        ran.append(ctx.text)
        yield Done(text="ok")

    signer = gw_keys["a"]

    def broken(cc):
        raise RuntimeError("hsm offline")

    monkeypatch.setattr(signer, "sign", broken)
    e = await env(spec("b", Fn(b_run)), context_signer=signer)
    await e.register("b")
    sent_before = len(e.partner_hc._transport.requests)
    res = await e.host.client.consult("b", "hi", wait_seconds=5)
    assert (res.state, res.reason) == ("unavailable", "signing failed")
    assert ran == []
    assert len(e.partner_hc._transport.requests) == sent_before


def test_host_adds_own_key_to_verifier(tmp_path, gw_keys):
    trusts_b = gw_keys["trusts_b"]
    host = AgentHost(
        "http://a", context_signer=gw_keys["a"], context_verifier=trusts_b, audit=False
    )
    assert set(host.context_verifier.trusted) == {"gw-a", "gw-b"}
    assert host.context_verifier.trusted["gw-a"][0] == "https://a.example"
    assert set(trusts_b.trusted) == {"gw-b"}  # the caller's verifier is not mutated
    cc = CallContext(origin="o", root_agent="a", path=("a",))
    assert host.context_verifier.verify(gw_keys["a"].sign(cc)) == cc
    # Already trusted with the same issuer and key: accepted as is.
    both = AgentHost("http://a", context_signer=gw_keys["a"], context_verifier=gw_keys["verifier"])
    assert set(both.context_verifier.trusted) == {"gw-a", "gw-b"}
    # Only a verifier, or only a signer: nothing to add.
    assert AgentHost("http://a", context_verifier=trusts_b).context_verifier is trusts_b


def test_host_rejects_conflicting_own_kid(gw_keys):
    clash = CallContextVerifier({"gw-a": ("https://a.example", gw_keys["b"].public_jwk())})
    with pytest.raises(ValueError, match="gw-a"):
        AgentHost("http://a", context_signer=gw_keys["a"], context_verifier=clash)
    clash = CallContextVerifier({"gw-a": ("https://evil.example", gw_keys["a"].public_jwk())})
    with pytest.raises(ValueError, match="gw-a"):
        AgentHost("http://a", context_signer=gw_keys["a"], context_verifier=clash)
