"""OAuth2 outbound credentials: client credentials and RFC 8693 token exchange."""

from __future__ import annotations

import asyncio
import base64
import time
from urllib.parse import parse_qs

import httpx
import jwt
import pytest
import respx
from a2a.client import ClientConfig, ClientFactory
from a2a.types import Message, Part, Role, SendMessageRequest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from google.protobuf.json_format import MessageToDict
from streaming_asgi import StreamingASGITransport

from a2agw.consult import netguard, oauth
from a2agw.consult.credentials import CredentialError, MissingCredential
from a2agw.consult.netguard import UnsafeURL
from a2agw.consult.oauth import OAuthClientCredentials, OAuthTokenExchange, TokenError
from a2agw.consult.registry import PartnerRecord
from a2agw.context.call_context import current_inbound_token
from a2agw.core.events import Done
from a2agw.security.auth import AuthConfig, JwtConfig
from a2agw.serve.agent import AgentSpec, SkillSpec
from a2agw.serve.host import AgentHost

TOKEN_URL = "https://auth.example.com/oauth/token"
SECRET = "s3cr3t-client-value"


@pytest.fixture
def public_dns(monkeypatch):
    async def fake(host: str) -> list[str]:
        if host == "internal.corp":
            return ["10.0.0.7"]
        return ["93.184.216.34"]

    monkeypatch.setattr(netguard, "_resolve", fake)


@pytest.fixture
def secret_env(monkeypatch):
    monkeypatch.setenv("OAUTH_SECRET", SECRET)


def partner(ref: str | None = "oauth") -> PartnerRecord:
    return PartnerRecord(
        id="p1",
        card_url="https://p1.example.com/card",
        card={"name": "p1"},
        card_hash="h",
        tier="public",
        status="active",
        credential_ref=ref,
    )


def token_response(tok: str, expires_in: float | None = 300) -> httpx.Response:
    body: dict = {"access_token": tok, "token_type": "Bearer"}
    if expires_in is not None:
        body["expires_in"] = expires_in
    return httpx.Response(200, json=body)


def form(request: httpx.Request) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(request.content.decode()).items()}


def basic(request: httpx.Request) -> tuple[str, str]:
    scheme, _, value = request.headers["authorization"].partition(" ")
    assert scheme == "Basic"
    user, _, pw = base64.b64decode(value).decode().partition(":")
    return user, pw


async def test_client_credentials_caches_until_expiry(public_dns, secret_env, monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(oauth, "_now", lambda: now[0])
    creds = OAuthClientCredentials(
        TOKEN_URL, "client-1", "OAUTH_SECRET", scope="read", audience="partners", refs={"oauth"}
    )
    with respx.mock(assert_all_called=True) as rx:
        route = rx.post(TOKEN_URL).mock(
            side_effect=[token_response("tok-1", 100), token_response("tok-2", 100)]
        )
        assert await creds.headers(partner(), None) == {"Authorization": "Bearer tok-1"}
        now[0] += 69  # 31 s before expiry: still cached
        assert await creds.headers(partner(), None) == {"Authorization": "Bearer tok-1"}
        assert route.call_count == 1
        now[0] += 2  # within the 30 s margin: refreshed
        assert await creds.headers(partner(), None) == {"Authorization": "Bearer tok-2"}
        assert route.call_count == 2
        req = route.calls[0].request
        assert form(req) == {
            "grant_type": "client_credentials",
            "scope": "read",
            "audience": "partners",
        }
        assert req.headers["content-type"] == "application/x-www-form-urlencoded"
        assert basic(req) == ("client-1", SECRET)
        # Partners outside ``refs`` get nothing.
        assert await creds.headers(partner("other"), None) == {}
        assert route.call_count == 2
        # invalidate() drops the cached token.
        creds.invalidate(partner())
        route.mock(return_value=token_response("tok-3"))
        assert await creds.headers(partner(), None) == {"Authorization": "Bearer tok-3"}


async def test_single_flight_refresh(public_dns, secret_env):
    creds = OAuthClientCredentials(TOKEN_URL, "client-1", "OAUTH_SECRET")  # refs=None: all

    async def slow(request):
        await asyncio.sleep(0.05)
        return token_response("tok-1")

    with respx.mock as rx:
        route = rx.post(TOKEN_URL).mock(side_effect=slow)
        got = await asyncio.gather(*(creds.headers(partner(None), None) for _ in range(10)))
    assert route.call_count == 1
    assert all(h == {"Authorization": "Bearer tok-1"} for h in got)


async def test_token_url_ssrf_rejected(public_dns, secret_env):
    with pytest.raises(UnsafeURL):
        OAuthClientCredentials("ftp://auth.example.com/token", "c", "OAUTH_SECRET")
    with pytest.raises(UnsafeURL):
        OAuthTokenExchange("https://u:p@auth.example.com/token", "c", "OAUTH_SECRET", "aud")
    with respx.mock(assert_all_called=False) as rx:
        route = rx.route().mock(return_value=token_response("never"))
        for url in (
            "https://169.254.169.254/latest/token",
            "https://127.0.0.1/token",
            "https://internal.corp/token",
        ):
            creds = OAuthClientCredentials(url, "c", "OAUTH_SECRET")
            with pytest.raises(TokenError) as info:
                await creds.headers(partner(None), None)
            assert isinstance(info.value, CredentialError)
            assert "unsafe" in str(info.value)
        assert route.call_count == 0


async def test_secret_never_in_repr_or_errors(public_dns, secret_env, monkeypatch):
    creds = OAuthClientCredentials(TOKEN_URL, "client-1", "OAUTH_SECRET")
    with respx.mock as rx:
        rx.post(TOKEN_URL).mock(
            return_value=httpx.Response(400, json={"error": "invalid_client", "echo": SECRET})
        )
        with pytest.raises(TokenError) as info:
            await creds.headers(partner(), None)
        assert SECRET not in str(info.value) and "invalid_client" not in str(info.value)
        assert info.value.__cause__ is None

        rx.post(TOKEN_URL).mock(return_value=token_response("live-token-xyz"))
        await creds.headers(partner(), None)
    for text in (repr(creds), str(vars(creds))):
        assert SECRET not in text
    assert "live-token-xyz" not in repr(creds)

    exchange = OAuthTokenExchange(TOKEN_URL, "client-1", "OAUTH_SECRET", "aud")
    assert SECRET not in repr(exchange)
    with pytest.raises(MissingCredential):  # no inbound token to exchange
        await exchange.headers(partner(), None)

    monkeypatch.delenv("OAUTH_SECRET")
    creds.invalidate(partner())
    with pytest.raises(MissingCredential) as missing:
        await creds.headers(partner(), None)
    assert "OAUTH_SECRET" in str(missing.value)


async def test_token_exchange_cache_is_per_subject(public_dns, secret_env):
    exchange = OAuthTokenExchange(TOKEN_URL, "client-1", "OAUTH_SECRET", "partner-aud")
    with respx.mock as rx:
        route = rx.post(TOKEN_URL).mock(
            side_effect=[token_response("for-a"), token_response("for-b")]
        )
        for subject, expected in (("a.b.c", "for-a"), ("d.e.f", "for-b"), ("a.b.c", "for-a")):
            token = current_inbound_token.set(subject)
            try:
                assert await exchange.headers(partner(), None) == {
                    "Authorization": f"Bearer {expected}"
                }
            finally:
                current_inbound_token.reset(token)
    assert route.call_count == 2
    assert form(route.calls[0].request) == {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": "a.b.c",
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "audience": "partner-aud",
        "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
    }


# -- end to end: the inbound JWT is exchanged for the partner call ---------------------

ISS, AUD = "https://issuer.example", "a2agw"


class Echo:
    durable_sessions = False

    async def run(self, ctx):
        yield Done(text=f"echo: {ctx.text}")


class Forward:
    durable_sessions = False

    def __init__(self) -> None:
        self.host: AgentHost | None = None

    async def run(self, ctx):
        assert self.host is not None and self.host.client is not None
        res = await self.host.client.consult("back", ctx.text, wait_seconds=5)
        yield Done(text=f"{res.state}: {res.text}")


def spec(agent_id: str, adapter) -> AgentSpec:
    return AgentSpec(
        id=agent_id,
        name=agent_id.title(),
        description="t",
        skills=[SkillSpec(id="s", name="S", description="d")],
        adapter=adapter,
    )


async def test_token_exchange_uses_inbound_token(tmp_path, public_dns, secret_env, monkeypatch):
    monkeypatch.setenv("A2AGW_DEV", "1")
    key = ec.generate_private_key(ec.SECP256R1())
    pub = (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    inbound_jwt = jwt.encode(
        {"sub": "alice", "iss": ISS, "aud": AUD, "exp": int(time.time()) + 300},
        key,
        algorithm="ES256",
    )

    back = AgentHost("http://back", db_url=f"sqlite+aiosqlite:///{tmp_path / 'back.db'}")
    back.add(spec("back", Echo()))
    await back.startup()
    partner_transport = StreamingASGITransport({"back": back.app()})
    partner_hc = httpx.AsyncClient(transport=partner_transport)

    forward = Forward()
    front = AgentHost(
        "http://front",
        db_url=f"sqlite+aiosqlite:///{tmp_path / 'front.db'}",
        auth=AuthConfig(jwt=JwtConfig(issuer=ISS, audience=AUD, public_key_pem=pub)),
        credentials=OAuthTokenExchange(
            TOKEN_URL, "gw-client", "OAUTH_SECRET", "back-aud", refs={"xchg"}
        ),
        partner_http=partner_hc,
    )
    forward.host = front
    front.add(spec("front", forward))
    await front.startup()
    await front.partners.add_from_card(
        "back", MessageToDict(back.cards["back"]), "internal", credential_ref="xchg"
    )
    seen_auth: list[str] = []

    async def hook(request: httpx.Request) -> None:
        seen_auth.append(request.headers.get("authorization", ""))

    partner_hc.event_hooks["request"].append(hook)
    inbound = httpx.AsyncClient(
        transport=StreamingASGITransport({"front": front.app()}),
        headers={"Authorization": f"Bearer {inbound_jwt}"},
    )
    try:
        with respx.mock as rx:
            route = rx.post(TOKEN_URL).mock(return_value=token_response("exchanged-1"))
            client = ClientFactory(ClientConfig(httpx_client=inbound, streaming=False)).create(
                front.cards["front"]
            )
            msg = Message(message_id="m1", role=Role.ROLE_USER, parts=[Part(text="hi")])
            events = [ev async for ev in client.send_message(SendMessageRequest(message=msg))]
        task = events[-1].task if events[-1].HasField("task") else None
        assert task is not None
        texts = [p.text for a in task.artifacts for p in a.parts] + [
            p.text for p in task.status.message.parts
        ]
        assert any("completed: echo: hi" in t for t in texts), texts
        assert route.call_count == 1
        sent = form(route.calls[0].request)
        assert sent["subject_token"] == inbound_jwt
        assert sent["grant_type"] == "urn:ietf:params:oauth:grant-type:token-exchange"
        assert sent["audience"] == "back-aud"
        assert basic(route.calls[0].request) == ("gw-client", SECRET)
        assert seen_auth and all(a == "Bearer exchanged-1" for a in seen_auth)
        # The contextvar does not leak out of the request.
        assert current_inbound_token.get() is None
    finally:
        await inbound.aclose()
        await front.shutdown()
        await partner_hc.aclose()
        await back.shutdown()
