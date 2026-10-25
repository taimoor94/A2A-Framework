"""OAuth2 outbound credentials: client credentials and RFC 8693 token exchange."""

from __future__ import annotations

import asyncio
import base64
import time
import uuid
from urllib.parse import parse_qs

import httpx
import jwt
import pytest
import respx
from a2a.client import ClientConfig, ClientFactory
from a2a.types import (
    CancelTaskRequest,
    Message,
    Part,
    Role,
    SendMessageConfiguration,
    SendMessageRequest,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from google.protobuf.json_format import MessageToDict
from streaming_asgi import StreamingASGITransport

from a2agw.consult import netguard, oauth
from a2agw.consult.credentials import CredentialError, MissingCredential
from a2agw.consult.netguard import UnsafeURL
from a2agw.consult.oauth import OAuthClientCredentials, OAuthTokenExchange, TokenError
from a2agw.consult.registry import PartnerRecord
from a2agw.context.call_context import current_inbound_token, use_inbound_token, use_maintenance
from a2agw.core.events import Done, Status
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
            side_effect=[token_response("tok-1", 100), token_response("tok-2", "100")]
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
        # expires_in "100" (a numeric string) was honoured: tok-2 is cached.
        now[0] += 60
        assert await creds.headers(partner(), None) == {"Authorization": "Bearer tok-2"}
        assert route.call_count == 2
        # invalidate() of a token other than the cached one keeps the cached one.
        assert creds.invalidate(partner(), "tok-1") is True
        assert await creds.headers(partner(), None) == {"Authorization": "Bearer tok-2"}
        assert creds.invalidate(partner("other"), "tok-2") is False
        # invalidate() of the cached token drops it.
        assert creds.invalidate(partner(), "tok-2") is True
        route.mock(return_value=token_response("tok-3"))
        assert await creds.headers(partner(), None) == {"Authorization": "Bearer tok-3"}


async def test_tokens_are_scoped_to_refs(public_dns, secret_env):
    creds = OAuthClientCredentials(TOKEN_URL, "client-1", "OAUTH_SECRET", refs={"oauth"})
    unscoped = OAuthClientCredentials(TOKEN_URL, "client-1", "OAUTH_SECRET")  # refs=None
    for bad in (None, set()):
        with pytest.raises(ValueError, match="refs"):
            OAuthTokenExchange(TOKEN_URL, "client-1", "OAUTH_SECRET", "aud", bad)
    exchange = OAuthTokenExchange(TOKEN_URL, "client-1", "OAUTH_SECRET", "aud", {"oauth"})
    with respx.mock(assert_all_called=False) as rx:
        route = rx.post(TOKEN_URL).mock(return_value=token_response("tok"))
        with use_inbound_token("a.b.c"):
            for provider in (creds, unscoped, exchange):
                assert await provider.headers(partner(None), None) == {}  # no credential_ref
            for provider in (creds, exchange):
                assert await provider.headers(partner("other"), None) == {}  # not in refs
                assert provider.invalidate(partner("other")) is False
            assert route.call_count == 0
            # refs=None means "any partner with a credential_ref".
            assert await unscoped.headers(partner("other"), None) == {"Authorization": "Bearer tok"}
            assert await exchange.headers(partner(), None) == {"Authorization": "Bearer tok"}


async def test_single_flight_refresh(public_dns, secret_env):
    creds = OAuthClientCredentials(TOKEN_URL, "client-1", "OAUTH_SECRET")

    async def slow(request):
        await asyncio.sleep(0.05)
        return token_response("tok-1")

    with respx.mock as rx:
        route = rx.post(TOKEN_URL).mock(side_effect=slow)
        got = await asyncio.gather(*(creds.headers(partner(), None) for _ in range(10)))
    assert route.call_count == 1
    assert all(h == {"Authorization": "Bearer tok-1"} for h in got)


async def test_idp_outage_is_shared_not_refetched(public_dns, secret_env, monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(oauth, "_now", lambda: now[0])
    creds = OAuthClientCredentials(TOKEN_URL, "client-1", "OAUTH_SECRET")

    async def down(request):
        await asyncio.sleep(0.05)
        return httpx.Response(503)

    with respx.mock as rx:
        route = rx.post(TOKEN_URL).mock(side_effect=down)
        got = await asyncio.gather(
            *(creds.headers(partner(), None) for _ in range(10)), return_exceptions=True
        )
        assert all(isinstance(g, TokenError) for g in got)
        assert route.call_count == 1
        now[0] += oauth.NEGATIVE_CACHE_S  # the failure is forgotten: next call retries
        route.mock(return_value=token_response("tok-1"))
        assert await creds.headers(partner(), None) == {"Authorization": "Bearer tok-1"}
        assert route.call_count == 2


async def test_token_url_ssrf_rejected(public_dns, secret_env):
    with pytest.raises(UnsafeURL):
        OAuthClientCredentials("ftp://auth.example.com/token", "c", "OAUTH_SECRET")
    with pytest.raises(UnsafeURL):
        OAuthTokenExchange(
            "https://u:p@auth.example.com/token", "c", "OAUTH_SECRET", "aud", {"oauth"}
        )
    with respx.mock(assert_all_called=False) as rx:
        route = rx.route().mock(return_value=token_response("never"))
        for url in (
            "https://169.254.169.254/latest/token",
            "https://127.0.0.1/token",
            "https://internal.corp/token",
        ):
            creds = OAuthClientCredentials(url, "c", "OAUTH_SECRET")
            with pytest.raises(TokenError) as info:
                await creds.headers(partner(), None)
            assert isinstance(info.value, CredentialError)
            assert "unsafe" in str(info.value)
        assert route.call_count == 0


async def test_secret_never_in_repr_or_errors(public_dns, secret_env, monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(oauth, "_now", lambda: now[0])
    creds = OAuthClientCredentials(TOKEN_URL, "client-1", "OAUTH_SECRET")
    with respx.mock as rx:
        rx.post(TOKEN_URL).mock(
            return_value=httpx.Response(400, json={"error": "invalid_client", "echo": SECRET})
        )
        with pytest.raises(TokenError) as info:
            await creds.headers(partner(), None)
        assert SECRET not in str(info.value) and "invalid_client" not in str(info.value)
        assert info.value.__cause__ is None

        now[0] += oauth.NEGATIVE_CACHE_S
        rx.post(TOKEN_URL).mock(return_value=token_response("live-token-xyz"))
        await creds.headers(partner(), None)
    for text in (repr(creds), str(vars(creds))):
        assert SECRET not in text
    assert "live-token-xyz" not in repr(creds)

    exchange = OAuthTokenExchange(TOKEN_URL, "client-1", "OAUTH_SECRET", "aud", {"oauth"})
    assert SECRET not in repr(exchange)
    with pytest.raises(MissingCredential):  # no inbound token to exchange
        await exchange.headers(partner(), None)

    monkeypatch.delenv("OAUTH_SECRET")
    creds.invalidate(partner())
    with pytest.raises(MissingCredential) as missing:
        await creds.headers(partner(), None)
    assert "OAUTH_SECRET" in str(missing.value)


async def test_token_exchange_cache_is_per_subject(public_dns, secret_env):
    exchange = OAuthTokenExchange(
        TOKEN_URL, "client-1", "OAUTH_SECRET", "partner-aud", refs={"oauth"}
    )
    with respx.mock as rx:
        route = rx.post(TOKEN_URL).mock(
            side_effect=[token_response("for-a"), token_response("for-b")]
        )
        for subject, expected in (("a.b.c", "for-a"), ("d.e.f", "for-b"), ("a.b.c", "for-a")):
            with use_inbound_token(subject):
                assert await exchange.headers(partner(), None) == {
                    "Authorization": f"Bearer {expected}"
                }
    assert route.call_count == 2
    assert form(route.calls[0].request) == {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": "a.b.c",
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "audience": "partner-aud",
        "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
    }


async def test_exchange_fallback_only_for_maintenance_calls(public_dns, secret_env):
    class Service:
        async def headers(self, partner, caller):
            return {"Authorization": "Bearer service"}

    exchange = OAuthTokenExchange(
        TOKEN_URL, "client-1", "OAUTH_SECRET", "aud", {"oauth"}, fallback=Service()
    )
    with pytest.raises(MissingCredential):  # an ordinary call without an inbound token
        await exchange.headers(partner(), None)
    with use_maintenance():
        assert await exchange.headers(partner(), None) == {"Authorization": "Bearer service"}
    with respx.mock as rx:  # with an inbound token, the exchange wins even in maintenance
        rx.post(TOKEN_URL).mock(return_value=token_response("exchanged"))
        with use_maintenance(), use_inbound_token("a.b.c"):
            assert await exchange.headers(partner(), None) == {"Authorization": "Bearer exchanged"}


# -- end to end: the inbound JWT is exchanged for the partner call ---------------------

ISS, AUD = "https://issuer.example", "a2agw"


class Echo:
    durable_sessions = False

    async def run(self, ctx):
        yield Done(text=f"echo: {ctx.text}")


class Gated:
    durable_sessions = False

    def __init__(self) -> None:
        self.gate = asyncio.Event()

    async def run(self, ctx):
        yield Status(text="thinking")
        await self.gate.wait()
        yield Done(text="finally")


class Forward:
    """Consults ``back``; with ``hold`` it then waits (so the inbound task stays working)."""

    durable_sessions = False

    def __init__(self, *, wait_seconds: float = 5, hold: bool = False) -> None:
        self.host: AgentHost | None = None
        self.wait_seconds = wait_seconds
        self.hold = hold
        self.seen_tokens: list[str | None] = []
        self.consulted = asyncio.Event()

    async def run(self, ctx):
        assert self.host is not None and self.host.client is not None
        self.seen_tokens.append(current_inbound_token.get())
        res = await self.host.client.consult("back", ctx.text, wait_seconds=self.wait_seconds)
        self.consulted.set()
        if self.hold:
            yield Status(text=f"{res.state}")
            await asyncio.Event().wait()
        yield Done(text=f"{res.state}: {res.text}")


def spec(agent_id: str, adapter) -> AgentSpec:
    return AgentSpec(
        id=agent_id,
        name=agent_id.title(),
        description="t",
        skills=[SkillSpec(id="s", name="S", description="d")],
        adapter=adapter,
    )


class JwtHosts:
    """``front`` (JWT auth, token exchange) consults ``back`` (no auth) over in-process HTTP."""

    def __init__(self, tmp_path, forward: Forward, back_adapter) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        pub = (
            self.key.public_key()
            .public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            .decode()
        )
        self.back = AgentHost("http://back", db_url=f"sqlite+aiosqlite:///{tmp_path / 'b.db'}")
        self.back.add(spec("back", back_adapter))
        self.partner_hc = httpx.AsyncClient(
            transport=StreamingASGITransport({"back": self.back.app()})
        )
        self.front = AgentHost(
            "http://front",
            db_url=f"sqlite+aiosqlite:///{tmp_path / 'f.db'}",
            auth=AuthConfig(jwt=JwtConfig(issuer=ISS, audience=AUD, public_key_pem=pub)),
            credentials=OAuthTokenExchange(
                TOKEN_URL, "gw-client", "OAUTH_SECRET", "back-aud", refs={"xchg"}
            ),
            partner_http=self.partner_hc,
        )
        forward.host = self.front
        self.front.add(spec("front", forward))
        self.seen_auth: list[str] = []
        self._inbound: list[httpx.AsyncClient] = []

    def jwt(self, **extra) -> str:
        claims = {"sub": "alice", "iss": ISS, "aud": AUD, "exp": int(time.time()) + 300}
        return jwt.encode({**claims, **extra}, self.key, algorithm="ES256")

    async def start(self) -> None:
        await self.back.startup()
        await self.front.startup()
        await self.front.partners.add_from_card(
            "back", MessageToDict(self.back.cards["back"]), "internal", credential_ref="xchg"
        )

        async def hook(request: httpx.Request) -> None:
            self.seen_auth.append(request.headers.get("authorization", ""))

        self.partner_hc.event_hooks["request"].append(hook)

    def client(self, token: str):
        hc = httpx.AsyncClient(
            transport=StreamingASGITransport({"front": self.front.app()}),
            headers={"Authorization": f"Bearer {token}"},
        )
        self._inbound.append(hc)
        return ClientFactory(ClientConfig(httpx_client=hc, streaming=False)).create(
            self.front.cards["front"]
        )

    async def close(self) -> None:
        for hc in self._inbound:
            await hc.aclose()
        await self.front.shutdown()
        await self.partner_hc.aclose()
        await self.back.shutdown()


@pytest.fixture
async def jwt_hosts(tmp_path, public_dns, secret_env, monkeypatch):
    monkeypatch.setenv("A2AGW_DEV", "1")
    made: list[JwtHosts] = []

    async def make(forward: Forward, back_adapter) -> JwtHosts:
        hosts = JwtHosts(tmp_path, forward, back_adapter)
        made.append(hosts)
        await hosts.start()
        return hosts

    yield make
    for hosts in made:
        await hosts.close()


def user_msg(text: str) -> Message:
    return Message(message_id=uuid.uuid4().hex, role=Role.ROLE_USER, parts=[Part(text=text)])


async def test_token_exchange_uses_inbound_token(jwt_hosts):
    forward = Forward()
    h = await jwt_hosts(forward, Echo())
    inbound_jwt = h.jwt()
    with respx.mock as rx:
        route = rx.post(TOKEN_URL).mock(return_value=token_response("exchanged-1"))
        client = h.client(inbound_jwt)
        req = SendMessageRequest(message=user_msg("hi"))
        events = [ev async for ev in client.send_message(req)]
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
    assert h.seen_auth and all(a == "Bearer exchanged-1" for a in h.seen_auth)
    # The adapter run saw the caller's token; it was reset once the run ended.
    assert forward.seen_tokens == [inbound_jwt]
    assert current_inbound_token.get() is None


async def test_user_cancel_cascades_with_cancellers_token(jwt_hosts):
    gated = Gated()
    forward = Forward(wait_seconds=0.2, hold=True)
    h = await jwt_hosts(forward, gated)
    start_jwt, cancel_jwt = h.jwt(jti="start"), h.jwt(jti="cancel")
    assert start_jwt != cancel_jwt
    try:
        with respx.mock as rx:
            route = rx.post(TOKEN_URL).mock(
                side_effect=[token_response("for-start"), token_response("for-cancel")]
            )
            req = SendMessageRequest(message=user_msg("go"))
            req.configuration.CopyFrom(SendMessageConfiguration(return_immediately=True))
            [first] = [ev async for ev in h.client(start_jwt).send_message(req)]
            task_id = first.task.id
            assert h.front.handles is not None
            # Once the consult has returned a working handle, only the cancel cascade can
            # cancel the partner task (not the cleanup of an interrupted consult).
            await asyncio.wait_for(forward.consulted.wait(), 5)
            [row] = await h.front.handles.by_inbound(task_id)
            assert row["caller_id"] == "jwt:alice"
            await h.client(cancel_jwt).cancel_task(CancelTaskRequest(id=task_id))
        assert route.call_count == 2
        assert form(route.calls[1].request)["subject_token"] == cancel_jwt
        assert h.seen_auth[-1] == "Bearer for-cancel"
        [after] = await h.front.handles.by_inbound(task_id)
        assert after["state"] == "TASK_STATE_CANCELED"
    finally:
        gated.gate.set()
