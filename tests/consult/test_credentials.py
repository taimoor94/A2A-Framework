import httpx
import pytest
from a2a.client import ClientConfig, ClientFactory
from a2a.client.client import ClientCallContext
from a2a.client.errors import A2AClientError
from a2a.client.interceptors import BeforeArgs
from a2a.types import AgentCard, AgentInterface, SendMessageRequest

from a2agw.consult.credentials import (
    ChainCredentials,
    CredentialInterceptor,
    EnvCredentials,
    InvalidCredential,
    MissingCredential,
    StaticCredentials,
)
from a2agw.consult.registry import PartnerRecord
from a2agw.security.principal import Principal

SECRET = "s3cr3t-value-xyz"


def partner(ref="p1"):
    return PartnerRecord(id="p", card={}, card_hash="h", tier="partner", credential_ref=ref)


async def test_env_credentials_header(monkeypatch):
    monkeypatch.setenv("P1_TOKEN", SECRET)
    c = EnvCredentials({"p1": ("Authorization", "P1_TOKEN")})
    assert await c.headers(partner(), None) == {"Authorization": SECRET}


async def test_env_credentials_empty_when_no_or_unknown_ref():
    c = EnvCredentials({"p1": ("X-Key", "P1_TOKEN")})
    assert await c.headers(partner(None), None) == {}
    assert await c.headers(partner("other"), None) == {}


async def test_missing_env_raises_without_value_in_message(monkeypatch):
    monkeypatch.delenv("P1_TOKEN", raising=False)
    monkeypatch.setenv("OTHER_TOKEN", SECRET)
    c = EnvCredentials({"p1": ("X-Key", "P1_TOKEN")})
    with pytest.raises(MissingCredential) as ei:
        await c.headers(partner(), None)
    assert "p1" in str(ei.value) and "P1_TOKEN" in str(ei.value)
    assert SECRET not in str(ei.value) and SECRET not in repr(ei.value)
    monkeypatch.setenv("P1_TOKEN", "")
    with pytest.raises(MissingCredential):
        await c.headers(partner(), None)


async def test_static_and_chain():
    s = StaticCredentials({"p1": {"X-Key": SECRET}})
    assert await s.headers(partner(), None) == {"X-Key": SECRET}
    assert await s.headers(partner("zz"), None) == {}
    env = EnvCredentials({"p2": ("X-E", "NOPE")})
    chain = ChainCredentials(env, s)
    assert await chain.headers(partner("p1"), None) == {"X-Key": SECRET}
    assert await chain.headers(partner("zz"), None) == {}


def test_repr_does_not_leak():
    s = StaticCredentials({"p1": {"X-Key": SECRET}})
    assert SECRET not in repr(s)
    assert SECRET not in repr(ChainCredentials(s))
    assert SECRET not in str(MissingCredential("p1", "ENV"))


async def test_interceptor_sets_service_parameters():
    prov = StaticCredentials({"p1": {"X-Key": SECRET}})
    ic = CredentialInterceptor(prov, partner(), Principal("key:a", "api_key", frozenset()))
    args = BeforeArgs(input=None, method="send_message", agent_card=AgentCard(), context=None)
    await ic.before(args)
    assert args.context.service_parameters == {"X-Key": SECRET}
    ctx = ClientCallContext(service_parameters={"A": "b"})
    args2 = BeforeArgs(input=None, method="m", agent_card=AgentCard(), context=ctx)
    await ic.before(args2)
    assert ctx.service_parameters == {"A": "b", "X-Key": SECRET}


async def test_interceptor_headers_reach_httpx_request():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(500)

    card = AgentCard(
        name="x",
        description="d",
        version="1",
        supported_interfaces=[
            AgentInterface(url="http://t/rpc", protocol_binding="JSONRPC", protocol_version="1.0")
        ],
    )
    hc = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ic = CredentialInterceptor(StaticCredentials({"p1": {"X-Key": SECRET}}), partner())
    client = ClientFactory(ClientConfig(httpx_client=hc, streaming=False)).create(card, [ic])
    from a2a.helpers import new_text_message

    with pytest.raises(A2AClientError):
        async for _ in client.send_message(SendMessageRequest(message=new_text_message("hi"))):
            pass
    assert seen and seen[0].headers["X-Key"] == SECRET


async def test_env_rejects_crlf_without_leaking(monkeypatch):
    bad = "tok\r\nX-Evil: 1"
    monkeypatch.setenv("P1_TOKEN", bad)
    c = EnvCredentials({"p1": ("X-Key", "P1_TOKEN")})
    with pytest.raises(InvalidCredential) as ei:
        await c.headers(partner(), None)
    assert "tok" not in str(ei.value) and "Evil" not in str(ei.value)
    assert "p1" in str(ei.value) and "X-Key" in str(ei.value)


async def test_interceptor_rejects_crlf_from_any_provider():
    ic = CredentialInterceptor(StaticCredentials({"p1": {"X-Key": "a\nb" + SECRET}}), partner())
    args = BeforeArgs(input=None, method="m", agent_card=AgentCard(), context=None)
    with pytest.raises(InvalidCredential) as ei:
        await ic.before(args)
    assert SECRET not in str(ei.value)


async def test_interceptor_does_not_mutate_callers_dict():
    orig = {"A": "b"}
    ctx = ClientCallContext(service_parameters=orig)
    ic = CredentialInterceptor(StaticCredentials({"p1": {"X-Key": SECRET}}), partner())
    await ic.before(BeforeArgs(input=None, method="m", agent_card=AgentCard(), context=ctx))
    assert orig == {"A": "b"}
    assert ctx.service_parameters == {"A": "b", "X-Key": SECRET}


async def test_before_propagates_missing_credential(monkeypatch):
    monkeypatch.delenv("P1_TOKEN", raising=False)
    ic = CredentialInterceptor(EnvCredentials({"p1": ("X-Key", "P1_TOKEN")}), partner())
    with pytest.raises(MissingCredential):
        await ic.before(BeforeArgs(input=None, method="m", agent_card=AgentCard(), context=None))
