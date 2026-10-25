"""DNS-rebinding-proof outbound connections: every outbound client connects only to an IP
address it vetted itself, at connect time, for the host's tier."""

from __future__ import annotations

import asyncio
import datetime
import ssl
from typing import Any

import httpcore
import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from a2agw import cli
from a2agw.consult import client as client_mod
from a2agw.consult import guarded_net, netguard
from a2agw.consult.client import PartnerClient
from a2agw.consult.guarded_net import GuardedBackend, fixed_tier, guarded_async_client
from a2agw.consult.netguard import FetchError, UnsafeURL
from a2agw.consult.oauth import OAuthClientCredentials, TokenError
from a2agw.consult.registry import CardFetchError, PartnerRecord, PartnerRegistry
from a2agw.consult.tls import TlsClientConfig
from a2agw.core.events import Done
from a2agw.security.cardsign import CardSignatureError, CardVerifier
from a2agw.serve.agent import AgentSpec, SkillSpec
from a2agw.serve.host import AgentHost
from a2agw.serve.push import PushSettings

PUBLIC_IP = "93.184.216.34"
METADATA_IP = "169.254.169.254"


# -- helpers ---------------------------------------------------------------------------


class RecordingInner(httpcore.AsyncNetworkBackend):
    """Records the addresses it is asked to connect to. Connections to an address listed in
    ``route`` go to that local port on 127.0.0.1; everything else is refused."""

    def __init__(self, route: dict[str, int] | None = None) -> None:
        self.ips: list[str] = []
        self.route = route or {}
        self.real = httpcore.AnyIOBackend()

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        self.ips.append(host)
        if host not in self.route:
            raise httpcore.ConnectError("refused")
        return await self.real.connect_tcp("127.0.0.1", self.route[host], timeout=timeout)

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise httpcore.ConnectError("no unix sockets")

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)


def resolver(*answers: list[str]):
    """A resolver giving each answer in turn (the last one repeats)."""
    calls: list[str] = []

    async def resolve(host: str) -> list[str]:
        calls.append(host)
        return list(answers[min(len(calls), len(answers)) - 1])

    resolve.calls = calls  # type: ignore[attr-defined]
    return resolve


@pytest.fixture
async def http_server():
    """A plain HTTP/1.1 server on 127.0.0.1; records each request's Host header."""
    seen: list[str] = []

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        head = await reader.readuntil(b"\r\n\r\n")
        for line in head.decode("latin-1").split("\r\n"):
            if line.lower().startswith("host:"):
                seen.append(line.split(":", 1)[1].strip())
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    yield port, seen
    server.close()
    await server.wait_closed()


def _issue(cn, issuer_cert, issuer_key, *, ca=False, san=None, client=False):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    b = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_cert.subject if issuer_cert else name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if san:
        b = b.add_extension(x509.SubjectAlternativeName(san), critical=False)
    if not ca:
        eku = ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH
        b = b.add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
    return b.sign(issuer_key or key, hashes.SHA256()), key


def _write(path, cert, key) -> None:
    path.with_suffix(".crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    path.with_suffix(".key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    """A CA, a server cert for DNS name ``localhost`` only (no IP SAN) and a client cert."""
    d = tmp_path_factory.mktemp("gpki")
    ca, ca_key = _issue("guard-ca", None, None, ca=True)
    _write(d / "ca", ca, ca_key)
    _write(d / "server", *_issue("localhost", ca, ca_key, san=[x509.DNSName("localhost")]))
    _write(d / "client", *_issue("client", ca, ca_key, client=True))
    (d / "client.key").chmod(0o600)
    return d


@pytest.fixture
async def tls_server(pki):
    """A real TLS server on 127.0.0.1 presenting the ``localhost`` certificate. Records the SNI
    name of each handshake."""
    sni: list[str | None] = []
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(pki / "server.crt", pki / "server.key")
    ctx.sni_callback = lambda _sock, name, _ctx: sni.append(name)

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\ntls")
            await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=ctx)
    port = server.sockets[0].getsockname()[1]
    yield port, sni
    server.close()
    await server.wait_closed()


# -- the brief's tests -----------------------------------------------------------------


async def test_rebinding_between_check_and_connect_blocked(monkeypatch):
    rebind = resolver([PUBLIC_IP], [METADATA_IP])
    monkeypatch.setattr(netguard, "_resolve", rebind)
    url = "https://rebind.example/x"
    await netguard.check_url(url, "public")  # the first answer is public: check passes

    inner = RecordingInner()
    async with guarded_async_client(fixed_tier("public"), inner=inner) as c:
        with pytest.raises(httpx.ConnectError) as ei:
            await c.get(url)
    assert rebind.calls == ["rebind.example", "rebind.example"]  # resolved again at connect
    assert inner.ips == []  # never connected, least of all to the metadata address
    assert str(ei.value) == "unsafe address"

    # Without the guard, httpcore hands the *name* to the network backend, which resolves it
    # again on its own: whatever DNS answers at that moment is where the socket goes.
    plain = RecordingInner()
    pool = httpcore.AsyncConnectionPool(network_backend=plain)
    async with httpx.AsyncClient() as c:
        monkeypatch.setattr(c._transport, "_pool", pool)
        with pytest.raises(httpx.ConnectError):
            await c.get(url)
    assert plain.ips == ["rebind.example"]


async def test_rebinding_blocked_end_to_end_through_safe_get(monkeypatch):
    """The default safe_get client (card, JWKS and token fetches) re-resolves and refuses."""
    monkeypatch.setattr(netguard, "_resolve", resolver([PUBLIC_IP], [METADATA_IP]))
    connected: list[str] = []

    async def record(self, host, port, timeout=None, local_address=None, socket_options=None):
        connected.append(host)
        raise httpcore.ConnectError("refused")

    monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", record)
    with pytest.raises(FetchError, match="ConnectError"):
        await netguard.safe_get(
            "https://rebind.example/card", "public", max_bytes=100, deadline_s=5
        )
    assert connected == []


async def test_sni_hostname_preserved(tls_server, pki):
    port, sni = tls_server
    ca = ssl.create_default_context(cafile=str(pki / "ca.crt"))

    class Real(RecordingInner):
        async def connect_tcp(self, host, port, timeout=None, **kw):
            self.ips.append(host)
            return await self.real.connect_tcp(host, port, timeout=timeout)

    real = Real()
    async with guarded_async_client(fixed_tier("internal"), verify=ca, inner=real) as c:
        r = await c.get(f"https://localhost:{port}/")
    assert r.status_code == 200 and r.text == "tls"
    # The socket went to an IP address; TLS still verified (and sent SNI for) the hostname.
    assert real.ips and all(ip in ("127.0.0.1", "::1") for ip in real.ips)
    assert sni == ["localhost"]


async def test_sni_wrong_hostname_fails_verification(tls_server, pki):
    """Same IP, different hostname: verification is against the name, so it fails."""
    port, sni = tls_server
    ca = ssl.create_default_context(cafile=str(pki / "ca.crt"))
    to_local = resolver(["127.0.0.1"])
    async with guarded_async_client(fixed_tier("internal"), verify=ca, resolver=to_local) as c:
        with pytest.raises(httpx.ConnectError) as ei:
            await c.get(f"https://wrong.test:{port}/")
    assert sni == ["wrong.test"]
    assert to_local.calls == ["wrong.test"]
    chain, seen = [], ei.value
    while seen is not None and len(chain) < 10:
        chain.append(seen)
        seen = seen.__cause__ or seen.__context__
    assert any(isinstance(e, ssl.SSLCertVerificationError) for e in chain)


async def test_internal_tier_allows_private(http_server):
    port, seen = http_server
    async with guarded_async_client(fixed_tier("internal")) as c:
        assert (await c.get(f"http://127.0.0.1:{port}/")).text == "ok"
        assert (await c.get(f"http://localhost:{port}/")).text == "ok"
    for tier in ("partner", "public"):
        async with guarded_async_client(fixed_tier(tier)) as c:
            with pytest.raises(httpx.ConnectError, match="^unsafe address$"):
                await c.get(f"http://127.0.0.1:{port}/")
    assert len(seen) == 2


# -- backend behaviour -----------------------------------------------------------------


async def test_connects_to_vetted_ip_with_original_host_header(http_server):
    port, seen = http_server
    inner = RecordingInner({PUBLIC_IP: port})
    res = resolver([PUBLIC_IP])
    async with guarded_async_client(fixed_tier("public"), resolver=res, inner=inner) as c:
        r = await c.get("http://api.example.com/x")
    assert r.text == "ok"
    assert inner.ips == [PUBLIC_IP]
    assert seen == ["api.example.com"]


async def test_tries_next_vetted_address_on_connect_failure(http_server):
    port, _seen = http_server
    inner = RecordingInner({"93.184.216.35": port})  # the first address refuses
    res = resolver([PUBLIC_IP, "93.184.216.35", PUBLIC_IP])
    async with guarded_async_client(fixed_tier("public"), resolver=res, inner=inner) as c:
        assert (await c.get("http://api.example.com/")).text == "ok"
    assert inner.ips == [PUBLIC_IP, "93.184.216.35"]


async def test_connect_failure_on_every_address_is_connect_error():
    inner = RecordingInner()
    res = resolver([PUBLIC_IP, "93.184.216.35"])
    async with guarded_async_client(fixed_tier("public"), resolver=res, inner=inner) as c:
        with pytest.raises(httpx.ConnectError):
            await c.get("http://api.example.com/")
    assert inner.ips == [PUBLIC_IP, "93.184.216.35"]


@pytest.mark.parametrize(
    "answer",
    [
        [PUBLIC_IP, "10.0.0.5"],  # any private address taints the whole answer
        [METADATA_IP],
        ["::ffff:169.254.169.254"],
        ["127.0.0.1"],
    ],
)
async def test_any_disallowed_address_refuses_without_connecting(answer):
    inner = RecordingInner({PUBLIC_IP: 1})
    for tier in ("partner", "public"):
        backend = GuardedBackend(fixed_tier(tier), resolver=resolver(answer), inner=inner)
        with pytest.raises(httpcore.ConnectError) as ei:
            await backend.connect_tcp("evil.example", 443)
        assert str(ei.value) == "unsafe address"
        assert ei.value.__cause__ is None and ei.value.__suppress_context__
    assert inner.ips == []


async def test_ip_literal_vetted_directly():
    res = resolver([PUBLIC_IP])
    inner = RecordingInner()
    backend = GuardedBackend(fixed_tier("public"), resolver=res, inner=inner)
    with pytest.raises(httpcore.ConnectError, match="^unsafe address$"):
        await backend.connect_tcp(METADATA_IP, 80)
    with pytest.raises(httpcore.ConnectError, match="^refused$"):
        await backend.connect_tcp(PUBLIC_IP, 80)
    assert res.calls == []  # literals are never looked up
    assert inner.ips == [PUBLIC_IP]


async def test_error_messages_never_name_host_or_ip():
    async def unresolvable(host):
        raise OSError(f"cannot resolve {host}")

    cases = [
        GuardedBackend(fixed_tier("public"), resolver=resolver(["10.1.2.3"])),
        GuardedBackend(fixed_tier("internal"), resolver=unresolvable),
        GuardedBackend(fixed_tier("public"), resolver=unresolvable),
    ]
    for backend in cases:
        with pytest.raises(httpcore.ConnectError) as ei:
            await backend.connect_tcp("secret-host.example", 443)
        text = str(ei.value) + repr(ei.value)
        assert "secret-host" not in text and "10.1.2.3" not in text
        assert ei.value.__cause__ is None


async def test_tier_lookup_failure_fails_closed():
    def broken(host: str):
        raise RuntimeError("boom")

    inner = RecordingInner({PUBLIC_IP: 1})
    backend = GuardedBackend(broken, resolver=resolver([PUBLIC_IP]), inner=inner)
    with pytest.raises(httpcore.ConnectError, match="^unsafe address$"):
        await backend.connect_tcp("api.example.com", 443)
    assert inner.ips == []


async def test_resolution_timeout_is_connect_timeout():
    async def slow(host):
        await asyncio.sleep(5)
        return [PUBLIC_IP]

    backend = GuardedBackend(fixed_tier("public"), resolver=slow, inner=RecordingInner())
    with pytest.raises(httpcore.ConnectTimeout):
        await backend.connect_tcp("api.example.com", 443, timeout=0.05)


async def test_resolve_and_vet_shared_with_check_url(monkeypatch):
    monkeypatch.setattr(netguard, "_resolve", resolver([PUBLIC_IP, PUBLIC_IP, "2606:2800::1"]))
    assert await netguard.resolve_and_vet("a.example", "public") == [PUBLIC_IP, "2606:2800::1"]
    monkeypatch.setattr(netguard, "_resolve", resolver(["10.0.0.1"]))
    assert await netguard.resolve_and_vet("a.example", "internal") == ["10.0.0.1"]
    with pytest.raises(UnsafeURL, match="non-public"):
        await netguard.resolve_and_vet("a.example", "partner")
    calls: list[str] = []

    async def spy(host, tier, *, resolver=None):
        calls.append(tier)
        return [PUBLIC_IP]

    monkeypatch.setattr(netguard, "resolve_and_vet", spy)
    await netguard.check_url("https://a.example/", "public")
    await netguard.check_url("https://a.example/", "internal")  # R2: no lookup at all
    assert calls == ["public"]


def test_client_never_follows_redirects():
    c = guarded_async_client(fixed_tier("public"))
    assert c.follow_redirects is False
    for bad in ("follow_redirects", "transport", "mounts", "proxy"):
        with pytest.raises(TypeError):
            guarded_async_client(fixed_tier("public"), **{bad: True})


def test_pool_swap_installs_guarded_backend():
    """httpx does not let a transport take a network backend, so the guarded client replaces
    the transport's private ``_pool``. If httpx renames or restructures it this fails."""
    c = guarded_async_client(fixed_tier("public"), limits=httpx.Limits(max_connections=7))
    pool = c._transport._pool  # type: ignore[attr-defined]
    assert type(pool) is httpcore.AsyncConnectionPool
    assert isinstance(pool._network_backend, GuardedBackend)
    assert pool._max_connections == 7

    t = httpx.AsyncHTTPTransport()
    del t._pool
    with pytest.raises(RuntimeError, match="httpx"):
        guarded_net._swap_pool(t, httpcore.AsyncConnectionPool())


# -- tier resolution -------------------------------------------------------------------


def _rec(id: str, url: str, tier: str, iface: str | None = None) -> PartnerRecord:
    card: dict[str, Any] = {"name": id}
    if iface:
        card["supportedInterfaces"] = [
            {"url": iface, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
        ]
    return PartnerRecord(id=id, card_url=url, card=card, card_hash="h", tier=tier, status="active")


def test_partner_tier_for_host_from_registry():
    reg = PartnerRegistry()
    reg._records = {
        "a": _rec("a", "https://cards.a.example/card", "partner", "https://rpc.a.example/rpc"),
        "b": _rec("b", "http://internal.corp/card", "internal", "http://Svc.Corp:8080/rpc"),
        "c": _rec("c", "https://shared.example/c", "public"),
        "d": _rec("d", "https://shared.example/d", "internal"),
    }
    client = PartnerClient(reg)
    tier = client._tier_for_host
    assert tier("cards.a.example") == "partner"
    assert tier("rpc.a.example") == "partner"
    assert tier("svc.corp") == "internal"
    assert tier("shared.example") == "public"  # strictest of the partners claiming the host
    assert tier("unknown.example") == "public"


class Echo:
    durable_sessions = False

    async def run(self, ctx):
        yield Done(text="ok")


# -- every outbound path goes through the guard ----------------------------------------


@pytest.fixture
def recorded(monkeypatch):
    """Patch GuardedBackend.connect_tcp: record (host, tier), then refuse."""
    seen: list[tuple[str, str]] = []

    async def record(self, host, port, timeout=None, local_address=None, socket_options=None):
        seen.append((host, self._tier_for_host(host)))
        raise httpcore.ConnectError("recorded")

    monkeypatch.setattr(GuardedBackend, "connect_tcp", record)

    async def public(host):
        return [PUBLIC_IP]

    monkeypatch.setattr(netguard, "_resolve", public)
    return seen


CARD = {
    "name": "P",
    "description": "d",
    "version": "1",
    "supportedInterfaces": [
        {"url": "https://rpc.p.example/rpc", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
    ],
    "capabilities": {},
    "defaultInputModes": ["text/plain"],
    "defaultOutputModes": ["text/plain"],
    "skills": [{"id": "s", "name": "S", "description": "d", "tags": ["t"]}],
}


async def test_all_outbound_paths_use_guarded_client(recorded, pki, tmp_path, monkeypatch):
    monkeypatch.setattr(client_mod, "RETRY_BASE_S", 0.001)
    monkeypatch.setattr(client_mod, "RETRY_CAP_S", 0.002)
    tls = {"p": TlsClientConfig(pki / "client.crt", pki / "client.key", pki / "ca.crt")}

    # Card fetch (plain and mTLS).
    reg = PartnerRegistry(tls=tls)
    with pytest.raises(CardFetchError):
        await reg.add_from_url("x", "https://card.p.example", "partner")
    with pytest.raises(CardFetchError):
        await reg.add_from_url("y", "https://mtls.p.example", "internal", tls_ref="p")
    assert recorded[-2:] == [("card.p.example", "partner"), ("mtls.p.example", "internal")]

    # Partner calls: the shared client and the per-partner mTLS client.
    await reg.add_from_card("p", CARD, "partner")
    await reg.add_from_card("q", {**CARD, "name": "Q"}, "partner")
    reg._records["q"] = reg.get("q").model_copy(update={"tls_ref": "p"})
    client = PartnerClient(reg, tls=tls)
    try:
        for pid in ("p", "q"):
            n = len(recorded)
            res = await client.consult(pid, "hi", wait_seconds=2)
            assert res.state != "completed"
            assert recorded[n:] and set(recorded[n:]) == {("rpc.p.example", "partner")}
    finally:
        await client.aclose()

    # JWKS fetch.
    jwks = "https://keys.p.example/jwks.json"
    with pytest.raises(CardSignatureError):
        await CardVerifier(jwks_urls=[jwks])._fetch_jwks(jwks)
    assert recorded[-1] == ("keys.p.example", "public")

    # OAuth token endpoint.
    monkeypatch.setenv("G_SECRET", "x")
    oauth = OAuthClientCredentials("https://auth.p.example/token", "cid", "G_SECRET")
    with pytest.raises(TokenError):
        rec = _rec("p", "https://card.p.example", "partner")
        await oauth.headers(rec.model_copy(update={"credential_ref": "oauth"}), None)
    assert recorded[-1] == ("auth.p.example", "public")

    # Push deliveries, both settings.
    for allow_private, tier in ((True, "internal"), (False, "public")):
        host = AgentHost(
            "http://gw.test",
            db_url=f"sqlite+aiosqlite:///{tmp_path}/push{allow_private}.db",
            push=PushSettings(allow_private=allow_private, timeout_s=2),
            audit=False,
        )
        host.add(
            AgentSpec(
                id="a",
                name="A",
                description="d",
                skills=[SkillSpec(id="s", name="S", description="d")],
                adapter=Echo(),
            )
        )
        await host.startup()
        try:
            with pytest.raises(httpx.ConnectError):
                await host.push_senders["a"]._post("https://hook.p.example/h", b"{}", {})
        finally:
            await host.shutdown()
        assert recorded[-1] == ("hook.p.example", tier)

    # CLI call: card fetch, then the call itself, both with the --tier tier.
    n = len(recorded)
    with pytest.raises(CardFetchError):
        await cli._call("https://cli.p.example", "hi", None, "partner", 2)
    assert recorded[n:] == [("cli.p.example", "partner")]

    async def card_ok(self, id, url, tier, **kw):
        return await self.add_from_card(id, CARD, tier)

    monkeypatch.setattr(PartnerRegistry, "add_from_url", card_ok)
    n = len(recorded)
    with pytest.raises(ValueError, match="call failed"):
        await cli._call("https://rpc.p.example", "hi", None, "partner", 2)
    assert recorded[n:] and set(recorded[n:]) == {("rpc.p.example", "partner")}


async def test_injected_clients_bypass_the_guard(recorded):
    """``http=`` / ``partner_http`` are the test seam: they are used as given."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=CARD)

    hc = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    reg = PartnerRegistry(http=hc)
    await reg.add_from_url("p", "https://card.p.example", "partner")
    await hc.aclose()
    assert recorded == []


# -- Task 10: metadata on every tier, happy eyeballs, UnsafeAddress ----------------------


@pytest.mark.parametrize(
    "answer",
    [
        [METADATA_IP],
        ["fd00:ec2::254"],
        ["::ffff:169.254.169.254"],
        ["10.0.0.1", METADATA_IP],
        ["64:ff9b::a9fe:a9fe"],  # NAT64
        ["64:ff9b::6464:64c8"],  # NAT64 of 100.100.100.200
        ["2002:a9fe:a9fe::1"],  # 6to4
        ["::a9fe:a9fe"],  # IPv4-compatible
    ],
)
async def test_metadata_ip_refused_on_internal_tier(answer):
    with pytest.raises(UnsafeURL, match="metadata"):
        await netguard.resolve_and_vet("meta.internal", "internal", resolver=resolver(answer))
    inner = RecordingInner({a: 1 for a in answer})
    backend = GuardedBackend(fixed_tier("internal"), resolver=resolver(answer), inner=inner)
    with pytest.raises(guarded_net.UnsafeAddress, match="^unsafe address$"):
        await backend.connect_tcp("meta.internal", 80)
    assert inner.ips == []


@pytest.mark.parametrize(
    "url",
    [
        f"http://{METADATA_IP}/latest",
        "http://[fd00:ec2::254]/",
        "http://100.100.100.200/",
        "http://[::ffff:a9fe:a9fe]/",
        "http://[64:ff9b::a9fe:a9fe]/",
        "http://[2002:a9fe:a9fe::]/",
        "http://[::a9fe:a9fe]/",
        "http://2852039166/",  # decimal 169.254.169.254
        "http://0xa9fea9fe/",  # hex
    ],
)
async def test_check_url_refuses_metadata_literal_on_internal_tier(url):
    with pytest.raises(UnsafeURL, match="metadata"):
        await netguard.check_url(url, "internal")


async def test_check_url_internal_still_allows_private_and_unresolvable():
    await netguard.check_url("http://10.0.0.1/", "internal")
    await netguard.check_url("http://[64:ff9b::a00:5]/", "internal")  # NAT64 of 10.0.0.5
    await netguard.check_url("http://167772161/", "internal")  # decimal 10.0.0.1
    await netguard.check_url("http://169.254.1.1/", "internal")  # link-local, not metadata
    await netguard.check_url("http://no-such-host.invalid/", "internal")


class _Stream(httpcore.AsyncNetworkStream):
    def __init__(self, ip: str) -> None:
        self.ip = ip
        self.closed = False

    async def read(self, max_bytes, timeout=None):  # pragma: no cover - unused
        return b""

    async def write(self, buffer, timeout=None):  # pragma: no cover - unused
        return None

    async def aclose(self) -> None:
        self.closed = True


class _Scripted(httpcore.AsyncNetworkBackend):
    """Per-address scripted connects: ("hang",), ("ok", delay) or ("fail", delay)."""

    def __init__(self, script: dict[str, tuple]) -> None:
        self.script = script
        self.started: list[tuple[str, float]] = []
        self.cancelled: list[str] = []
        self.streams: list[_Stream] = []
        self.t0 = 0.0

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        loop = asyncio.get_running_loop()
        self.started.append((host, loop.time() - self.t0))
        action = self.script[host]
        try:
            if action[0] in ("hang", "slow_cancel"):
                await asyncio.sleep(3600)
            await asyncio.sleep(action[1])
        except asyncio.CancelledError:
            self.cancelled.append(host)
            if action[0] == "slow_cancel":  # a loser whose cancellation takes a while
                await asyncio.sleep(action[1])
            if action[0] != "stubborn":
                raise
            # Connected while being cancelled: the stream is handed back regardless.
        if action[0] == "fail":
            raise httpcore.ConnectError("refused")
        stream = _Stream(host)
        self.streams.append(stream)
        return stream

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise httpcore.ConnectError("no unix sockets")

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)


async def test_happy_eyeballs_blackholed_first_address_loses_to_second():
    second = "93.184.216.35"
    inner = _Scripted({PUBLIC_IP: ("hang",), second: ("ok", 0.01)})
    backend = GuardedBackend(
        fixed_tier("public"), resolver=resolver([PUBLIC_IP, second]), inner=inner
    )
    loop = asyncio.get_running_loop()
    inner.t0 = start = loop.time()
    stream = await asyncio.wait_for(backend.connect_tcp("api.example.com", 443, timeout=5), 4.5)
    elapsed = loop.time() - start
    assert stream.ip == second
    assert elapsed < 4.0  # not the 5 s timeout of the blackholed address
    assert [h for h, _ in inner.started] == [PUBLIC_IP, second]
    assert inner.started[1][1] >= guarded_net.HAPPY_EYEBALLS_DELAY_S * 0.9  # staggered
    assert inner.cancelled == [PUBLIC_IP]  # the loser was cancelled


async def test_happy_eyeballs_through_http_client(http_server):
    """End to end: the first vetted address blackholes, the second serves the request."""
    port, _seen = http_server

    class Blackhole(RecordingInner):
        async def connect_tcp(self, host, port, timeout=None, **kw):
            self.ips.append(host)
            if host == PUBLIC_IP:
                await asyncio.sleep(3600)
            return await self.real.connect_tcp("127.0.0.1", self.route[host], timeout=timeout)

    inner = Blackhole({"93.184.216.35": port})
    res = resolver([PUBLIC_IP, "93.184.216.35"])
    async with guarded_async_client(
        fixed_tier("public"), resolver=res, inner=inner, timeout=5
    ) as c:
        r = await asyncio.wait_for(c.get("http://api.example.com/"), 2)
    assert r.text == "ok"


async def test_happy_eyeballs_late_loser_stream_is_closed():
    """A losing attempt that still hands back a stream after the winner is chosen (it
    connected while being cancelled) has that stream closed."""
    second = "93.184.216.35"
    inner = _Scripted({PUBLIC_IP: ("stubborn", 3600), second: ("ok", 0.01)})
    backend = GuardedBackend(
        fixed_tier("public"), resolver=resolver([PUBLIC_IP, second]), inner=inner
    )
    stream = await asyncio.wait_for(backend.connect_tcp("api.example.com", 443, timeout=5), 3)
    assert stream.ip == second and not stream.closed
    (loser,) = [s for s in inner.streams if s is not stream]
    assert loser.ip == PUBLIC_IP and loser.closed


async def test_happy_eyeballs_keeps_overall_deadline():
    inner = _Scripted({PUBLIC_IP: ("hang",), "93.184.216.35": ("hang",)})
    backend = GuardedBackend(
        fixed_tier("public"), resolver=resolver([PUBLIC_IP, "93.184.216.35"]), inner=inner
    )
    loop = asyncio.get_running_loop()
    start = loop.time()
    with pytest.raises(httpcore.ConnectTimeout):
        await asyncio.wait_for(backend.connect_tcp("api.example.com", 443, timeout=0.4), 5)
    assert loop.time() - start < 3.0  # the 0.4 s overall deadline, not a hang
    assert sorted(inner.cancelled) == sorted([PUBLIC_IP, "93.184.216.35"])


async def test_unsafe_address_is_a_connect_error_detectable_through_httpx():
    assert issubclass(guarded_net.UnsafeAddress, httpcore.ConnectError)
    async with guarded_async_client(fixed_tier("public"), resolver=resolver(["10.0.0.1"])) as c:
        with pytest.raises(httpx.ConnectError) as ei:
            await c.get("http://api.example.com/")
    assert guarded_net.is_unsafe_address(ei.value)
    assert not guarded_net.is_unsafe_address(httpx.ConnectError("refused"))


# -- UnsafeAddress through the partner client --------------------------------------------


async def test_unsafe_partner_address_is_unavailable_and_not_retried(monkeypatch, caplog):
    """The host passed the endpoint check, then resolves somewhere private at connect time:
    one attempt (no retry), a breaker failure, an ``unavailable`` result, and a warning that
    names only the partner id."""
    calls: list[str] = []

    async def private(host):
        calls.append(host)
        return ["10.0.0.5"]

    reg = PartnerRegistry()
    monkeypatch.setattr(netguard, "_resolve", resolver([PUBLIC_IP]))
    await reg.add_from_card("p", CARD, "partner")
    monkeypatch.setattr(netguard, "_resolve", private)

    async def passed(_id):  # the endpoint check passed just before DNS changed
        return None

    monkeypatch.setattr(reg, "verify_endpoints", passed)
    client = PartnerClient(reg)
    try:
        with caplog.at_level("WARNING"):
            res = await client.consult("p", "hi", wait_seconds=5)
        assert res.state == "unavailable" and res.reason == "unsafe partner address"
        assert calls == ["rpc.p.example"]  # one connect attempt: never retried
        assert client._breakers["p"]._failures == 1
        assert "partner p: connection refused, unsafe address" in caplog.text
        assert "rpc.p.example" not in caplog.text and "10.0.0.5" not in caplog.text

        checked = await client.check("p", "t1")
        assert checked.state == "unavailable" and checked.reason == "unsafe partner address"
        assert client._breakers["p"]._failures == 2
    finally:
        await client.aclose()


def test_kind_classifies_unsafe_address():
    try:
        try:
            raise guarded_net.UnsafeAddress("unsafe address")
        except guarded_net.UnsafeAddress as inner:
            raise httpx.ConnectError("unsafe address") from inner
    except httpx.ConnectError as exc:
        assert client_mod._kind(exc) == "unsafe"
    assert client_mod._kind(httpx.ConnectError("refused")) == "connect"


async def test_happy_eyeballs_winner_closed_when_caller_cancelled():
    """The caller is cancelled after a winner connected but before connect_tcp returned
    (a loser is still being cancelled): the winner's stream is closed, not leaked."""
    second = "93.184.216.35"
    inner = _Scripted({PUBLIC_IP: ("slow_cancel", 0.5), second: ("ok", 0.01)})
    backend = GuardedBackend(
        fixed_tier("public"), resolver=resolver([PUBLIC_IP, second]), inner=inner
    )
    task = asyncio.create_task(backend.connect_tcp("api.example.com", 443, timeout=5))
    for _ in range(200):  # until the second address has won
        if inner.streams:
            break
        await asyncio.sleep(0.01)
    assert inner.streams and not task.done()  # the loser's cancellation still runs
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 3)
    (winner,) = inner.streams
    assert winner.ip == second and winner.closed
