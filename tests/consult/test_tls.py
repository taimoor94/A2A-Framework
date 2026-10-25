"""mTLS: per-partner client certificates (outbound) and TLS serving (inbound)."""

from __future__ import annotations

import asyncio
import datetime
import ipaddress
import socket
import ssl

import httpx
import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from google.protobuf.json_format import MessageToDict
from typer.testing import CliRunner

from a2agw import cli
from a2agw.consult import client as client_mod
from a2agw.consult.client import PartnerClient
from a2agw.consult.registry import PartnerRecord, PartnerRegistry
from a2agw.consult.tls import TlsClientConfig
from a2agw.core.events import Done
from a2agw.serve.agent import AgentSpec, SkillSpec
from a2agw.serve.host import AgentHost

# -- throwaway PKI ---------------------------------------------------------------------


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _write(path, cert, key) -> None:
    path.with_suffix(".crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    path.with_suffix(".key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def _issue(cn, issuer_cert, issuer_key, *, ca=False, san=None, client=False):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.UTC)
    b = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(issuer_cert.subject if issuer_cert else _name(cn))
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
    cert = b.sign(issuer_key or key, hashes.SHA256())
    return cert, key


@pytest.fixture(scope="session")
def pki(tmp_path_factory):
    d = tmp_path_factory.mktemp("pki")
    ca, ca_key = _issue("test-ca", None, None, ca=True)
    other_ca, other_key = _issue("other-ca", None, None, ca=True)
    san = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    server = _issue("localhost", ca, ca_key, san=san)
    client = _issue("partner-client", ca, ca_key, client=True)
    rogue = _issue("rogue-client", other_ca, other_key, client=True)
    for name, (c, k) in {
        "ca": (ca, ca_key),
        "other-ca": (other_ca, other_key),
        "server": server,
        "client": client,
        "rogue": rogue,
    }.items():
        _write(d / name, c, k)
    return d


def cfg(pki, name="client", ca="ca") -> TlsClientConfig:
    return TlsClientConfig(pki / f"{name}.crt", pki / f"{name}.key", pki / f"{ca}.crt")


# -- a real TLS server -----------------------------------------------------------------


class Echo:
    durable_sessions = False

    async def run(self, ctx):
        yield Done(text=f"echo: {ctx.text}")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
async def tls_server(pki, tmp_path, monkeypatch):
    monkeypatch.setenv("A2AGW_DEV", "1")
    port = _free_port()
    host = AgentHost(f"https://localhost:{port}", db_url=f"sqlite+aiosqlite:///{tmp_path}/h.db")
    host.add(
        AgentSpec(
            id="alpha",
            name="Alpha",
            description="d",
            skills=[SkillSpec(id="s", name="S", description="d")],
            adapter=Echo(),
        )
    )
    server = uvicorn.Server(
        uvicorn.Config(
            host.app(),
            host="127.0.0.1",
            port=port,
            ssl_certfile=str(pki / "server.crt"),
            ssl_keyfile=str(pki / "server.key"),
            ssl_ca_certs=str(pki / "ca.crt"),
            ssl_cert_reqs=ssl.CERT_REQUIRED,
            log_level="error",
            lifespan="off",
        )
    )
    await host.startup()
    task = asyncio.create_task(server.serve())
    for _ in range(200):
        if server.started:
            break
        await asyncio.sleep(0.01)
    assert server.started
    yield host, port
    server.should_exit = True
    await asyncio.wait_for(task, 10)
    await host.shutdown()


async def _consult(host, port, tmp_path, *, partner_tls_ref, tls):
    registry = PartnerRegistry()
    card = MessageToDict(host.cards["alpha"])
    await registry.add_from_card("alpha", card, "internal")
    rec = registry.get("alpha")
    registry._records["alpha"] = rec.model_copy(update={"tls_ref": partner_tls_ref})
    client = PartnerClient(registry, tls=tls)
    try:
        return client, await client.consult("alpha", "hi", wait_seconds=5)
    except BaseException:
        await client.aclose()
        raise


@pytest.fixture(autouse=True)
def _fast(monkeypatch):
    monkeypatch.setattr(client_mod, "RETRY_BASE_S", 0.001)
    monkeypatch.setattr(client_mod, "RETRY_CAP_S", 0.002)


# -- the brief's cases -----------------------------------------------------------------


async def test_partner_with_client_cert_succeeds(tls_server, pki, tmp_path):
    host, port = tls_server
    client, res = await _consult(host, port, tmp_path, partner_tls_ref="p", tls={"p": cfg(pki)})
    try:
        assert res.state == "completed", res
        assert "echo: hi" in res.text
    finally:
        await client.aclose()


async def test_partner_without_client_cert_fails_unavailable(tls_server, pki, tmp_path):
    host, port = tls_server
    client, res = await _consult(host, port, tmp_path, partner_tls_ref=None, tls={})
    try:
        assert res.state == "unavailable", res
    finally:
        await client.aclose()


async def test_wrong_ca_fails(tls_server, pki, tmp_path):
    host, port = tls_server
    # trusts the wrong CA for the server, and presents a cert the server's CA did not issue
    bad = cfg(pki, "rogue", ca="other-ca")
    client, res = await _consult(host, port, tmp_path, partner_tls_ref="p", tls={"p": bad})
    try:
        assert res.state == "unavailable", res
    finally:
        await client.aclose()
    # right trust root, client cert from another CA: the server rejects the handshake
    bad2 = cfg(pki, "rogue", ca="ca")
    client, res = await _consult(host, port, tmp_path, partner_tls_ref="p", tls={"p": bad2})
    try:
        assert res.state == "unavailable", res
    finally:
        await client.aclose()


async def test_tls_clients_closed_on_aclose(tls_server, pki, tmp_path):
    host, port = tls_server
    client, _res = await _consult(host, port, tmp_path, partner_tls_ref="p", tls={"p": cfg(pki)})
    assert len(client._tls_http) == 1
    hc = next(iter(client._tls_http.values()))
    assert not hc.is_closed
    await client.aclose()
    assert hc.is_closed and not client._tls_http


async def test_injected_http_is_overridden_by_tls_ref(tls_server, pki, tmp_path):
    host, _port = tls_server
    registry = PartnerRegistry()
    await registry.add_from_card("alpha", MessageToDict(host.cards["alpha"]), "internal")
    rec = registry.get("alpha")
    registry._records["alpha"] = rec.model_copy(update={"tls_ref": "p"})
    plain = httpx.AsyncClient()  # no client certificate: would fail the handshake
    client = PartnerClient(registry, http=plain, tls={"p": cfg(pki)})
    try:
        res = await client.consult("alpha", "hi", wait_seconds=5)
        assert res.state == "completed", res
    finally:
        await client.aclose()
        await plain.aclose()


async def test_unknown_tls_ref_is_unavailable(tls_server, pki, tmp_path):
    host, port = tls_server
    client, res = await _consult(host, port, tmp_path, partner_tls_ref="nope", tls={})
    try:
        assert res.state == "unavailable" and res.reason == "tls config missing"
        assert not client._tls_http
    finally:
        await client.aclose()


# -- TlsClientConfig -------------------------------------------------------------------


def test_config_validates_paths(pki, tmp_path):
    missing = tmp_path / "nope.pem"
    with pytest.raises(ValueError, match="nope.pem"):
        TlsClientConfig(missing, pki / "client.key")
    with pytest.raises(ValueError, match="nope.pem"):
        TlsClientConfig(pki / "client.crt", pki / "client.key", missing)


def test_config_does_not_leak_key_contents(pki, tmp_path):
    bad = tmp_path / "bad.key"
    bad.write_text("SECRET-KEY-MATERIAL")
    c = TlsClientConfig(pki / "client.crt", bad)
    with pytest.raises(ValueError) as ei:
        c.ssl_context()
    assert "SECRET-KEY-MATERIAL" not in str(ei.value)


def test_ssl_context_settings_and_cache(pki):
    c = cfg(pki)
    ctx = c.ssl_context()
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
    assert ctx.check_hostname is True and ctx.verify_mode == ssl.CERT_REQUIRED
    assert c.ssl_context() is ctx


def test_partner_record_without_tls_ref_loads():
    rec = PartnerRecord.model_validate(
        {"id": "p", "card": {}, "card_hash": "h", "tier": "internal"}
    )
    assert rec.tls_ref is None


# -- inbound: AgentHost.run and the CLI ------------------------------------------------


def _host(tmp_path):
    return AgentHost("https://x", db_url=f"sqlite+aiosqlite:///{tmp_path}/h.db")


def test_run_maps_ssl_kwargs(tmp_path, monkeypatch):
    calls = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: calls.update(kw))
    _host(tmp_path).run(
        ssl_certfile="c", ssl_keyfile="k", ssl_ca_certs="ca", require_client_cert=True
    )
    assert calls["ssl_certfile"] == "c" and calls["ssl_keyfile"] == "k"
    assert calls["ssl_ca_certs"] == "ca" and calls["ssl_cert_reqs"] == ssl.CERT_REQUIRED
    calls.clear()
    _host(tmp_path).run(ssl_certfile="c", ssl_keyfile="k")
    assert calls["ssl_cert_reqs"] == ssl.CERT_NONE
    calls.clear()
    _host(tmp_path).run()
    assert not any(k.startswith("ssl") for k in calls)


def test_require_client_cert_without_ca_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: pytest.fail("must not start"))
    with pytest.raises(ValueError, match="ssl_ca_certs"):
        _host(tmp_path).run(ssl_certfile="c", ssl_keyfile="k", require_client_cert=True)


def test_cli_serve_passes_tls_flags(tmp_path, monkeypatch):
    (tmp_path / "a2agw.yaml").write_text("base_url: http://x\nagents: []\n")
    calls = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: calls.update(kw))
    r = CliRunner().invoke(
        cli.app,
        [
            "serve",
            "-c",
            str(tmp_path / "a2agw.yaml"),
            "--ssl-certfile",
            "c",
            "--ssl-keyfile",
            "k",
            "--ssl-ca-certs",
            "ca",
            "--require-client-cert",
        ],
    )
    assert r.exit_code == 0, r.output
    assert calls["ssl_certfile"] == "c" and calls["ssl_ca_certs"] == "ca"
    assert calls["ssl_cert_reqs"] == ssl.CERT_REQUIRED


def test_cli_require_client_cert_without_ca_is_one_line_error(tmp_path):
    (tmp_path / "a2agw.yaml").write_text("base_url: http://x\nagents: []\n")
    r = CliRunner().invoke(
        cli.app,
        [
            "serve",
            "-c",
            str(tmp_path / "a2agw.yaml"),
            "--ssl-certfile",
            "c",
            "--require-client-cert",
        ],
    )
    assert r.exit_code == 1 and "ssl_ca_certs" in r.output
