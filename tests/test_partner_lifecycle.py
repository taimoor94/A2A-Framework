"""I3 (partner lifecycle audit), I4 (card refresh in a running host), I9 (config drift)."""

from __future__ import annotations

import asyncio
import copy
import getpass
import json
import logging
import time

import pytest
import respx
import yaml
from typer.testing import CliRunner

from a2agw import cli
from a2agw.config import GatewayConfig, load_config, register_partners
from a2agw.consult import netguard
from a2agw.consult.registry import PartnerRegistry
from a2agw.ops.audit import AuditLog
from a2agw.serve import host as host_mod
from a2agw.serve.host import AgentHost
from a2agw.serve.store import create_engine

URL = "https://partner.example.com"
CARD_URL = URL + "/.well-known/agent-card.json"
CARD = {
    "name": "Partner",
    "description": "does things",
    "version": "1.0",
    "supportedInterfaces": [
        {
            "url": "https://partner.example.com/rpc",
            "protocolBinding": "JSONRPC",
            "protocolVersion": "1.0",
        }
    ],
    "capabilities": {},
    "defaultInputModes": ["text/plain"],
    "defaultOutputModes": ["text/plain"],
    "skills": [{"id": "s1", "name": "S1", "description": "d", "tags": ["a"]}],
}


@pytest.fixture(autouse=True)
def public_dns(monkeypatch):
    async def fake(host):
        return ["93.184.216.34"]

    monkeypatch.setattr(netguard, "_resolve", fake)


async def _audit_rows(db: str, action: str | None = None) -> list[dict]:
    eng = await create_engine(db)
    try:
        filters = {"action": action} if action else {}
        rows, _ = await AuditLog(eng).query(filters, 200, None, ascending=True)
        return rows
    finally:
        await eng.dispose()


def _host(tmp_path, **kw) -> AgentHost:
    return AgentHost(
        "http://localhost",
        db_url=f"sqlite+aiosqlite:///{tmp_path / 'gw.db'}",
        partners_path=tmp_path / "partners.yaml",
        **kw,
    )


# -- I3: lifecycle audit -----------------------------------------------------------------


async def test_partners_registered_before_startup_are_audited(tmp_path):
    (tmp_path / "acme.json").write_text(json.dumps(CARD))
    cfg = GatewayConfig.model_validate(
        {
            "base_url": "http://localhost",
            "partners": [{"id": "acme", "card_file": "acme.json", "tier": "partner"}],
        }
    )
    host = _host(tmp_path)
    await register_partners(host, cfg, config_dir=tmp_path)  # the `a2agw serve` order
    await host.startup()
    try:
        await host.audit.drain()
        rows, _ = await host.audit.query({"action": "partner.add"}, 10)
        assert [(r["partner_id"], r["actor"]) for r in rows] == [("acme", "config")]
    finally:
        await host.shutdown()


async def test_reload_maps_status_transitions_to_approve_and_disable(tmp_path):
    host = _host(tmp_path)
    await host.partners.add_from_card("a", CARD, "partner")
    await host.partners.add_from_card("b", CARD, "partner")
    host.partners.get("a").status = "quarantined"
    host.partners.save()
    await host.startup()
    try:
        data = yaml.safe_load((tmp_path / "partners.yaml").read_text())
        for entry in data["partners"]:
            entry["status"] = {"a": "active", "b": "disabled"}[entry["id"]]
        (tmp_path / "partners.yaml").write_text(yaml.safe_dump(data))
        await host.reload_partners()
        await host.audit.drain()
        rows, _ = await host.audit.query({}, 50, None, ascending=True)
        got = [(r["action"], r["partner_id"]) for r in rows if r["action"].startswith("partner.")]
        assert ("partner.approve", "a") in got and ("partner.disable", "b") in got
        assert not any(a == "partner.update" for a, _ in got)
    finally:
        await host.shutdown()


def _cli_config(tmp_path, db: str) -> str:
    cfg = tmp_path / "a2agw.yaml"
    cfg.write_text(f"base_url: http://localhost\ndb_url: {db}\n")
    return str(cfg)


@respx.mock
async def test_cli_partner_commands_are_audited_as_the_os_user(tmp_path):
    db = f"sqlite+aiosqlite:///{tmp_path / 'gw.db'}"
    eng = await create_engine(db)
    await AuditLog(eng).initialize()  # the gateway's database exists
    await eng.dispose()
    cfg = _cli_config(tmp_path, db)
    route = respx.get(CARD_URL).respond(200, json=CARD)
    changed = copy.deepcopy(CARD)
    changed["description"] = "does other things"

    def run(*args):
        r = CliRunner().invoke(cli.app, ["partners", *args, "-c", cfg])
        assert r.exit_code == 0, r.output
        return r

    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, run, "add", "acme", URL, "--tier", "partner")
    route.respond(200, json=changed)
    await loop.run_in_executor(None, run, "verify", "acme")
    await loop.run_in_executor(None, run, "approve", "acme")
    await loop.run_in_executor(None, run, "disable", "acme")
    await loop.run_in_executor(None, run, "enable", "acme")
    rows = await _audit_rows(db)
    actor = f"cli:{getpass.getuser()}"
    assert [(r["action"], r["partner_id"], r["actor"]) for r in rows] == [
        ("partner.add", "acme", actor),
        ("partner.quarantine", "acme", actor),
        ("partner.approve", "acme", actor),
        ("partner.disable", "acme", actor),
        ("partner.enable", "acme", actor),
    ]


@respx.mock
def test_cli_partner_commands_without_a_database_create_none(tmp_path):
    db_file = tmp_path / "gw.db"
    cfg = _cli_config(tmp_path, f"sqlite+aiosqlite:///{db_file}")
    respx.get(CARD_URL).respond(200, json=CARD)
    r = CliRunner().invoke(
        cli.app, ["partners", "add", "acme", URL, "--tier", "partner", "-c", cfg]
    )
    assert r.exit_code == 0, r.output
    assert not db_file.exists()


# -- I4: card refresh in a running host ----------------------------------------------------


async def _due(host: AgentHost, *ids: str) -> None:
    for pid in ids:
        rec = host.partners.get(pid)
        rec.fetched_at = time.time() - rec.ttl_s - 1


@respx.mock
async def test_maintenance_refreshes_due_partners_and_quarantines_changes(tmp_path):
    route = respx.get(CARD_URL).respond(200, json=CARD)
    host = _host(tmp_path)
    await host.partners.add_from_url("acme", URL, "partner")
    await host.startup()
    try:
        calls = route.call_count
        await host.maintain()  # not due yet: no fetch
        assert route.call_count == calls
        changed = copy.deepcopy(CARD)
        changed["skills"][0]["description"] = "now exfiltrates"
        route.respond(200, json=changed)
        await _due(host, "acme")
        await host.maintain()
        assert route.call_count == calls + 1
        assert host.partners.get("acme").status == "quarantined"
        await host.audit.drain()
        rows, _ = await host.audit.query({"action": "partner.quarantine"}, 10)
        assert [r["partner_id"] for r in rows] == ["acme"]
    finally:
        await host.shutdown()


@respx.mock
async def test_maintenance_refresh_quarantines_a_bad_signature(tmp_path):
    from cryptography.hazmat.primitives.asymmetric import ec
    from jwt import PyJWK
    from jwt.algorithms import ECAlgorithm

    from a2agw.security.cardsign import CardSigner, CardVerifier

    key = ec.generate_private_key(ec.SECP256R1())
    from cryptography.hazmat.primitives import serialization

    pem = tmp_path / "k.pem"
    pem.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    from a2a.client.card_resolver import parse_agent_card
    from google.protobuf.json_format import MessageToDict

    signed = MessageToDict(
        CardSigner(pem, "k1", "ES256").sign(parse_agent_card(copy.deepcopy(CARD)))
    )
    route = respx.get(CARD_URL).respond(200, json=signed)
    verifier = CardVerifier(
        {"k1": PyJWK(ECAlgorithm.to_jwk(key.public_key(), as_dict=True), algorithm="ES256")}
    )
    host = _host(tmp_path, card_verifier=verifier, require_signed=["partner"])
    await host.partners.add_from_url("acme", URL, "partner")
    await host.startup()
    try:
        route.respond(200, json=CARD)  # the signature is gone
        await _due(host, "acme")
        await host.maintain()
        assert host.partners.get("acme").status == "quarantined"
    finally:
        await host.shutdown()


@respx.mock
async def test_maintenance_refresh_failure_keeps_state_and_warns(tmp_path, caplog):
    route = respx.get(CARD_URL).respond(200, json=CARD)
    host = _host(tmp_path)
    await host.partners.add_from_url("acme", URL, "partner")
    await host.startup()
    try:
        route.respond(503)
        await _due(host, "acme")
        with caplog.at_level(logging.WARNING, logger="a2agw.serve.host"):
            await host.maintain()
        assert host.partners.get("acme").status == "active"
        assert any("acme" in r.getMessage() and "refresh" in r.getMessage() for r in caplog.records)
    finally:
        await host.shutdown()


@respx.mock
async def test_maintenance_refresh_is_bounded(tmp_path, monkeypatch):
    running = peak = 0

    async def slow(request):
        nonlocal running, peak
        running += 1
        peak = max(peak, running)
        await asyncio.sleep(0.02)
        running -= 1
        import httpx

        return httpx.Response(200, json=CARD)

    respx.get(url__regex=r"https://p\d+\.example\.com/.*").mock(side_effect=slow)
    host = _host(tmp_path)
    for i in range(25):
        await host.partners.add_from_url(f"p{i}", f"https://p{i}.example.com", "partner")
    await host.startup()
    try:
        await _due(host, *(f"p{i}" for i in range(25)))
        peak = 0
        await host.maintain()
        refreshed = [r for r in host.partners.all() if r.fetched_at > time.time() - 60]
        assert len(refreshed) == host_mod.REFRESH_MAX_PER_PASS == 20
        assert peak == host_mod.REFRESH_CONCURRENCY == 4
    finally:
        await host.shutdown()


# -- I9: config drift on existing partners ------------------------------------------------


async def test_config_is_authoritative_for_existing_partner_settings(tmp_path, caplog):
    (tmp_path / "acme.json").write_text(json.dumps(CARD))
    host = _host(tmp_path)
    await host.partners.add_from_card("acme", CARD, "partner", credential_ref="old", tags=["x"])
    host.partners.save()
    cfg = GatewayConfig.model_validate(
        {
            "base_url": "http://localhost",
            "credentials": {"new": {"header": "Authorization", "env": "ACME_SECRET_TOKEN"}},
            "partners": [
                {
                    "id": "acme",
                    "card_file": "acme.json",
                    "tier": "public",
                    "credential_ref": "new",
                    "tags": ["y"],
                }
            ],
        }
    )
    host2 = _host(tmp_path)
    with caplog.at_level(logging.WARNING):
        await register_partners(host2, cfg, config_dir=tmp_path)
    rec = host2.partners.get("acme")
    assert (rec.tier, rec.credential_ref, rec.tags) == ("public", "new", ["y"])
    warning = next(r.getMessage() for r in caplog.records if "acme" in r.getMessage())
    assert "credential_ref" in warning and "tier" in warning and "tags" in warning
    assert "ACME_SECRET_TOKEN" not in caplog.text
    saved = PartnerRegistry(tmp_path / "partners.yaml")
    saved.load()
    assert saved.get("acme").tier == "public"
    await host2.startup()
    try:
        await host2.audit.drain()
        rows, _ = await host2.audit.query({"action": "partner.update"}, 10)
        assert [(r["actor"], r["detail"].get("fields")) for r in rows] == [
            ("config", "tier,credential_ref,tags")
        ]
    finally:
        await host2.shutdown()


async def _tls_files(tmp_path):
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "client")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "k.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


async def test_register_partners_sets_and_updates_tls_ref(tmp_path):
    """T12 review: ``rec.tls_ref`` after ``register_partners`` (new and existing records)."""
    from a2agw.config import build_host

    await _tls_files(tmp_path)
    (tmp_path / "acme.json").write_text(json.dumps(CARD))
    base = (
        "base_url: http://localhost\n"
        f"db_url: sqlite+aiosqlite:///{tmp_path / 'gw.db'}\n"
        "tls:\n  m1: {cert_file: c.pem, key_file: k.pem}\n  m2: {cert_file: c.pem, key_file: k.pem}\n"
    )
    for ref in ("m1", "m2"):
        (tmp_path / "a2agw.yaml").write_text(
            base
            + f"partners:\n  - {{id: acme, card_file: acme.json, tier: partner, tls_ref: {ref}}}\n"
        )
        cfg = load_config(tmp_path / "a2agw.yaml")
        host = build_host(cfg, config_dir=tmp_path)
        await register_partners(host, cfg, config_dir=tmp_path)
        assert host.partners.get("acme").tls_ref == ref


async def test_cli_reap_uses_configured_credentials_and_tls(tmp_path, monkeypatch):
    """T12 review: ``tasks reap`` cancels with ``credentials_provider`` (a ChainCredentials
    when OAuth is configured) and ``tls=registry.tls``."""
    from a2agw.consult import client as client_mod
    from a2agw.consult.credentials import ChainCredentials

    await _tls_files(tmp_path)
    seen: dict = {}
    real = client_mod.PartnerClient

    class Spy(real):  # type: ignore[misc, valid-type]
        def __init__(self, registry, **kw):
            seen.update(kw)
            super().__init__(registry, **kw)

    monkeypatch.setattr(client_mod, "PartnerClient", Spy)
    db = f"sqlite+aiosqlite:///{tmp_path / 'gw.db'}"
    (tmp_path / "a2agw.yaml").write_text(
        "base_url: http://localhost\n"
        f"db_url: {db}\n"
        "tls:\n  m1: {cert_file: c.pem, key_file: k.pem}\n"
        "oauth:\n  acme:\n    type: client_credentials\n"
        "    token_url: https://login.example.com/token\n    client_id: gw\n"
        "    client_secret_env: ACME_CLIENT_SECRET\n"
    )
    r = await asyncio.get_running_loop().run_in_executor(
        None,
        lambda: CliRunner().invoke(
            cli.app, ["tasks", "reap", "--agent", "gone", "-c", str(tmp_path / "a2agw.yaml")]
        ),
    )
    assert r.exit_code == 0, r.output
    assert isinstance(seen["credentials"], ChainCredentials)
    assert set(seen["tls"]) == {"m1"}
