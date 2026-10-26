"""C1: the ``require_signed`` invariant holds for every record, however it got there.

A record whose tier is in ``require_signed`` must carry a ``signed_key_id`` whose key the
current verifier still trusts (for a pinned key: same key material, and the stored card
still verifies against it). Anything else is quarantined ("unsigned card" / "signing key no
longer trusted") and audited, and ``PartnerClient`` never builds a client for it.
"""

from __future__ import annotations

import copy

import pytest
import respx
import yaml

from a2agw.consult import netguard
from a2agw.consult.client import PartnerClient
from a2agw.consult.registry import KEY_UNTRUSTED, UNSIGNED, PartnerRegistry, card_hash
from a2agw.security.cardsign import CardSigner, CardVerifier, load_public_key

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


def _keypair(tmp_path, name):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

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
def keys(tmp_path):
    return {kid: _keypair(tmp_path, kid) for kid in ("k1", "k2", "k1b")}


def verifier_for(keys, *kids, as_kid=None):
    """A verifier trusting ``kids`` (``as_kid`` maps a kid to the key file of another)."""
    as_kid = as_kid or {}
    return CardVerifier({k: load_public_key(keys[as_kid.get(k, k)][1]) for k in kids})


def sign(keys, card, kid="k1"):
    from a2a.client.card_resolver import parse_agent_card
    from google.protobuf.json_format import MessageToDict

    signed = CardSigner(keys[kid][0], kid, "ES256").sign(parse_agent_card(copy.deepcopy(card)))
    return MessageToDict(signed)


def strict(path, verifier):
    return PartnerRegistry(path, verifier=verifier, require_signed=frozenset({"public"}))


def recorder(reg):
    events: list[tuple[str, str, str | None]] = []
    reg.on_change = lambda r, e: events.append((r.id, e, (reg.change_info or {}).get("reason")))
    return events


async def assert_refused(reg, pid, reason):
    client = PartnerClient(reg)
    built: list[str] = []
    orig = client._client_for

    def spy(rec):
        built.append(rec.id)
        return orig(rec)

    client._client_for = spy
    try:
        _rec, sdk_client, early = await client._prepare(pid)
        assert sdk_client is None and built == []
        assert early is not None and early.state == "unavailable"
        assert early.reason == reason
    finally:
        await client.aclose()


async def test_turning_require_signed_on_later_quarantines_unsigned_records(tmp_path, keys):
    p = tmp_path / "partners.yaml"
    legacy = PartnerRegistry(p)  # a Phase 1 / pre-require_signed registry
    await legacy.add_from_card("acme", CARD, "public")
    await legacy.add_from_card("other", CARD, "partner")  # tier not required: untouched
    reg = strict(p, verifier_for(keys, "k1"))
    events = recorder(reg)
    reg.load()
    rec = reg.get("acme")
    assert rec.status == "quarantined" and rec.signed_key_id is None
    assert [r.id for r in reg.active()] == ["other"]
    assert events == [("acme", "quarantined", UNSIGNED)]
    # Persisted: the file now says quarantined too.
    saved = {r["id"]: r for r in yaml.safe_load(p.read_text())["partners"]}
    assert saved["acme"]["status"] == "quarantined"
    await assert_refused(reg, "acme", UNSIGNED)
    # Approving cannot make an unsigned record active again.
    with pytest.raises(ValueError, match="unsigned card"):
        reg.approve("acme")
    assert reg.get("acme").status == "quarantined"


async def test_unsigned_record_arriving_through_reload_is_quarantined(tmp_path, keys):
    p = tmp_path / "partners.yaml"
    reg = strict(p, verifier_for(keys, "k1"))
    await reg.add_from_card("good", sign(keys, CARD), "public")
    events = recorder(reg)
    # Someone writes an unsigned public record into the file (by hand, or an old CLI).
    other = PartnerRegistry(tmp_path / "other.yaml")
    rec = await other.add_from_card("evil", CARD, "public")
    data = yaml.safe_load(p.read_text())
    data["partners"].append(rec.model_dump(mode="json"))
    p.write_text(yaml.safe_dump(data))
    changes = reg.reload()
    assert changes["added"] == ["evil"]
    assert reg.get("evil").status == "quarantined"
    assert reg.get("good").status == "active"
    assert ("evil", "quarantined", UNSIGNED) in events
    await assert_refused(reg, "evil", UNSIGNED)


async def test_removed_or_replaced_trusted_key_quarantines(tmp_path, keys):
    p = tmp_path / "partners.yaml"
    reg = strict(p, verifier_for(keys, "k1", "k2"))
    await reg.add_from_card("a", sign(keys, CARD, "k1"), "public")
    await reg.add_from_card("b", sign(keys, CARD, "k2"), "public")
    # k1 removed from trust.card_keys.
    reg2 = strict(p, verifier_for(keys, "k2"))
    events = recorder(reg2)
    reg2.load()
    assert reg2.get("a").status == "quarantined" and reg2.get("b").status == "active"
    assert events == [("a", "quarantined", KEY_UNTRUSTED)]
    await assert_refused(reg2, "a", KEY_UNTRUSTED)
    # Same kid, other key material: the thumbprint no longer matches.
    reg3 = strict(p, verifier_for(keys, "k1", "k2", as_kid={"k2": "k1b"}))
    reg3.load()
    assert reg3.get("b").status == "quarantined"


async def test_stored_card_must_still_verify_against_its_pinned_key(tmp_path, keys):
    p = tmp_path / "partners.yaml"
    reg = strict(p, verifier_for(keys, "k1"))
    await reg.add_from_card("a", sign(keys, CARD), "public")
    data = yaml.safe_load(p.read_text())
    entry = data["partners"][0]
    entry["card"]["description"] = "rewritten on disk"  # signature no longer matches
    entry["card_hash"] = card_hash(entry["card"])
    p.write_text(yaml.safe_dump(data))
    reg2 = strict(p, verifier_for(keys, "k1"))
    reg2.load()
    assert reg2.get("a").status == "quarantined"
    assert reg2.change_info is None  # only set while on_change runs


async def test_client_refuses_a_record_that_bypassed_the_registry_checks(tmp_path, keys):
    reg = strict(None, verifier_for(keys, "k1"))
    rec = await reg.add_from_card("a", sign(keys, CARD), "public")
    rec.signed_key_id = None  # e.g. mutated in place after loading
    await assert_refused(reg, "a", UNSIGNED)
    assert reg.get("a").status == "quarantined"


@respx.mock
async def test_failed_startup_refresh_leaves_unsigned_record_quarantined(tmp_path, keys):
    from a2agw.config import GatewayConfig, register_partners
    from a2agw.serve.host import AgentHost

    p = tmp_path / "partners.yaml"
    respx.get(CARD_URL).respond(200, json=CARD)
    legacy = PartnerRegistry(p)
    await legacy.add_from_url("acme", URL, "public")
    respx.get(CARD_URL).respond(500)  # the refresh at startup fails
    host = AgentHost(
        "http://localhost:8000",
        db_url=f"sqlite+aiosqlite:///{tmp_path / 'gw.db'}",
        partners_path=p,
        card_verifier=verifier_for(keys, "k1"),
        require_signed=["public"],
    )
    cfg = GatewayConfig.model_validate(
        {
            "base_url": "http://localhost:8000",
            "partners": [{"id": "acme", "url": URL, "tier": "public"}],
        }
    )
    await register_partners(host, cfg, config_dir=tmp_path)
    assert host.partners.get("acme").status == "quarantined"
    await host.startup()
    try:
        assert host.partners.get("acme").status == "quarantined"
        result = await host.client.consult("acme", "hi")
        assert result.state == "unavailable"
        await host.audit.drain()
        rows, _ = await host.audit.query({"action": "partner.quarantine"}, 10)
        assert [(r["partner_id"], r["detail"].get("reason")) for r in rows] == [("acme", UNSIGNED)]
    finally:
        await host.shutdown()


async def test_card_file_partner_registered_unsigned_is_quarantined(tmp_path, keys):
    import json

    from a2agw.config import GatewayConfig, register_partners
    from a2agw.serve.host import AgentHost

    p = tmp_path / "partners.yaml"
    (tmp_path / "acme.json").write_text(json.dumps(CARD))
    cfg_data = {
        "base_url": "http://localhost:8000",
        "partners": [{"id": "acme", "card_file": "acme.json", "tier": "public"}],
    }
    # Registered while require_signed was off.
    first = AgentHost("http://localhost:8000", db_url="sqlite+aiosqlite://", partners_path=p)
    await register_partners(first, GatewayConfig.model_validate(cfg_data), config_dir=tmp_path)
    assert first.partners.get("acme").status == "active"
    # Then require_signed is turned on: the existing card_file record is not "left alone".
    host = AgentHost(
        "http://localhost:8000",
        db_url=f"sqlite+aiosqlite:///{tmp_path / 'gw.db'}",
        partners_path=p,
        card_verifier=verifier_for(keys, "k1"),
        require_signed=["public"],
    )
    await register_partners(host, GatewayConfig.model_validate(cfg_data), config_dir=tmp_path)
    assert host.partners.get("acme").status == "quarantined"
    await host.startup()
    try:
        await host.audit.drain()
        rows, _ = await host.audit.query({"action": "partner.quarantine"}, 10)
        assert [(r["partner_id"], r["detail"].get("reason")) for r in rows] == [("acme", UNSIGNED)]
    finally:
        await host.shutdown()
