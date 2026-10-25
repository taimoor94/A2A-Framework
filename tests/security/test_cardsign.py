"""Signed agent cards: signing, verification, JWKS fetching and the host's served card."""

from __future__ import annotations

import copy
import hashlib
import hmac
import json

import pytest
import respx
from a2a.client.card_resolver import parse_agent_card
from a2a.types import AgentCard, AgentCardSignature
from a2a.utils.signing import _canonicalize_agent_card
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from jwt.utils import base64url_decode, base64url_encode

from a2agw.consult import netguard
from a2agw.core.events import Done
from a2agw.security.cardsign import (
    CardSignatureError,
    CardSigner,
    CardVerifier,
    load_private_key,
    load_public_key,
)
from a2agw.serve.agent import AgentSpec, SkillSpec

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
JKU = "https://keys.example.com/jwks.json"


def _write_keypair(tmp_path, name, private_key):
    priv = tmp_path / f"{name}.pem"
    priv.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    pub = tmp_path / f"{name}.pub.pem"
    pub.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return priv, pub


@pytest.fixture
def keys(tmp_path):
    """name -> (private PEM path, public PEM path, alg)."""
    return {
        "ec": (*_write_keypair(tmp_path, "ec", ec.generate_private_key(ec.SECP256R1())), "ES256"),
        "rsa": (
            *_write_keypair(
                tmp_path, "rsa", rsa.generate_private_key(public_exponent=65537, key_size=2048)
            ),
            "RS256",
        ),
        "ed": (*_write_keypair(tmp_path, "ed", ed25519.Ed25519PrivateKey.generate()), "EdDSA"),
    }


@pytest.fixture(autouse=True)
def public_dns(monkeypatch):
    async def fake(host):
        return ["93.184.216.34"]

    monkeypatch.setattr(netguard, "_resolve", fake)


def card() -> AgentCard:
    return parse_agent_card(copy.deepcopy(CARD))


def signer(keys, name, kid="k1", jku=None) -> CardSigner:
    priv, _, alg = keys[name]
    return CardSigner(priv, kid, alg, jku=jku)


def trusted(keys, name, kid="k1"):
    return {kid: load_public_key(keys[name][1])}


@pytest.mark.parametrize("name", ["ec", "ed", "rsa"])
async def test_sign_then_verify_roundtrip_es256_and_eddsa(keys, name):
    signed = signer(keys, name).sign(card())
    assert len(signed.signatures) == 1
    header = json.loads(base64url_decode(signed.signatures[0].protected))
    assert header["kid"] == "k1" and header["alg"] == keys[name][2] and "jku" not in header
    assert await CardVerifier(trusted(keys, name)).verify(signed) == "k1"


async def test_sign_does_not_mutate_input(keys):
    original = card()
    signer(keys, "ec").sign(original)
    assert len(original.signatures) == 0


async def test_verify_rejects_tampered_card(keys):
    signed = signer(keys, "ec").sign(card())
    signed.description = "now does evil things"
    with pytest.raises(CardSignatureError):
        await CardVerifier(trusted(keys, "ec")).verify(signed)


async def test_verify_rejects_unsigned_card(keys):
    with pytest.raises(CardSignatureError, match="not signed"):
        await CardVerifier(trusted(keys, "ec")).verify(card())


async def test_verify_rejects_unknown_kid(keys):
    signed = signer(keys, "ec", kid="other").sign(card())
    with pytest.raises(CardSignatureError):
        await CardVerifier(trusted(keys, "ec", kid="k1")).verify(signed)


async def test_verify_rejects_key_of_wrong_type_under_trusted_kid(keys):
    # Signed by the Ed25519 key, but kid k1 is pinned to the EC key.
    signed = signer(keys, "ed").sign(card())
    with pytest.raises(CardSignatureError):
        await CardVerifier(trusted(keys, "ec")).verify(signed)


def _hand_signed(header: dict, sig: bytes) -> AgentCard:
    c = card()
    protected = base64url_encode(json.dumps(header).encode()).decode()
    payload = base64url_encode(_canonicalize_agent_card(c).encode()).decode()
    c.signatures.append(
        AgentCardSignature(protected=protected, signature=base64url_encode(sig).decode())
    )
    return c, f"{protected}.{payload}".encode()


async def test_verify_rejects_alg_none_and_hs256(keys):
    verifier = CardVerifier(trusted(keys, "ec"))
    none_card, _ = _hand_signed({"alg": "none", "kid": "k1"}, b"")
    with pytest.raises(CardSignatureError):
        await verifier.verify(none_card)
    # Classic key confusion: HMAC keyed with the trusted public key's PEM bytes.
    hs_card, signing_input = _hand_signed({"alg": "HS256", "kid": "k1"}, b"")
    secret = keys["ec"][1].read_bytes()
    mac = hmac.new(secret, signing_input, hashlib.sha256).digest()
    hs_card.signatures[0].signature = base64url_encode(mac).decode()
    with pytest.raises(CardSignatureError):
        await verifier.verify(hs_card)


async def test_verify_accepts_if_any_signature_is_valid(keys):
    c = signer(keys, "ed", kid="untrusted").sign(card())
    c = signer(keys, "ec", kid="k1").sign(c)
    assert await CardVerifier(trusted(keys, "ec")).verify(c) == "k1"


def _jwks(keys, name, kid):
    jwk = load_public_key(keys[name][1])
    data = dict(jwk._jwk_data)
    data["kid"] = kid
    return {"keys": [data]}


@respx.mock
async def test_jwks_from_allowlisted_jku_verifies_and_is_cached(keys):
    route = respx.get(JKU).respond(200, json=_jwks(keys, "ec", "k7"))
    verifier = CardVerifier(jwks_urls=[JKU])
    signed = signer(keys, "ec", kid="k7", jku=JKU).sign(card())
    assert await verifier.verify(signed) == "k7"
    assert await verifier.verify(signed) == "k7"
    assert route.call_count == 1


@respx.mock
async def test_jwks_cache_expires(keys, monkeypatch):
    from a2agw.security import cardsign

    route = respx.get(JKU).respond(200, json=_jwks(keys, "ec", "k7"))
    verifier = CardVerifier(jwks_urls=[JKU])
    signed = signer(keys, "ec", kid="k7", jku=JKU).sign(card())
    await verifier.verify(signed)
    monkeypatch.setattr(cardsign, "JWKS_TTL_S", 0.0)
    await verifier.verify(signed)
    assert route.call_count == 2


@respx.mock
async def test_jku_outside_allowlist_ignored(keys):
    evil = "https://evil.example.com/jwks.json"
    route = respx.get(evil).respond(200, json=_jwks(keys, "ec", "k7"))
    signed = signer(keys, "ec", kid="k7", jku=evil).sign(card())
    with pytest.raises(CardSignatureError):
        await CardVerifier(jwks_urls=[JKU]).verify(signed)
    assert not route.called


@respx.mock
async def test_jwks_fetch_ssrf_guarded(keys):
    meta = "https://169.254.169.254/jwks.json"
    route = respx.get(meta).respond(200, json=_jwks(keys, "ec", "k7"))
    signed = signer(keys, "ec", kid="k7", jku=meta).sign(card())
    # Even an allowlisted jku must pass the public-tier SSRF check.
    with pytest.raises(CardSignatureError):
        await CardVerifier(jwks_urls=[meta]).verify(signed)
    plain = "http://169.254.169.254/"
    signed = signer(keys, "ec", kid="k7", jku=plain).sign(card())
    with pytest.raises(CardSignatureError):
        await CardVerifier(jwks_urls=[plain]).verify(signed)
    assert not route.called


@respx.mock
async def test_jwks_too_large_rejected(keys):
    respx.get(JKU).respond(200, content=b"{" + b" " * (1024 * 1024 + 10) + b"}")
    signed = signer(keys, "ec", kid="k7", jku=JKU).sign(card())
    with pytest.raises(CardSignatureError, match="jwks"):
        await CardVerifier(jwks_urls=[JKU]).verify(signed)


@respx.mock
async def test_jwks_symmetric_keys_ignored(keys):
    oct_key = {"kty": "oct", "kid": "k7", "k": base64url_encode(b"secret" * 6).decode()}
    respx.get(JKU).respond(200, json={"keys": [oct_key]})
    c, signing_input = _hand_signed({"alg": "HS256", "kid": "k7", "jku": JKU}, b"")
    mac = hmac.new(b"secret" * 6, signing_input, hashlib.sha256).digest()
    c.signatures[0].signature = base64url_encode(mac).decode()
    with pytest.raises(CardSignatureError):
        await CardVerifier(jwks_urls=[JKU]).verify(c)


def test_signer_rejects_mismatched_alg_and_unknown_alg(keys):
    with pytest.raises(ValueError):
        CardSigner(keys["ed"][0], "k1", "ES256")
    with pytest.raises(ValueError):
        CardSigner(keys["ec"][0], "k1", "HS256")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        CardSigner(keys["ec"][0], "", "ES256")


def test_load_private_key_infers_alg_and_rejects_garbage(keys, tmp_path):
    assert load_private_key(keys["ec"][0]).algorithm_name == "ES256"
    assert load_private_key(keys["rsa"][0]).algorithm_name == "RS256"
    assert load_private_key(keys["ed"][0]).algorithm_name == "EdDSA"
    bad = tmp_path / "bad.pem"
    bad.write_text("not a key")
    with pytest.raises(ValueError) as ei:
        load_private_key(bad)
    assert "not a key" not in str(ei.value)
    small = tmp_path / "small.pem"
    small.write_bytes(
        ec.generate_private_key(ec.SECP384R1()).private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    with pytest.raises(ValueError):
        load_private_key(small)


def test_verifier_rejects_disallowed_trusted_key():
    from jwt import PyJWK

    hs = PyJWK({"kty": "oct", "k": base64url_encode(b"x" * 32).decode()}, algorithm="HS256")
    with pytest.raises(ValueError):
        CardVerifier({"k1": hs})


class _Echo:
    durable_sessions = False

    async def run(self, ctx):
        yield Done(text="hi")


async def test_host_serves_signed_card(env, keys):
    spec = AgentSpec(
        id="alpha",
        name="Alpha",
        description="Test agent",
        skills=[SkillSpec(id="s", name="S", description="d")],
        adapter=_Echo(),
    )
    e = await env(spec, card_signer=signer(keys, "ec"))
    verifier = CardVerifier(trusted(keys, "ec"))
    hc = e.hc
    for path in ("/.well-known/agent-card.json", "/agents/alpha/.well-known/agent-card.json"):
        r = await hc.get(path)
        assert r.headers["cache-control"] == "public, max-age=300"
        body = r.json()
        assert len(body["signatures"]) == 1
        assert await verifier.verify(parse_agent_card(body)) == "k1"
    assert len(e.host.cards["alpha"].signatures) == 1
