"""Signed call contexts: signer, verifier and the executor's admission rule for the JWS."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid

import jwt
import pytest
from a2a.types import Message, Part, Role
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from jwt import PyJWK

from a2agw.context.call_context import (
    EXTENSION_URI,
    METADATA_KEY,
    CallContext,
    CallContextViolation,
)
from a2agw.context.signing import (
    JWS_METADATA_KEY,
    MAX_TOKEN_BYTES,
    TYP,
    CallContextSigner,
    CallContextVerifier,
)
from a2agw.security.cardsign import load_public_key
from a2agw.serve.agent import AgentSpec, SkillSpec
from a2agw.serve.executor import AdapterExecutor


def _write(tmp_path, name, private_key):
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
    return {
        "ES256": _write(tmp_path, "ec", ec.generate_private_key(ec.SECP256R1())),
        "RS256": _write(
            tmp_path, "rsa", rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ),
        "EdDSA": _write(tmp_path, "ed", ed25519.Ed25519PrivateKey.generate()),
    }


@pytest.fixture
def ec_pair(keys):
    priv, pub = keys["ES256"]
    signer = CallContextSigner(priv, "gw-a", "ES256", "https://a.example")
    verifier = CallContextVerifier({"gw-a": ("https://a.example", load_public_key(pub))})
    return signer, verifier, priv


def _cc(**kw) -> CallContext:
    base = {
        "origin": "o1",
        "root_agent": "a",
        "hop": 1,
        "path": ("a",),
        "deadline": time.time() + 120,
    }
    base.update(kw)
    return CallContext(**base)


def _private(priv_path):
    return serialization.load_pem_private_key(priv_path.read_bytes(), password=None)


def _claims(cc: CallContext, **kw) -> dict:
    now = int(time.time())
    claims = {
        "cc": cc.to_metadata()[METADATA_KEY],
        "iss": "https://a.example",
        "iat": now,
        "nbf": now,
        "exp": now + 60,
        "jti": uuid.uuid4().hex,
    }
    claims.update(kw)
    return claims


def _forge(priv_path, claims, *, alg="ES256", headers=None) -> str:
    h = {"kid": "gw-a", "typ": TYP}
    h.update(headers or {})
    return jwt.encode(claims, _private(priv_path), algorithm=alg, headers=h)


def _b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


# -- signer and round trip ------------------------------------------------------------


@pytest.mark.parametrize("alg", ["ES256", "RS256", "EdDSA"])
def test_round_trip_each_alg(keys, alg):
    priv, pub = keys[alg]
    signer = CallContextSigner(priv, "k1", alg, "gw")
    verifier = CallContextVerifier({"k1": ("gw", load_public_key(pub))})
    cc = _cc(on_behalf_of="jwt:bob", max_calls=5, calls_used=2, traceparent="00-x-y-01")
    assert verifier.verify(signer.sign(cc)) == cc


def test_token_header_and_claims(ec_pair):
    signer, _, _ = ec_pair
    cc = _cc(deadline=time.time() + 30.7)
    token = signer.sign(cc)
    header = jwt.get_unverified_header(token)
    assert header == {"alg": "ES256", "kid": "gw-a", "typ": "a2agw-cc+jwt"}
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["cc"] == cc.to_metadata()[METADATA_KEY]
    assert claims["iss"] == "https://a.example"
    assert claims["nbf"] == claims["iat"]
    assert claims["exp"] <= cc.deadline
    assert claims["exp"] == int(cc.deadline)
    assert isinstance(claims["jti"], str) and claims["jti"]
    again = jwt.decode(signer.sign(cc), options={"verify_signature": False})
    assert again["jti"] != claims["jti"]


def test_exp_capped_at_ten_minutes(ec_pair):
    signer, _, _ = ec_pair
    for deadline in (None, time.time() + 86_400):
        claims = jwt.decode(
            signer.sign(_cc(deadline=deadline)), options={"verify_signature": False}
        )
        assert claims["exp"] == claims["iat"] + 600


def test_signer_rejects_bad_config(keys):
    priv, _ = keys["ES256"]
    with pytest.raises(ValueError, match="alg"):
        CallContextSigner(priv, "k", "HS256", "gw")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="does not match"):
        CallContextSigner(priv, "k", "RS256", "gw")
    with pytest.raises(ValueError, match="kid"):
        CallContextSigner(priv, "", "ES256", "gw")
    with pytest.raises(ValueError, match="issuer"):
        CallContextSigner(priv, "k", "ES256", "")


def test_verifier_rejects_bad_trusted_key(keys):
    good = load_public_key(keys["ES256"][1])
    with pytest.raises(ValueError, match="issuer"):
        CallContextVerifier({"k": ("", good)})
    hmac_key = PyJWK({"kty": "oct", "k": _b64("secret")}, algorithm="HS256")
    with pytest.raises(ValueError, match="not an allowed"):
        CallContextVerifier({"k": ("gw", hmac_key)})


# -- verification failures --------------------------------------------------------------


def _bad(verifier, token):
    with pytest.raises(CallContextViolation, match="^bad signature$"):
        verifier.verify(token)


def test_tampered_hop_rejected(ec_pair):
    signer, verifier, _ = ec_pair
    token = signer.sign(_cc(hop=3))
    head, payload, sig = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    claims["cc"]["hop"] = 0
    claims["cc"]["path"] = []
    _bad(verifier, f"{head}.{_b64(claims)}.{sig}")


def test_expired_rejected(ec_pair):
    _, verifier, priv = ec_pair
    now = int(time.time())
    _bad(verifier, _forge(priv, _claims(_cc(), iat=now - 700, nbf=now - 700, exp=now - 31)))


def test_expired_within_leeway_accepted(ec_pair):
    _, verifier, priv = ec_pair
    now = int(time.time())
    cc = _cc()
    assert verifier.verify(_forge(priv, _claims(cc, exp=now - 5))) == cc


def test_not_yet_valid_rejected(ec_pair):
    _, verifier, priv = ec_pair
    now = int(time.time())
    _bad(verifier, _forge(priv, _claims(_cc(), nbf=now + 120, iat=now + 120, exp=now + 300)))


def test_wrong_issuer_for_kid_rejected(ec_pair):
    _, verifier, priv = ec_pair
    _bad(verifier, _forge(priv, _claims(_cc(), iss="https://b.example")))


@pytest.mark.parametrize("missing", ["exp", "iat", "iss"])
def test_missing_required_claim_rejected(ec_pair, missing):
    _, verifier, priv = ec_pair
    claims = _claims(_cc())
    del claims[missing]
    _bad(verifier, _forge(priv, claims))


def test_alg_none_rejected(ec_pair):
    _, verifier, _ = ec_pair
    header = {"alg": "none", "kid": "gw-a", "typ": TYP}
    _bad(verifier, f"{_b64(header)}.{_b64(_claims(_cc()))}.")


def test_hs256_rejected(ec_pair, keys):
    _, verifier, _ = ec_pair
    # The classic confusion: HMAC keyed with the verifier's public key bytes.
    secret = keys["ES256"][1].read_bytes()
    header = {"alg": "HS256", "kid": "gw-a", "typ": TYP}
    signing_input = f"{_b64(header)}.{_b64(_claims(_cc()))}"
    sig = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
    _bad(verifier, f"{signing_input}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}")


def test_alg_header_mismatching_key_rejected(ec_pair, keys):
    _, verifier, _ = ec_pair
    rsa_priv, _ = keys["RS256"]
    _bad(verifier, _forge(rsa_priv, _claims(_cc()), alg="RS256"))


def test_typ_missing_rejected(ec_pair):
    _, verifier, priv = ec_pair
    token = jwt.encode(
        _claims(_cc()), _private(priv), algorithm="ES256", headers={"kid": "gw-a", "typ": None}
    )
    assert "typ" not in jwt.get_unverified_header(token)
    _bad(verifier, token)


def test_wrong_typ_rejected(ec_pair):
    _, verifier, priv = ec_pair
    _bad(verifier, _forge(priv, _claims(_cc()), headers={"typ": "JWT"}))


def test_oversized_token_rejected(ec_pair):
    _, verifier, priv = ec_pair
    big = _claims(_cc(), pad="x" * MAX_TOKEN_BYTES)
    token = _forge(priv, big)
    assert len(token) > MAX_TOKEN_BYTES
    _bad(verifier, token)
    assert MAX_TOKEN_BYTES == 8 * 1024


def test_unknown_kid_rejected(ec_pair):
    _, verifier, priv = ec_pair
    _bad(verifier, _forge(priv, _claims(_cc()), headers={"kid": "someone-else"}))


@pytest.mark.parametrize(
    "bad_cc", [None, "x", {"root_agent": "a"}, {"origin": "o", "root_agent": "a", "path": "a"}]
)
def test_invalid_cc_claim_rejected(ec_pair, bad_cc):
    _, verifier, priv = ec_pair
    claims = _claims(_cc())
    claims["cc"] = bad_cc
    _bad(verifier, _forge(priv, claims))


@pytest.mark.parametrize("token", ["", "garbage", "a.b.c", 42, None])
def test_garbage_rejected(ec_pair, token):
    _, verifier, _ = ec_pair
    _bad(verifier, token)


# -- executor admission -----------------------------------------------------------------


class _Nop:
    durable_sessions = False

    def run(self, ctx):  # pragma: no cover - never run here
        raise AssertionError


def _executor(verifier=None, agent="a") -> AdapterExecutor:
    spec = AgentSpec(
        id=agent,
        name=agent,
        description="d",
        skills=[SkillSpec(id="s", name="S", description="d")],
        adapter=_Nop(),
    )
    return AdapterExecutor(spec, None, None, context_verifier=verifier)  # type: ignore[arg-type]


def _message(unsigned: CallContext | None, token=None) -> Message:
    m = Message(message_id="m", role=Role.ROLE_USER, parts=[Part(text="x")])
    if unsigned is not None:
        m.metadata.update(unsigned.to_metadata())
    if token is not None:
        m.metadata.update({JWS_METADATA_KEY: token})
    return m


def test_jws_metadata_key():
    assert JWS_METADATA_KEY == "https://a2agw.dev/ext/call-context/v1#jws"
    assert JWS_METADATA_KEY == f"{EXTENSION_URI}#jws"


def test_admit_uses_signed_context_over_unsigned(ec_pair):
    signer, verifier, _ = ec_pair
    signed = _cc(path=("a", "x"), hop=2)
    stripped = _cc(path=(), hop=0)
    # Without a verifier the stripped unsigned context admits "a" ...
    cc, reason = _executor()._admit(_message(stripped, signer.sign(signed)))
    assert reason == "" and cc is not None and cc.path == ()
    # ... with one, the signed path shows the cycle.
    cc, reason = _executor(verifier)._admit(_message(stripped, signer.sign(signed)))
    assert (cc, reason) == (None, "cycle detected")


def test_admit_signed_context_is_clamped(ec_pair):
    signer, verifier, _ = ec_pair
    signed = _cc(path=("x",), hop=1, max_hops=50)
    cc, reason = _executor(verifier)._admit(_message(None, signer.sign(signed)))
    assert reason == ""
    assert cc is not None and cc.max_hops == 8 and cc.path == ("x",) and cc.origin == "o1"


def test_admit_signed_hop_limit(ec_pair):
    signer, verifier, _ = ec_pair
    signed = _cc(path=("x",), hop=8)
    cc, reason = _executor(verifier)._admit(_message(_cc(hop=0, path=()), signer.sign(signed)))
    assert (cc, reason) == (None, "hop limit exceeded")


def test_admit_bad_jws_with_verifier_rejects(ec_pair):
    signer, verifier, priv = ec_pair
    token = signer.sign(_cc(path=("x",)))
    tampered = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
    for bad in (tampered, 42, _forge(priv, _claims(_cc()), headers={"kid": "unknown"})):
        cc, reason = _executor(verifier)._admit(_message(_cc(path=("x",)), bad))
        assert (cc, reason) == (None, "invalid call context")


def test_admit_unknown_kid_without_verifier_ignores_jws(ec_pair):
    _, _, priv = ec_pair
    token = _forge(priv, _claims(_cc(path=("a",))), headers={"kid": "unknown"})
    cc, reason = _executor()._admit(_message(_cc(path=("x",)), token))
    assert reason == "" and cc is not None and cc.path == ("x",)
    # Even garbage is ignored when signing is not configured: Phase 1 behaviour.
    cc, reason = _executor()._admit(_message(_cc(path=("x",)), "garbage"))
    assert reason == "" and cc is not None


def test_admit_no_jws_unchanged_with_verifier(ec_pair):
    _, verifier, _ = ec_pair
    cc, reason = _executor(verifier)._admit(_message(_cc(path=("x",))))
    assert reason == "" and cc is not None and cc.path == ("x",)
    cc, reason = _executor(verifier)._admit(_message(_cc(path=("a",))))
    assert (cc, reason) == (None, "cycle detected")
