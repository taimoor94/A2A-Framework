"""Phase 2 config sections: signing, trust, oauth, tls, policy, push, audit, server_tls."""

from __future__ import annotations

import os
import sys
import textwrap

import httpx
import pytest
from a2a.client.card_resolver import parse_agent_card
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from a2agw.config import ConfigError, build_host, load_config
from a2agw.consult.credentials import ChainCredentials
from a2agw.consult.oauth import OAuthClientCredentials, OAuthTokenExchange
from a2agw.security.cardsign import CardVerifier, load_public_key

MARKER = "SEKRIT-MARKER-7f3a"

AGENT_MOD = "p2cfg_agent_mod"


@pytest.fixture
def proj(tmp_path):
    """A config dir with an agent module and an Ed25519 key pair under keys/."""
    (tmp_path / f"{AGENT_MOD}.py").write_text(
        "from a2agw.adapters.callable import agent\n"
        "@agent(id='e1', description='d')\n"
        "async def e1(ctx):\n    return ctx.text\n"
    )
    keys = tmp_path / "keys"
    keys.mkdir()
    for name in ("gw", "peer"):
        key = ed25519.Ed25519PrivateKey.generate()
        (keys / f"{name}.pem").write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        (keys / f"{name}.pub.pem").write_bytes(
            key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    yield tmp_path
    sys.modules.pop(AGENT_MOD, None)


def write(d, body: str, name="a2agw.yaml"):
    p = d / name
    head = (
        "base_url: http://gw.test\n"
        f"db_url: sqlite+aiosqlite:///{d / 'gw.db'}\n"
        f"agents:\n  - spec: {AGENT_MOD}:e1\n"
    )
    p.write_text(head + textwrap.dedent(body))
    return p


def load(d, body, env=None):
    return load_config(write(d, body), env=env or {})


def build(d, body, env=None):
    return build_host(load(d, body, env), config_dir=d)


# -- signing / trust --------------------------------------------------------------------


async def test_signing_signs_cards_contexts_and_push(proj):
    host = build(
        proj,
        """
        signing: {key_file: keys/gw.pem, kid: gw-1, alg: EdDSA}
        push: {allow_private: true, max_attempts: 2}
        """,
    )
    assert host.card_signer is not None and host.card_signer.kid == "gw-1"
    assert host.context_signer is not None and host.context_signer.issuer == "http://gw.test"
    # Own key trusted for loop detection even without trust.context_issuers.
    assert host.context_verifier is not None and "gw-1" in host.context_verifier.trusted
    assert host.push is not None and host.push.jwt_signer is host.card_signer
    assert host.push.max_attempts == 2 and host.push.allow_private is True
    await host.startup()
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(host.app()), base_url="http://gw.test"
        ) as hc:
            r = await hc.get("/agents/e1/.well-known/agent-card.json")
        card = parse_agent_card(r.json())
        verifier = CardVerifier(trusted={"gw-1": load_public_key(proj / "keys/gw.pub.pem")})
        assert (await verifier.verify(card)).kid == "gw-1"
    finally:
        await host.shutdown()


def test_signing_issuer_override_and_bad_alg(proj):
    host = build(proj, "signing: {key_file: keys/gw.pem, kid: k, alg: EdDSA, issuer: urn:gw}\n")
    assert host.context_signer.issuer == "urn:gw"
    with pytest.raises(ConfigError, match=r"signing\.alg"):
        load(proj, "signing: {key_file: keys/gw.pem, kid: k, alg: HS256}\n")
    with pytest.raises(ConfigError, match="signing") as ei:
        build(proj, "signing: {key_file: keys/gw.pem, kid: k, alg: ES256}\n")
    assert "BEGIN" not in str(ei.value)


def test_trust_section(proj):
    host = build(
        proj,
        """
        trust:
          card_keys: {peer-1: keys/peer.pub.pem}
          jwks_urls: [https://keys.example.com/jwks.json]
          require_signed: [partner, public]
          context_issuers:
            peer-1: {issuer: https://peer.example.com, key_file: keys/peer.pub.pem}
        """,
    )
    reg = host.partners
    assert set(reg.verifier.trusted) == {"peer-1"}
    assert reg.verifier.jwks_urls == {"https://keys.example.com/jwks.json"}
    assert reg.require_signed == frozenset({"partner", "public"})
    assert host.context_verifier.trusted["peer-1"][0] == "https://peer.example.com"
    with pytest.raises(ConfigError, match="require_signed needs"):
        load(proj, "trust: {require_signed: [public]}\n")


@pytest.mark.parametrize(
    "body, where",
    [
        ("signing: {key_file: keys/nope.pem, kid: k, alg: EdDSA}\n", "keys/nope.pem"),
        ("trust: {card_keys: {k: keys/nope.pub.pem}}\n", "keys/nope.pub.pem"),
        ("policy_file: nope-policy.yaml\n", "nope-policy.yaml"),
    ],
)
def test_missing_files_name_the_file(proj, body, where):
    with pytest.raises(ConfigError) as ei:
        build(proj, body)
    assert where in str(ei.value)


def test_unreadable_or_garbage_key_never_leaks_contents(proj):
    (proj / "keys/bad.pem").write_text(f"-----BEGIN PRIVATE KEY-----\n{MARKER}\n")
    with pytest.raises(ConfigError) as ei:
        build(proj, "signing: {key_file: keys/bad.pem, kid: k, alg: EdDSA}\n")
    assert "bad.pem" in str(ei.value) and MARKER not in str(ei.value)
    if os.geteuid() != 0:
        os.chmod(proj / "keys/gw.pem", 0)
        try:
            with pytest.raises(ConfigError, match="gw.pem"):
                build(proj, "signing: {key_file: keys/gw.pem, kid: k, alg: EdDSA}\n")
        finally:
            os.chmod(proj / "keys/gw.pem", 0o600)


# -- oauth / credentials ----------------------------------------------------------------


def test_oauth_section_builds_providers(proj):
    host = build(
        proj,
        """
        oauth:
          svc:
            type: client_credentials
            token_url: https://idp.example.com/token
            client_id: gw
            client_secret_env: GW_SECRET
            scope: a2a
          obo:
            type: token_exchange
            token_url: https://idp.example.com/token
            client_id: gw
            client_secret_env: GW_SECRET
            audience: https://acme.example.com
            fallback: svc
        credentials:
          static: {header: Authorization, env: STATIC_TOKEN}
        partners:
          - {id: acme, card_file: acme.json, tier: partner, credential_ref: obo}
        """,
    )
    creds = host.credentials
    assert isinstance(creds, ChainCredentials)
    kinds = {type(p) for p in creds.providers}
    assert {OAuthClientCredentials, OAuthTokenExchange} <= kinds
    obo = next(p for p in creds.providers if isinstance(p, OAuthTokenExchange))
    assert obo.refs == {"obo"} and obo.audience == "https://acme.example.com"
    assert isinstance(obo.fallback, OAuthClientCredentials) and obo.fallback.refs == {"obo"}
    svc = next(p for p in creds.providers if type(p) is OAuthClientCredentials)
    assert svc.refs == {"svc"} and svc.scope == "a2a"


@pytest.mark.parametrize(
    "body, match",
    [
        (
            (
                "oauth: {x: {type: token_exchange, token_url: 'https://i.example/t', client_id: c,"
                " client_secret_env: S}}\n"
            ),
            "audience",
        ),
        (
            (
                "oauth: {x: {type: client_credentials, token_url: 'https://i.example/t',"
                " client_id: c, client_secret_env: S, fallback: y}}\n"
            ),
            "fallback",
        ),
        (
            (
                "oauth: {x: {type: client_credentials, token_url: 'https://i.example/t',"
                " client_id: c, client_secret_env: S}}\n"
                "credentials: {x: {header: Authorization, env: T}}\n"
            ),
            "both",
        ),
        (
            "partners: [{id: a, card_file: a.json, tier: partner, credential_ref: nope}]\n",
            "unknown credential_ref",
        ),
        (
            "partners: [{id: a, card_file: a.json, tier: partner, tls_ref: nope}]\n",
            "unknown tls_ref",
        ),
    ],
)
def test_cross_reference_errors(proj, body, match):
    with pytest.raises(ConfigError, match=match):
        load(proj, body)


@pytest.mark.parametrize(
    "body, key",
    [
        (
            (
                "oauth: {x: {type: client_credentials, token_url: 'https://i.example/t',"
                f" client_id: c, client_secret: {MARKER}}}}}\n"
            ),
            "oauth.x.client_secret",
        ),
        (
            f"credentials: {{x: {{header: Authorization, token: {MARKER}}}}}\n",
            "credentials.x.token",
        ),
        (f"push: {{encryption_key: {MARKER}}}\n", "push.encryption_key"),
        (f"signing: {{private_key: {MARKER}, kid: k, alg: EdDSA}}\n", "signing.private_key"),
        (f"auth: {{jwt: {{password: {MARKER}}}}}\n", "auth.jwt.password"),
    ],
)
def test_inline_secrets_rejected_with_env_hint(proj, body, key):
    with pytest.raises(ConfigError) as ei:
        load(proj, body)
    msg = str(ei.value)
    assert key in msg and "_env" in msg and MARKER not in msg


def test_inline_db_password_rejected_but_env_password_allowed(proj):
    with pytest.raises(ConfigError) as ei:
        load_config(
            write(proj, f"db_url: postgresql+asyncpg://gw:{MARKER}@db.example/x\n", "d.yaml"),
            env={},
        )
    assert "db_url" in str(ei.value) and MARKER not in str(ei.value)
    cfg = load_config(
        write(proj, "db_url: postgresql+asyncpg://gw:${DB_PW}@db.example/x\n", "e.yaml"),
        env={"DB_PW": MARKER},
    )
    assert MARKER in cfg.db_url
    cfg = load_config(write(proj, "db_url: ${DB_URL}\n", "f.yaml"), env={"DB_URL": "sqlite://"})
    assert cfg.db_url == "sqlite://"


# -- tls --------------------------------------------------------------------------------


def _pem_pair(d):
    """A self-signed cert + key, good enough for TlsClientConfig's load checks."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
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
    (d / "client.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (d / "client.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(d / "client.key", 0o600)


async def test_tls_section_shared_by_registry_and_client(proj):
    _pem_pair(proj / "keys")
    host = build(
        proj,
        """
        tls:
          acme: {cert_file: keys/client.crt, key_file: keys/client.key, ca_file: keys/client.crt}
        """,
    )
    assert set(host.partners.tls) == {"acme"}
    assert host.partners.tls["acme"].cert_file == proj / "keys/client.crt"
    await host.startup()
    try:
        assert host.client.tls["acme"] is host.partners.tls["acme"]
    finally:
        await host.shutdown()


def test_tls_missing_file_is_config_error(proj):
    with pytest.raises(ConfigError, match=r"tls\.acme.*missing\.crt"):
        build(proj, "tls: {acme: {cert_file: keys/missing.crt, key_file: keys/gw.pem}}\n")


# -- policy / push / audit / server_tls -------------------------------------------------


def test_policy_file_and_classifier(proj):
    (proj / "policy.yaml").write_text(
        "version: 1\nauthz:\n  - {principal: '*', agents: '*', skills: '*', effect: allow}\n"
    )
    host = build(proj, "policy_file: policy.yaml\nclassifier: regex_pii\n")
    assert host.policy is not None and host.policy.classifier is not None
    (proj / "bad-policy.yaml").write_text(f"version: 1\nbogus: {MARKER}\n")
    with pytest.raises(ConfigError) as ei:
        build(proj, "policy_file: bad-policy.yaml\n")
    assert "bad-policy.yaml" in str(ei.value) and MARKER not in str(ei.value)
    with pytest.raises(ConfigError, match="classifier needs policy_file"):
        load(proj, "classifier: regex_pii\n")


def test_push_section_round_trip(proj):
    cfg = load(
        proj,
        """
        push:
          allow_private: true
          timeout_s: 3
          max_attempts: 5
          encryption_key_env: PUSH_KEY
          max_configs_per_task: 4
          max_concurrent_deliveries: 8
          max_pending_tasks: 50
        """,
    )
    host = build_host(cfg, config_dir=proj)
    p = host.push
    assert (p.timeout_s, p.max_attempts, p.encryption_key_env) == (3, 5, "PUSH_KEY")
    assert (p.max_configs_per_task, p.max_concurrent_deliveries, p.max_pending_tasks) == (4, 8, 50)
    assert p.jwt_signer is None
    with pytest.raises(ConfigError, match=r"push\.max_retries"):
        load(proj, "push: {max_retries: 3}\n")
    with pytest.raises(ConfigError, match=r"push\.max_attempts"):
        load(proj, "push: {max_attempts: 0}\n")


def test_audit_and_defaults(proj):
    host = build(proj, "")
    assert host.audit_enabled is True and host.push is None and host.policy is None
    assert host.card_signer is None and host.context_signer is None
    assert host.partners.verifier is None and host.partners.tls == {}
    assert build(proj, "audit: false\n").audit_enabled is False


def test_server_tls_validation(proj):
    cfg = load(proj, "server_tls: {cert_file: c.crt, key_file: c.key}\n")
    assert cfg.server_tls.require_client_cert is False
    with pytest.raises(ConfigError, match="require_client_cert needs ca_file"):
        load(proj, "server_tls: {cert_file: c.crt, key_file: c.key, require_client_cert: true}\n")


# -- strictness -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body, path",
    [
        ("auth: {jwt: {issuer: i, audience: a, public_key_pem: x, bogus: 1}}\n", "auth.jwt.bogus"),
        ("auth: {api_keys: {}, bogus: 1}\n", "auth.bogus"),
        ("signing: {key_file: k, kid: k, alg: EdDSA, bogus: 1}\n", "signing.bogus"),
        ("trust: {bogus: 1}\n", "trust.bogus"),
        ("tls: {a: {cert_file: c, key_file: k, bogus: 1}}\n", "tls.a.bogus"),
        ("server_tls: {cert_file: c, key_file: k, bogus: 1}\n", "server_tls.bogus"),
        ("partners: [{id: a, card_file: a.json, tier: partner, bogus: 1}]\n", "partners.0.bogus"),
        ("telemetry: {service_name: s, bogus: 1}\n", "telemetry.bogus"),
        ("push: {timeout_s: soon}\n", "push.timeout_s"),
        ("audit: maybe\n", "audit"),
        ("outbound_ttl_s: 0\n", "outbound_ttl_s"),
        ("trust: {require_signed: [galaxy]}\n", "trust.require_signed.0"),
    ],
)
def test_unknown_keys_and_wrong_types_are_path_qualified(proj, body, path):
    with pytest.raises(ConfigError) as ei:
        load(proj, body)
    assert path in str(ei.value)


def test_jwt_http_jwks_is_dev_only(proj, monkeypatch):
    body = "auth: {jwt: {issuer: i, audience: a, jwks_url: 'http://idp.local/jwks', jwks_tier: internal}}\n"
    monkeypatch.delenv("A2AGW_DEV", raising=False)
    with pytest.raises(ConfigError, match="https"):
        load(proj, body)
    monkeypatch.setenv("A2AGW_DEV", "1")
    assert load(proj, body).auth.jwt.jwks_tier == "internal"


def test_outbound_ttl_default(proj):
    assert load(proj, "").outbound_ttl_s == 86400


def test_operator_chosen_names_are_not_mistaken_for_secrets(proj):
    cfg = load(
        proj,
        """
        credentials:
          token: {header: Authorization, env: TOKEN_VALUE}
        partners:
          - {id: a, card_file: a.json, tier: partner, credential_ref: token}
        """,
    )
    assert "token" in cfg.credentials


def test_limits_and_maintenance_interval_reach_the_host(tmp_path):
    from a2agw.config import build_host, load_config

    cfg_file = tmp_path / "a2agw.yaml"
    cfg_file.write_text(
        "base_url: http://localhost\n"
        "maintenance_interval_s: 42\n"
        "limits: {max_concurrent_tasks_per_caller: 3, max_consults_per_task: 5}\n"
    )
    host = build_host(load_config(cfg_file), config_dir=tmp_path)
    assert host.maintenance_interval_s == 42
    assert host.caller_limiter.max_per_caller == 3 and host.max_consults_per_task == 5
    defaults = build_host(
        load_config_text(tmp_path, "base_url: http://localhost\n"), config_dir=tmp_path
    )
    assert defaults.caller_limiter.max_per_caller == 32 and defaults.max_consults_per_task == 16
    assert defaults.maintenance_interval_s == 300


def load_config_text(tmp_path, text):
    from a2agw.config import load_config

    p = tmp_path / "other.yaml"
    p.write_text(text)
    return load_config(p)
