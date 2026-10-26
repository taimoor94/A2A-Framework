"""I5 (token endpoint / card JWKS tiers, https), T12-1 (inline secret in a default), T12-3
(``server_tls`` with ``build_host``)."""

from __future__ import annotations

import logging

import pytest
import respx

from a2agw.config import ConfigError, build_host, load_config, server_run_kwargs
from a2agw.consult import netguard
from a2agw.consult.netguard import UnsafeURL
from a2agw.consult.oauth import OAuthClientCredentials, OAuthTokenExchange, TokenError
from a2agw.consult.registry import PartnerRecord
from a2agw.security.cardsign import CardSignatureError, CardVerifier


@pytest.fixture(autouse=True)
def dns(monkeypatch):
    async def fake(host: str) -> list[str]:
        return ["10.0.0.7"] if host.endswith(".corp") else ["93.184.216.34"]

    monkeypatch.setattr(netguard, "_resolve", fake)
    monkeypatch.delenv("A2AGW_DEV", raising=False)
    monkeypatch.setenv("OAUTH_SECRET", "s3cr3t")


def _partner() -> PartnerRecord:
    return PartnerRecord(
        id="p1", card={"name": "p1"}, card_hash="h", tier="public", credential_ref="oauth"
    )


# -- I5: OAuth token endpoint tier -------------------------------------------------------


async def test_token_endpoint_tier_defaults_to_public_and_can_be_internal():
    url = "https://idp.corp/token"  # resolves to a private address
    with respx.mock(assert_all_called=False) as rx:
        route = rx.post(url).respond(200, json={"access_token": "tok", "expires_in": 300})
        public = OAuthClientCredentials(url, "c", "OAUTH_SECRET")
        assert public.tier == "public"
        with pytest.raises(TokenError, match="unsafe"):
            await public.headers(_partner(), None)
        assert route.call_count == 0
        internal = OAuthClientCredentials(url, "c", "OAUTH_SECRET", tier="internal")
        assert await internal.headers(_partner(), None) == {"Authorization": "Bearer tok"}
        exchange = OAuthTokenExchange(url, "c", "OAUTH_SECRET", "aud", {"oauth"}, tier="internal")
        assert exchange.tier == "internal"


def test_token_endpoint_needs_https_on_every_tier(monkeypatch):
    for tier in ("internal", "partner", "public"):
        with pytest.raises(UnsafeURL, match="https"):
            OAuthClientCredentials("http://idp.corp/token", "c", "OAUTH_SECRET", tier=tier)
    monkeypatch.setenv("A2AGW_DEV", "1")
    OAuthClientCredentials("http://idp.corp/token", "c", "OAUTH_SECRET", tier="internal")


# -- I5: card JWKS tier --------------------------------------------------------------------


async def test_card_jwks_tier_defaults_to_public_and_can_be_internal():
    url = "https://keys.corp/jwks.json"
    with respx.mock(assert_all_called=False) as rx:
        route = rx.get(url).respond(200, json={"keys": []})
        public = CardVerifier(jwks_urls=[url])
        assert public.jwks_tier == "public"
        with pytest.raises(CardSignatureError, match="refused"):
            await public._fetch_jwks(url)
        assert route.call_count == 0
        internal = CardVerifier(jwks_urls=[url], jwks_tier="internal")
        assert await internal._fetch_jwks(url) == {}
        assert route.call_count == 1


def test_card_jwks_urls_need_https_on_every_tier():
    for tier in ("internal", "public"):
        with pytest.raises(UnsafeURL, match="https"):
            CardVerifier(jwks_urls=["http://keys.corp/jwks.json"], jwks_tier=tier)


def _cfg(tmp_path, body: str):
    p = tmp_path / "a2agw.yaml"
    p.write_text("base_url: http://localhost\n" + body)
    return p


def test_config_wires_tiers_and_checks_https_at_load(tmp_path, monkeypatch):
    p = _cfg(
        tmp_path,
        "oauth:\n  acme:\n    type: client_credentials\n    token_url: https://idp.corp/t\n"
        "    client_id: gw\n    client_secret_env: OAUTH_SECRET\n    token_tier: internal\n"
        "trust:\n  jwks_urls: [https://keys.corp/jwks.json]\n  jwks_tier: internal\n",
    )
    host = build_host(load_config(p), config_dir=tmp_path)
    oauth = [c for c in host.credentials.providers if isinstance(c, OAuthClientCredentials)]
    assert [c.tier for c in oauth] == ["internal"]
    assert host.partners.verifier.jwks_tier == "internal"
    defaults = _cfg(
        tmp_path,
        "oauth:\n  acme:\n    type: client_credentials\n    token_url: https://idp.example.com/t\n"
        "    client_id: gw\n    client_secret_env: OAUTH_SECRET\n",
    )
    assert load_config(defaults).oauth["acme"].token_tier == "public"
    bad_jwks = _cfg(tmp_path, "trust:\n  jwks_urls: [http://keys.example.com/jwks.json]\n")
    with pytest.raises(ConfigError, match=r"trust\.jwks_urls.*https"):
        load_config(bad_jwks)
    bad_token = _cfg(
        tmp_path,
        "oauth:\n  acme:\n    type: client_credentials\n    token_url: http://idp.example.com/t\n"
        "    client_id: gw\n    client_secret_env: OAUTH_SECRET\n",
    )
    with pytest.raises(ConfigError, match=r"oauth\.acme\.token_url.*https"):
        load_config(bad_token)
    monkeypatch.setenv("A2AGW_DEV", "1")
    load_config(bad_jwks)
    load_config(bad_token)


# -- T12-1: inline password in a ${VAR:-default} -------------------------------------------


def test_inline_password_in_a_db_url_default_is_refused(tmp_path):
    p = _cfg(tmp_path, "db_url: ${GW_DB_URL_T12:-postgresql+asyncpg://gw:hunter2@db/gw}\n")
    with pytest.raises(ConfigError, match="inline database password") as info:
        load_config(p, env={})
    assert "hunter2" not in str(info.value)
    # A default without a password is fine.
    ok = _cfg(tmp_path, "db_url: ${GW_DB_URL_T12:-sqlite+aiosqlite:///gw.db}\n")
    assert load_config(ok, env={}).db_url == "sqlite+aiosqlite:///gw.db"


# -- T12-3: server_tls with build_host -----------------------------------------------------


def test_server_tls_reaches_run_through_server_run_kwargs(tmp_path, caplog):
    for name in ("c.pem", "k.pem", "ca.pem"):
        (tmp_path / name).write_text("x")
    p = _cfg(
        tmp_path,
        "server_tls: {cert_file: c.pem, key_file: k.pem, ca_file: ca.pem, "
        "require_client_cert: true}\n",
    )
    cfg = load_config(p)
    with caplog.at_level(logging.WARNING, logger="a2agw.config"):
        build_host(cfg, config_dir=tmp_path)
    assert any("server_run_kwargs" in r.getMessage() for r in caplog.records)
    assert server_run_kwargs(cfg, config_dir=tmp_path) == {
        "ssl_certfile": str(tmp_path / "c.pem"),
        "ssl_keyfile": str(tmp_path / "k.pem"),
        "ssl_ca_certs": str(tmp_path / "ca.pem"),
        "require_client_cert": True,
    }
    plain = load_config(_cfg(tmp_path, ""))
    assert server_run_kwargs(plain, config_dir=tmp_path) == {}
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="a2agw.config"):
        build_host(plain, config_dir=tmp_path)
    assert not any("server_run_kwargs" in r.getMessage() for r in caplog.records)


def test_serve_uses_server_tls_from_config(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from a2agw import cli
    from a2agw.serve.host import AgentHost

    for name in ("c.pem", "k.pem"):
        (tmp_path / name).write_text("x")
    p = _cfg(tmp_path, "server_tls: {cert_file: c.pem, key_file: k.pem}\n")
    seen: dict = {}
    monkeypatch.setattr(AgentHost, "run", lambda self, **kw: seen.update(kw))
    r = CliRunner().invoke(cli.app, ["serve", "-c", str(p)])
    assert r.exit_code == 0, r.output
    assert seen["ssl_certfile"] == str(tmp_path / "c.pem")
    assert seen["ssl_keyfile"] == str(tmp_path / "k.pem")
    assert seen["require_client_cert"] is False


def test_https_helper(monkeypatch):
    netguard.require_https("https://x.example.com/")
    with pytest.raises(UnsafeURL):
        netguard.require_https("http://x.example.com/")
    monkeypatch.setenv("A2AGW_DEV", "1")
    netguard.require_https("http://x.example.com/")
