"""Phase 2 CLI: init --secure, config-driven TLS/trust for partner commands, DB errors."""

from __future__ import annotations

import re
import stat
import sys

import httpx
import pytest
from a2a.client.card_resolver import parse_agent_card
from typer.testing import CliRunner

from a2agw import cli
from a2agw.config import build_host, load_config
from a2agw.security.auth import hash_api_key
from a2agw.security.cardsign import CardVerifier, load_public_key

runner = CliRunner()
PASSWORD = "s3cretPW-marker"


def run(*args, env=None):
    return runner.invoke(cli.app, list(args), env=env)


# -- init --secure ----------------------------------------------------------------------


async def test_init_secure_scaffold_starts_and_serves_a_signed_card(tmp_path):
    d = tmp_path / "proj"
    r = run("init", str(d), "--secure")
    assert r.exit_code == 0, r.output
    m = re.search(r"API key: (\S+)", r.stdout)
    assert m, r.stdout
    api_key = m.group(1)
    assert "WARNING" in r.stdout and "only once" in r.stdout

    names = {p.name for p in d.iterdir()}
    assert {"a2agw.yaml", "agent.py", ".env.example", ".gitignore", "policy.yaml", "keys"} <= names
    assert "keys/" in (d / ".gitignore").read_text().splitlines()
    for key in (d / "keys").iterdir():
        assert stat.S_IMODE(key.stat().st_mode) == 0o600, key.name
    assert stat.S_IMODE((d / "keys").stat().st_mode) == 0o700
    # The plaintext key is never written; its hash is.
    for p in d.rglob("*"):
        if p.is_file():
            assert api_key.encode() not in p.read_bytes(), p.name
    assert hash_api_key(api_key) in (d / "a2agw.yaml").read_text()

    cfg = load_config(
        d / "a2agw.yaml", env={"A2AGW_DB_URL": f"sqlite+aiosqlite:///{tmp_path / 'g.db'}"}
    )
    assert cfg.signing is not None and cfg.policy_file and cfg.audit and cfg.auth is not None
    assert not cfg.admin_without_auth
    host = build_host(cfg, config_dir=d)
    await host.startup()
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(host.app()), base_url="http://localhost:8000"
        ) as hc:
            card_json = (await hc.get("/agents/echo/.well-known/agent-card.json")).json()
            anon = await hc.get("/a2agw/admin/agents")
            admin = await hc.get("/a2agw/admin/agents", headers={"X-API-Key": api_key})
        card = parse_agent_card(card_json)
        public = load_public_key(d / "keys" / "signing.pub.pem")
        verified = await CardVerifier(trusted={cfg.signing.kid: public}).verify(card)
        assert verified.kid == cfg.signing.kid
        assert anon.status_code == 401 and admin.status_code == 200
    finally:
        await host.shutdown()
        sys.modules.pop("agent", None)


def test_init_secure_refuses_existing_keys(tmp_path):
    d = tmp_path / "proj"
    assert run("init", str(d), "--secure").exit_code == 0
    r = run("init", str(d), "--secure")
    assert r.exit_code == 1 and "refusing" in r.output
    sys.modules.pop("agent", None)


# -- partner commands use the configured trust and TLS ----------------------------------


def _pem_pair(d):
    from test_config_phase2 import _pem_pair as make

    make(d)


def test_partner_commands_use_config_tls_and_trust(tmp_path):
    keys = tmp_path / "keys"
    keys.mkdir()
    _pem_pair(keys)
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    pub = ed25519.Ed25519PrivateKey.generate().public_key()
    (keys / "peer.pub.pem").write_bytes(
        pub.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    (tmp_path / "a2agw.yaml").write_text(
        "base_url: http://x\n"
        "tls:\n  acme: {cert_file: keys/client.crt, key_file: keys/client.key}\n"
        "trust:\n  card_keys: {peer: keys/peer.pub.pem}\n  require_signed: [public]\n"
    )
    reg = cli._registry(tmp_path / "a2agw.yaml", None)
    assert set(reg.tls) == {"acme"} and set(reg.verifier.trusted) == {"peer"}
    assert reg.require_signed == frozenset({"public"})
    r = run(
        "partners",
        "add",
        "p1",
        "https://partner.example.com",
        "--tier",
        "partner",
        "--tls-ref",
        "nope",
        "-c",
        str(tmp_path / "a2agw.yaml"),
    )
    assert r.exit_code == 1 and "unknown tls_ref" in r.output and "Traceback" not in r.output


# -- serve: server_tls from config ------------------------------------------------------


def test_serve_uses_server_tls_from_config(tmp_path, monkeypatch):
    keys = tmp_path / "keys"
    keys.mkdir()
    _pem_pair(keys)
    (tmp_path / "a2agw.yaml").write_text(
        f"base_url: https://x\ndb_url: sqlite+aiosqlite:///{tmp_path / 'g.db'}\n"
        "server_tls:\n  cert_file: keys/client.crt\n  key_file: keys/client.key\n"
        "  ca_file: keys/client.crt\n  require_client_cert: true\n"
    )
    calls = {}
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: calls.update(kw))
    r = run("serve", "-c", str(tmp_path / "a2agw.yaml"))
    assert r.exit_code == 0, r.output
    assert calls["ssl_certfile"] == str(keys / "client.crt")
    assert calls["ssl_keyfile"] == str(keys / "client.key")
    assert calls["ssl_ca_certs"] == str(keys / "client.crt")
    import ssl

    assert calls["ssl_cert_reqs"] == ssl.CERT_REQUIRED
    # A flag overrides the config.
    other = tmp_path / "other.crt"
    other.write_bytes((keys / "client.crt").read_bytes())
    r = run("serve", "-c", str(tmp_path / "a2agw.yaml"), "--ssl-certfile", str(other))
    assert r.exit_code == 0, r.output
    assert calls["ssl_certfile"] == str(other)


def test_serve_server_tls_missing_file(tmp_path, monkeypatch):
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: pytest.fail("must not serve"))
    (tmp_path / "a2agw.yaml").write_text(
        "base_url: https://x\nserver_tls: {cert_file: nope.crt, key_file: nope.key}\n"
    )
    r = run("serve", "-c", str(tmp_path / "a2agw.yaml"))
    assert r.exit_code == 1 and "nope.crt" in r.output and "Traceback" not in r.output


# -- database errors --------------------------------------------------------------------


def _db_config(tmp_path, db_url_expr="${DB_URL}"):
    p = tmp_path / "a2agw.yaml"
    p.write_text(f"base_url: http://x\ndb_url: {db_url_expr}\n")
    return str(p)


def _one_line_error(r):
    assert r.exit_code == 1, r.output
    assert "Traceback" not in r.output
    lines = [x for x in r.output.splitlines() if x.strip()]
    assert len(lines) == 1 and lines[0].startswith("error: "), r.output
    assert PASSWORD not in r.output
    return lines[0]


@pytest.mark.parametrize("command", [["audit", "verify"], ["audit", "export"], ["serve"]])
def test_db_connection_refused_is_one_line_without_password(tmp_path, monkeypatch, command):
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: None)
    cfg = _db_config(tmp_path)
    url = f"postgresql+asyncpg://bob:{PASSWORD}@127.0.0.1:1/db"
    line = _one_line_error(run(*command, "-c", cfg, env={"DB_URL": url}))
    assert "127.0.0.1:1/db" in line and "***@" in line and "bob" not in line


@pytest.mark.parametrize("url", ["not a url", "mysql+nodriver://bob:{pw}@h/d"])
def test_db_bad_url_is_one_line(tmp_path, url):
    cfg = _db_config(tmp_path)
    line = _one_line_error(
        run("audit", "verify", "-c", cfg, env={"DB_URL": url.format(pw=PASSWORD)})
    )
    assert "database" in line


def test_db_auth_failure_is_one_line(tmp_path, monkeypatch):
    import asyncpg.exceptions
    import sqlalchemy.ext.asyncio as sa_async

    class Engine:
        def connect(self):
            raise asyncpg.exceptions.InvalidPasswordError(
                f'password authentication failed for user "bob" ({PASSWORD})'
            )

        async def dispose(self):
            return None

    monkeypatch.setattr(sa_async, "create_async_engine", lambda *a, **k: Engine())
    cfg = _db_config(tmp_path)
    url = f"postgresql+asyncpg://bob:{PASSWORD}@db.example:5432/gw"
    line = _one_line_error(run("audit", "verify", "-c", cfg, env={"DB_URL": url}))
    assert "InvalidPasswordError" in line


def test_db_driver_missing_is_one_line(tmp_path, monkeypatch):
    import sqlalchemy.ext.asyncio as sa_async

    def missing(*a, **k):
        raise ModuleNotFoundError("No module named 'asyncpg'", name="asyncpg")

    monkeypatch.setattr(sa_async, "create_async_engine", missing)
    cfg = _db_config(tmp_path)
    url = f"postgresql+asyncpg://bob:{PASSWORD}@db.example/gw"
    line = _one_line_error(run("audit", "verify", "-c", cfg, env={"DB_URL": url}))
    assert "asyncpg" in line and "postgres" in line


def test_serve_sqlite_in_missing_directory_is_one_line(tmp_path, monkeypatch):
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: pytest.fail("must not serve"))
    cfg = _db_config(tmp_path, f"sqlite+aiosqlite:///{tmp_path / 'nope' / 'g.db'}")
    line = _one_line_error(run("serve", "-c", cfg))
    assert "g.db" in line
