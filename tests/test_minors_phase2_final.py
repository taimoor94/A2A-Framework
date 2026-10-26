"""Final-review minors: M1 admin CSRF header, M3 push JWT typ, M5 unguarded partner_http
warning, M9 startup-failure audit drain, T12 minors 4/5/7, T5 cancellation audit."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import stat

import httpx
import jwt as pyjwt
import pytest
from typer.testing import CliRunner

from a2agw import cli
from a2agw.consult.guarded_net import fixed_tier, guarded_async_client
from a2agw.ops.audit import AuditLog
from a2agw.security.auth import ApiKeyEntry, AuthConfig
from a2agw.serve.host import AgentHost
from a2agw.serve.store import create_engine

ADMIN_KEY = "admin-secret"


def _auth() -> AuthConfig:
    return AuthConfig(
        api_keys={
            hashlib.sha256(ADMIN_KEY.encode()).hexdigest(): ApiKeyEntry(
                principal_id="ops", scopes=["a2agw:admin"]
            )
        }
    )


# -- M1: admin POSTs need X-A2AGW-Admin: 1 ---------------------------------------------------


@pytest.mark.parametrize("mode", ["auth", "admin_without_auth"])
async def test_admin_posts_require_the_admin_header(tmp_path, mode):
    kw = {"auth": _auth()} if mode == "auth" else {"admin_without_auth": True}
    host = AgentHost(
        "http://t",
        db_url=f"sqlite+aiosqlite:///{tmp_path / 'h.db'}",
        partners_path=tmp_path / "partners.yaml",
        **kw,
    )
    await host.startup()
    base = {"X-API-Key": ADMIN_KEY} if mode == "auth" else {}
    hc = httpx.AsyncClient(transport=httpx.ASGITransport(app=host.app()), base_url="http://t")
    try:
        for path in ("/a2agw/admin/partners/reload", "/a2agw/admin/tasks/reap?agent=gone"):
            r = await hc.post(path, headers=base)
            assert r.status_code == 403, path
            assert (await hc.post(path, headers={**base, "X-A2AGW-Admin": "0"})).status_code == 403
            ok = await hc.post(path, headers={**base, "X-A2AGW-Admin": "1"})
            assert ok.status_code == 200, (path, ok.text)
        # Reads do not need it.
        assert (await hc.get("/a2agw/admin/agents", headers=base)).status_code == 200
    finally:
        await hc.aclose()
        await host.shutdown()


@pytest.mark.parametrize(
    ("bind", "warned"), [("0.0.0.0", True), ("127.0.0.1", False), ("::1", False)]
)
def test_admin_without_auth_on_a_public_bind_warns(monkeypatch, caplog, bind, warned):
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: None)
    host = AgentHost("http://t", db_url="sqlite+aiosqlite://", admin_without_auth=True)
    with caplog.at_level(logging.WARNING, logger="a2agw.serve.host"):
        host.run(host=bind)
    hit = any("admin_without_auth" in r.getMessage() for r in caplog.records)
    assert hit is warned


# -- M3: push JWT typ ------------------------------------------------------------------------


async def test_push_jwt_carries_its_typ(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from a2agw.security.cardsign import CardSigner
    from a2agw.serve.push import PUSH_JWT_TYP, GuardedPushSender, PushSettings

    key = ec.generate_private_key(ec.SECP256R1())
    pem = tmp_path / "k.pem"
    pem.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    from a2a.types import TaskPushNotificationConfig

    sender = GuardedPushSender(
        httpx.AsyncClient(),
        None,  # type: ignore[arg-type]
        settings=PushSettings(jwt_signer=CardSigner(pem, "k1", "ES256")),
        agent_id="a",
        base_url="https://gw.example",
    )
    headers = sender._headers("t1", TaskPushNotificationConfig(url="https://r.example/h"), "d", "x")
    token = headers["Authorization"].removeprefix("Bearer ")
    assert pyjwt.get_unverified_header(token)["typ"] == PUSH_JWT_TYP == "a2agw-push+jwt"
    await sender.http.aclose()


# -- M5: unguarded partner_http --------------------------------------------------------------


def test_unguarded_partner_http_logs_a_warning(caplog):
    with caplog.at_level(logging.WARNING, logger="a2agw.serve.host"):
        AgentHost("http://t", db_url="sqlite+aiosqlite://", partner_http=httpx.AsyncClient())
    assert any("partner_http" in r.getMessage() for r in caplog.records)
    caplog.clear()
    guarded = guarded_async_client(fixed_tier("public"))
    with caplog.at_level(logging.WARNING, logger="a2agw.serve.host"):
        AgentHost("http://t", db_url="sqlite+aiosqlite://", partner_http=guarded)
    assert not any("partner_http" in r.getMessage() for r in caplog.records)


# -- M9: a failed startup still writes the audit events it submitted -------------------------


async def test_failed_startup_drains_submitted_audit_events(tmp_path, monkeypatch):
    from a2agw.consult.handles import OutboundHandleStore

    reg_card = {
        "name": "P",
        "description": "d",
        "version": "1",
        "supportedInterfaces": [
            {"url": "http://p.internal/rpc", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
        ],
        "capabilities": {},
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [{"id": "s", "name": "s", "description": "d", "tags": []}],
    }
    db = f"sqlite+aiosqlite:///{tmp_path / 'h.db'}"
    host = AgentHost("http://t", db_url=db, partners_path=tmp_path / "partners.yaml")
    original = host.partners.load

    def load_then_change():
        original()
        host.partners.disable("p")  # a registry change during startup: audit.submit

    await host.partners.add_from_card("p", reg_card, "internal")
    host.partners.load = load_then_change  # type: ignore[method-assign]

    async def broken(self):
        await asyncio.sleep(0)
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(OutboundHandleStore, "initialize", broken)
    with pytest.raises(RuntimeError):
        await host.startup()
    assert host.audit is not None and not host.audit._pending  # drained, not left running
    eng = await create_engine(db)
    try:
        rows, _ = await AuditLog(eng).query({"action": "partner.disable"}, 10)
        assert [r["partner_id"] for r in rows] == ["p"]
    finally:
        await eng.dispose()


# -- T12 minor 4: BrokenPipeError is not a database error ------------------------------------


def test_broken_pipe_is_not_a_database_error():
    assert not cli._is_db_error(BrokenPipeError())
    assert cli._is_db_error(ConnectionRefusedError())


# -- T12 minor 5: init --secure --force keeps .gitignore, writes configs 0600 ----------------


def test_init_secure_force_appends_gitignore_and_writes_private_configs(tmp_path):
    d = tmp_path / "proj"
    d.mkdir()
    (d / ".gitignore").write_text("node_modules/\n*.log\n")
    (d / "a2agw.yaml").write_text("old\n")
    r = CliRunner().invoke(cli.app, ["init", str(d), "--secure", "--force"])
    assert r.exit_code == 0, r.output
    lines = (d / ".gitignore").read_text().splitlines()
    assert lines[:2] == ["node_modules/", "*.log"]
    assert "keys/" in lines and ".env" in lines and lines.count("keys/") == 1
    for name in ("a2agw.yaml", "policy.yaml"):
        assert stat.S_IMODE((d / name).stat().st_mode) == 0o600, name
    # Running again (keys already exist) is refused before anything is rewritten.
    again = CliRunner().invoke(cli.app, ["init", str(d), "--secure", "--force"])
    assert again.exit_code == 1
    assert (d / ".gitignore").read_text().splitlines().count("keys/") == 1


# -- T12 minor 7: the demo writes its key like the CLI ---------------------------------------


def test_demo_key_is_written_like_the_cli(tmp_path, monkeypatch):
    from examples.software_team import team

    calls: list = []
    real = cli._write_private

    def spy(path, data):
        calls.append(path)
        real(path, data)

    monkeypatch.setattr(cli, "_write_private", spy)
    private, public = team.generate_signing_key(tmp_path / "keys")
    assert calls == [private]
    assert stat.S_IMODE(private.stat().st_mode) == 0o600
    assert public.exists()


# -- T5 deferred: a cancelled consult is audited ---------------------------------------------


async def test_cancelled_consult_is_audited_as_error(env):
    from cascade_support import Fn, spec

    from a2agw.core.events import Done

    started = asyncio.Event()

    async def slow(ctx):
        started.set()
        await asyncio.sleep(30)
        yield Done(text="late")

    e = await env(spec("b", Fn(slow)))
    await e.register("b")
    call = asyncio.create_task(e.host.client.consult("b", "hi", wait_seconds=30))
    await asyncio.wait_for(started.wait(), 5)
    call.cancel()
    with pytest.raises(asyncio.CancelledError):
        await call
    await e.host.audit.drain()
    rows, _ = await e.host.audit.query({"action": "partner.call"}, 10)
    assert [(r["partner_id"], r["outcome"]) for r in rows] == [("b", "error")]


# -- M7: concurrent writers on one SQLite database keep one chain ----------------------------


async def test_two_sqlite_writers_keep_one_audit_chain(tmp_path):
    """The CLI partner commands append to a running SQLite gateway's audit log: two writer
    processes (here two engines, each with its own lock) must not fork the chain."""
    from a2agw.ops.audit import AuditEvent

    db = f"sqlite+aiosqlite:///{tmp_path / 'a.db'}"
    engines = [await create_engine(db) for _ in range(4)]
    try:
        logs = [AuditLog(e) for e in engines]
        await logs[0].initialize()

        async def burst(log, who):
            for i in range(60):
                await log.append(AuditEvent(actor=who, action="admin.read", outcome=str(i)))

        await asyncio.gather(*(burst(log, str(n)) for n, log in enumerate(logs)))
        assert await logs[0].verify_chain() is None
        rows, _ = await logs[0].query({}, 500)
        assert len(rows) == 240
    finally:
        for e in engines:
            await e.dispose()
