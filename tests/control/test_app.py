"""Control-plane app: lifespan, /healthz, one error shape, OpenAPI, the import guard, the CLI."""

from __future__ import annotations

import ast
import asyncio
import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from pydantic import BaseModel
from sqlalchemy import select
from typer.testing import CliRunner

import a2agw
from a2agw import cli
from a2agw.control.store import API_KEYS, COMMANDS, GATEWAY_TOKENS, GATEWAYS, token_digest
from a2agw.serve.store import create_engine

fastapi = pytest.importorskip("fastapi")

from a2agw.control.app import create_app


async def test_healthz_public(cp_settings, run_app):
    app = create_app(cp_settings)
    async with run_app(app) as c:
        r = await c.get("/healthz")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


async def test_lifespan_disposes_engine_and_closes_owned_http(sqlite_settings, run_app):
    app = create_app(sqlite_settings)
    async with run_app(app):
        engine, http = app.state.engine, app.state.http
        assert app.state.store is not None and app.state.audit is not None
    assert engine.pool.checkedout() == 0 and http.is_closed


class Body(BaseModel):
    name: str
    count: int


async def test_error_shape(sqlite_settings, run_app):
    app = create_app(sqlite_settings)

    @app.post("/_probe/{n}")
    async def probe(n: int, body: Body) -> dict[str, str]:
        return {"ok": "yes"}

    @app.get("/_boom")
    async def boom() -> None:
        raise RuntimeError("secret internals sk-123")

    async with run_app(app) as c:
        missing = await c.get("/nope")
        wrong_method = await c.delete("/healthz")
        invalid = await c.post("/_probe/x", json={"name": "s3cr3t-value", "count": "many"})
        bad_json = await c.post("/_probe/1", content=b"{", headers={"content-type": "x"})
        boom_r = await c.get("/_boom")
    assert missing.status_code == 404
    assert missing.json() == {"error": "not_found", "detail": "Not Found"}
    assert wrong_method.status_code == 405 and wrong_method.json()["error"] == "method_not_allowed"
    assert invalid.status_code == 422
    body = invalid.json()
    assert body["error"] == "invalid" and set(body) == {"error", "detail", "fields"}
    assert sorted(body["fields"]) == ["body.count", "path.n"]
    assert "s3cr3t" not in invalid.text and "many" not in invalid.text
    assert bad_json.status_code == 422 and bad_json.json()["error"] == "invalid"
    assert boom_r.status_code == 500
    assert boom_r.json() == {"error": "internal", "detail": "internal error"}


async def test_unhandled_error_logs_class_and_request_id_only(sqlite_settings, caplog):
    """The 500 is answered by the app itself: nothing is re-raised to the server (which
    would log the traceback and the message), and the one log line names the exception
    class and the request id."""
    import logging

    import httpx

    app = create_app(sqlite_settings)

    @app.get("/_boom")
    async def boom() -> None:
        raise RuntimeError("secret internals sk-123")

    caplog.set_level(logging.DEBUG)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=True)
        async with httpx.AsyncClient(transport=transport, base_url="https://cp.example") as c:
            r = await c.get("/_boom")  # would raise here if the app re-raised
    assert r.status_code == 500
    assert r.json() == {"error": "internal", "detail": "internal error"}
    request_id = r.headers["x-request-id"]
    assert len(request_id) >= 16
    lines = [rec for rec in caplog.records if "RuntimeError" in rec.getMessage()]
    assert len(lines) == 1 and request_id in lines[0].getMessage()
    assert lines[0].levelno == logging.ERROR
    for rec in caplog.records:
        assert rec.exc_info is None and rec.exc_text is None
        assert "sk-123" not in rec.getMessage()
    assert "sk-123" not in caplog.text and "Traceback" not in caplog.text


async def test_openapi_mounted_and_docs_disabled(sqlite_settings, run_app):
    # the document needs the read permission: see test_authn.py::test_openapi_requires_auth
    app = create_app(sqlite_settings)
    async with run_app(app) as c:
        _key_id, key = await app.state.store.create_api_key("v", "viewer", actor="t")
        doc = await c.get("/api/openapi.json", headers={"authorization": f"Bearer {key}"})
        docs = [await c.get(p) for p in ("/docs", "/redoc", "/openapi.json")]
    assert doc.status_code == 200 and "/healthz" in doc.json()["paths"]
    assert [r.status_code for r in docs] == [404, 404, 404]


async def test_maintenance_runs_once_with_injected_clock(sqlite_settings, run_app):
    now = {"t": 1000.0 + 10 * 86400}
    app = create_app(sqlite_settings, clock=lambda: now["t"], maintenance_interval_s=3600)
    async with run_app(app):
        engine = app.state.engine
        async with engine.begin() as conn:
            for cid, created, expires in [
                ("old", 1000.0, 2000.0),
                ("due", now["t"] - 5, now["t"]),
                ("done", 1000.0, 2000.0),
            ]:
                await conn.execute(
                    COMMANDS.insert().values(
                        id=cid,
                        gateway_id="g",
                        kind="k",
                        args_json="{}",
                        status="done" if cid == "done" else "pending",
                        actor="a",
                        created_at=created,
                        expires_at=expires,
                        finished_at=1500.0 if cid == "done" else None,
                    )
                )
        calls: list[float] = []

        async def hook(t: float) -> None:
            calls.append(t)

        app.state.maintenance.hooks.append(hook)
        report = await app.state.maintenance.run_once()
        async with engine.connect() as conn:
            rows = dict((await conn.execute(select(COMMANDS.c.id, COMMANDS.c.status))).all())
    # "old" and "due" expire now, so both stay (purged by when they finished, not when
    # they were created); "done" finished 10 days ago (retention 7) and is purged
    assert rows == {"old": "expired", "due": "expired"}
    assert report == {"expired": 2, "events": 0, "commands": 1, "login_states": 0, "sessions": 0}
    assert calls == [now["t"]]


async def test_maintenance_loop_keeps_running_after_a_failure(sqlite_settings, run_app):
    app = create_app(sqlite_settings, maintenance_interval_s=0.01)
    seen = asyncio.Event()
    calls = 0

    async def hook(_t: float) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("first pass fails")
        seen.set()

    async with run_app(app):
        app.state.maintenance.hooks.append(hook)
        await asyncio.wait_for(seen.wait(), 5)
    assert calls >= 2


CORE_IMPORTS = textwrap.dedent(
    """\
    import importlib, importlib.util, sys

    importers = []

    class Spy:
        \"\"\"Records the file of the code that asks for each fastapi module.\"\"\"

        def find_spec(self, name, path=None, target=None):
            if name.split(".")[0] == "fastapi":
                f = sys._getframe(1)
                while f is not None and (
                    f.f_code.co_filename.startswith("<frozen")
                    or "importlib" in f.f_code.co_filename
                ):
                    f = f.f_back
                importers.append(f.f_code.co_filename if f is not None else "?")
            return None

    sys.meta_path.insert(0, Spy())
    for m in ["a2agw", "a2agw.cli", "a2agw.serve.host", "a2agw.ops.cp_client"]:
        if m == "a2agw.ops.cp_client" and importlib.util.find_spec(m) is None:
            continue  # added by a later task
        importlib.import_module(m)
    print("\\n".join(importers))
    """
)


def test_core_does_not_import_fastapi():
    """No a2agw module imports fastapi; only a2agw.control.app does (on demand).

    ``"fastapi" in sys.modules`` alone cannot be the check while fastapi is installed: the
    a2a SDK's ``a2a.server.routes`` imports it opportunistically. So the child records the
    file of every module that triggers a fastapi import, and none may be under ``a2agw/``.
    A second child blocks fastapi entirely and imports the core: it must still work."""
    out = subprocess.run(
        [sys.executable, "-c", CORE_IMPORTS],
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert out.returncode == 0, out.stderr
    importers = [line for line in out.stdout.splitlines() if line]
    ours = [f for f in importers if "/a2agw/" in f.replace("\\", "/")]
    assert ours == [], ours
    # A module importing fastapi after the SDK did is not seen by the spy: scan the source.
    root = Path(a2agw.__file__).parent
    control = root / "control"
    allowed = {
        control / "app.py",
        control / "rbac.py",
        control / "authn.py",
        control / "channel.py",
        control / "admin.py",
        control / "catalogue.py",
        control / "policies.py",
        control / "views.py",
        control / "operations.py",
        control / "__init__.py",
    }
    importing = []
    for path in root.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            names = (
                [a.name for a in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
                if isinstance(node, ast.ImportFrom)
                else []
            )
            if any(n.split(".")[0] == "fastapi" for n in names) and path not in allowed:
                importing.append(str(path.relative_to(root)))
    assert importing == [], importing
    blocked = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys; sys.modules['fastapi'] = None\n"
                "import a2agw, a2agw.cli, a2agw.serve.host, a2agw.control, a2agw.control.cli\n"
                "assert sys.modules['fastapi'] is None\n"
                "print('ok')"
            ),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert blocked.returncode == 0 and blocked.stdout.strip() == "ok", blocked.stderr


def test_missing_extra_message():
    script = textwrap.dedent(
        """\
        import sys
        sys.modules["fastapi"] = None  # the control extra is not installed
        from typer.testing import CliRunner
        from a2agw.cli import app
        r = CliRunner().invoke(app, ["control", "serve", "-c", "control.yaml"])
        print(r.exit_code)
        print(r.output)
        from a2agw import control
        try:
            control.require_fastapi()
        except ImportError as e:
            print("IMPORT:", e)
        """
    )
    out = subprocess.run(
        [sys.executable, "-c", script], check=False, capture_output=True, text=True, timeout=120
    )
    assert out.returncode == 0, out.stderr
    code, *rest = out.stdout.splitlines()
    text = "\n".join(rest)
    assert code == "1"
    assert text.count("pip install 'a2a-gateway[control]'") == 2, text


# -- CLI ---------------------------------------------------------------------------------

runner = CliRunner()


def _init(tmp_path) -> str:
    r = runner.invoke(cli.app, ["control", "init", str(tmp_path)])
    assert r.exit_code == 0, r.output
    cfg = tmp_path / "control.yaml"
    text = cfg.read_text()
    assert text.lstrip().startswith("#") and "client_secret_env" in text
    # point the scaffolded config at a database in tmp_path
    cfg.write_text(
        text.replace(
            "sqlite+aiosqlite:///a2agw-control.db", f"sqlite+aiosqlite:///{tmp_path}/cp.db"
        )
    )
    return str(cfg)


async def _rows(db: str, table) -> list[dict]:
    eng = await create_engine(f"sqlite+aiosqlite:///{db}")
    try:
        async with eng.connect() as conn:
            return [dict(r._mapping) for r in (await conn.execute(select(table))).all()]
    finally:
        await eng.dispose()


def test_control_init_and_create_api_key_prints_once(tmp_path, monkeypatch):
    monkeypatch.setenv("A2AGW_CONTROL_BASE_URL", "https://cp.example")
    cfg = _init(tmp_path)
    again = runner.invoke(cli.app, ["control", "init", str(tmp_path)])
    assert again.exit_code == 1 and "refusing to overwrite" in again.output
    r = runner.invoke(
        cli.app, ["control", "create-api-key", "--name", "ci", "--role", "admin", "-c", cfg]
    )
    assert r.exit_code == 0, r.output
    keys = asyncio.run(_rows(str(tmp_path / "cp.db"), API_KEYS))
    assert len(keys) == 1 and keys[0]["role"] == "admin" and keys[0]["name"] == "ci"
    printed = [w for w in r.output.split() if token_digest(w) == keys[0]["digest"]]
    assert len(printed) == 1  # the key appears once
    assert r.output.count(printed[0]) == 1
    assert printed[0] not in json.dumps(keys, default=str)
    bad = runner.invoke(
        cli.app, ["control", "create-api-key", "--name", "x", "--role", "root", "-c", cfg]
    )
    assert bad.exit_code == 1 and "error:" in bad.output and "role" in bad.output


def test_control_create_gateway_prints_id_and_token_once(tmp_path, monkeypatch):
    monkeypatch.setenv("A2AGW_CONTROL_BASE_URL", "https://cp.example")
    cfg = _init(tmp_path)
    r = runner.invoke(cli.app, ["control", "create-gateway", "--name", "east", "-c", cfg])
    assert r.exit_code == 0, r.output
    gws = asyncio.run(_rows(str(tmp_path / "cp.db"), GATEWAYS))
    toks = asyncio.run(_rows(str(tmp_path / "cp.db"), GATEWAY_TOKENS))
    assert [g["name"] for g in gws] == ["east"] and gws[0]["id"] in r.output
    token = [w for w in r.output.split() if token_digest(w) == toks[0]["digest"]]
    assert len(token) == 1 and r.output.count(token[0]) == 1
    dup = runner.invoke(cli.app, ["control", "create-gateway", "--name", "east", "-c", cfg])
    assert dup.exit_code == 1 and "already exists" in dup.output


def test_control_serve_runs_uvicorn_with_the_app(tmp_path, monkeypatch):
    monkeypatch.setenv("A2AGW_CONTROL_BASE_URL", "https://cp.example")
    cfg = _init(tmp_path)
    seen = {}

    def fake_run(app, **kw):
        seen["app"], seen["kw"] = app, kw

    import uvicorn

    monkeypatch.setattr(uvicorn, "run", fake_run)
    r = runner.invoke(cli.app, ["control", "serve", "-c", cfg, "--port", "8123"])
    assert r.exit_code == 0, r.output
    assert isinstance(seen["app"], fastapi.FastAPI)
    assert seen["kw"]["host"] == "127.0.0.1" and seen["kw"]["port"] == 8123
