"""``a2agw vsc``: the admin-API commands against an in-process gateway, and offline verify."""

from __future__ import annotations

import asyncio
import json

import httpx
from typer.testing import CliRunner

from a2agw import cli
from a2agw.config import build_host, load_config
from a2agw.security.auth import hash_api_key
from a2agw.vsc.receipt import verify_receipt

from .conftest import make_repo, worker
from .test_runner import REPO_FILES, TESTS, FixedPlanner, edit, merge_step, until

runner = CliRunner()
KEY = "key-vsc"


class _LoopTransport(httpx.BaseTransport):
    """A sync transport (for the CLI, running in a thread) that forwards every request to the
    in-process gateway app on the test's event loop."""

    def __init__(self, app, loop) -> None:
        self._client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t"
        )
        self._loop = loop

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        async def go() -> httpx.Response:
            r = await self._client.request(
                request.method, str(request.url), headers=request.headers, content=request.read()
            )
            await r.aread()
            return r

        r = asyncio.run_coroutine_threadsafe(go(), self._loop).result(60)
        return httpx.Response(r.status_code, headers=r.headers, content=r.content)


def _config(tmp_path) -> str:
    make_repo(tmp_path, "repo-a", REPO_FILES)
    w = worker("apply")
    cfg = {
        "base_url": "http://t",
        "db_url": f"sqlite+aiosqlite:///{tmp_path / 'g.db'}",
        "auth": {
            "api_keys": {
                hash_api_key(KEY): {"principal_id": "op", "scopes": ["a2agw:vsc"]},
            }
        },
        "vsc": {
            "systems": [{"id": "alpha", "repo": "./repo-a", "tests": TESTS}],
            "workers": [{"id": w.id, "command": w.command, "cost_class": "cheap"}],
            "planner": "scripted",
        },
    }
    path = tmp_path / "a2agw.yaml"
    path.write_text(json.dumps(cfg))
    return str(path)


async def _invoke(*args: str, key: str | None = KEY):
    env = {"A2AGW_API_KEY": key} if key is not None else {}
    return await asyncio.to_thread(runner.invoke, cli.app, list(args), env=env)


async def test_cli_against_gateway(tmp_path, monkeypatch):
    config = _config(tmp_path)
    host = build_host(load_config(config), config_dir=tmp_path)
    runtime = host.vsc
    await host.startup()
    monkeypatch.setattr(
        cli, "_admin_transport", _LoopTransport(host.app(), asyncio.get_running_loop())
    )
    try:
        runtime.planner_factory = lambda job_id: FixedPlanner([edit("alpha"), merge_step()])
        r = await _invoke("vsc", "submit", "greet", "-c", config)
        assert r.exit_code == 0, r.output
        job_id = r.stdout.strip()
        assert await runtime.store.get_job(job_id) is not None

        async def waiting() -> bool:
            return (await runtime.store.get_job(job_id))["state"] == "awaiting_approval"

        await until(waiting)
        r = await _invoke("vsc", "status", job_id, "-c", config)
        assert r.exit_code == 0 and f"job {job_id}: awaiting_approval" in r.stdout
        assert "merge-alpha" in r.stdout

        r = await _invoke("vsc", "approve", job_id, "merge-alpha", "-c", config, key=None)
        assert r.exit_code == 1 and "401" in r.output  # no key: refused by the gateway

        r = await _invoke("vsc", "approve", job_id, "merge-alpha", "--note", "ok", "-c", config)
        assert r.exit_code == 0, r.output

        async def accepted() -> bool:
            return (await runtime.store.get_job(job_id))["state"] == "accepted"

        await until(accepted)
        out = tmp_path / "receipt.json"
        r = await _invoke("vsc", "receipt", "export", job_id, str(out), "-c", config)
        assert r.exit_code == 0, r.output
        assert verify_receipt(json.loads(out.read_text())) == []

        r = await _invoke("vsc", "status", "nope", "-c", config)
        assert r.exit_code == 1 and "404" in r.output and "Traceback" not in r.output

        spec = tmp_path / "spec.json"
        spec.write_text(json.dumps({"request": "x", "done": "x", "systems": ["alpha"],
                                    "acceptance": [], "budgets": {}}))  # fmt: skip
        r = await _invoke("vsc", "spec", "edit", job_id, str(spec), "-c", config)
        assert r.exit_code == 1 and "409" in r.output
    finally:
        await host.shutdown()


async def test_cli_receipt_verify_offline(tmp_path, monkeypatch):
    config = _config(tmp_path)
    host = build_host(load_config(config), config_dir=tmp_path)
    runtime = host.vsc
    await host.startup()
    try:
        runtime.planner_factory = lambda job_id: FixedPlanner([edit("alpha")])
        job_id = await runtime.runner.submit("greet", owner="key:op")
        assert (await runtime.runner.run(job_id))["state"] == "accepted"
        r = await asyncio.wait_for(runtime.receipt(job_id), 30)
    finally:
        await host.shutdown()

    good = tmp_path / "good.json"
    good.write_text(json.dumps(r))
    # No gateway, no config, no key: the bundle alone.
    monkeypatch.setattr(cli, "_admin_transport", None)
    res = runner.invoke(cli.app, ["vsc", "receipt", "verify", str(good)], env={})
    assert res.exit_code == 0, res.output
    assert r["receipt_hash"] in res.stdout

    r["steps"][0]["state"] = "passed-ish"
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(r))
    res = runner.invoke(cli.app, ["vsc", "receipt", "verify", str(bad)], env={})
    assert res.exit_code == 1 and "receipt_hash" in res.output

    bad.write_text("{not json")
    res = runner.invoke(cli.app, ["vsc", "receipt", "verify", str(bad)], env={})
    assert res.exit_code == 1 and "Traceback" not in res.output
