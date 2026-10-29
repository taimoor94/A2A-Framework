"""The compose example's gateway config (examples/docker): it loads, registers its partner,
and gives webhook agents a consult URL the coder container can reach."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from google.protobuf.json_format import MessageToDict

from a2agw.config import build_host, load_config, register_partners
from a2agw.serve.agent import build_card

DOCKER = Path(__file__).resolve().parents[1] / "examples" / "docker"
ENV = {
    "A2AGW_DB_URL": "sqlite+aiosqlite:///unused.db",
    "CODER_SECRET": "s3cret-for-test",
    "GATEWAY_SELF_KEY": "self-key",
}


def _cfg(tmp_path):
    cfg = load_config(DOCKER / "a2agw.compose.yaml", env=ENV)
    cfg.db_url = f"sqlite+aiosqlite:///{tmp_path / 'gw.db'}"
    cfg.partners_file = str(tmp_path / "partners.yaml")  # /data/partners.yaml in the image
    return cfg


async def test_compose_config_loads_and_registers_echo(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(DOCKER))
    for name, value in ENV.items():
        monkeypatch.setenv(name, value)  # secret_env is read from the process environment
    cfg = _cfg(tmp_path)
    assert cfg.partners_file and cfg.sidecar.consult_url == "http://gateway:8000/a2agw/v1"
    host = build_host(cfg, config_dir=DOCKER)
    assert host.base_url == "http://localhost:8000"  # cards still advertise base_url
    assert host.consult_tokens.url == "http://gateway:8000/a2agw/v1"
    await register_partners(host, cfg, config_dir=DOCKER)
    echo = host.partners.get("echo")
    assert echo.tier == "internal" and echo.credential_ref == "self"


def test_echo_card_file_is_the_echo_agents_card(monkeypatch):
    monkeypatch.syspath_prepend(str(DOCKER))
    import echo_agent

    served = MessageToDict(build_card(echo_agent.echo, "http://localhost:8000", security=None))
    assert json.loads((DOCKER / "cards" / "echo.json").read_text()) == served


def test_compose_file_is_valid():
    if shutil.which("docker") is None:
        pytest.skip("docker is not on PATH")
    env = {**os.environ, "POSTGRES_PASSWORD": "pw", **ENV}
    out = subprocess.run(
        ["docker", "compose", "-f", str(DOCKER / "compose.yaml"), "config", "--format", "json"],
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if out.returncode != 0 and "Cannot connect" in out.stderr:
        pytest.skip("docker compose unavailable")
    assert out.returncode == 0, out.stderr
    services = json.loads(out.stdout)["services"]
    assert services["coder"]["environment"]["CONSULT_PARTNER"] == "echo"
    assert services["coder"]["environment"]["CODER_SECRET"] == ENV["CODER_SECRET"]
    assert services["gateway"]["environment"]["GATEWAY_SELF_KEY"] == ENV["GATEWAY_SELF_KEY"]
