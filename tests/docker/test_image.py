"""Docker image tests: build the image, serve a card, run as non-root.

Opt-in: set ``A2AGW_DOCKER_TESTS=1`` and have a reachable Docker daemon. They build the real
image (slow, needs network for base images and wheels), so they never run in the default gate.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = ROOT / "examples" / "docker"
BUILD_TIMEOUT_S = 1800


def _docker_ready() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return (
            subprocess.run(
                ["docker", "info"], check=False, capture_output=True, timeout=30
            ).returncode
            == 0
        )
    except (OSError, subprocess.TimeoutExpired):
        return False


pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(
        os.environ.get("A2AGW_DOCKER_TESTS") != "1" or not _docker_ready(),
        reason="set A2AGW_DOCKER_TESTS=1 and start Docker to run the image tests",
    ),
]


def _docker(*args: str, timeout: int = 120, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout, check=check
    )


@pytest.fixture(scope="module")
def image():
    tag = f"a2agw-test:{uuid.uuid4().hex[:12]}"
    try:
        _docker("build", "-t", tag, str(ROOT), timeout=BUILD_TIMEOUT_S)
        yield tag
    finally:
        _docker("rmi", "-f", tag, check=False)


def test_image_builds_and_serves_card(image):
    name = f"a2agw-test-{uuid.uuid4().hex[:8]}"
    try:
        _docker(
            "run", "-d", "--name", name, "-p", "127.0.0.1::8000",
            "-v", f"{CONFIG_DIR}:/config:ro", image,
        )  # fmt: skip
        port = _docker("port", name, "8000/tcp").stdout.split(":")[-1].strip()
        url = f"http://127.0.0.1:{port}/agents/echo/.well-known/agent-card.json"
        deadline = time.monotonic() + 120
        status = None
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(url, timeout=3) as resp:
                    status = resp.status
                    break
            except (urllib.error.URLError, OSError):
                if _docker("inspect", "-f", "{{.State.Running}}", name).stdout.strip() != "true":
                    pytest.fail(f"container exited:\n{_docker('logs', name, check=False).stderr}")
                time.sleep(1)
        assert status == 200, _docker("logs", name, check=False).stderr
        # The image's own healthcheck (python/urllib, no curl) turns healthy.
        health = ""
        while time.monotonic() < deadline + 60:
            health = _docker("inspect", "-f", "{{.State.Health.Status}}", name).stdout.strip()
            if health == "healthy":
                break
            time.sleep(2)
        assert health == "healthy"
    finally:
        _docker("rm", "-f", name, check=False)


def test_runs_as_non_root(image):
    out = _docker("run", "--rm", "--entrypoint", "id", image, "-u").stdout.strip()
    assert out == "10001"


@pytest.mark.parametrize("extras", ["postgres,crewai", "postgres,CrewAI"])
def test_crewai_extra_is_refused(extras):
    r = _docker(
        "build", "--build-arg", f"EXTRAS={extras}", "-t", f"a2agw-neg:{uuid.uuid4().hex[:8]}",
        str(ROOT), timeout=BUILD_TIMEOUT_S, check=False,
    )  # fmt: skip
    assert r.returncode != 0
    assert "must not contain crewai" in r.stderr + r.stdout


def test_config_read_only_data_writable(image):
    out = _docker(
        "run", "--rm", "-v", f"{CONFIG_DIR}:/config:ro", "--entrypoint", "sh", image, "-c",
        "touch /config/x 2>/dev/null && echo cfg-writable; touch /data/x && echo data-ok",
    ).stdout  # fmt: skip
    assert "cfg-writable" not in out
    assert "data-ok" in out


LOCKED = ("a2a-sdk", "mcp", "httpx", "starlette", "asyncpg", "pydantic")


def _locked_versions() -> dict[str, str]:
    import tomllib

    lock = tomllib.loads((ROOT / "uv.lock").read_text())
    return {p["name"]: p["version"] for p in lock["package"] if p["name"] in LOCKED}


def test_image_installs_the_locked_versions(image):
    """The image installs exactly what uv.lock pins (``uv export --frozen``), not a fresh
    resolution. Read with importlib.metadata in the image's venv (uv venvs carry no pip)."""
    import json

    script = (
        "import importlib.metadata as m, json, sys; "
        "print(json.dumps({n: m.version(n) for n in sys.argv[1:]}))"
    )
    out = _docker("run", "--rm", "--entrypoint", "python", image, "-c", script, *LOCKED).stdout
    assert json.loads(out) == _locked_versions()
