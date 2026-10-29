"""The CI workflow parses and runs the gate, the CrewAI script and a fresh resolution."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def _steps(job: dict) -> str:
    return "\n".join(str(s.get("run", "")) for s in job["steps"])


def test_ci_workflow_jobs():
    wf = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    jobs = wf["jobs"]
    assert set(jobs) == {"gate", "crewai", "fresh-resolution"}
    gate = _steps(jobs["gate"])
    assert "uv sync --locked" in gate
    assert "uv run pytest -q -W error" in gate and "uv run ruff check" in gate
    assert "scripts/test-crewai.sh" in _steps(jobs["crewai"])
    fresh = _steps(jobs["fresh-resolution"])
    assert "uv venv" in fresh and "'.[all]'" in fresh and "uv sync" not in fresh
    for path in ("tests/adapters", "tests/gateway", "tests/test_dev_env.py"):
        assert path in fresh
    assert "--ignore=tests/adapters/test_adk.py" in fresh
    assert "--ignore=tests/adapters/test_crewai.py" in fresh


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_crewai_script_prints_the_lock_check_output(tmp_path):
    """A failing ``uv lock --check`` shows uv's own message, not only ours."""
    (tmp_path / "scripts").mkdir()
    shutil.copy(ROOT / "scripts" / "test-crewai.sh", tmp_path / "scripts" / "test-crewai.sh")
    (tmp_path / "uv.lock").write_text("")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_uv = bin_dir / "uv"
    fake_uv.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = cache ]; then echo /nonexistent-cache; exit 0; fi\n'
        'if [ "$1" = lock ]; then echo "error: the lockfile needs to be updated" >&2; exit 1; fi\n'
        "exit 99\n"
    )
    fake_uv.chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}
    r = subprocess.run(
        ["bash", str(tmp_path / "scripts" / "test-crewai.sh")],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )
    assert r.returncode == 1
    assert "the lockfile needs to be updated" in r.stderr
    assert "uv.lock does not match pyproject.toml" in r.stderr
