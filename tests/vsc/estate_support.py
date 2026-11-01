"""Helpers for the demo estate (``examples/vsc_estate``): create it, load its config and
scenarios, and apply a scenario's acceptance files and reference patch.

Conventions (also in ``examples/vsc_estate/README.md``):

- a per-system acceptance test's ``files`` are relative to that system's repository root;
- a whole-system test's (``system: null``) ``files`` start with the repository id, e.g.
  ``contract/tests/test_x.py``;
- ``reference_patch`` is one unified diff over the three repositories whose paths start with
  the repository id (``a/orders-api/app.py``). Each repository's part is applied inside that
  repository with ``git apply -p2``, which is ``git apply -p1`` once the id is stripped.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

from a2agw.config import load_config
from a2agw.vsc.config import VscConfig

ESTATE_DIR = Path(__file__).resolve().parents[2] / "examples" / "vsc_estate"
SCENARIO_DIR = ESTATE_DIR / "scenarios"
REPOS = ("orders-api", "inventory-service", "contract")
SCENARIO_KEYS = {"id", "request", "systems", "acceptance", "reference_patch", "notes"}


def init_estate(target: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(ESTATE_DIR / "init_estate.py"), str(target)],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )


def estate_config(estate: Path) -> VscConfig:
    """The estate's ``vsc:`` section with every repository pointed at ``estate/<id>`` and a
    leading ``python`` replaced by this interpreter (so no ``python`` on PATH is needed)."""
    cfg = load_config(ESTATE_DIR / "a2agw.yaml", env={}).vsc
    assert cfg is not None

    def cmd(command: list[str] | None) -> list[str] | None:
        if command and command[0] == "python":
            return [sys.executable, *command[1:]]
        return command

    systems = [
        s.model_copy(
            update={"repo": str(estate / s.id), "gate": cmd(s.gate), "tests": cmd(s.tests)}
        )
        for s in cfg.systems
    ]
    checks = [c.model_copy(update={"run": cmd(c.run)}) for c in cfg.checks]
    return cfg.model_copy(update={"systems": systems, "checks": checks})


def scenario_paths() -> list[Path]:
    return sorted(SCENARIO_DIR.glob("*.yaml"))


def load_scenario(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text())
    assert isinstance(data, dict), path
    return data


_HEADER = re.compile(r"^diff --git a/(\S+) b/(\S+)$", re.MULTILINE)


def split_patch(patch: str) -> dict[str, str]:
    """The reference patch cut into one diff per repository id."""
    starts = [m.start() for m in _HEADER.finditer(patch)]
    if not starts or patch[: starts[0]].strip():
        raise ValueError("reference_patch must start with a 'diff --git' header")
    out: dict[str, str] = {}
    for start, end in zip(starts, [*starts[1:], len(patch)], strict=True):
        chunk = patch[start:end]
        m = _HEADER.match(chunk)
        assert m is not None
        repo_a, repo_b = m.group(1).split("/", 1)[0], m.group(2).split("/", 1)[0]
        if repo_a != repo_b or repo_a not in REPOS:
            raise ValueError(f"patch path outside the estate repositories: {m.group(0)}")
        out[repo_a] = out.get(repo_a, "") + chunk
    return out


def apply_patch(patch: str, repos: dict[str, Path]) -> None:
    for repo_id, chunk in split_patch(patch).items():
        subprocess.run(
            ["git", "apply", "-p2", "--whitespace=nowarn", "-"],
            cwd=repos[repo_id],
            input=chunk,
            text=True,
            check=True,
            capture_output=True,
        )


def split_files(files: dict[str, str]) -> dict[str, dict[str, str]]:
    """A whole-system test's files grouped by repository id (the first path component)."""
    out: dict[str, dict[str, str]] = {}
    for rel, content in files.items():
        repo_id, _, rest = rel.partition("/")
        if repo_id not in REPOS or not rest:
            raise ValueError(f"whole-system acceptance file must start with a repo id: {rel}")
        out.setdefault(repo_id, {})[rest] = content
    return out


def write_files(root: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
