"""Create the demo estate: three git repositories on ``main``, one commit each.

    python examples/vsc_estate/init_estate.py examples/vsc_estate/estate

copies ``orders-api/``, ``inventory-service/`` and ``contract/`` (next to this file) into the
target directory and runs ``git init -b main``, ``git add -A`` and ``git commit`` in each, with
a local ``user.name``/``user.email``. The target must be missing or empty: the script never
overwrites an existing estate.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPOS = ("orders-api", "inventory-service", "contract")
_IGNORE = shutil.ignore_patterns(
    "__pycache__", "*.pyc", ".pytest_cache", "*.db", "node_modules", ".DS_Store"
)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def init_estate(target: Path) -> dict[str, Path]:
    target = Path(target)
    if target.exists() and (not target.is_dir() or any(target.iterdir())):
        raise SystemExit(f"init_estate: {target} exists and is not empty; refusing to overwrite")
    target.mkdir(parents=True, exist_ok=True)
    repos: dict[str, Path] = {}
    for name in REPOS:
        repo = target / name
        shutil.copytree(HERE / name, repo, ignore=_IGNORE)
        _git(repo, "init", "-q", "-b", "main")
        _git(repo, "config", "user.name", "Estate Bot")
        _git(repo, "config", "user.email", "estate@example.invalid")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", f"{name}: initial import")
        repos[name] = repo
    return repos


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: init_estate.py <target-dir>", file=sys.stderr)
        return 2
    for name, repo in init_estate(Path(argv[0])).items():
        print(f"{name}: {repo}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
