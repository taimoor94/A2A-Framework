"""Mine benchmark tasks from a repository's history.

``mine_history`` walks ``git log --first-parent --name-status`` newest first. A commit (with a
parent) whose changed paths fall under at least ``min_systems`` of the declared systems'
``path`` sub-trees becomes a task:

- ``request``: the commit's subject and body;
- ``base``: ``{repository id: first parent}`` (the repository id is the workspace rule's: the
  directory name reduced to ``[A-Za-z0-9._-]``);
- ``acceptance``: per touched system, the test files the commit *added* under that system's
  ``tests/`` (``files`` = their content at the commit, repository-relative), run with the
  system's ``tests`` command restricted to those files where the runner's file form is known
  (``restrict_command``: ``[python, -m, pytest, -q, tests]`` becomes ``[python, -m, pytest,
  -q, tests/test_new.py]``; unknown runners keep their command);
- ``reference_patch``: the commit's diff with the repository id prefixed to every path.

A commit with no added tests for any touched system is skipped, and so is a task whose
acceptance does not fail on the parent (each test is run there through ``reproduction_before``
on a throwaway worktree) or does not pass at the commit itself (same command, a throwaway
worktree of the commit): a broken command or an unsolvable test never becomes a task. The systems must all live in ``repo``.
"""

from __future__ import annotations

import asyncio
import fnmatch
import posixpath
import subprocess
import tempfile
from pathlib import Path

from a2agw.vsc.bench.corpus import BenchTask
from a2agw.vsc.config import SystemConfig
from a2agw.vsc.spec import REQUEST_MAX_CHARS, AcceptanceTest
from a2agw.vsc.verify import _write_files, reproduction_before, run_check
from a2agw.vsc.workspace import Workspace, WorkspaceManager, _safe

__all__ = ["amine_history", "mine_history", "restrict_command"]

REPRO_TIMEOUT_S = 300.0


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True, timeout=120
    ).stdout


def _under(path: str, prefix: str) -> str | None:
    """``path`` relative to the sub-tree ``prefix`` (``.`` = everything), or None."""
    prefix = posixpath.normpath(prefix)
    if prefix == ".":
        return path
    if path.startswith(prefix + "/"):
        return path[len(prefix) + 1 :]
    return None


# Options known to take no value; any other option is assumed to take the next argument.
_FLAGS = frozenset(
    {
        "-q", "-qq", "-v", "-vv", "-x", "-s", "-l", "-B", "--quiet", "--verbose", "--exitfirst",
        "--disable-plugin-autoload", "--strict-markers", "--lf", "--ff", "--no-header", "--test",
    }
)  # fmt: skip


def _tool(cmd: list[str]) -> str | None:
    """The test runner a command uses, when its file form is known."""
    names = [posixpath.basename(a) for a in cmd]
    for i, a in enumerate(cmd):
        if a in ("pytest", "unittest") and i > 0 and cmd[i - 1] == "-m":
            return a
    if names and names[0] in ("pytest", "py.test"):
        return "pytest"
    if names and names[0] == "node" and "--test" in cmd:
        return "node"
    return None


def restrict_command(command: list[str], files: list[str]) -> list[str]:
    """``command`` (a system's ``tests``) run on ``files`` only (paths relative to its cwd).

    Only for runners whose file form is known: pytest and ``node --test`` drop trailing
    arguments that cover every file (a directory holding them or a glob matching them), never
    an option's value, and append the files; ``python -m unittest`` (``discover`` and its
    arguments dropped) takes the files. Any other command is returned unchanged: it still runs
    the new test files, with the rest of the suite."""
    cmd = list(command)
    tool = _tool(cmd)
    if tool is None:
        return cmd
    if tool == "unittest":
        at = cmd.index("unittest")
        rest = cmd[at + 1 :]
        if "discover" in rest:
            rest = rest[: rest.index("discover")]
        return [*cmd[: at + 1], *rest, *files]

    def option_value(i: int) -> bool:
        prev = cmd[i - 1]
        return prev.startswith("-") and "=" not in prev and prev not in _FLAGS

    def covers(arg: str) -> bool:
        if arg.startswith("-"):
            return False
        d = posixpath.normpath(arg)
        return all(f.startswith(d + "/") or fnmatch.fnmatch(f, arg) for f in files)

    while len(cmd) > 2 and covers(cmd[-1]) and not option_value(len(cmd) - 1):
        cmd.pop()
    return [*cmd, *files]


def _commits(repo: Path) -> list[tuple[str, list[str], list[tuple[str, str]]]]:
    """(sha, parents, [(status, path)]) newest first, following first parents only."""
    out = _git(
        repo,
        "log",
        "--first-parent",
        "--no-renames",
        "--name-status",
        "--diff-merges=first-parent",
        "--format=%x00%H %P",
    )
    commits = []
    for chunk in out.split("\x00")[1:]:
        lines = chunk.splitlines()
        head = lines[0].split()
        changes = []
        for line in lines[1:]:
            if "\t" in line:
                status, _, path = line.partition("\t")
                changes.append((status[:1], path))
        commits.append((head[0], head[1:], changes))
    return commits


def _candidate(
    repo: Path,
    repo_id: str,
    systems: list[SystemConfig],
    sha: str,
    parent: str,
    changes: list[tuple[str, str]],
    min_systems: int,
) -> BenchTask | None:
    touched = [s for s in systems if any(_under(p, s.path) is not None for _, p in changes)]
    if len(touched) < min_systems:
        return None
    acceptance: list[AcceptanceTest] = []
    for s in touched:
        added = [
            p
            for status, p in changes
            if status == "A" and (_under(p, s.path) or "").startswith("tests/")
        ]
        if not added or s.tests is None:
            continue
        rel = [_under(p, s.path) or p for p in added]
        acceptance.append(
            AcceptanceTest(
                id=f"{s.id}-added-tests",
                system=s.id,
                files={p: _git(repo, "show", f"{sha}:{p}") for p in added},
                run=restrict_command(s.tests, rel),
            )
        )
    if not acceptance:
        return None
    message = _git(repo, "log", "-1", "--format=%B", sha).strip()
    patch = _git(
        repo,
        "diff",
        "--no-renames",
        "--binary",
        f"--src-prefix=a/{repo_id}/",
        f"--dst-prefix=b/{repo_id}/",
        parent,
        sha,
    )
    return BenchTask(
        id=f"{repo_id}-{sha[:12]}",
        source="history",
        request=message[:REQUEST_MAX_CHARS] or sha,
        systems=[s.id for s in touched],
        base={repo_id: parent},
        acceptance=acceptance,
        reference_patch=patch,
        origin=str(repo),
    )


async def _fails_on_parent(
    manager: WorkspaceManager, repo_id: str, task: BenchTask, systems: dict[str, SystemConfig]
) -> bool:
    ws = Workspace("mine", repo_id, manager.root, "", task.base[repo_id])
    for test in task.acceptance:
        assert test.system is not None
        res = await reproduction_before(
            manager, ws, test, systems[test.system], timeout_s=REPRO_TIMEOUT_S
        )
        if not res.passed:
            return False
    return True


async def _passes_at_commit(
    manager: WorkspaceManager,
    repo_id: str,
    sha: str,
    task: BenchTask,
    systems: dict[str, SystemConfig],
) -> bool:
    """Every acceptance test, with its (restricted) command, passes at the commit itself: the
    task is solvable and the command really runs the tests."""
    ws = Workspace("mine", repo_id, manager.root, "", sha)
    for test in task.acceptance:
        assert test.system is not None
        system = systems[test.system]
        command = test.run or system.tests
        if command is None:
            return False
        async with manager.throwaway(ws) as tmp:
            if _write_files(tmp, test.files):
                return False
            res = await run_check(
                "reproduction_after", test.id, command, tmp / system.path, timeout_s=REPRO_TIMEOUT_S
            )
        if not res.passed:
            return False
    return True


async def amine_history(
    repo: Path, systems: list[SystemConfig], *, min_systems: int = 2, limit: int = 50
) -> list[BenchTask]:
    """``mine_history`` for callers already inside an event loop."""
    repo = Path(repo).resolve()
    repo_id = _safe(repo.name)
    local = [s.model_copy(update={"repo": str(repo)}) for s in systems]
    by_id = {s.id: s for s in local}
    tasks: list[BenchTask] = []
    with tempfile.TemporaryDirectory(prefix="a2agw-mine-") as tmp:
        manager = WorkspaceManager(Path(tmp), local, repo)
        for sha, parents, changes in _commits(repo):
            if len(tasks) >= limit:
                break
            if not parents:
                continue
            task = _candidate(repo, repo_id, local, sha, parents[0], changes, min_systems)
            if (
                task is not None
                and await _fails_on_parent(manager, repo_id, task, by_id)
                and await _passes_at_commit(manager, repo_id, sha, task, by_id)
            ):
                tasks.append(task)
    return tasks


def mine_history(
    repo: Path, systems: list[SystemConfig], *, min_systems: int = 2, limit: int = 50
) -> list[BenchTask]:
    """Tasks from ``repo``'s first-parent history, newest first (see the module docstring)."""
    return asyncio.run(amine_history(repo, systems, min_systems=min_systems, limit=limit))
