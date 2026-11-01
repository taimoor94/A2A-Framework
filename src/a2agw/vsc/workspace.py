"""Isolated git worktrees: one worker edits one repository for one job.

Layout: ``<root>/<job_id>/<repo_id>/`` on branch ``vsc/<job_id>/<repo_id>``.

``repo_id`` rule: the last component of the resolved repository path, reduced to
``[A-Za-z0-9._-]`` (anything else becomes ``-``). If two distinct resolved paths among the
configured systems end in the same name, every one of them gets ``-<8 hex of sha256(path)>``
appended. Systems sharing one repository therefore share one workspace.

Diffs include untracked files by running ``git add -N`` (intent-to-add) first, so the plain
``git diff <base_ref>`` shows them.

Verification never runs in the tree a worker controlled: ``snapshot`` turns the worker's tree
(tracked and untracked files, never ignored ones) into a candidate commit object without moving
any ref, and ``throwaway`` checks a commit out detached in a fresh worktree cleaned with
``clean -fdx``. A candidate that passed becomes the job branch's head (``advance``).

Git hygiene: every git process gets the allowlisted environment of ``a2agw.vsc._env`` (minus
``GIT_DIR``, ``GIT_WORK_TREE`` and ``GIT_INDEX_FILE``) with ``GIT_TERMINAL_PROMPT=0``, runs
with ``core.hooksPath=/dev/null`` (no repository hook ever runs) in its own session, and is
killed (its whole process group) and reaped when the caller is cancelled. Commits are made
with ``commit.gpgsign=false`` and ``--no-verify``.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import posixpath
import re
import signal
import tempfile
import tomllib
import uuid
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

from a2agw.vsc._env import child_env
from a2agw.vsc.config import SystemConfig

_TIMEOUT_S = 120.0
_KILL_WAIT_S = 5.0
_GIT_LOCATION_VARS = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE")
_NO_HOOKS = ("-c", "core.hooksPath=/dev/null")
_IDENTITY = ("-c", "user.name=a2agw", "-c", "user.email=a2agw@localhost")
# Test files and test configuration: a change to one is flagged (``touched_tests``).
_TEST_DIRS = frozenset({"tests", "test", "__tests__"})
_TEST_FILES = frozenset({"conftest.py", "pytest.ini", "tox.ini", "noxfile.py"})


class GitError(RuntimeError):
    """A git command failed; the message is its stderr."""


class MergeRefused(GitError):
    """The merge would not be a fast-forward, or is not bound to the verified head."""


@dataclass(frozen=True)
class Workspace:
    job_id: str
    repo_id: str
    path: Path
    branch: str
    base_ref: str


def _kill(proc: asyncio.subprocess.Process) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(proc.pid, signal.SIGKILL)


async def _git(
    cwd: Path, *args: str, strip: bool = True, env: Mapping[str, str] | None = None
) -> str:
    proc = await asyncio.create_subprocess_exec(
        "git",
        *_NO_HOOKS,
        *args,
        cwd=cwd,
        env=child_env({"GIT_TERMINAL_PROMPT": "0", **(env or {})}, drop=_GIT_LOCATION_VARS),
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), _TIMEOUT_S)
    except TimeoutError:
        _kill(proc)
        await proc.wait()
        raise GitError(f"git {' '.join(args)} timed out after {_TIMEOUT_S:.0f}s") from None
    except asyncio.CancelledError:
        _kill(proc)  # never leave a git process (or what it spawned) behind
        with contextlib.suppress(Exception):
            await asyncio.wait_for(proc.wait(), _KILL_WAIT_S)
        raise
    if proc.returncode != 0:
        raise GitError(err.decode(errors="replace").strip())
    text = out.decode(errors="replace")
    return text.strip() if strip else text


def _is_test_path(path: str) -> bool:
    parts = path.split("/")
    return bool(_TEST_DIRS.intersection(parts[:-1])) or parts[-1] in _TEST_FILES


def _pytest_section(text: str | None) -> object:
    if text is None:
        return None
    try:
        return tomllib.loads(text).get("tool", {}).get("pytest")
    except tomllib.TOMLDecodeError:
        return "<unparsable>"


def _test_scripts(text: str | None) -> object:
    if text is None:
        return None
    try:
        scripts = json.loads(text).get("scripts") or {}
    except (ValueError, AttributeError):
        return "<unparsable>"
    if not isinstance(scripts, dict):
        return "<unparsable>"
    return {k: v for k, v in scripts.items() if isinstance(k, str) and k.startswith("test")}


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "-", name).strip(".") or "repo"


class WorkspaceManager:
    def __init__(self, root: Path, systems: list[SystemConfig], config_dir: Path) -> None:
        self.root = Path(root)
        self._systems = {s.id: s for s in systems}
        self._repos: dict[str, Path] = {
            s.id: (Path(config_dir) / s.repo).resolve() for s in systems
        }
        by_name: dict[str, set[Path]] = {}
        for p in self._repos.values():
            by_name.setdefault(_safe(p.name), set()).add(p)
        self._ids: dict[Path, str] = {}
        for name, paths in by_name.items():
            for p in paths:
                digest = hashlib.sha256(str(p).encode()).hexdigest()[:8]
                self._ids[p] = f"{name}-{digest}" if len(paths) > 1 else name
        self._locks: dict[str, asyncio.Lock] = {}

    def _repo_for(self, system_id: str) -> tuple[Path, str]:
        repo = self._repos[system_id]
        return repo, self._ids[repo]

    def repo_id(self, system_id: str) -> str:
        return self._repo_for(system_id)[1]

    async def create(self, job_id: str, system_id: str) -> Workspace:
        repo, repo_id = self._repo_for(system_id)
        branch = f"vsc/{job_id}/{repo_id}"
        path = self.root / job_id / repo_id
        async with self._locks.setdefault(f"{job_id}/{repo_id}", asyncio.Lock()):
            if path.exists():
                try:
                    base = await _git(repo, "config", "--get", f"branch.{branch}.vscbase")
                except GitError:
                    # Interrupted create (worktree added, config not written): the base is where
                    # the job branch forked from the default branch.
                    try:
                        base = await _git(
                            repo, "merge-base", self._systems[system_id].default_branch, branch
                        )
                    except GitError as e:
                        raise GitError(
                            f"workspace {path} exists but its base ref is unknown "
                            f"(branch.{branch}.vscbase missing and no merge-base): {e}"
                        ) from None
                    await _git(repo, "config", f"branch.{branch}.vscbase", base)
                return Workspace(job_id, repo_id, path, branch, base)
            base = await _git(
                repo, "rev-parse", "--verify", self._systems[system_id].default_branch
            )
            path.parent.mkdir(parents=True, exist_ok=True)
            await _git(repo, "config", f"branch.{branch}.vscbase", base)
            await _git(repo, "worktree", "add", "-b", branch, str(path), base)
            return Workspace(job_id, repo_id, path, branch, base)

    async def diff(self, ws: Workspace) -> str:
        await _git(ws.path, "add", "-N", ".")
        return await _git(ws.path, "diff", "--no-renames", ws.base_ref, strip=False)

    async def changed_paths(self, ws: Workspace) -> list[str]:
        await _git(ws.path, "add", "-N", ".")
        out = await _git(ws.path, "diff", "--no-renames", "--name-only", ws.base_ref)
        return [line for line in out.splitlines() if line]

    async def snapshot(self, ws: Workspace, message: str, *, parent: str | None = None) -> str:
        """The worker's tree (tracked and untracked files; ignored files never) as a commit
        object on ``parent`` (default ``ws.base_ref``). No ref moves and the workspace's own
        index is untouched: a private index file is used."""
        parent = parent or ws.base_ref
        with tempfile.TemporaryDirectory(prefix="a2agw-index-") as tmp:
            index = {"GIT_INDEX_FILE": str(Path(tmp) / "index")}
            await _git(ws.path, "read-tree", parent, env=index)
            await _git(ws.path, "add", "-A", ".", env=index)
            tree = await _git(ws.path, "write-tree", env=index)
        return await _git(ws.path, *_IDENTITY, "commit-tree", tree, "-p", parent, "-m", message)

    async def diff_commits(self, ws: Workspace, old: str, new: str) -> str:
        return await _git(ws.path, "diff", "--no-renames", old, new, strip=False)

    async def changed_between(self, ws: Workspace, old: str, new: str) -> list[str]:
        out = await _git(ws.path, "diff", "--no-renames", "--name-only", old, new)
        return [line for line in out.splitlines() if line]

    async def _show(self, ws: Workspace, ref: str, path: str) -> str | None:
        try:
            return await _git(ws.path, "show", f"{ref}:{path}", strip=False)
        except GitError:
            return None

    async def touched_tests(self, ws: Workspace, old: str, new: str) -> list[str]:
        """Changed paths between two commits that are tests or test configuration: under a
        ``tests/`` (``test/``, ``__tests__/``) directory, a ``conftest.py``, ``pytest.ini``,
        ``tox.ini`` or ``noxfile.py``, a ``pyproject.toml`` whose ``[tool.pytest]`` section
        changed, or a ``package.json`` whose ``test*`` scripts changed."""
        out: list[str] = []
        for path in await self.changed_between(ws, old, new):
            name = path.rsplit("/", 1)[-1]
            if _is_test_path(path):
                out.append(path)
            elif name == "pyproject.toml":
                a, b = await self._show(ws, old, path), await self._show(ws, new, path)
                if _pytest_section(a) != _pytest_section(b):
                    out.append(path)
            elif name == "package.json":
                a, b = await self._show(ws, old, path), await self._show(ws, new, path)
                if _test_scripts(a) != _test_scripts(b):
                    out.append(path)
        return out

    def confine(self, ws: Workspace, system_id: str, paths: list[str]) -> list[str]:
        """The given repo-relative paths that lie outside the system's ``path`` sub-tree."""
        prefix = posixpath.normpath(self._systems[system_id].path)

        def inside(p: str) -> bool:
            norm = posixpath.normpath(p)
            if norm.startswith(("/", "../")) or norm == "..":
                return False
            return prefix == "." or norm == prefix or norm.startswith(prefix + "/")

        outside = [p for p in paths if not inside(p)]
        return outside

    @asynccontextmanager
    async def throwaway(self, ws: Workspace, ref: str | None = None) -> AsyncIterator[Path]:
        """A detached checkout of ``ref`` (default ``ws.base_ref``) under
        ``<root>/<job_id>/.tmp/``, cleaned with ``clean -fdx``, removed on exit."""
        repo = self._repo_of(ws)
        tmp = self.root / ws.job_id / ".tmp" / uuid.uuid4().hex
        tmp.parent.mkdir(parents=True, exist_ok=True)
        await _git(repo, "worktree", "add", "--detach", str(tmp), ref or ws.base_ref)
        try:
            await _git(tmp, "clean", "-fdx")
            yield tmp
        finally:
            await _git(repo, "worktree", "remove", "--force", str(tmp))
            if tmp.parent.is_dir() and not any(tmp.parent.iterdir()):
                tmp.parent.rmdir()

    async def commit(self, ws: Workspace, message: str) -> str:
        await _git(ws.path, "add", "-A")
        await _git(
            ws.path,
            *_IDENTITY,
            "-c", "commit.gpgsign=false",
            "commit", "--no-verify", "--allow-empty", "-m", message,
        )  # fmt: skip
        return await _git(ws.path, "rev-parse", "HEAD")

    async def head(self, ws: Workspace) -> str:
        """The job branch's head (the branch ref, wherever the worktree's HEAD points)."""
        return await _git(ws.path, "rev-parse", "--verify", f"refs/heads/{ws.branch}")

    async def reset(self, ws: Workspace, ref: str) -> None:
        """Check the job branch out at ``ref`` (moving it there) and drop every uncommitted
        change in the workspace (ignored files are kept)."""
        await _git(ws.path, "checkout", "-q", "-f", "-B", ws.branch, ref)
        await _git(ws.path, "clean", "-fd")

    async def advance(self, ws: Workspace, commit: str) -> str:
        """Make ``commit`` (a verified candidate) the job branch's head and check it out."""
        await self.reset(ws, commit)
        return commit

    async def check_target(self, ws: Workspace, target_branch: str) -> None:
        """MergeRefused unless ``target_branch`` is a valid name of an existing local branch."""
        repo = self._repo_of(ws)
        if not target_branch or target_branch.startswith("-"):
            raise MergeRefused(f"invalid target branch {target_branch!r}")
        try:
            if await _git(repo, "check-ref-format", "--branch", target_branch) != target_branch:
                raise GitError("expanded")  # "@{-1}" and friends name another branch
            await _git(repo, "rev-parse", "--verify", "--quiet", f"refs/heads/{target_branch}")
        except GitError:
            raise MergeRefused(f"{target_branch!r} is not an existing local branch") from None

    async def merge_ff(
        self, ws: Workspace, target_branch: str, *, expected_head: str | None = None
    ) -> str:
        """Fast-forward ``target_branch`` in the main repository to the workspace branch's head;
        with ``expected_head``, only if the branch head is exactly that commit (the target then
        moves to that commit, never to whatever the branch points at later)."""
        repo = self._repo_of(ws)
        await self.check_target(ws, target_branch)
        head = await _git(repo, "rev-parse", "--verify", f"refs/heads/{ws.branch}")
        if expected_head is not None and head != expected_head:
            raise MergeRefused(
                f"{ws.branch} is at {head}, not at the verified head {expected_head}"
            )
        target_ref = f"refs/heads/{target_branch}"
        try:
            await _git(repo, "merge-base", "--is-ancestor", target_ref, head)
        except GitError:
            raise MergeRefused(f"{target_branch} is not an ancestor of {ws.branch}") from None
        try:
            current = await _git(repo, "symbolic-ref", "-q", "HEAD")
        except GitError:  # detached HEAD
            current = ""
        if current == target_ref:
            await _git(repo, "merge", "--ff-only", head)
        else:  # target not checked out in the main repository: move the ref (ff-only by default)
            await _git(repo, "fetch", ".", f"{head}:{target_ref}")
        return await _git(repo, "rev-parse", target_ref)

    def _repo_of(self, ws: Workspace) -> Path:
        for repo, rid in self._ids.items():
            if rid == ws.repo_id:
                return repo
        raise KeyError(ws.repo_id)

    async def discard(self, job_id: str, repo_id: str | None = None) -> None:
        """Remove the job's worktrees and branches (only ``repo_id``'s when given)."""
        for repo, rid in self._ids.items():
            if repo_id is not None and rid != repo_id:
                continue
            path = self.root / job_id / rid
            branch = f"vsc/{job_id}/{rid}"
            if path.exists():
                await _git(repo, "worktree", "remove", "--force", str(path))
            if await _git(repo, "branch", "--list", branch):
                await _git(repo, "branch", "-D", branch)
            await _git(repo, "worktree", "prune")
        job_dir = self.root / job_id
        if job_dir.is_dir() and not any(job_dir.iterdir()):
            job_dir.rmdir()
