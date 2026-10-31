"""Isolated git worktrees: one worker edits one repository for one job.

Layout: ``<root>/<job_id>/<repo_id>/`` on branch ``vsc/<job_id>/<repo_id>``.

``repo_id`` rule: the last component of the resolved repository path, reduced to
``[A-Za-z0-9._-]`` (anything else becomes ``-``). If two distinct resolved paths among the
configured systems end in the same name, every one of them gets ``-<8 hex of sha256(path)>``
appended. Systems sharing one repository therefore share one workspace.

Diffs include untracked files by running ``git add -N`` (intent-to-add) first, so the plain
``git diff <base_ref>`` shows them.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import posixpath
import re
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

from a2agw.vsc.config import SystemConfig

_TIMEOUT_S = 120.0


class GitError(RuntimeError):
    """A git command failed; the message is its stderr."""


class MergeRefused(GitError):
    """The merge would not be a fast-forward."""


@dataclass(frozen=True)
class Workspace:
    job_id: str
    repo_id: str
    path: Path
    branch: str
    base_ref: str


async def _git(cwd: Path, *args: str, strip: bool = True) -> str:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    proc = await asyncio.create_subprocess_exec(
        "git",
        *args,
        cwd=cwd,
        env=env,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), _TIMEOUT_S)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        raise GitError(f"git {' '.join(args)} timed out after {_TIMEOUT_S:.0f}s") from None
    if proc.returncode != 0:
        raise GitError(err.decode(errors="replace").strip())
    text = out.decode(errors="replace")
    return text.strip() if strip else text


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
    async def throwaway(self, ws: Workspace) -> AsyncIterator[Path]:
        """A detached checkout of ``ws.base_ref`` under ``<root>/<job_id>/.tmp/``, removed on exit."""
        repo = self._repo_of(ws)
        tmp = self.root / ws.job_id / ".tmp" / uuid.uuid4().hex
        tmp.parent.mkdir(parents=True, exist_ok=True)
        await _git(repo, "worktree", "add", "--detach", str(tmp), ws.base_ref)
        try:
            yield tmp
        finally:
            await _git(repo, "worktree", "remove", "--force", str(tmp))
            if tmp.parent.is_dir() and not any(tmp.parent.iterdir()):
                tmp.parent.rmdir()

    async def commit(self, ws: Workspace, message: str) -> str:
        await _git(ws.path, "add", "-A")
        await _git(
            ws.path,
            "-c", "user.name=a2agw",
            "-c", "user.email=a2agw@localhost",
            "commit", "--allow-empty", "-m", message,
        )  # fmt: skip
        return await _git(ws.path, "rev-parse", "HEAD")

    async def merge_ff(self, ws: Workspace, target_branch: str) -> str:
        """Fast-forward ``target_branch`` in the main repository to the workspace branch."""
        repo = self._repo_of(ws)
        try:
            await _git(repo, "merge-base", "--is-ancestor", target_branch, ws.branch)
        except GitError:
            raise MergeRefused(f"{target_branch} is not an ancestor of {ws.branch}") from None
        current = await _git(repo, "rev-parse", "--abbrev-ref", "HEAD")
        if current == target_branch:
            await _git(repo, "merge", "--ff-only", ws.branch)
        else:  # target not checked out in the main repository: move the ref (ff-only by default)
            await _git(repo, "fetch", ".", f"{ws.branch}:{target_branch}")
        return await _git(repo, "rev-parse", target_branch)

    def _repo_of(self, ws: Workspace) -> Path:
        for repo, rid in self._ids.items():
            if rid == ws.repo_id:
                return repo
        raise KeyError(ws.repo_id)

    async def discard(self, job_id: str) -> None:
        for repo, repo_id in self._ids.items():
            path = self.root / job_id / repo_id
            branch = f"vsc/{job_id}/{repo_id}"
            if path.exists():
                await _git(repo, "worktree", "remove", "--force", str(path))
            if await _git(repo, "branch", "--list", branch):
                await _git(repo, "branch", "-D", branch)
            await _git(repo, "worktree", "prune")
        job_dir = self.root / job_id
        if job_dir.is_dir() and not any(job_dir.iterdir()):
            job_dir.rmdir()
