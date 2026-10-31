from __future__ import annotations

import subprocess

import pytest

from a2agw.vsc.config import SystemConfig
from a2agw.vsc.workspace import MergeRefused, WorkspaceManager

from .conftest import make_repo


def git(repo, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()


def manager(tmp_path, repo, systems=None):
    systems = systems or [SystemConfig(id="core", repo=str(repo))]
    return WorkspaceManager(tmp_path / "root", systems, tmp_path)


async def test_create_worktree_on_branch(tmp_path):
    repo = make_repo(tmp_path, "core", {"a.txt": "a\n"})
    ws = await manager(tmp_path, repo).create("job1", "core")
    assert ws.branch == f"vsc/job1/{ws.repo_id}"
    assert ws.path == tmp_path / "root" / "job1" / ws.repo_id
    assert (ws.path / "a.txt").read_text() == "a\n"
    assert git(ws.path, "rev-parse", "--abbrev-ref", "HEAD") == ws.branch
    assert ws.base_ref == git(repo, "rev-parse", "main")


async def test_same_repo_same_job_shares_worktree(tmp_path):
    repo = make_repo(tmp_path, "core", {"a.txt": "a\n", "sub/b.txt": "b\n"})
    systems = [
        SystemConfig(id="core", repo=str(repo)),
        SystemConfig(id="sub", repo=str(repo), path="sub"),
    ]
    m = manager(tmp_path, repo, systems)
    one = await m.create("job1", "core")
    two = await m.create("job1", "sub")
    again = await m.create("job1", "core")
    assert one == two == again
    assert (await m.create("job2", "core")).path != one.path


async def test_diff_includes_untracked(tmp_path):
    repo = make_repo(tmp_path, "core", {"a.txt": "a\n"})
    m = manager(tmp_path, repo)
    ws = await m.create("job1", "core")
    (ws.path / "a.txt").write_text("changed\n")
    (ws.path / "new.txt").write_text("fresh\n")
    d = await m.diff(ws)
    assert "+changed" in d and "+fresh" in d and "new.txt" in d
    assert sorted(await m.changed_paths(ws)) == ["a.txt", "new.txt"]


async def test_confine_reports_paths_outside_system(tmp_path):
    repo = make_repo(tmp_path, "core", {"src/a.txt": "a\n"})
    m = manager(tmp_path, repo, [SystemConfig(id="core", repo=str(repo), path="src")])
    ws = await m.create("job1", "core")
    outside = m.confine(ws, "core", ["src/a.txt", "src/x/y.txt", "README.md", "srcother/z", "../q"])
    assert outside == ["README.md", "srcother/z", "../q"]


async def test_discard_removes_worktree_and_branch(tmp_path):
    repo = make_repo(tmp_path, "core", {"a.txt": "a\n"})
    m = manager(tmp_path, repo)
    ws = await m.create("job1", "core")
    await m.discard("job1")
    assert not ws.path.exists()
    assert git(repo, "branch", "--list", ws.branch) == ""
    assert "job1" not in git(repo, "worktree", "list")
    await m.discard("job1")  # idempotent


async def test_merge_ff_refuses_diverged(tmp_path):
    repo = make_repo(tmp_path, "core", {"a.txt": "a\n"})
    m = manager(tmp_path, repo)
    ws = await m.create("job1", "core")
    (ws.path / "w.txt").write_text("w\n")
    head = await m.commit(ws, "worker change")
    assert await m.merge_ff(ws, "main") == head
    assert git(repo, "rev-parse", "main") == head

    ws2 = await m.create("job2", "core")
    (ws2.path / "x.txt").write_text("x\n")
    await m.commit(ws2, "x")
    (repo / "y.txt").write_text("y\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-m", "moved on")
    before = git(repo, "rev-parse", "main")
    with pytest.raises(MergeRefused):
        await m.merge_ff(ws2, "main")
    assert git(repo, "rev-parse", "main") == before
