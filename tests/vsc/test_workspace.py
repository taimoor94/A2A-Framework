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


async def test_repo_id_collision_gets_distinct_workspaces(tmp_path):
    a = make_repo(tmp_path / "one", "app", {"a.txt": "a\n"})
    b = make_repo(tmp_path / "two", "app", {"b.txt": "b\n"})
    m = manager(
        tmp_path,
        a,
        [SystemConfig(id="a", repo=str(a)), SystemConfig(id="b", repo=str(b))],
    )
    wa = await m.create("job1", "a")
    wb = await m.create("job1", "b")
    assert wa.repo_id != wb.repo_id
    assert wa.path != wb.path
    assert (wa.path / "a.txt").exists() and (wb.path / "b.txt").exists()
    assert git(wa.path, "rev-parse", "--show-toplevel") != git(
        wb.path, "rev-parse", "--show-toplevel"
    )


async def test_merge_ff_target_not_checked_out(tmp_path):
    repo = make_repo(tmp_path, "core", {"a.txt": "a\n"})
    git(repo, "branch", "release")
    m = manager(tmp_path, repo)
    ws = await m.create("job1", "core")  # main stays checked out; release is not
    (ws.path / "w.txt").write_text("w\n")
    head = await m.commit(ws, "w")
    assert git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
    assert await m.merge_ff(ws, "release") == head
    assert git(repo, "rev-parse", "release") == head
    assert git(repo, "rev-parse", "main") == ws.base_ref

    git(repo, "branch", "other", ws.base_ref)
    git(repo, "checkout", "other")
    (repo / "o.txt").write_text("o\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-m", "diverge")
    git(repo, "checkout", "main")
    ws2 = await m.create("job2", "core")
    (ws2.path / "x.txt").write_text("x\n")
    await m.commit(ws2, "x")
    before = git(repo, "rev-parse", "other")
    with pytest.raises(MergeRefused):
        await m.merge_ff(ws2, "other")
    assert git(repo, "rev-parse", "other") == before


async def test_discard_removes_branch_and_vscbase_config(tmp_path):
    repo = make_repo(tmp_path, "core", {"a.txt": "a\n"})
    m = manager(tmp_path, repo)
    ws = await m.create("job1", "core")
    key = f"branch.{ws.branch}.vscbase"
    assert git(repo, "config", "--get", key) == ws.base_ref
    await m.discard("job1")
    assert git(repo, "branch", "--list", ws.branch) == ""
    assert key not in git(repo, "config", "--list")


async def test_changed_paths_sees_move_from_outside_system_path(tmp_path):
    repo = make_repo(tmp_path, "core", {"src/a.txt": "a\n", "secret.txt": "line1\nline2\nline3\n"})
    m = manager(tmp_path, repo, [SystemConfig(id="core", repo=str(repo), path="src")])
    ws = await m.create("job1", "core")
    git(ws.path, "mv", "secret.txt", "src/secret.txt")
    paths = await m.changed_paths(ws)
    assert "secret.txt" in paths and "src/secret.txt" in paths
    assert "secret.txt" in m.confine(ws, "core", paths)


async def test_diff_ends_with_newline_and_applies(tmp_path):
    repo = make_repo(tmp_path, "core", {"a.txt": "a\n"})
    m = manager(tmp_path, repo)
    ws = await m.create("job1", "core")
    (ws.path / "a.txt").write_text("changed\n")
    (ws.path / "new.txt").write_text("fresh\n")
    d = await m.diff(ws)
    assert d.endswith("\n")
    patch = tmp_path / "p.patch"
    patch.write_text(d)
    other = tmp_path / "fresh-wt"
    git(repo, "worktree", "add", "--detach", str(other), ws.base_ref)
    git(other, "apply", "--check", str(patch))


async def test_create_recovers_from_partial_create(tmp_path):
    repo = make_repo(tmp_path, "core", {"a.txt": "a\n"})
    m = manager(tmp_path, repo)
    ws = await m.create("job1", "core")
    git(repo, "config", "--unset", f"branch.{ws.branch}.vscbase")  # died before the config write
    again = await m.create("job1", "core")
    assert again.base_ref == ws.base_ref
    assert again.path == ws.path


async def test_throwaway_checks_out_base_and_cleans_up(tmp_path):
    repo = make_repo(tmp_path, "core", {"a.txt": "a\n"})
    m = manager(tmp_path, repo)
    ws = await m.create("job1", "core")
    (ws.path / "a.txt").write_text("changed\n")
    async with m.throwaway(ws) as tmp:
        assert (tmp / "a.txt").read_text() == "a\n"
        assert tmp.parent == tmp_path / "root" / "job1" / ".tmp"
        seen = tmp
    assert not seen.exists()
    assert str(seen) not in git(repo, "worktree", "list")


async def test_snapshot_is_a_commit_of_the_tree_moving_no_ref(tmp_path):
    repo = make_repo(tmp_path, "core", {".gitignore": "ignored/\n", "a.txt": "a\n"})
    m = manager(tmp_path, repo)
    ws = await m.create("job1", "core")
    (ws.path / "a.txt").write_text("changed\n")
    (ws.path / "new.txt").write_text("fresh\n")
    (ws.path / "ignored").mkdir()
    (ws.path / "ignored" / "x").write_text("never\n")
    sha = await m.snapshot(ws, "candidate")
    assert git(repo, "rev-parse", f"{sha}^") == ws.base_ref
    assert sorted(git(repo, "ls-tree", "-r", "--name-only", sha).split()) == [
        ".gitignore",
        "a.txt",
        "new.txt",
    ]
    assert await m.head(ws) == ws.base_ref  # the branch did not move
    assert git(ws.path, "status", "--porcelain")  # the worker's tree and index are untouched
    assert await m.changed_between(ws, ws.base_ref, sha) == ["a.txt", "new.txt"]
    assert "+fresh" in await m.diff_commits(ws, ws.base_ref, sha)
    await m.advance(ws, sha)
    assert await m.head(ws) == sha
    assert git(ws.path, "rev-parse", "--abbrev-ref", "HEAD") == ws.branch


async def test_touched_tests_flags_test_files_and_test_config(tmp_path):
    pyproject = '[project]\nname = "x"\n\n[tool.pytest.ini_options]\naddopts = "-q"\n'
    package = '{"scripts": {"test": "jest", "build": "tsc"}}'
    repo = make_repo(
        tmp_path,
        "core",
        {"src/a.py": "a\n", "pyproject.toml": pyproject, "web/package.json": package},
    )
    m = manager(tmp_path, repo)
    ws = await m.create("job1", "core")
    (ws.path / "src" / "a.py").write_text("b\n")
    (ws.path / "tests").mkdir()
    (ws.path / "tests" / "test_new.py").write_text("\n")
    (ws.path / "src" / "conftest.py").write_text("\n")
    (ws.path / "pyproject.toml").write_text(pyproject.replace('"x"', '"y"'))  # not tests
    (ws.path / "web" / "package.json").write_text(package.replace("jest", "true"))
    sha = await m.snapshot(ws, "c")
    assert sorted(await m.touched_tests(ws, ws.base_ref, sha)) == [
        "src/conftest.py",
        "tests/test_new.py",
        "web/package.json",
    ]
    (ws.path / "pyproject.toml").write_text(pyproject.replace("-q", "-x"))
    sha2 = await m.snapshot(ws, "c2")
    assert "pyproject.toml" in await m.touched_tests(ws, ws.base_ref, sha2)


async def test_repository_hooks_never_run_and_signing_is_off(tmp_path):
    repo = make_repo(tmp_path, "core", {"a.txt": "a\n"})
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    marker = tmp_path / "hook-ran"
    for name in ("pre-commit", "commit-msg", "post-checkout", "post-commit"):
        hook = hooks / name
        hook.write_text(f"#!/bin/sh\ntouch {marker}\nexit 1\n")
        hook.chmod(0o755)
    git(repo, "config", "core.hooksPath", str(hooks))
    git(repo, "config", "commit.gpgsign", "true")
    git(repo, "config", "gpg.program", "/nonexistent/gpg")
    m = manager(tmp_path, repo)
    ws = await m.create("job1", "core")  # worktree add: post-checkout
    (ws.path / "w.txt").write_text("w\n")
    head = await m.commit(ws, "worker change")
    assert head != ws.base_ref
    async with m.throwaway(ws, head):
        pass
    assert not marker.exists()


async def test_git_process_is_killed_on_cancellation(tmp_path, monkeypatch):
    import asyncio
    import os

    from a2agw.vsc import workspace

    repo = make_repo(tmp_path, "core", {"a.txt": "a\n"})
    started: list[int] = []
    real = asyncio.create_subprocess_exec

    async def spy(*args, **kw):
        proc = await real(*args, **kw)
        started.append(proc.pid)
        return proc

    monkeypatch.setattr(workspace.asyncio, "create_subprocess_exec", spy)
    task = asyncio.create_task(workspace._git(repo, "-c", "alias.slow=!sleep 30", "slow"))
    while not started:
        await asyncio.sleep(0.01)
    await asyncio.sleep(0.3)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 10)
    with pytest.raises(ProcessLookupError):
        os.killpg(started[0], 0)  # the whole group (git and its sleep) is gone


async def test_merge_ff_bound_to_expected_head_and_existing_branch(tmp_path):
    repo = make_repo(tmp_path, "core", {"a.txt": "a\n"})
    m = manager(tmp_path, repo)
    ws = await m.create("job1", "core")
    (ws.path / "w.txt").write_text("w\n")
    verified = await m.commit(ws, "verified")
    (ws.path / "later.txt").write_text("l\n")
    await m.commit(ws, "after verification")
    with pytest.raises(MergeRefused, match="verified head"):
        await m.merge_ff(ws, "main", expected_head=verified)
    assert git(repo, "rev-parse", "main") == ws.base_ref
    for bad in ("nope", "-main", "@{-1}", "a..b"):
        with pytest.raises(MergeRefused):
            await m.merge_ff(ws, bad)
    await m.reset(ws, verified)
    assert await m.merge_ff(ws, "main", expected_head=verified) == verified
