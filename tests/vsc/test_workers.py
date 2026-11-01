"""run_worker against a real scripted stdio worker (``worker_agent.py``)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from a2agw.ops.audit import AuditLog
from a2agw.serve.store import create_engine
from a2agw.vsc.verify import CheckResult
from a2agw.vsc.workers import run_worker
from a2agw.vsc.workspace import Workspace

from .conftest import worker, worker_task


def ws_at(path: Path) -> Workspace:
    return Workspace(job_id="job1", repo_id="core", path=path, branch="b", base_ref="main")


async def test_run_worker_applies_files_in_worktree(tmp_path):
    t = worker_task({"src/a.txt": "hi", "b.txt": "yo"})
    r = await run_worker(worker("apply"), t, ws_at(tmp_path), consult=None, audit=None, actor="u")
    assert r.failed is None
    assert (tmp_path / "src" / "a.txt").read_text() == "hi"
    assert (tmp_path / "b.txt").read_text() == "yo"
    assert "done" in r.text
    assert "applying" in r.status_lines


async def test_run_worker_reports_usage(tmp_path):
    r = await run_worker(
        worker("usage"),
        worker_task({"a": "1"}),
        ws_at(tmp_path),
        consult=None,
        audit=None,
        actor="u",
    )
    assert (r.tokens_in, r.tokens_out, r.cost, r.usage_reported) == (10, 20, 0.01, True)


async def test_run_worker_usage_unreported_flag(tmp_path):
    r = await run_worker(
        worker("apply", reports_usage=False),
        worker_task({"a": "1"}),
        ws_at(tmp_path),
        consult=None,
        audit=None,
        actor="u",
    )
    assert r.usage_reported is False and r.tokens_in == r.tokens_out == 0 and r.cost == 0.0
    r2 = await run_worker(
        worker("apply"),
        worker_task({"a": "1"}),
        ws_at(tmp_path),
        consult=None,
        audit=None,
        actor="u",
    )
    assert r2.usage_reported is False  # configured to report, but none arrived


async def test_run_worker_failed_event(tmp_path):
    r = await run_worker(
        worker("fail"), worker_task({}), ws_at(tmp_path), consult=None, audit=None, actor="u"
    )
    assert r.failed == "worker gave up"


async def test_run_worker_audits_step(tmp_path, db_url):
    engine = await create_engine(db_url)
    try:
        audit = AuditLog(engine)
        await audit.initialize()
        await run_worker(
            worker("usage"),
            worker_task({"a": "1"}),
            ws_at(tmp_path),
            consult=None,
            audit=audit,
            actor="key:alice",
        )
        rows, _ = await audit.query({"action": "vsc.step"})
    finally:
        await engine.dispose()
    assert len(rows) == 1
    row = rows[0]
    assert (row["actor"], row["agent_id"], row["task_id"], row["outcome"]) == (
        "key:alice",
        "deliver",
        "job1",
        "worker",
    )
    d = row["detail"]
    assert (d["worker"], d["step"], d["attempt"]) == ("fake", "s1", 1)
    assert (d["tokens_in"], d["tokens_out"], d["cost"], d["usage_reported"]) == (10, 20, 0.01, True)


async def test_run_worker_stops_process(tmp_path, monkeypatch):
    from a2agw.adapters import stdio

    pids: list[int | None] = []
    real = stdio.StdioAdapter.start

    async def spy(self):
        await real(self)
        pids.append(self.pid)

    monkeypatch.setattr(stdio.StdioAdapter, "start", spy)
    await run_worker(
        worker("apply"),
        worker_task({"a": "1"}),
        ws_at(tmp_path),
        consult=None,
        audit=None,
        actor="u",
    )
    assert len(pids) == 1 and pids[0] is not None
    with pytest.raises(ProcessLookupError):
        os.kill(pids[0], 0)


async def test_run_worker_passes_consult_and_prompt(tmp_path):
    async def consult(ctx):
        return None

    got = []
    from a2agw.adapters import stdio

    real = stdio.StdioAdapter.__init__

    def spy(self, *a, **kw):
        got.append(kw.get("consult"))
        real(self, *a, **kw)

    import unittest.mock as m

    with m.patch.object(stdio.StdioAdapter, "__init__", spy):
        await run_worker(
            worker("apply"),
            worker_task({"a": "1"}),
            ws_at(tmp_path),
            consult=consult,
            audit=None,
            actor="u",
        )
    assert got == [consult]


def test_prompt_renders_confinement_and_failure():
    failure = CheckResult(
        kind="gate",
        id="g",
        command=["make"],
        exit_code=2,
        passed=False,
        duration_s=1.0,
        log_sha256="",
        stderr_tail="boom tail",
        reason="exit 2",
    )
    p = worker_task({"a": "1"}, failure=failure, attempt=2).prompt()
    assert "greeting exists" in p and "greet" in p and "add the greeting" in p
    assert "edit only under" in p
    assert "boom tail" in p and "exit 2" in p
    assert p.rstrip().endswith("}")  # the FILES block stays last
