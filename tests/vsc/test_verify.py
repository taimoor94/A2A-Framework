from __future__ import annotations

import sys

from a2agw.vsc.config import BudgetConfig, CheckConfig, SystemConfig
from a2agw.vsc.spec import AcceptanceTest, Contract, ExecutableSpec
from a2agw.vsc.verify import (
    all_passed,
    reproduction_before,
    run_check,
    verify_step,
    verify_whole,
)
from a2agw.vsc.workspace import WorkspaceManager

from .conftest import make_repo

PY = sys.executable


def py(code: str) -> list[str]:
    return [PY, "-c", code]


def spec_for(acceptance=(), contracts=()):
    return ExecutableSpec(
        request="r",
        done="d",
        systems=["core"],
        acceptance=list(acceptance),
        contracts=list(contracts),
        budgets=BudgetConfig(),
    )


async def test_run_check_timeout_fails_with_reason(tmp_path):
    r = await run_check("gate", "g", py("import time; time.sleep(30)"), tmp_path, timeout_s=0.5)
    assert not r.passed and r.reason == "timeout"
    assert r.duration_s < 10


async def test_run_check_output_capped(tmp_path):
    code = "import sys\nfor _ in range(8*1024):\n    sys.stdout.write('x'*1023+'\\n')"
    r = await run_check("gate", "g", py(code), tmp_path, timeout_s=30)
    assert not r.passed and r.reason == "truncated"
    assert len(r.log_sha256) == 64


async def test_run_check_passes_and_fails_by_exit_code(tmp_path):
    ok = await run_check("gate", "g", py("pass"), tmp_path, timeout_s=10)
    bad = await run_check("gate", "g", py("import sys; sys.exit(3)"), tmp_path, timeout_s=10)
    assert ok.passed and ok.exit_code == 0
    assert not bad.passed and bad.exit_code == 3


async def test_stderr_tail_sanitised(tmp_path):
    code = (
        "import sys; sys.stderr.write('boom token=ghp_abcdefghijklmnopqrstuvwxyz0123456789 "
        "Authorization: Bearer abc.def.ghi-123456 end')"
    )
    r = await run_check("gate", "g", py(code), tmp_path, timeout_s=10)
    assert "ghp_abcdefghijklmnopqrstuvwxyz0123456789" not in r.stderr_tail
    assert "abc.def.ghi-123456" not in r.stderr_tail
    assert "boom" in r.stderr_tail and len(r.stderr_tail.encode()) <= 2048


async def _setup(tmp_path, **sys_kwargs):
    repo = make_repo(tmp_path, "core", {"a.txt": "a\n"})
    system = SystemConfig(id="core", repo=str(repo), **sys_kwargs)
    m = WorkspaceManager(tmp_path / "root", [system], tmp_path)
    ws = await m.create("job1", "core")
    return m, ws, system


async def test_reproduction_before_requires_failure(tmp_path):
    test_cmd = py("import sys; sys.exit(0 if open('new.txt').read()=='x' else 1)")
    m, ws, system = await _setup(tmp_path, tests=test_cmd)
    failing = AcceptanceTest(id="t", system="core", files={"new.txt": "y"})
    r = await reproduction_before(m, ws, failing, system, timeout_s=30)
    assert r.kind == "reproduction_before" and r.passed  # failed on base, as required
    passing = AcceptanceTest(id="t2", system="core", files={"new.txt": "x"})
    r = await reproduction_before(m, ws, passing, system, timeout_s=30)
    assert not r.passed and r.reason == "passed on base"


async def test_verify_step_stops_at_confinement(tmp_path):
    repo = make_repo(tmp_path, "core", {"sub/a.txt": "a\n", "other.txt": "o\n"})
    system = SystemConfig(id="core", repo=str(repo), path="sub", gate=py("pass"))
    m = WorkspaceManager(tmp_path / "root", [system], tmp_path)
    ws = await m.create("job1", "core")
    (ws.path / "other.txt").write_text("changed\n")
    results = await verify_step(ws, system, spec_for(), manager=m, timeout_s=10)
    assert [r.kind for r in results] == ["path_confinement"]
    assert not all_passed(results)


async def test_verify_step_order(tmp_path):
    m, ws, system = await _setup(
        tmp_path,
        gate=py("pass"),
        tests=py("import os; assert os.path.exists('acc.txt') or True"),
    )
    (ws.path / "a.txt").write_text("changed\n")
    (ws.path / "t_contract.py").write_text("")
    spec = spec_for(
        acceptance=[
            AcceptanceTest(id="a1", system="core", files={"acc.txt": "1"}, run=py("pass")),
            AcceptanceTest(id="other", system="elsewhere", files={}),
            AcceptanceTest(id="w", check="whole"),
        ],
        contracts=[
            Contract(name="c", systems=["core"], path="t_contract.py"),
            Contract(name="skip", systems=["elsewhere"], path="t_contract.py"),
        ],
    )
    results = await verify_step(ws, system, spec, manager=m, timeout_s=30)
    assert [r.kind for r in results] == [
        "path_confinement",
        "gate",
        "reproduction_after",
        "regression",
        "contract",
    ]
    assert all_passed(results)
    assert (ws.path / "acc.txt").read_text() == "1"


async def test_verify_step_no_gate_and_stops_on_first_failure(tmp_path):
    m, ws, system = await _setup(tmp_path, tests=py("import sys; sys.exit(1)"))
    results = await verify_step(ws, system, spec_for(), manager=m, timeout_s=10)
    assert [(r.kind, r.passed) for r in results] == [
        ("path_confinement", True),
        ("gate", True),
        ("regression", False),
    ]
    assert results[1].reason == "no gate"


async def test_verify_whole_passes_env_paths(tmp_path):
    _m1, ws1, _ = await _setup(tmp_path / "x")
    repo2 = make_repo(tmp_path / "y", "node-coder", {"b.txt": "b\n"})
    s2 = SystemConfig(id="node-coder", repo=str(repo2))
    ws2 = await WorkspaceManager(tmp_path / "root2", [s2], tmp_path / "y").create(
        "job1", "node-coder"
    )
    code = (
        "import os,sys; "
        "sys.exit(0 if os.environ['VSC_WS_CORE']==sys.argv[1] "
        "and os.environ['VSC_WS_NODE_CODER']==sys.argv[2] and os.getcwd()==sys.argv[1] else 1)"
    )
    check = CheckConfig(
        id="c",
        systems=["core", "node-coder"],
        run=[PY, "-c", code, str(ws1.path.resolve()), str(ws2.path.resolve())],
    )
    r = await verify_whole(check, {"core": ws1, "node-coder": ws2}, timeout_s=30)
    assert r.kind == "whole_system" and r.passed, r.stderr_tail
