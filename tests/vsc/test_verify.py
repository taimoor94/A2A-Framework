from __future__ import annotations

import sys

from a2agw.vsc.config import BudgetConfig, CheckConfig, SystemConfig
from a2agw.vsc.spec import AcceptanceTest, Contract, ExecutableSpec
from a2agw.vsc.verify import (
    all_passed,
    executable_checks,
    reproduction_before,
    reproduction_before_whole,
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
        tests=py("import os; assert os.path.exists('acc.txt')"),
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
    assert not (ws.path / "acc.txt").exists()  # written in the throwaway checkout only


async def test_verify_step_runs_in_a_throwaway_checkout_of_the_candidate(tmp_path):
    """Ignored files the worker left in its tree never reach the checks; untracked ones do
    (they are part of the candidate)."""
    repo = make_repo(tmp_path, "core", {".gitignore": "cache/\n", "a.txt": "a\n"})
    probe = py(
        "import os, sys; sys.exit(0 if os.path.exists('new.txt') "
        "and not os.path.exists('cache/poison') and os.getcwd() != sys.argv[1] else 1)"
    )
    system = SystemConfig(id="core", repo=str(repo), tests=probe)
    m = WorkspaceManager(tmp_path / "root", [system], tmp_path)
    ws = await m.create("job1", "core")
    system = system.model_copy(update={"tests": [*probe, str(ws.path.resolve())]})
    (ws.path / "new.txt").write_text("n\n")
    (ws.path / "cache").mkdir()
    (ws.path / "cache" / "poison").write_text("x")
    results = await verify_step(ws, system, spec_for(), manager=m, timeout_s=30)
    assert all_passed(results), results


async def test_verify_step_without_any_executed_check_fails(tmp_path):
    m, ws, system = await _setup(tmp_path)  # no gate, no tests, no acceptance test
    results = await verify_step(ws, system, spec_for(), manager=m, timeout_s=10)
    assert not all_passed(results)
    assert (results[-1].kind, results[-1].reason) == ("regression", "no checks")
    covered = await verify_step(ws, system, spec_for(), manager=m, timeout_s=10, whole_covered=True)
    assert all_passed(covered)


def test_executable_checks():
    bare = SystemConfig(id="core", repo="./core")
    assert not executable_checks(bare, spec_for())
    assert executable_checks(bare.model_copy(update={"gate": py("pass")}), spec_for())
    assert executable_checks(bare.model_copy(update={"tests": py("pass")}), spec_for())
    with_run = spec_for(acceptance=[AcceptanceTest(id="a", system="core", run=py("pass"))])
    assert executable_checks(bare, with_run)
    no_run = spec_for(acceptance=[AcceptanceTest(id="a", system="core")])
    assert not executable_checks(bare, no_run)
    whole = spec_for(acceptance=[AcceptanceTest(id="w", check="c")])
    check = CheckConfig(id="c", systems=["core", "other"], run=py("pass"))
    assert not executable_checks(bare, whole)
    assert executable_checks(bare, whole, [check])  # covered in the whole-system phase


async def test_reproduction_before_whole_requires_failure_on_base(tmp_path):
    _m, _ws, system = await _setup(tmp_path)
    repo2 = make_repo(tmp_path, "node-coder", {"b.txt": "b\n"})
    s2 = SystemConfig(id="node-coder", repo=str(repo2))
    m = WorkspaceManager(tmp_path / "root", [system, s2], tmp_path)
    wss = {"core": await m.create("job1", "core"), "node-coder": await m.create("job1", "node-coder")}
    present = py(
        "import os, sys; sys.exit(0 if os.path.exists(os.path.join(os.environ['VSC_WS_CORE'], "
        "'w.txt')) and os.path.exists(os.path.join(os.environ['VSC_WS_CORE'], 'a.txt')) else 1)"
    )
    needs_change = py(
        "import os, sys; sys.exit(0 if os.path.exists(os.path.join(os.environ['VSC_WS_CORE'], "
        "'changed.txt')) else 1)"
    )
    test = AcceptanceTest(id="w", check="c", files={"core/w.txt": "x"})
    passes = CheckConfig(id="c", systems=["core", "node-coder"], run=present)
    r = await reproduction_before_whole(m, passes, wss, [test], timeout_s=30)
    assert r is not None and not r.passed and r.reason == "passed on base"
    fails = CheckConfig(id="c", systems=["core", "node-coder"], run=needs_change)
    r = await reproduction_before_whole(m, fails, wss, [test], timeout_s=30)
    assert r is not None and r.passed and r.kind == "reproduction_before"
    assert not (wss["core"].path / "w.txt").exists()  # never in the job's workspace
    assert await reproduction_before_whole(m, fails, wss, [], timeout_s=30) is None


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


async def test_env_secret_value_printed_by_child_is_redacted(tmp_path, monkeypatch):
    monkeypatch.setenv("A2AGW_TEST_API_TOKEN", "plainvalue-xyz-12345")
    code = "import sys; sys.stderr.write('oops plainvalue-xyz-12345 done')"
    r = await run_check(
        "gate",
        "g",
        py(code),
        tmp_path,
        timeout_s=10,
        env={"A2AGW_TEST_API_TOKEN": "plainvalue-xyz-12345"},
    )
    assert "plainvalue-xyz-12345" not in r.stderr_tail
    assert "oops" in r.stderr_tail


async def test_json_quoted_password_and_auth_scheme_redacted(tmp_path):
    code = (
        'import sys; sys.stderr.write(\'{"password": "hunter 2 spaced"} '
        "Authorization: Token abcdef123456 Authorization: Custom zzz999')"
    )
    r = await run_check("gate", "g", py(code), tmp_path, timeout_s=10)
    assert "hunter" not in r.stderr_tail and "spaced" not in r.stderr_tail
    assert "abcdef123456" not in r.stderr_tail and "zzz999" not in r.stderr_tail


async def test_stderr_tail_drops_partial_first_line(tmp_path):
    code = "import sys; sys.stderr.write('PARTIALHEAD' + 'x'*3000 + '\\nlast line here\\n')"
    r = await run_check("gate", "g", py(code), tmp_path, timeout_s=10)
    assert r.stderr_tail.strip() == "last line here"


async def test_non_allowlisted_parent_env_not_visible_to_child(tmp_path, monkeypatch):
    monkeypatch.setenv("A2AGW_TEST_SECRET", "s3cr3t-value-123")
    monkeypatch.setenv("UV_FOO_TEST", "kept")
    code = (
        "import os,sys; sys.exit(0 if 'A2AGW_TEST_SECRET' not in os.environ "
        "and os.environ.get('UV_FOO_TEST')=='kept' and os.environ.get('X_EXTRA')=='1' else 1)"
    )
    r = await run_check("gate", "g", py(code), tmp_path, timeout_s=10, env={"X_EXTRA": "1"})
    assert r.passed, r


async def test_reproduction_before_spawn_failure_is_inconclusive(tmp_path):
    m, ws, system = await _setup(tmp_path, tests=["/nonexistent/binary-xyz"])
    r = await reproduction_before(
        m, ws, AcceptanceTest(id="t", system="core", files={"n.txt": "y"}), system, timeout_s=10
    )
    assert not r.passed and r.reason.startswith("spawn")


_FILE_CHECK = "import sys,os; sys.exit(0 if len(sys.argv)<2 or os.path.isfile(sys.argv[1]) else 1)"


async def test_contract_path_resolves_from_workspace_root(tmp_path):
    repo = make_repo(tmp_path, "core", {"svc/a.txt": "a\n", "contracts/test_x.py": "\n"})
    system = SystemConfig(id="core", repo=str(repo), path="svc", tests=py(_FILE_CHECK))
    m = WorkspaceManager(tmp_path / "root", [system], tmp_path)
    ws = await m.create("job1", "core")
    contract = Contract(name="c", systems=["core"], path="contracts/test_x.py")
    results = await verify_step(ws, system, spec_for(contracts=[contract]), manager=m, timeout_s=10)
    assert results[-1].kind == "contract" and results[-1].passed
    missing = Contract(name="m", systems=["core"], path="contracts/gone.py")
    results = await verify_step(ws, system, spec_for(contracts=[missing]), manager=m, timeout_s=10)
    assert results[-1].kind == "contract"
    assert not results[-1].passed and results[-1].reason == "contract file missing"


async def test_contract_text_only_skipped_and_no_tests_fails(tmp_path):
    m, ws, system = await _setup(tmp_path, tests=py("pass"))
    text_only = Contract(name="t", systems=["core"], text="prose")
    results = await verify_step(
        ws, system, spec_for(contracts=[text_only]), manager=m, timeout_s=10
    )
    assert results[-1].kind == "contract" and results[-1].passed
    assert results[-1].reason == "no contract test"
    m2, ws2, system2 = await _setup(tmp_path / "n")
    (ws2.path / "c.py").write_text("")
    pc = Contract(name="p", systems=["core"], path="c.py")
    results = await verify_step(ws2, system2, spec_for(contracts=[pc]), manager=m2, timeout_s=10)
    assert not results[-1].passed and results[-1].reason == "no tests command"
