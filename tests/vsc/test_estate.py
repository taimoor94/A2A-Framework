"""The demo estate is real: it builds, its whole-system check passes on the base commits, and
every scenario's acceptance tests fail on the base and pass with its reference patch."""

from __future__ import annotations

import shutil
import subprocess

import pytest

from a2agw.vsc.spec import AcceptanceTest
from a2agw.vsc.verify import reproduction_before, run_check, verify_whole
from a2agw.vsc.workspace import WorkspaceManager

from .estate_support import (
    REPOS,
    SCENARIO_KEYS,
    apply_patch,
    estate_config,
    init_estate,
    load_scenario,
    scenario_paths,
    split_files,
    split_patch,
    write_files,
)

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node is not on PATH")

TIMEOUT_S = 90.0
SCENARIOS = scenario_paths()
REQUIRED_SCENARIOS = {
    "reserve-stock-on-order",
    "release-stock-on-cancel",
    "idempotency-key",
    "backorders-end-to-end",
    "rename-qty-to-quantity",
    "order-total-with-tax-from-inventory-price",
    "soft-delete-products",
    "pagination-on-list-orders",
    "inventory-low-stock-webhook-to-orders",
    "contract-version-header",
}


def git(repo, *args) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()


@pytest.fixture(scope="module")
def estate(tmp_path_factory):
    root = tmp_path_factory.mktemp("estate")
    res = init_estate(root / "estate")
    assert res.returncode == 0, res.stderr
    cfg = estate_config(root / "estate")
    manager = WorkspaceManager(root / "ws", cfg.systems, root)
    return cfg, manager


def test_init_estate_creates_three_repos(tmp_path):
    target = tmp_path / "estate"
    res = init_estate(target)
    assert res.returncode == 0, res.stderr
    assert sorted(p.name for p in target.iterdir()) == sorted(REPOS)
    for name in REPOS:
        repo = target / name
        assert git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
        assert git(repo, "rev-list", "--count", "HEAD") == "1"
        assert git(repo, "status", "--porcelain") == ""
        assert git(repo, "config", "user.email") == "estate@example.invalid"
    assert (target / "orders-api" / "app.py").is_file()
    assert (target / "inventory-service" / "server.mjs").is_file()
    assert (target / "contract" / "openapi" / "orders.yaml").is_file()
    assert (target / "contract" / "openapi" / "inventory.yaml").is_file()
    assert (target / "contract" / "tests" / "test_contract.py").is_file()
    again = init_estate(target)  # never overwrites an existing estate
    assert again.returncode != 0 and "not empty" in again.stderr


async def test_every_system_passes_gate_and_tests_on_base(estate):
    cfg, manager = estate
    for system in cfg.systems:
        ws = await manager.create("base-systems", system.id)
        for kind, command in (("gate", system.gate), ("regression", system.tests)):
            if command is None:
                continue
            res = await run_check(kind, system.id, command, ws.path, timeout_s=TIMEOUT_S)
            assert res.passed, (system.id, kind, res.reason, res.stderr_tail)


async def test_contract_suite_passes_on_base(estate):
    cfg, manager = estate
    (check,) = cfg.checks
    assert check.systems[0] == "contract"  # the check runs in the first system's workspace
    wss = {sid: await manager.create("base-whole", sid) for sid in check.systems}
    res = await verify_whole(check, wss, timeout_s=TIMEOUT_S)
    assert res.passed, (res.reason, res.stderr_tail)


def test_the_required_scenarios_exist():
    assert REQUIRED_SCENARIOS <= {p.stem for p in SCENARIOS}


@pytest.mark.parametrize("path", SCENARIOS, ids=lambda p: p.stem)
def test_scenario_file_is_well_formed(path, estate):
    cfg, _ = estate
    data = load_scenario(path)
    assert set(data) <= SCENARIO_KEYS and SCENARIO_KEYS - {"notes"} <= set(data)
    assert data["id"] == path.stem
    assert len(data["request"].split()) >= 15  # written as a person would ask
    systems = set(data["systems"])
    assert systems <= {s.id for s in cfg.systems}
    tests = [AcceptanceTest.model_validate(t) for t in data["acceptance"]]
    assert tests and len({t.id for t in tests}) == len(tests)
    touched = set(split_patch(data["reference_patch"]))
    for t in tests:
        assert t.files, t.id
        if t.system is None:
            (check,) = [c for c in cfg.checks if c.id == t.check]
            assert set(check.systems) <= systems  # else the runner never runs the check
            touched |= set(split_files(t.files))
        else:
            assert t.system in systems
            touched.add(t.system)
    assert touched <= systems, f"systems must list every repository touched: {touched}"


@pytest.mark.parametrize("path", SCENARIOS, ids=lambda p: p.stem)
async def test_each_scenario_fails_before_and_passes_with_reference_patch(path, estate):
    cfg, manager = estate
    data = load_scenario(path)
    job = data["id"]
    systems = {s.id: s for s in cfg.systems}
    checks = {c.id: c for c in cfg.checks}
    tests = [AcceptanceTest.model_validate(t) for t in data["acceptance"]]

    # Before: on the base commits every acceptance test fails, by a failing test (exit 1),
    # not by a crash or a collection error.
    for t in tests:
        if t.system is not None:
            ws = await manager.create(job, t.system)
            res = await reproduction_before(manager, ws, t, systems[t.system], timeout_s=TIMEOUT_S)
            assert res.passed and res.exit_code == 1, (t.id, res.reason, res.stderr_tail)
        else:
            check = checks[t.check]
            if t.run is not None:
                check = check.model_copy(update={"run": t.run})
            wss = {sid: await manager.create(f"{job}-before", sid) for sid in check.systems}
            for repo_id, files in split_files(t.files).items():
                write_files(wss[repo_id].path, files)
            res = await verify_whole(check, wss, timeout_s=TIMEOUT_S)
            assert res.exit_code == 1, (t.id, res.reason, res.stderr_tail)
    await manager.discard(f"{job}-before")

    # After: the reference patch plus the acceptance files pass every check.
    wss = {sid: await manager.create(job, sid) for sid in REPOS}
    apply_patch(data["reference_patch"], {sid: ws.path for sid, ws in wss.items()})
    for t in tests:
        if t.system is not None:
            write_files(wss[t.system].path, t.files)
        else:
            for repo_id, files in split_files(t.files).items():
                write_files(wss[repo_id].path, files)
    for sid in data["systems"]:
        system = systems[sid]
        cwd = wss[sid].path / system.path
        # the contract suite runs below as the whole-system check; do not run it twice
        whole = any(c.systems[0] == sid and c.run == system.tests for c in cfg.checks)
        for kind, command in (("gate", system.gate), ("regression", system.tests)):
            if command is None or (kind == "regression" and whole):
                continue
            res = await run_check(kind, sid, command, cwd, timeout_s=TIMEOUT_S)
            assert res.passed, (sid, kind, res.reason, res.stderr_tail)
    for t in tests:
        if t.system is not None and t.run is not None:
            cwd = wss[t.system].path / systems[t.system].path
            res = await run_check("reproduction_after", t.id, t.run, cwd, timeout_s=TIMEOUT_S)
            assert res.passed, (t.id, res.reason, res.stderr_tail)
    for check in cfg.checks:
        res = await verify_whole(
            check, {sid: wss[sid] for sid in check.systems}, timeout_s=TIMEOUT_S
        )
        assert res.passed, (check.id, res.reason, res.stderr_tail)
    await manager.discard(job)
