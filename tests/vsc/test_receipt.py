"""Receipts: built from a real accepted job, exported, and verified offline."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import stat

import pytest

from a2agw.ops.audit import AuditLog, canonical_json
from a2agw.serve.store import create_engine
from a2agw.vsc.receipt import build_receipt, export_receipt, verify_receipt
from a2agw.vsc.store import VscStore
from a2agw.vsc.workspace import WorkspaceManager

from .test_runner import Env, FixedPlanner, edit, two_repo_cfg, worker


@pytest.fixture
async def env(tmp_path):
    engine = await create_engine(f"sqlite+aiosqlite:///{tmp_path / 'g.db'}")
    store, audit = VscStore(engine), AuditLog(engine)
    await store.initialize()
    await audit.initialize()
    try:
        yield Env(tmp_path, store, audit, engine)
    finally:
        await engine.dispose()


@pytest.fixture
async def built(env):
    cfg = two_repo_cfg(env.tmp)
    runner = env.runner(cfg, FixedPlanner([edit("alpha"), edit("beta")]), [worker("apply")])
    job_id = await runner.submit("greet everywhere systems: alpha, beta", owner="key:a")
    job = await runner.run(job_id)
    assert job["state"] == "accepted", job
    ws = WorkspaceManager(env.tmp / "root", cfg.systems, env.tmp)
    receipt = await build_receipt(env.store, env.audit, ws, job_id)
    return env, job_id, receipt


async def test_receipt_hash_covers_everything(built):
    env, job_id, receipt = built
    assert receipt["version"] == "a2agw.receipt/1"
    assert receipt["job_id"] == job_id and receipt["state"] == "accepted"
    assert verify_receipt(receipt) == []
    attempts = [s for s in receipt["steps"]]
    assert [(s["step_id"], s["attempt"]) for s in attempts] == [("edit-alpha", 1), ("edit-beta", 1)]
    assert all(len(s["diff_sha256"]) == 64 and s["checks"] for s in attempts)
    assert receipt["audit"]["rows"] and receipt["tasks"] == [job_id]
    # whole-system results come from the audit rows
    assert any(
        r["action"] == "vsc.check" and "step" not in r["detail"] for r in receipt["audit"]["rows"]
    )
    for key in ("spec", "plan", "usage", "approvals", "created_at", "audit"):
        tampered = copy.deepcopy(receipt)
        tampered[key] = "x" if key != "audit" else {**tampered[key], "last_seq": 10**6}
        assert verify_receipt(tampered), key
    stored = await env.store.get_receipt(job_id)
    assert stored["receipt"] == receipt and stored["receipt_hash"] == receipt["receipt_hash"]
    again = await build_receipt(
        env.store, env.audit, WorkspaceManager(env.tmp / "root", [], env.tmp), job_id
    )
    assert again == receipt  # built once


async def test_verify_detects_tampered_step(built):
    _, _, receipt = built
    bad = copy.deepcopy(receipt)
    bad["steps"][0]["diff_sha256"] = "0" * 64
    assert any("receipt_hash" in p for p in verify_receipt(bad))
    # a forger who recomputes the receipt hash is still caught on the plan and spec hashes
    forged = copy.deepcopy(receipt)
    forged["plan"]["steps"][0]["system"] = "beta"
    body = {k: v for k, v in forged.items() if k != "receipt_hash"}
    forged["receipt_hash"] = hashlib.sha256(canonical_json(body).encode()).hexdigest()
    problems = verify_receipt(forged)
    assert any("plan_hash" in p for p in problems) and not any(
        "receipt_hash" in p for p in problems
    )


async def test_verify_detects_broken_audit_chain(built):
    _, _, receipt = built

    def reseal(r: dict) -> dict:
        body = {k: v for k, v in r.items() if k != "receipt_hash"}
        r["receipt_hash"] = hashlib.sha256(canonical_json(body).encode()).hexdigest()
        return r

    edited = copy.deepcopy(receipt)
    edited["audit"]["rows"][2]["outcome"] = "forged"
    assert any("audit" in p for p in verify_receipt(reseal(edited)))
    dropped = copy.deepcopy(receipt)
    del dropped["audit"]["rows"][2]
    assert any("audit" in p for p in verify_receipt(reseal(dropped)))


async def test_receipt_row_on_audit_chain(built):
    env, job_id, receipt = built
    rows, _ = await env.audit.query({"action": "vsc.receipt"}, 10, ascending=True)
    assert len(rows) == 1 and rows[0]["task_id"] == job_id
    assert rows[0]["detail"] == {"receipt_hash": receipt["receipt_hash"]}
    stored = await env.store.get_receipt(job_id)
    assert stored["audit_seq"] == rows[0]["seq"]
    assert rows[0]["seq"] > receipt["audit"]["last_seq"]
    assert await env.audit.verify_chain() is None
    # a receipt row inside the bundle must agree with the receipt hash
    withrow = copy.deepcopy(receipt)
    withrow["audit"]["rows"].append({**rows[0], "detail": {"receipt_hash": "f" * 64}})
    assert verify_receipt(withrow)


async def test_export_mode_0600(built, tmp_path):
    _, _, receipt = built
    path = tmp_path / "out" / "receipt.json"
    path.parent.mkdir()
    path.write_text("old and much longer than the receipt " * 1000)
    os.chmod(path, 0o644)
    export_receipt(receipt, path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert verify_receipt(json.loads(path.read_text())) == []
