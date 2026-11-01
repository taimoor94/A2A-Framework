"""Receipts: built from a real accepted job, exported, and verified offline."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import os
import stat
import sys

import pytest

from a2agw.ops.audit import AuditLog, canonical_json
from a2agw.serve.store import create_engine
from a2agw.vsc.receipt import build_receipt, export_receipt, verify_receipt
from a2agw.vsc.store import VscStore

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
    receipt = await build_receipt(env.store, env.audit, job_id)
    return env, job_id, receipt


async def test_receipt_hash_covers_everything(built):
    env, job_id, receipt = built
    assert receipt["version"] == "a2agw.receipt/1"
    assert receipt["job_id"] == job_id and receipt["state"] == "accepted"
    assert verify_receipt(receipt) == []
    attempts = [s for s in receipt["steps"]]
    assert [(s["step_id"], s["attempt"]) for s in attempts] == [("edit-alpha", 1), ("edit-beta", 1)]
    assert all(len(s["diff_sha256"]) == 64 and s["checks"] for s in attempts)
    assert receipt["audit"]["rows"] and receipt["tasks"] == []  # no A2A task drove it
    # whole-system results: the command, exit code and log hash, citing their audit row
    (whole,) = receipt["whole_checks"]
    assert whole["exit_code"] == 0 and whole["command"] and len(whole["log_sha256"]) == 64
    assert isinstance(whole["audit_seq"], int)
    assert set(receipt["base_refs"]) == set(receipt["verified_heads"]) == {"repo-a", "repo-b"}
    assert receipt["verified_heads"]["repo-a"] == receipt["steps"][0]["commit"]
    for key in ("spec", "plan", "usage", "approvals", "created_at", "audit"):
        tampered = copy.deepcopy(receipt)
        tampered[key] = "x" if key != "audit" else {**tampered[key], "last_seq": 10**6}
        assert verify_receipt(tampered), key
    stored = await env.store.get_receipt(job_id)
    assert stored["receipt"] == receipt and stored["receipt_hash"] == receipt["receipt_hash"]
    again = await build_receipt(env.store, env.audit, job_id)
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


async def _two_jobs(env):
    cfg = two_repo_cfg(env.tmp, run=[sys.executable, "-c", "pass"])
    r1 = env.runner(cfg, FixedPlanner([edit("alpha")]), [worker("apply")])
    r2 = env.runner(cfg, FixedPlanner([edit("beta")]), [worker("apply")])
    j1 = await r1.submit("greet alpha systems: alpha", owner="key:a")
    j2 = await r2.submit("greet beta systems: beta", owner="key:b")
    await asyncio.gather(r1.run(j1), r2.run(j2))
    assert await env.state(j1) == "accepted" and await env.state(j2) == "accepted"
    return j1, j2


async def test_interleaved_jobs_both_verify_and_hide_foreign_rows(env):
    j1, j2 = await _two_jobs(env)
    r1 = await build_receipt(env.store, env.audit, j1)
    r2 = await build_receipt(env.store, env.audit, j2)  # appended a vsc.receipt for j1 first
    for mine, other, receipt in ((j1, j2, r1), (j2, j1, r2)):
        assert verify_receipt(receipt) == []
        rows = receipt["audit"]["rows"]
        stubs = [r for r in rows if set(r) == {"seq", "prev_hash", "hash"}]
        assert stubs, "the other job's rows must be interleaved for this test to mean anything"
        assert all(r.get("task_id") == mine for r in rows if "task_id" in r)
        assert other not in json.dumps(receipt)
    # a tampered stub hash breaks the chain
    bad = copy.deepcopy(r1)
    stub = next(r for r in bad["audit"]["rows"] if set(r) == {"seq", "prev_hash", "hash"})
    stub["hash"] = "0" * 64
    body = {k: v for k, v in bad.items() if k != "receipt_hash"}
    bad["receipt_hash"] = hashlib.sha256(canonical_json(body).encode()).hexdigest()
    assert any("audit" in p for p in verify_receipt(bad))


async def test_unfinished_job_refused(env):
    cfg = two_repo_cfg(env.tmp)
    runner = env.runner(cfg, FixedPlanner([edit("alpha")]), [worker("apply")])
    job_id = await runner.submit("greet alpha systems: alpha", owner="key:a")
    await env.store.set_state(job_id, "running")
    with pytest.raises(ValueError, match="not finished"):
        await build_receipt(env.store, env.audit, job_id)
    assert await env.store.get_receipt(job_id) is None


async def test_concurrent_builds_append_one_receipt_row(env):
    j1, _ = await _two_jobs(env)
    built = await asyncio.gather(*(build_receipt(env.store, env.audit, j1) for _ in range(4)))
    assert all(r == built[0] for r in built)
    rows, _ = await env.audit.query({"action": "vsc.receipt"}, 50, ascending=True)
    assert [r["task_id"] for r in rows] == [j1]


async def test_non_dict_audit_row_is_a_problem(built):
    _, _, receipt = built
    bad = copy.deepcopy(receipt)
    bad["audit"]["rows"][1] = "garbage"
    assert any("audit" in p for p in verify_receipt(bad))
    empty = copy.deepcopy(receipt)
    empty["audit"]["rows"] = []
    verify_receipt(empty)  # no crash


def _reseal(r: dict) -> dict:
    body = {k: v for k, v in r.items() if k != "receipt_hash"}
    r["receipt_hash"] = hashlib.sha256(canonical_json(body).encode()).hexdigest()
    return r


async def test_stubbed_job_row_is_rejected(built):
    _, _, receipt = built
    forged = copy.deepcopy(receipt)
    rows = forged["audit"]["rows"]
    i = next(i for i, r in enumerate(rows) if r.get("action") == "vsc.check")
    seq = rows[i]["seq"]
    rows[i] = {k: rows[i][k] for k in ("seq", "prev_hash", "hash")}  # chain still links
    problems = verify_receipt(_reseal(forged))
    assert any(str(seq) in p for p in problems), problems
    # dropping the seq from job_seqs and the count does not help: the claims still cite it
    forged["audit"]["job_seqs"].remove(seq)
    forged["audit"]["job_rows"] -= 1
    assert any(str(seq) in p for p in verify_receipt(_reseal(forged)))


async def test_cited_seqs_are_full_rows(built):
    _, _, receipt = built
    audit = receipt["audit"]
    full = {r["seq"] for r in audit["rows"] if "task_id" in r}
    cited = [s["audit_seq"] for s in receipt["steps"]]
    cited += [c["audit_seq"] for s in receipt["steps"] for c in s["checks"]]
    cited += [a["audit_seq"] for a in receipt["approvals"] if "audit_seq" in a]
    cited += [c["audit_seq"] for c in receipt["whole_checks"]]
    assert cited and all(isinstance(c, int) for c in cited)
    assert set(cited) <= set(audit["job_seqs"]) <= full
    assert audit["job_rows"] == len(audit["job_seqs"]) == len(full)


async def test_hidden_extra_job_row_is_rejected(built):
    _, _, receipt = built
    forged = copy.deepcopy(receipt)
    forged["audit"]["job_seqs"].pop()
    forged["audit"]["job_rows"] -= 1
    assert any("job_seqs" in p for p in verify_receipt(_reseal(forged)))


async def test_receipt_lists_tasks_planner_turns_and_auto_approvals(env):
    from a2agw.vsc.config import AutoApprove
    from a2agw.vsc.plan import PlanStep

    cfg = two_repo_cfg(env.tmp).model_copy(
        update={
            "auto_approve": [AutoApprove(system="alpha", action="merge", target_branch="main")]
        }
    )

    class TurnPlanner(FixedPlanner):
        def turns(self):
            turn = {"task_id": "planner-task-1", "tokens_in": 3, "tokens_out": 4, "cost": 0.5}
            return [turn] * self.intakes

    merge = PlanStep(
        id="merge-alpha",
        system="alpha",
        kind="merge",
        target_branch="main",
        depends_on=["edit-alpha"],
        instructions="m",
    )
    runner = env.runner(cfg, TurnPlanner([edit("alpha"), edit("beta"), merge]), [worker("apply")])
    job_id = await runner.submit("greet  systems: alpha, beta", owner="key:a")
    await env.store.set_task(job_id, "task-1")
    await env.store.set_task(job_id, "task-2")
    job = await runner.run(job_id)
    assert job["state"] == "accepted", job
    receipt = await build_receipt(env.store, env.audit, job_id)
    assert verify_receipt(receipt) == []
    assert receipt["tasks"] == ["task-1", "task-2"]
    (turn,) = receipt["planner"]
    assert turn["task_id"] == "planner-task-1" and turn["tokens_out"] == 4
    assert isinstance(turn["audit_seq"], int)
    assert receipt["spec"]["request"] == "greet  systems: alpha, beta"
    (auto,) = receipt["approvals"]
    assert (auto["actor"], auto["auto"], auto["outcome"]) == ("policy", True, "approved")
    assert isinstance(auto["audit_seq"], int)
    merged = next(s for s in receipt["steps"] if s["step_id"] == "merge-alpha")
    assert merged["verified_head"] == merged["head"] == receipt["verified_heads"]["repo-a"]
    assert merged["target_branch"] == "main"


async def test_verify_receipt_survives_unhashable_and_missing_seqs(built):
    _, _, receipt = built
    weird = copy.deepcopy(receipt)
    weird["audit"]["job_seqs"].append({"x": 1})
    weird["steps"][0]["audit_seq"] = [1]
    problems = verify_receipt(_reseal(weird))  # no TypeError
    assert any("not integers" in p for p in problems)
    missing = copy.deepcopy(receipt)
    missing["steps"][0]["audit_seq"] = None
    assert any("cites no row" in p for p in verify_receipt(_reseal(missing)))
    approval = copy.deepcopy(receipt)
    approval["approvals"] = [{"step": "s", "auto": False, "audit_seq": None}]
    assert any("cites no row" in p for p in verify_receipt(_reseal(approval)))
