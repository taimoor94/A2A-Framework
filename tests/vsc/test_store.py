from __future__ import annotations

from a2agw.serve.store import create_engine
from a2agw.vsc.config import BudgetConfig
from a2agw.vsc.spec import ExecutableSpec, spec_hash
from a2agw.vsc.store import VscStore


async def make(db_url):
    eng = await create_engine(db_url)
    store = VscStore(eng)
    await store.initialize()
    return eng, store


def step(i: str, system: str = "core") -> dict:
    return {"id": i, "system": system, "kind": "change"}


async def test_job_roundtrip(db_url):
    eng, store = await make(db_url)
    try:
        await store.initialize()  # idempotent
        assert await store.get_job("j1") is None
        await store.create_job("j1", "do it", "key:a")
        job = await store.get_job("j1")
        assert job["state"] == "submitted"
        assert job["request"] == "do it" and job["owner"] == "key:a"
        assert job["attempts"] == 0 and job["tokens_in"] == 0
        await store.set_state("j1", "failed", reason="boom")
        await store.set_task("j1", "t-9")
        await store.set_plan("j1", {"steps": [1]}, "ph")
        spec = ExecutableSpec(
            request="r",
            done="d",
            systems=["core"],
            acceptance=[{"id": "a1", "system": "core"}],
            budgets=BudgetConfig(),
        )
        await store.set_spec("j1", spec)
        job = await store.get_job("j1")
        assert (job["state"], job["reason"], job["current_task_id"]) == ("failed", "boom", "t-9")
        assert job["plan_hash"] == "ph" and '"steps"' in job["plan_json"]
        assert job["spec_hash"] == spec_hash(spec)
        assert ExecutableSpec.model_validate_json(job["spec_json"]) == spec
        assert job["updated_at"] >= job["created_at"]
        await store.create_job("j2", "x", "key:a")
        assert {j["job_id"] for j in await store.list_jobs()} == {"j1", "j2"}
        assert [j["job_id"] for j in await store.list_jobs(state="failed")] == ["j1"]
        assert len(await store.list_jobs(limit=1)) == 1
    finally:
        await eng.dispose()


async def test_steps_latest_attempt_per_step(db_url):
    eng, store = await make(db_url)
    try:
        await store.create_job("j", "r", "o")
        await store.add_step("j", step("b"), 1)
        await store.add_step("j", step("a"), 0)
        assert [s["step_id"] for s in await store.steps("j")] == ["a", "b"]
        assert (await store.steps("j"))[0]["state"] == "pending"
        await store.start_attempt("j", "a", 0, "w1", "/ws/1")
        await store.end_attempt("j", "a", 0, "failed", {"err": 1}, {"tokens": 5})
        await store.start_attempt("j", "a", 1, "w2", "/ws/2")
        rows = await store.steps("j")
        assert [(r["step_id"], r["attempt"], r["state"]) for r in rows] == [
            ("a", 1, "running"),
            ("b", 0, "pending"),
        ]
        assert rows[0]["worker"] == "w2" and rows[0]["seq"] == 0 and rows[0]["system"] == "core"
        await store.end_attempt("j", "a", 1, "passed", {"ok": True}, {"tokens": 7})
        a = (await store.steps("j"))[0]
        assert a["state"] == "passed" and '"ok"' in a["result_json"]
        assert a["ended_at"] >= a["started_at"]
    finally:
        await eng.dispose()


async def test_resumable_lists_running_only(db_url):
    eng, store = await make(db_url)
    try:
        for jid, st in [
            ("s", "submitted"),
            ("r", "running"),
            ("v", "verifying"),
            ("w", "awaiting_approval"),
            ("a", "accepted"),
            ("f", "failed"),
            ("c", "cancelled"),
            ("p", "planning"),
        ]:
            await store.create_job(jid, "r", "o")
            await store.set_state(jid, st)
        assert sorted(await store.resumable()) == ["r", "v", "w"]
    finally:
        await eng.dispose()


async def test_add_usage_accumulates(db_url):
    eng, store = await make(db_url)
    try:
        await store.create_job("j", "r", "o")
        await store.add_usage("j", 10, 5, 0.25)
        await store.add_usage("j", 1, 2, 0.5)
        job = await store.get_job("j")
        assert (job["tokens_in"], job["tokens_out"], job["cost"]) == (11, 7, 0.75)
    finally:
        await eng.dispose()


async def test_receipt_roundtrip(db_url):
    eng, store = await make(db_url)
    try:
        assert await store.get_receipt("j") is None
        await store.put_receipt("j", {"a": 1}, "h1", 4)
        got = await store.get_receipt("j")
        assert got["receipt"] == {"a": 1}
        assert (got["receipt_hash"], got["audit_seq"]) == ("h1", 4)
    finally:
        await eng.dispose()
