"""The approval gate: policy auto-approve, wait/approve/reject, resume from the audit log."""

from __future__ import annotations

import asyncio

import pytest

from a2agw.ops.audit import AuditLog
from a2agw.serve.store import create_engine
from a2agw.vsc.config import AutoApprove, VscConfig
from a2agw.vsc.gate import Approval, Gate, Rejected
from a2agw.vsc.plan import PlanStep


def cfg(*auto: AutoApprove) -> VscConfig:
    return VscConfig.model_construct(auto_approve=list(auto))


def step(kind: str = "deploy", system: str = "prod", sid: str = "s1") -> PlanStep:
    kw = {"target_branch": "main"} if kind == "merge" else {}
    return PlanStep(id=sid, system=system, kind=kind, instructions="x", **kw)


@pytest.fixture
async def audit(tmp_path):
    engine = await create_engine(f"sqlite+aiosqlite:///{tmp_path / 'a.db'}")
    log = AuditLog(engine)
    await log.initialize()
    try:
        yield log
    finally:
        await engine.dispose()


async def test_auto_approve_matches_system_and_action():
    g = Gate(cfg(AutoApprove(system="prod", action="deploy")), None)
    assert await g.wait("j", step()) == Approval(actor="policy", auto=True, note="")
    # a different system or action is not covered, so it waits
    t = asyncio.create_task(g.wait("j", step("migrate")))
    t2 = asyncio.create_task(g.wait("j", step(system="other", sid="s2")))
    await asyncio.sleep(0.05)
    assert not t.done() and not t2.done()
    t.cancel()
    t2.cancel()


async def test_wait_until_approve(audit):
    waited: list[str] = []

    async def on_wait(job_id, st):
        waited.append(f"{job_id}/{st.id}")

    g = Gate(cfg(), audit, on_wait=on_wait)
    t = asyncio.create_task(g.wait("j", step()))
    await asyncio.sleep(0.05)
    assert not t.done() and waited == ["j/s1"]
    await g.approve("j", "s1", actor="alice", note="lgtm")
    a = await asyncio.wait_for(t, 2)
    assert a == Approval(actor="alice", auto=False, note="lgtm")
    rows, _ = await audit.query({"action": "vsc.approve"})
    assert rows[0]["outcome"] == "approved" and rows[0]["task_id"] == "j"
    assert rows[0]["detail"]["step"] == "s1"


async def test_reject_raises(audit):
    g = Gate(cfg(), audit)
    t = asyncio.create_task(g.wait("j", step()))
    await asyncio.sleep(0.05)
    await g.reject("j", "s1", actor="bob", note="not today")
    with pytest.raises(Rejected, match="not today"):
        await asyncio.wait_for(t, 2)
    assert not await g.already_approved("j", "s1")


async def test_already_approved_from_audit(audit):
    await Gate(cfg(), audit).approve("j", "s1", actor="alice")
    g2 = Gate(cfg(), audit)  # a fresh process resuming the job
    assert await g2.already_approved("j", "s1")
    assert not await g2.already_approved("j", "s2")
    assert not await g2.already_approved("other", "s1")
    assert await asyncio.wait_for(g2.wait("j", step()), 2) == Approval("alice", False, "")


async def test_edit_steps_never_gate(audit):
    g = Gate(cfg(), audit)
    a = await asyncio.wait_for(g.wait("j", step("edit")), 2)
    assert a == Approval(actor="none", auto=True, note="")
    rows, _ = await audit.query({"action": "vsc.approve"})
    assert rows == []
