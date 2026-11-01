"""The approval gate: privileged steps (merge, deploy, migrate, send) pause for a human unless
policy auto-approves them. Decisions are audited (``vsc.approve``), so a resumed job finds an
earlier approval in the log instead of asking again."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from a2agw.ops.audit import AuditEvent, AuditLog
from a2agw.vsc.config import VscConfig
from a2agw.vsc.plan import PRIVILEGED_KINDS, PlanStep

NOTE_MAX_CHARS = 256
_AGENT = "deliver"
_PAGE = 200


class Rejected(Exception):
    def __init__(self, note: str = "") -> None:
        super().__init__(note)
        self.note = note


@dataclass(frozen=True)
class Approval:
    actor: str
    auto: bool
    note: str = ""


class Gate:
    def __init__(
        self,
        cfg: VscConfig,
        audit: AuditLog | None,
        *,
        on_wait: Callable[[str, PlanStep], Awaitable[None]] | None = None,
    ) -> None:
        self._cfg = cfg
        self._audit = audit
        self._on_wait = on_wait
        # (job_id, step_id) -> decision; waiters block on the matching future.
        self._decided: dict[tuple[str, str], Approval | Rejected] = {}
        self._waiters: dict[tuple[str, str], asyncio.Future[Approval | Rejected]] = {}

    async def wait(self, job_id: str, step: PlanStep) -> Approval:
        if step.kind not in PRIVILEGED_KINDS:
            return Approval(actor="none", auto=True)
        if any(a.system == step.system and a.action == step.kind for a in self._cfg.auto_approve):
            return Approval(actor="policy", auto=True)
        key = (job_id, step.id)
        done = self._decided.get(key) or await self._from_audit(job_id, step.id)
        if done is None:
            if self._on_wait is not None:
                await self._on_wait(job_id, step)
            done = self._decided.get(key)  # decided while on_wait ran
            if done is None:
                fut = self._waiters.setdefault(key, asyncio.get_running_loop().create_future())
                try:
                    done = await asyncio.shield(fut)
                finally:
                    if fut.done():
                        self._waiters.pop(key, None)
        if isinstance(done, Rejected):
            raise done
        return done

    async def approve(self, job_id: str, step_id: str, *, actor: str, note: str = "") -> None:
        await self._decide(job_id, step_id, actor, note, "approved")

    async def reject(self, job_id: str, step_id: str, *, actor: str, note: str) -> None:
        await self._decide(job_id, step_id, actor, note, "rejected")

    async def already_approved(self, job_id: str, step_id: str) -> bool:
        d = self._decided.get((job_id, step_id))
        if isinstance(d, Approval):
            return True
        return await self._from_audit(job_id, step_id) is not None

    async def _decide(self, job_id: str, step_id: str, actor: str, note: str, outcome: str) -> None:
        note = note[:NOTE_MAX_CHARS]
        if self._audit is not None:
            await self._audit.emit(
                AuditEvent(
                    actor=actor,
                    action="vsc.approve",
                    agent_id=_AGENT,
                    task_id=job_id,
                    outcome=outcome,
                    detail={"step": step_id, "note": note},
                )
            )
        key = (job_id, step_id)
        result: Approval | Rejected = (
            Approval(actor=actor, auto=False, note=note) if outcome == "approved" else Rejected(note)
        )
        self._decided[key] = result
        fut = self._waiters.get(key)
        if fut is not None and not fut.done():
            fut.set_result(result)

    async def _from_audit(self, job_id: str, step_id: str) -> Approval | None:
        if self._audit is None:
            return None
        cursor: str | None = None
        while True:
            rows, cursor = await self._audit.query(
                {"action": "vsc.approve", "agent": _AGENT}, _PAGE, cursor, ascending=True
            )
            for r in rows:
                if (
                    r["task_id"] == job_id
                    and r["outcome"] == "approved"
                    and r["detail"].get("step") == step_id
                ):
                    return Approval(actor=r["actor"], auto=False, note=r["detail"].get("note", ""))
            if cursor is None:
                return None
