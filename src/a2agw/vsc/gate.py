"""The approval gate: privileged steps (merge, deploy, migrate, send) pause for a human unless
policy auto-approves them. Decisions are audited (``vsc.approve``), so a resumed job finds an
earlier approval in the log instead of asking again; a policy approval is audited too (outcome
``auto``, actor ``policy``).

Who may approve (``approval_refusal``): an admin always; otherwise, when ``vsc.approvers`` is
set, only a listed principal; when it is empty, anyone but the job's owner unless
``vsc.allow_self_approval``. Rejecting is open to the owner too (it only stops the job)."""

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


class NotApprover(PermissionError):
    """The principal may not approve this job's privileged steps."""


def approval_refusal(cfg: VscConfig, actor: str, owner: str, *, admin: bool = False) -> str | None:
    """Why ``actor`` may not approve a privileged step of a job owned by ``owner``; None if
    they may."""
    if admin:
        return None
    if cfg.approvers:
        return None if actor in cfg.approvers else "not an approver"
    if actor == owner and not cfg.allow_self_approval:
        return "the job's owner may not approve its own privileged steps"
    return None


class Rejected(Exception):
    def __init__(self, note: str = "") -> None:
        super().__init__(note)
        self.note = note


class GateNotified(Exception):
    """The wait announcement (``on_wait``) failed; every waiter on the step fails loudly."""


@dataclass(frozen=True)
class Approval:
    actor: str
    auto: bool
    note: str = ""


def _retrieve(fut: asyncio.Future) -> None:
    if not fut.cancelled():
        fut.exception()  # mark retrieved: no "never retrieved" noise


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
        self._counts: dict[tuple[str, str], int] = {}

    async def wait(self, job_id: str, step: PlanStep) -> Approval:
        if step.kind not in PRIVILEGED_KINDS:
            return Approval(actor="none", auto=True)
        if self._cfg.auto_approved(step.system, step.kind, step.target_branch):
            await self._audit_auto(job_id, step)
            return Approval(actor="policy", auto=True)
        key = (job_id, step.id)
        done = self._decided.get(key)
        if done is None:  # memory is authoritative once set; the log serves a resume
            done = await self._latest_from_audit(job_id, step.id)
        if done is None:
            done = await self._wait_decision(key, job_id, step)
        if isinstance(done, Rejected):
            raise Rejected(done.note)
        return done

    async def _wait_decision(
        self, key: tuple[str, str], job_id: str, step: PlanStep
    ) -> Approval | Rejected:
        fut = self._waiters.get(key)
        first = fut is None
        if fut is None:  # the first waiter announces; later ones just wait
            fut = asyncio.get_running_loop().create_future()
            fut.add_done_callback(_retrieve)
            self._waiters[key] = fut
        self._counts[key] = self._counts.get(key, 0) + 1
        try:
            if first and self._on_wait is not None:
                try:
                    await self._on_wait(job_id, step)
                except asyncio.CancelledError:
                    # Others may still wait on fut: leave it registered so a later decision
                    # resolves them (the finally below drops it if nobody is left).
                    raise
                except Exception as exc:
                    if not fut.done():
                        err = GateNotified(f"wait announcement failed: {exc!r}")
                        err.__cause__ = exc
                        fut.set_exception(err)
                    raise
            decided = self._decided.get(key)  # decided while on_wait ran
            if decided is not None:
                return decided
            return await asyncio.shield(fut)
        finally:
            self._counts[key] -= 1
            if self._counts[key] <= 0:
                del self._counts[key]
                if self._waiters.get(key) is fut:
                    del self._waiters[key]
            elif fut.done() and self._waiters.get(key) is fut:
                del self._waiters[key]

    async def _audit_auto(self, job_id: str, step: PlanStep) -> None:
        if self._audit is None:
            return
        detail: dict[str, str] = {"step": step.id, "note": "", "kind": step.kind}
        if step.target_branch is not None:
            detail["target_branch"] = step.target_branch
        await self._audit.emit(
            AuditEvent(
                actor="policy",
                action="vsc.approve",
                agent_id=_AGENT,
                task_id=job_id,
                outcome="auto",
                detail=detail,
            )
        )

    async def approve(
        self,
        job_id: str,
        step_id: str,
        *,
        actor: str,
        note: str = "",
        owner: str | None = None,
        admin: bool = False,
    ) -> None:
        """Approve the step as ``actor``. Given the job's ``owner``, the approver rules apply
        (``approval_refusal``; NotApprover). Every gateway entry point passes it."""
        if owner is not None:
            why = approval_refusal(self._cfg, actor, owner, admin=admin)
            if why is not None:
                raise NotApprover(why)
        await self._decide(job_id, step_id, actor, note, "approved")

    async def reject(self, job_id: str, step_id: str, *, actor: str, note: str) -> None:
        await self._decide(job_id, step_id, actor, note, "rejected")

    async def already_approved(self, job_id: str, step_id: str) -> bool:
        d = self._decided.get((job_id, step_id))
        if d is None:
            d = await self._latest_from_audit(job_id, step_id)
        return isinstance(d, Approval)

    async def _decide(self, job_id: str, step_id: str, actor: str, note: str, outcome: str) -> None:
        if not step_id:
            raise ValueError("step_id must not be empty")
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

    async def _latest_from_audit(self, job_id: str, step_id: str) -> Approval | Rejected | None:
        """The most recent decision (highest seq) for this job and step, or None."""
        if self._audit is None:
            return None
        latest: Approval | Rejected | None = None
        cursor: str | None = None
        while True:
            rows, cursor = await self._audit.query(
                {"action": "vsc.approve", "agent": _AGENT}, _PAGE, cursor, ascending=True
            )
            for r in rows:
                if r["task_id"] != job_id or r["detail"].get("step") != step_id:
                    continue
                note = r["detail"].get("note", "")
                if r["outcome"] == "approved":
                    latest = Approval(actor=r["actor"], auto=False, note=note)
                elif r["outcome"] == "rejected":
                    latest = Rejected(note)
            if cursor is None:
                return latest
