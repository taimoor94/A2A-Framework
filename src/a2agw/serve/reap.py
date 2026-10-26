"""Reaping the open tasks of an agent that no gateway serves any more.

Destructive, and on a shared database it could hit a live peer gateway, so it is guarded:
the agent must not be served by the caller's gateway, nothing happens without ``confirm``
(the call is a dry run that counts what would be reaped), rows touched within
``REAP_MIN_IDLE_S`` are refused unless ``force``, and every attempt appends a ``task.reap``
audit row (``outcome`` reaped / refused / failed, ``detail.count``, ``detail.reason``).
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from a2agw.ops.audit import AuditEvent, AuditLog
from a2agw.serve.store import (
    _ACTIVE_STATES,
    _TERMINAL_STATES,
    OutboundHandleStore,
    RecoveryReport,
    TaskIndex,
    reap_tasks,
)

if TYPE_CHECKING:
    from a2agw.consult.client import PartnerClient
    from a2agw.consult.handles import OutboundHandleStore as HandleStore

REAP_MIN_IDLE_S = 600.0


class ReapRefused(Exception):
    def __init__(self, reason: str, count: int = 0) -> None:
        super().__init__(reason)
        self.reason = reason
        self.count = count


class AgentServedError(ReapRefused, ValueError):
    """The agent is served by the calling gateway, so its tasks must not be reaped."""

    def __init__(self, message: str = "agent is served by this gateway") -> None:
        ReapRefused.__init__(self, "served", 0)
        self.args = (message,)


class RecentActivityError(ReapRefused):
    """Some target tasks changed within ``REAP_MIN_IDLE_S``: a live gateway may own them."""

    def __init__(self, count: int) -> None:
        super().__init__("recent", count)


@dataclass
class ReapResult:
    dry_run: bool
    tasks: int  # open index rows of the agent
    handles: int  # their non-terminal outbound partner tasks
    recent: int  # rows touched within REAP_MIN_IDLE_S
    report: RecoveryReport | None = None


def make_cancel_outbound(client: PartnerClient) -> Callable[[dict[str, Any]], Awaitable[None]]:
    """Cancel one recorded partner task as the caller it was started for (a maintenance
    call); raise unless the partner reports it canceled."""
    from a2agw.context.call_context import use_maintenance
    from a2agw.security.principal import Principal

    async def cancel(handle: dict[str, Any]) -> None:
        caller_id = handle.get("caller_id")
        caller = Principal.from_id(caller_id) if caller_id else None
        with use_maintenance():
            result = await client.cancel(handle["partner_id"], handle["task_id"], caller=caller)
        if result.state != "canceled":
            raise RuntimeError("not canceled")

    return cancel


async def reap_agent(
    index: TaskIndex,
    handles: OutboundHandleStore | None,
    cancel_outbound: Callable[..., Awaitable[object]] | None,
    audit: AuditLog | None,
    agent_id: str,
    *,
    served: set[str],
    confirm: bool = False,
    force: bool = False,
    actor: str = "system",
    cancel_timeout_s: float = 60.0,
) -> ReapResult:
    async def record(outcome: str, count: int, reason: str | None = None) -> None:
        if audit is not None:
            detail: dict[str, Any] = {"count": count}
            if reason is not None:
                detail["reason"] = reason
            await audit.emit(
                AuditEvent(
                    actor=actor,
                    action="task.reap",
                    agent_id=agent_id,
                    outcome=outcome,
                    detail=detail,
                )
            )

    if agent_id in served:
        await record("refused", 0, "served")
        raise AgentServedError
    try:
        now = time.time()
        rows = [r for r in await index.by_state(_ACTIVE_STATES) if r["agent_id"] == agent_id]
        recent = sum(1 for r in rows if now - r["updated_at"] < REAP_MIN_IDLE_S)
        open_handles = 0
        if handles is not None:
            for r in rows:
                open_handles += sum(
                    1
                    for h in await handles.by_inbound(r["task_id"])
                    if h.get("state") not in _TERMINAL_STATES
                )
    except Exception:
        await record("failed", 0)
        raise
    if not confirm:
        await record("refused", len(rows), "not_confirmed")
        return ReapResult(True, len(rows), open_handles, recent)
    if recent and not force:
        await record("refused", recent, "recent")
        raise RecentActivityError(recent)
    try:
        report = await reap_tasks(
            index, handles, cancel_outbound, agent_id, cancel_timeout_s=cancel_timeout_s
        )
    except Exception:
        await record("failed", len(rows))
        raise
    await record("reaped" if not report.errors else "failed", len(report.failed))
    return ReapResult(False, len(rows), open_handles, recent, report)


OUTBOUND_TTL_S = 86400.0
TTL_REASON = "ttl expired"
_CANCELED = "TASK_STATE_CANCELED"


@dataclass
class ExpireReport:
    expired: int = 0  # handles this gateway claimed and ended
    cancel_failed: int = 0  # of those, partner tasks that could not be confirmed canceled


async def expire_outbound(
    handles: HandleStore,
    cancel_outbound: Callable[[dict[str, Any]], Awaitable[object]] | None,
    audit: AuditLog | None,
    *,
    ttl_s: float = OUTBOUND_TTL_S,
    now: float | None = None,
    limit: int = 100,
    cancel_timeout_s: float = 30.0,
    actor: str = "system",
) -> ExpireReport:
    """Spec 8.2: end every non-terminal outbound handle older than ``ttl_s``.

    Each handle is first claimed with a compare-and-set (``OutboundHandleStore.claim_end``):
    it becomes ``TASK_STATE_CANCELED`` with ``end_reason`` "ttl expired", and only the gateway
    whose update matched goes on, so gateways sharing a database never expire one handle
    twice. The partner task is then cancelled best-effort, as the caller it was started for,
    and an ``outbound.expire`` audit row records the outcome (``canceled`` or
    ``cancel_failed``). An already-terminal handle is never selected."""
    report = ExpireReport()
    cutoff = (time.time() if now is None else now) - ttl_s
    for h in await handles.older_than(cutoff, limit=limit):
        claimed = await handles.claim_end(
            h["partner_id"], h["task_id"], h["state"], _CANCELED, TTL_REASON
        )
        if not claimed:
            continue  # another gateway, or a fresh partner update, got there first
        report.expired += 1
        outcome = "canceled"
        if cancel_outbound is not None:
            try:
                async with asyncio.timeout(cancel_timeout_s):
                    await cancel_outbound(h)
            except Exception:  # noqa: BLE001 - best effort; the handle stays ended
                outcome = "cancel_failed"
                report.cancel_failed += 1
        if audit is not None:
            await audit.emit(
                AuditEvent(
                    actor=actor,
                    action="outbound.expire",
                    partner_id=h["partner_id"],
                    task_id=h["task_id"],
                    outcome=outcome,
                    detail={"reason": TTL_REASON},
                )
            )
    return report
