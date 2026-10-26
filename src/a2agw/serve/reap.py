"""Reaping the open tasks of an agent that no gateway serves any more.

Destructive, and on a shared database it could hit a live peer gateway, so it is guarded:
the agent must not be served by the caller's gateway, nothing happens without ``confirm``
(the call is a dry run that counts what would be reaped), rows touched within
``REAP_MIN_IDLE_S`` are refused unless ``force``, and every attempt appends a ``task.reap``
audit row (``outcome`` reaped / refused / failed, ``detail.count``, ``detail.reason``).
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Awaitable, Callable, Collection
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
    from a2a.server.tasks import TaskStore
    from a2a.types import Task

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
    store: TaskStore | None = None,
    on_failed: Callable[[str, Task], Awaitable[object]] | None = None,
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
            index,
            handles,
            cancel_outbound,
            agent_id,
            cancel_timeout_s=cancel_timeout_s,
            store=store,
            on_failed=on_failed,
        )
    except Exception:
        await record("failed", len(rows))
        raise
    await record("reaped" if not report.errors else "failed", len(report.failed))
    return ReapResult(False, len(rows), open_handles, recent, report)


OUTBOUND_TTL_S = 86400.0
TTL_REASON = "ttl expired"
CANCEL_FAILED_REASON = "cancel failed"  # ended by TTL, partner cancel not yet confirmed
CANCEL_MAX_ATTEMPTS = 3
CANCEL_CONCURRENCY = 8
_CANCELED = "TASK_STATE_CANCELED"


@dataclass
class ExpireReport:
    expired: int = 0  # handles this gateway claimed (ended, or retried a cancel for)
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
    partner_ids: Collection[str] | None = None,
    agent_ids: Collection[str] | None = None,
    concurrency: int | None = None,
    pass_deadline_s: float | None = None,
    owners: Collection[str] = (),
) -> ExpireReport:
    """Spec 8.2: end every non-terminal outbound handle older than ``ttl_s``.

    Scope: with ``partner_ids`` / ``agent_ids`` (``AgentHost.maintain`` passes its registry's
    partners and its own agents) only handles of known partners whose inbound task belongs
    to one of those agents are touched, so gateways sharing a database never cancel each
    other's partner tasks (and never with a partner record they do not have). A handle with
    no inbound task is touched only when its ``owner`` is one of ``owners`` (the host's
    sidecar agents, ``sidecar:<agent id>``).

    Each handle is first claimed with a compare-and-set (``OutboundHandleStore.claim_end``):
    it becomes ``TASK_STATE_CANCELED`` with ``end_reason`` "ttl expired", and only the gateway
    whose update matched goes on. The partner task is then cancelled, as the caller it was
    started for, and an ``outbound.expire`` audit row records the outcome (``canceled`` or
    ``cancel_failed``) and ``detail.attempt``. A failed cancel leaves ``end_reason`` "cancel
    failed": the handle stays ended for its partner updates, but later passes claim it again
    and retry the cancel, up to ``CANCEL_MAX_ATTEMPTS`` attempts in all. An already-terminal
    handle the partner reported is never selected.

    Cancels run concurrently, at most ``concurrency`` (``CANCEL_CONCURRENCY``) at once, each
    within ``cancel_timeout_s`` and all within ``pass_deadline_s`` (default: four cancel
    timeouts): handles not started by then are left unclaimed for the next pass."""
    report = ExpireReport()
    loop = asyncio.get_running_loop()
    deadline = loop.time() + (
        pass_deadline_s if pass_deadline_s is not None else 4 * cancel_timeout_s
    )
    cutoff = (time.time() if now is None else now) - ttl_s
    rows = await handles.older_than(
        cutoff,
        limit=limit,
        partner_ids=partner_ids,
        agent_ids=agent_ids,
        retry_reason=CANCEL_FAILED_REASON,
        max_attempts=CANCEL_MAX_ATTEMPTS,
        owners=owners,
    )
    gate = asyncio.Semaphore(concurrency or CANCEL_CONCURRENCY)

    async def one(h: dict[str, Any]) -> None:
        if partner_ids is not None and h["partner_id"] not in partner_ids:
            return  # never claim a handle of a partner this gateway cannot call
        async with gate:
            remaining = deadline - loop.time()
            if remaining <= 0:
                return  # out of time for this pass: leave it for the next one
            attempts = int(h.get("cancel_attempts") or 0)
            retry = h.get("end_reason") == CANCEL_FAILED_REASON
            claimed = await handles.claim_end(
                h["partner_id"],
                h["task_id"],
                h["state"],
                _CANCELED,
                TTL_REASON,
                seen_reason=CANCEL_FAILED_REASON if retry else None,
                seen_attempts=attempts,
            )
            if not claimed:
                return  # another gateway, or a fresh partner update, got there first
            attempt = attempts + 1
            report.expired += 1
            outcome = "canceled"
            if cancel_outbound is not None:
                try:
                    async with asyncio.timeout(min(cancel_timeout_s, remaining)):
                        await cancel_outbound(h)
                except Exception:  # noqa: BLE001 - retried by a later pass, up to the cap
                    outcome = "cancel_failed"
                    report.cancel_failed += 1
                    await handles.mark_end_reason(
                        h["partner_id"], h["task_id"], TTL_REASON, CANCEL_FAILED_REASON, attempt
                    )
                except BaseException:
                    # The pass itself was cancelled (host shutdown) mid-cancel: record the
                    # attempt as failed so a later pass retries it (within the cap).
                    with contextlib.suppress(Exception):
                        await asyncio.shield(
                            handles.mark_end_reason(
                                h["partner_id"],
                                h["task_id"],
                                TTL_REASON,
                                CANCEL_FAILED_REASON,
                                attempt,
                            )
                        )
                    raise
        if audit is not None:
            await audit.emit(
                AuditEvent(
                    actor=actor,
                    action="outbound.expire",
                    partner_id=h["partner_id"],
                    task_id=h["task_id"],
                    outcome=outcome,
                    detail={"reason": TTL_REASON, "attempt": attempt},
                )
            )

    await asyncio.gather(*(one(h) for h in rows))
    return report
