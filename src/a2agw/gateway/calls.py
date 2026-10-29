"""The sidecar call path shared by the outbound REST API (``a2agw.gateway.rest``) and the MCP
server (``a2agw.gateway.mcp_server``): one partner-tool call, made by a caller that
``a2agw.gateway.auth`` identified, behaves the same whichever API it came through.

``SidecarCalls`` (one per host, ``AgentHost.sidecar_calls``) runs each operation as the agent
the caller acts as:

- **Linked** (a consult token): under the inbound task's call context, caller and agent
  (``use_call``, ``use_inbound``, ``use_agent``), audited with the grant id, and tracked so
  revoking the token (the run ended) ends the call (``inbound task ended``).
- **Standalone**: a fresh root call context; a partner task it starts is owned by
  ``sidecar:<agent id>`` and its principal, which may have at most
  ``max_open_sidecar_tasks_per_caller`` of them open (``too many open tasks``).

Partner tasks belong to whoever started them (``owns``): checking, cancelling, waiting on or
replying to any other task answers ``unknown task``, exactly like one that does not exist, and
nothing reaches the partner. A partner the agent may not use answers ``unknown partner``.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from opentelemetry import context as otel_context

from a2agw.consult.tools import UNKNOWN_PARTNER, UNKNOWN_TASK, PartnerTool, invoke, rejection
from a2agw.context.call_context import (
    CallContext,
    use_agent,
    use_call,
    use_grant,
    use_inbound,
    use_inbound_token,
)
from a2agw.gateway.auth import SidecarAuthError, SidecarIdentity
from a2agw.ops.audit import AuditEvent
from a2agw.ops.telemetry import extract_parent

if TYPE_CHECKING:
    from a2agw.serve.host import AgentHost

__all__ = [
    "INBOUND_ENDED",
    "TOKEN_REVOKED",
    "TOO_MANY_OPEN",
    "UNKNOWN_PARTNER",
    "UNKNOWN_TASK",
    "SidecarCalls",
    "unknown",
]

TOO_MANY_OPEN = "too many open tasks"
INBOUND_ENDED = "inbound task ended"  # the consult token was revoked while the call ran
TOKEN_REVOKED = "consult token revoked"

FIND_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "need": {"type": "string", "maxLength": 4096},
        "k": {"type": "integer", "minimum": 1, "maximum": 10, "default": 5},
    },
    "required": ["need"],
    "additionalProperties": False,
}

Args = dict[str, Any]
Work = Callable[[], Awaitable[Any]]


def unknown(partner_id: str, reason: str = UNKNOWN_PARTNER) -> dict[str, Any]:
    return {"partner": partner_id, "state": "unavailable", "reason": reason}


@contextmanager
def _acting_as(ident: SidecarIdentity, grant_id: str | None) -> Iterator[None]:
    """The context an embedded agent's tool call would run in: its call context, inbound
    task, caller and agent id. A standalone call is a fresh root with no inbound task. A
    linked call's partner calls are audited with ``grant_id``, and continue the turn's trace
    (the binding's traceparent is the turn's inbound span, see ``GrantIssuer``)."""
    b = ident.binding
    parent = None
    if b is not None:
        call = b.call or CallContext.new(ident.agent_id)
        task_id, principal = b.inbound_task_id, b.caller
        parent = extract_parent(call.traceparent)
    else:
        call, task_id, principal = CallContext.new(ident.agent_id), None, ident.principal
    attached = otel_context.attach(parent) if parent is not None else None
    try:
        with (
            use_call(call),
            use_inbound(task_id, principal),
            use_inbound_token(None),
            use_agent(ident.agent_id),
            use_grant(grant_id),
        ):
            yield
    finally:
        if attached is not None:
            otel_context.detach(attached)


@dataclass
class _Open:
    """In-process bookkeeping of one (owner, caller)'s standalone consults."""

    pending: int = 0  # consults past the cap check and not finished yet
    finished: int = 0  # consults finished so far (only ever grows)
    counting: int = 0  # cap checks reading the handle store right now


class SidecarCalls:
    """The sidecar operations of one host (see the module docstring)."""

    def __init__(self, host: AgentHost) -> None:
        self.host = host
        self._open: dict[tuple[str, str], _Open] = {}

    def tools(self, ident: SidecarIdentity) -> list[PartnerTool]:
        """The partner tools of the agent the caller acts as (routing policy applied)."""
        return self.host.partner_tools(ident.agent_id)

    def visible(self, tools: list[PartnerTool]) -> set[str]:
        """The partner ids ``tools`` can reach."""
        for t in tools:
            if t.kind in ("find", "consult_any"):
                active = {r.id for r in self.host.partners.active()}
                return active if t.allowed is None else active & t.allowed
        return {t.partner_id for t in tools if t.kind == "consult" and t.partner_id}

    async def run(self, ident: SidecarIdentity, tool: PartnerTool, args: Any) -> dict[str, Any]:
        """``invoke`` the tool as the caller (the context is set by ``call``)."""
        host = self.host
        assert host.client is not None
        b = ident.binding
        return await invoke(
            tool,
            args,
            host.client,
            b.inbound_task_id if b is not None else None,
            ident.principal,
            owner=None if b is not None else host.sidecar_owner(ident.agent_id),
        )

    async def owns(self, ident: SidecarIdentity, pid: str, tid: str) -> bool:
        """Whether the caller may act on partner task ``tid``: tasks belong to whoever
        started them (``PartnerClient.owns``, the predicate embedded tool calls use too). A
        linked call owns the partner tasks of its inbound task; a standalone call owns the
        unlinked ones its agent id started for the same principal."""
        host = self.host
        b, p = ident.binding, ident.principal
        if host.client is None or (b is None and p is None):
            return False
        return await host.client.owns(
            pid,
            tid,
            inbound_task_id=b.inbound_task_id if b is not None else None,
            caller_id=p.id if p is not None else None,
            owner=None if b is not None else host.sidecar_owner(ident.agent_id),
        )

    @asynccontextmanager
    async def _open_slot(self, ident: SidecarIdentity, pid: str) -> AsyncIterator[bool]:
        """Hold one of a standalone principal's open-task slots for a consult that may start
        a partner task; yields False (audited ``limit.exceeded``) when none is free.

        Hard within this process: the check counts the open tasks in the store, the
        consults still in flight (which may yet record one), and the consults that finished
        while the store was being read (whose task the read may have missed). Nothing is
        awaited between that check and taking the slot."""
        host = self.host
        p, cap = ident.principal, host.max_open_sidecar_tasks_per_caller
        if ident.binding is not None or host.handles is None or p is None:
            yield True
            return
        owner = host.sidecar_owner(ident.agent_id)
        key = (owner, p.id)
        st = self._open.setdefault(key, _Open())
        finished = st.finished
        st.counting += 1
        try:
            stored = await host.handles.count_open_unlinked(owner, p.id)
        except BaseException:
            st.counting -= 1
            self._forget(key, st)
            raise
        st.counting -= 1
        if stored + st.pending + (st.finished - finished) >= cap:
            self._forget(key, st)
            if host.audit is not None:
                await host.audit.emit(
                    AuditEvent(
                        actor=p.id,
                        action="limit.exceeded",
                        agent_id=ident.agent_id,
                        partner_id=pid,
                        outcome="unavailable",
                        detail={"limit": "max_open_sidecar_tasks_per_caller", "count": cap},
                    )
                )
            yield False
            return
        st.pending += 1
        try:
            yield True
        finally:
            st.pending -= 1
            st.finished += 1
            self._forget(key, st)

    def _forget(self, key: tuple[str, str], st: _Open) -> None:
        if st.pending == 0 and st.counting == 0 and self._open.get(key) is st:
            del self._open[key]

    async def call(self, ident: SidecarIdentity, partner: str | None, work: Work) -> Any:
        """Run ``work`` as the agent. A linked call is tracked: revoking its token (the run
        ended) cancels it, and it then answers ``unavailable``. Raises ``SidecarAuthError``
        (401, ``TOKEN_REVOKED``) if the token was revoked before the call started."""
        host = self.host
        b = ident.binding
        with _acting_as(ident, None if b is None else host.consult_tokens.grant_id(b)):
            if b is None:
                return await work()
            task = asyncio.ensure_future(work())
        with host.consult_tokens.track(b, task) as live:
            if not live:
                task.cancel()  # never started
                raise SidecarAuthError(
                    401, TOKEN_REVOKED, agent_id=ident.agent_id, principal=ident.principal
                )
            try:
                return await task
            except asyncio.CancelledError:
                this = asyncio.current_task()
                if this is not None and this.cancelling():
                    raise  # the request itself is being cancelled
        out: dict[str, Any] = {"state": "unavailable", "reason": INBOUND_ENDED}
        return out if partner is None else {"partner": partner, **out}

    # -- operations (run them with ``call``) -------------------------------------------

    def listing(self, ident: SidecarIdentity) -> list[dict[str, Any]]:
        return [
            {
                "name": t.name,
                "description": t.description,
                "parameters": t.parameters,
                "partner_id": t.partner_id,
                "kind": t.kind,
            }
            for t in self.tools(ident)
        ]

    async def consult(
        self, ident: SidecarIdentity, tool: PartnerTool, args: Any, pid: str
    ) -> dict[str, Any]:
        """Consult partner ``pid`` with ``tool`` (its ``consult`` tool, or ``consult_any``
        with ``partner_id`` in ``args``; the caller checked ``pid`` is visible). A reply
        (``task_id``) goes only into a task the caller owns (``invoke`` checks, with
        ``owns``); a new task needs a free standalone slot."""
        rejected = rejection(tool, args)
        if rejected is not None:
            return rejected
        if args.get("task_id") is not None:
            return await self.run(ident, tool, args)
        async with self._open_slot(ident, pid) as free:
            if not free:
                return unknown(pid, TOO_MANY_OPEN)
            return await self.run(ident, tool, args)

    async def task_op(
        self, ident: SidecarIdentity, tools: list[PartnerTool], kind: str, pid: str, tid: str
    ) -> dict[str, Any]:
        """``check`` or ``cancel`` partner task ``tid`` of ``pid``: ``invoke`` answers
        ``unknown partner`` for a partner the tools cannot reach and ``unknown task`` for a
        task the caller does not own (``owns``)."""
        tool = next(t for t in tools if t.kind == kind)
        return await self.run(ident, tool, {"partner_id": pid, "task_id": tid})

    async def wait(
        self, ident: SidecarIdentity, tools: list[PartnerTool], args: Any
    ) -> dict[str, Any]:
        """Wait on several partner tasks, every one of them the caller's. ``invoke`` checks
        the arguments first (at most 20 tasks), then looks each distinct task up once."""
        tool = next(t for t in tools if t.kind == "wait")
        return await self.run(ident, tool, args)

    async def find(
        self, ident: SidecarIdentity, tools: list[PartnerTool], args: Any
    ) -> dict[str, Any]:
        """Rank the visible partners for a need."""
        tool = next((t for t in tools if t.kind == "find"), None)
        if tool is None:  # few partners: no discovery tool, rank the visible ones
            tool = PartnerTool(
                "find_partners", "", FIND_SCHEMA, None, "find", frozenset(self.visible(tools))
            )
        return await self.run(ident, tool, args)
