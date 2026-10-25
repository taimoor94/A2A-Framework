"""Inbound bridge: runs an InboundAdapter behind the A2A SDK's AgentExecutor interface."""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from a2a.helpers import new_task_from_user_message, new_text_part
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.tasks import TaskUpdater
from a2a.types import Message, Part, TaskState
from google.protobuf.json_format import MessageToDict

from a2agw.context.call_context import (
    BudgetExceeded,
    CallContext,
    CallContextViolation,
    CycleDetected,
    DeadlineExceeded,
    HopLimitExceeded,
    use_call,
    use_inbound,
)
from a2agw.core.events import ArtifactChunk, Done, Failed, NeedAuth, NeedInput, Status, Usage
from a2agw.core.spi import InboundContext
from a2agw.ops.bus import EventBus, GatewayEvent
from a2agw.security.principal import Principal, PrincipalUser
from a2agw.serve.agent import AgentSpec
from a2agw.serve.store import TaskIndex

logger = logging.getLogger(__name__)

USAGE_KEY = "a2agw.usage"

_REASONS: dict[type[CallContextViolation], str] = {
    HopLimitExceeded: "hop limit exceeded",
    CycleDetected: "cycle detected",
    DeadlineExceeded: "deadline exceeded",
    BudgetExceeded: "budget exceeded",
}
_INVALID = "invalid call context"
_REENTRY = "re-entry"
_RESUMABLE = {TaskState.TASK_STATE_INPUT_REQUIRED, TaskState.TASK_STATE_AUTH_REQUIRED}
_TERMINAL = {
    TaskState.TASK_STATE_COMPLETED,
    TaskState.TASK_STATE_FAILED,
    TaskState.TASK_STATE_CANCELED,
    TaskState.TASK_STATE_REJECTED,
}
_CLOSED_MAX = 10_000  # remembered terminal/cancelled task ids (makes cancel() idempotent)


@dataclass
class _Run:
    """State of one execute() call: where to record changes, terminal flags, usage totals."""

    updater: TaskUpdater
    owner: str
    origin: str | None
    tokens_in: int = 0
    tokens_out: int = 0
    cost: float = 0.0
    usage_seen: bool = False
    last_state: int | None = None
    terminal: bool = False  # this run emitted a terminal state; later changes are ignored
    cancelled: bool = False  # cancel() claimed the task; only cancel() writes from now on
    # Serializes this run's index writes with cancel()'s, so an in-flight write never lands
    # after CANCELED.
    lock: asyncio.Lock = dataclasses.field(default_factory=asyncio.Lock)

    def usage_metadata(self) -> dict[str, Any] | None:
        if not self.usage_seen:
            return None
        return {
            USAGE_KEY: {
                "tokens_in": self.tokens_in,
                "tokens_out": self.tokens_out,
                "cost": self.cost,
            }
        }


def _caller(context: RequestContext) -> tuple[Principal | None, str]:
    user = context.call_context.user if context.call_context is not None else None
    if isinstance(user, PrincipalUser):
        return user.principal, user.user_name
    return None, "anonymous"


class AdapterExecutor(AgentExecutor):
    """Bridges the SDK's AgentExecutor to a framework-neutral InboundAdapter.

    Enforces call-context limits on admission, maps adapter events to A2A task updates, and
    records every state change in the task index and on the event bus.

    Each task reaches at most one terminal state. Once a run emits one, or cancel() claims
    the task, later state changes from that run are ignored, and cancel() on a terminal or
    already-cancelled task is a no-op (so ``on_cancel`` runs at most once per task).

    Re-entry: after the path-based cycle check, a new (not resumed) task for this agent with
    call-context origin O is rejected with "re-entry" when this agent already has another
    non-terminal task in O that is blocked downstream, i.e. has at least one non-terminal
    outbound partner task. This catches A -> P -> A even when P rewrites the path, while
    admitting parallel fan-out and diamond calls (PM -> arch -> sec, PM -> rev -> sec) to the
    same agent. Residual false positive: a shared agent that is itself waiting downstream
    (e.g. sec consulting a partner while the second diamond branch reaches it) rejects the
    second call. ``AgentSpec.allow_reentry`` disables the check. Two false-negative windows
    remain: admission is not atomic (two entries arriving at the same instant are both
    checked before either is recorded), and a partner that calls back before the caller has
    recorded its outbound handle (written when the partner's first response arrives) does
    not yet see the caller as blocked downstream.

    Known limits (Phase 1):
    - An ``ArtifactChunk`` with ``append=True`` for an unknown ``artifact_id`` is rejected by
      the SDK's event consumer, after the executor has enqueued it; the executor cannot
      observe that failure.
    - The call-context deadline is checked on admission only; it is not enforced while the
      adapter runs.
    """

    def __init__(
        self,
        spec: AgentSpec,
        index: TaskIndex,
        bus: EventBus,
        *,
        local_max_hops: int = 8,
        local_max_deadline_s: float = 3600.0,
        now: Callable[[], float] = time.time,
    ) -> None:
        self.spec = spec
        self.index = index
        self.bus = bus
        self.local_max_hops = local_max_hops
        self.local_max_deadline_s = local_max_deadline_s
        self._now = now
        self._active: dict[str, _Run] = {}
        self._running: dict[str, asyncio.Task[None]] = {}
        self._closed: OrderedDict[str, None] = OrderedDict()
        self.on_cancel: Callable[..., Awaitable[object]] | None = None
        self.cancel_wait_s = 5.0  # how long cancel() waits for the adapter to stop

    # -- bookkeeping -------------------------------------------------------------------

    def _close(self, task_id: str) -> None:
        self._closed[task_id] = None
        self._closed.move_to_end(task_id)
        while len(self._closed) > _CLOSED_MAX:
            self._closed.popitem(last=False)

    async def _record(self, run: _Run, state: int) -> None:
        async with run.lock:
            if run.cancelled or state == run.last_state:
                return
            run.last_state = state
            name = TaskState.Name(state)
            u = run.updater
            await self.index.upsert(
                u.task_id, self.spec.id, run.owner, u.context_id, name, run.origin
            )
            self._publish(u.task_id, u.context_id, name)

    def _publish(self, task_id: str, context_id: str, state: str) -> None:
        self.bus.publish(
            GatewayEvent(
                kind="task.state",
                agent_id=self.spec.id,
                data={"task_id": task_id, "context_id": context_id, "state": state},
            )
        )

    async def _status(self, run: _Run, state: int, text: str | None = None) -> None:
        if run.terminal or run.cancelled:
            return
        if state in _TERMINAL:
            run.terminal = True
            self._close(run.updater.task_id)
        message = self._agent_message(run.updater, text) if text is not None else None
        # Index first: a blocking caller may read the index as soon as the event is consumed.
        await self._record(run, state)
        if run.cancelled:  # cancel() claimed the task meanwhile and reports CANCELED
            return
        await run.updater.update_status(state, message=message, metadata=run.usage_metadata())

    @staticmethod
    def _agent_message(updater: TaskUpdater, text: str) -> Message:
        return updater.new_agent_message([new_text_part(text)])

    # -- AgentExecutor -----------------------------------------------------------------

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        message = context.message
        task_id, context_id = context.task_id, context.context_id
        if message is None or not task_id or not context_id:  # pragma: no cover
            raise ValueError("execute() requires a message, task_id and context_id")
        principal, owner = _caller(context)
        run = _Run(updater=TaskUpdater(event_queue, task_id, context_id), owner=owner, origin=None)
        if task_id in self._closed:
            # cancel() (or a terminal state) got here first, e.g. a cancel that landed while
            # the handler was still setting up a resumed turn: never run the adapter.
            return
        # Registered before any await, so a concurrent cancel() always finds this run.
        self._active[task_id] = run
        try:
            await self._execute(run, context, message, principal)
        finally:
            if self._active.get(task_id) is run:
                del self._active[task_id]

    async def _execute(
        self,
        run: _Run,
        context: RequestContext,
        message: Message,
        principal: Principal | None,
    ) -> None:
        updater = run.updater
        current = context.current_task
        resumed = current is not None and current.status.state in _RESUMABLE
        if current is None:
            await updater.event_queue.enqueue_event(new_task_from_user_message(message))
            await self._record(run, TaskState.TASK_STATE_SUBMITTED)
        elif resumed:
            prior = MessageToDict(current.metadata).get(USAGE_KEY)
            if isinstance(prior, dict):
                run.tokens_in = int(prior.get("tokens_in", 0))
                run.tokens_out = int(prior.get("tokens_out", 0))
                run.cost = float(prior.get("cost", 0.0))
        if run.cancelled:
            return

        cc, reason = self._admit(message)
        if cc is None:
            await self._status(run, TaskState.TASK_STATE_REJECTED, reason)
            return
        # A resumed turn keeps the origin recorded by the turn that created the task.
        run.origin = None if resumed else cc.origin
        if not resumed and not self.spec.allow_reentry:
            # The path check above misses a partner that forwards our origin but rewrites the
            # path: see "Re-entry" in the class docstring.
            if await self.index.blocked_downstream(self.spec.id, cc.origin, updater.task_id):
                await self._status(run, TaskState.TASK_STATE_REJECTED, _REENTRY)
                return
            if run.cancelled:
                return

        inbound = InboundContext.from_message(
            self.spec.id,
            message,
            task_id=updater.task_id,
            context_id=updater.context_id,
            principal=principal,
            call=cc.child(self.spec.id),
            metadata=MessageToDict(message.metadata),
            resumed=resumed,
        )
        if run.cancelled:
            return
        # No await between the check above and registration: cancel() sees one or the other.
        work = asyncio.create_task(self._drive(run, inbound), name=f"a2agw:{updater.task_id}")
        self._running[updater.task_id] = work
        try:
            await work
        except asyncio.CancelledError:
            this = asyncio.current_task()
            if this is not None and this.cancelling():
                raise  # the framework is cancelling execute() itself
            if run.cancelled:
                return  # cancel() stopped the work and reports CANCELED itself
            # The adapter raised CancelledError on its own: that is an adapter failure.
            logger.error(
                "adapter for agent %s raised CancelledError on task %s",
                self.spec.id,
                updater.task_id,
            )
            await self._status(run, TaskState.TASK_STATE_FAILED, "internal error")
        finally:
            if self._running.get(updater.task_id) is work:
                del self._running[updater.task_id]

    def _admit(self, message: Message) -> tuple[CallContext | None, str]:
        """Parse, clamp and admit the caller's call context. Returns (cc, "") or (None, reason)."""
        try:
            cc = CallContext.from_metadata(MessageToDict(message.metadata))
        except ValueError:
            return None, _INVALID
        if cc is None:
            # No caller context: this agent is the root. Start from an empty path so the
            # cycle check does not trip on the agent itself; child() below adds it.
            cc = dataclasses.replace(CallContext.new(self.spec.id), path=())
        cc = cc.clamp(
            local_max_hops=self.local_max_hops,
            local_max_deadline_s=self.local_max_deadline_s,
            now=self._now(),
        )
        try:
            cc.check_admit(self.spec.id, allow_reentry=self.spec.allow_reentry, now=self._now())
        except CallContextViolation as exc:
            return None, _REASONS.get(type(exc), _INVALID)
        return cc, ""

    async def _drive(self, run: _Run, inbound: InboundContext) -> None:
        events: Any = None
        # Outbound calls made by the adapter (partner tools) link to this task and caller.
        with use_call(inbound.call), use_inbound(inbound.task_id, inbound.principal):
            try:
                try:
                    await self._status(run, TaskState.TASK_STATE_WORKING)
                    events = self.spec.adapter.run(inbound)
                    async for ev in events:
                        if await self._apply(run, ev):
                            break
                    else:
                        await self._status(run, TaskState.TASK_STATE_COMPLETED)
                except Exception:  # CancelledError is a BaseException and propagates
                    logger.exception(
                        "adapter for agent %s failed on task %s",
                        self.spec.id,
                        run.updater.task_id,
                    )
                    await self._status(run, TaskState.TASK_STATE_FAILED, "internal error")
            finally:
                if events is not None:
                    await self._close_events(run, events)

    async def _close_events(self, run: _Run, events: Any) -> None:
        """Close the adapter's generator (it may be left mid-iteration). Never changes state."""
        aclose = getattr(events, "aclose", None)
        if aclose is None:
            return
        try:
            await aclose()
        except Exception:
            logger.exception(
                "adapter cleanup failed for agent %s on task %s",
                self.spec.id,
                run.updater.task_id,
            )

    async def _apply(self, run: _Run, ev: object) -> bool:
        """Map one adapter event onto the task. Returns True when the run should stop."""
        updater = run.updater
        match ev:
            case Status(text=text):
                await self._status(run, TaskState.TASK_STATE_WORKING, text)
            case ArtifactChunk():
                await updater.add_artifact(
                    list(ev.parts),
                    artifact_id=ev.artifact_id,
                    name=ev.name,
                    append=ev.append,
                    last_chunk=ev.last,
                )
            case Usage():
                run.tokens_in += ev.tokens_in
                run.tokens_out += ev.tokens_out
                run.cost += ev.cost
                run.usage_seen = True
            case NeedInput(question=question):
                await self._status(run, TaskState.TASK_STATE_INPUT_REQUIRED, question)
                return True
            case NeedAuth(scheme=scheme, detail=detail):
                text = detail or f"authentication required: {scheme}"
                await self._status(run, TaskState.TASK_STATE_AUTH_REQUIRED, text)
                return True
            case Done(text=text):
                if text is not None:
                    await updater.add_artifact([Part(text=text)], name="result")
                await self._status(run, TaskState.TASK_STATE_COMPLETED)
                return True
            case Failed(error=error):
                await self._status(run, TaskState.TASK_STATE_FAILED, error)
                return True
            case _:
                raise TypeError(f"unknown adapter event {type(ev).__name__}")
        return False

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        task_id = context.task_id
        if not task_id:  # pragma: no cover - the handler always supplies one
            return
        current = context.current_task
        if task_id in self._closed or (current is not None and current.status.state in _TERMINAL):
            return  # already terminal or already cancelled: nothing to do
        # Claim the task synchronously, before any await, so execute() and a second
        # cancel() both see it.
        self._close(task_id)
        run = self._active.get(task_id)
        if run is not None:
            run.cancelled = True
        context_id = context.context_id or (current.context_id if current is not None else "")

        work = self._running.pop(task_id, None)
        if work is not None and not work.done():
            work.cancel()
            _, pending = await asyncio.wait({work}, timeout=self.cancel_wait_s)
            if pending:
                # The adapter swallowed the cancellation. Its later changes are ignored
                # (run.cancelled), so report CANCELED without waiting any longer.
                logger.warning(
                    "adapter for agent %s did not stop within %.1fs of cancel on task %s",
                    self.spec.id,
                    self.cancel_wait_s,
                    task_id,
                )
        name = TaskState.Name(TaskState.TASK_STATE_CANCELED)
        if run is not None:
            async with run.lock:  # let an in-flight index write of the run land first
                await self.index.set_state(task_id, name)
        else:
            await self.index.set_state(task_id, name)
        self._publish(task_id, context_id, name)
        await TaskUpdater(event_queue, task_id, context_id).update_status(
            TaskState.TASK_STATE_CANCELED,
            metadata=run.usage_metadata() if run is not None else None,
        )
        if self.on_cancel is not None:
            try:
                await self.on_cancel(task_id)
            except Exception:
                logger.exception("on_cancel hook failed for task %s", task_id)
