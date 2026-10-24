"""Inbound bridge: runs an InboundAdapter behind the A2A SDK's AgentExecutor interface."""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import time
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
_RESUMABLE = {TaskState.TASK_STATE_INPUT_REQUIRED, TaskState.TASK_STATE_AUTH_REQUIRED}


@dataclass
class _Run:
    """Per-execute state: where to record state changes, and the usage totals so far."""

    updater: TaskUpdater
    owner: str
    origin: str | None
    tokens_in: int = 0
    tokens_out: int = 0
    cost: float = 0.0
    usage_seen: bool = False
    last_state: int | None = None

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
        self._running: dict[str, asyncio.Task[None]] = {}
        self.on_cancel: Callable[[str], Awaitable[None]] | None = None

    # -- bookkeeping -------------------------------------------------------------------

    async def _record(self, run: _Run, state: int) -> None:
        if state == run.last_state:
            return
        run.last_state = state
        name = TaskState.Name(state)
        u = run.updater
        await self.index.upsert(u.task_id, self.spec.id, run.owner, u.context_id, name, run.origin)
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
        message = self._agent_message(run.updater, text) if text is not None else None
        # Index first: a blocking caller may read the index as soon as the event is consumed.
        await self._record(run, state)
        await run.updater.update_status(state, message=message, metadata=run.usage_metadata())

    @staticmethod
    def _agent_message(updater: TaskUpdater, text: str) -> Message:
        return updater.new_agent_message([new_text_part(text)])

    # -- AgentExecutor -----------------------------------------------------------------

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        message = context.message
        if message is None:  # pragma: no cover - the handler always supplies one
            raise ValueError("execute() requires a message")
        principal, owner = _caller(context)
        current = context.current_task
        resumed = current is not None and current.status.state in _RESUMABLE
        if current is None:
            current = new_task_from_user_message(message)
            await event_queue.enqueue_event(current)
        updater = TaskUpdater(event_queue, current.id, current.context_id)
        run = _Run(updater=updater, owner=owner, origin=None)
        if resumed:
            prior = MessageToDict(current.metadata).get(USAGE_KEY)
            if isinstance(prior, dict):
                run.tokens_in = int(prior.get("tokens_in", 0))
                run.tokens_out = int(prior.get("tokens_out", 0))
                run.cost = float(prior.get("cost", 0.0))
        else:
            await self._record(run, current.status.state)

        cc, reason = self._admit(message)
        if cc is None:
            await self._record(run, TaskState.TASK_STATE_REJECTED)
            await updater.reject(message=self._agent_message(updater, reason))
            return
        run.origin = cc.origin

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
        work = asyncio.create_task(self._drive(run, inbound), name=f"a2agw:{updater.task_id}")
        self._running[updater.task_id] = work
        try:
            await work
        except asyncio.CancelledError:
            this = asyncio.current_task()
            if this is not None and this.cancelling():
                raise  # the framework is cancelling execute() itself
            # Otherwise cancel() stopped the work and reports CANCELED itself.
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
        updater = run.updater
        try:
            with use_call(inbound.call):
                await self._status(run, TaskState.TASK_STATE_WORKING)
                events = self.spec.adapter.run(inbound)
                try:
                    async for ev in events:
                        if await self._apply(run, ev):
                            return
                finally:
                    # Close the adapter's generator now (it may be left mid-iteration).
                    aclose = getattr(events, "aclose", None)
                    if aclose is not None:
                        await aclose()
            await self._status(run, TaskState.TASK_STATE_COMPLETED)
        except Exception:  # CancelledError is a BaseException and propagates
            logger.exception(
                "adapter for agent %s failed on task %s", self.spec.id, updater.task_id
            )
            await self._status(run, TaskState.TASK_STATE_FAILED, "internal error")

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
        context_id = context.context_id or (
            context.current_task.context_id if context.current_task is not None else ""
        )
        work = self._running.pop(task_id, None)
        if work is not None and not work.done():
            work.cancel()
            await asyncio.gather(work, return_exceptions=True)
        name = TaskState.Name(TaskState.TASK_STATE_CANCELED)
        await self.index.set_state(task_id, name)
        self._publish(task_id, context_id, name)
        await TaskUpdater(event_queue, task_id, context_id).cancel()
        if self.on_cancel is not None:
            try:
                await self.on_cancel(task_id)
            except Exception:
                logger.exception("on_cancel hook failed for task %s", task_id)
