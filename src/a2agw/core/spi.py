"""Inbound SPI: the context handed to, and the protocol implemented by, agent adapters."""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from a2a.types import Message, Part

from a2agw.core.events import AgentEvent

if TYPE_CHECKING:
    from a2agw.context.call_context import CallContext
    from a2agw.security.principal import Principal


@dataclass
class InboundContext:
    agent_id: str
    task_id: str
    context_id: str
    text: str
    parts: list[Part]
    message: Message
    principal: Principal | None = None
    call: CallContext | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    resumed: bool = False  # True when continuing an input-required task

    @classmethod
    def from_message(
        cls,
        agent_id: str,
        message: Message,
        *,
        task_id: str,
        context_id: str,
        principal: Principal | None = None,
        call: CallContext | None = None,
        metadata: dict[str, Any] | None = None,
        resumed: bool = False,
    ) -> InboundContext:
        parts = list(message.parts)
        text = "\n".join(p.text for p in parts if p.WhichOneof("content") == "text")
        return cls(
            agent_id=agent_id,
            task_id=task_id,
            context_id=context_id,
            text=text,
            parts=parts,
            message=message,
            principal=principal,
            call=call,
            metadata=dict(metadata) if metadata else {},
            resumed=resumed,
        )


@runtime_checkable
class InboundAdapter(Protocol):
    durable_sessions: bool

    def run(self, ctx: InboundContext) -> AsyncIterator[AgentEvent]: ...


@runtime_checkable
class LifecycleAdapter(Protocol):
    """An adapter that owns resources of its own (e.g. a supervised agent process).

    Duck-typed and additive: ``AgentHost`` calls ``start()`` at startup, once the stores are
    ready, and ``stop()`` at shutdown, before the database engine is disposed, for every
    adapter that has both methods. ``stop()`` must be safe to call when ``start()`` was not."""

    async def start(self) -> None: ...

    async def stop(self) -> None: ...
