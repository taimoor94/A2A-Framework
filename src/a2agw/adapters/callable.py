"""Callable adapter: any plain Python function becomes an A2A agent, and partners become
plain async functions usable as tools in any custom agent loop."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

from a2agw.adapters._stream import EVENT_TYPES as _EVENT_TYPES
from a2agw.adapters._stream import stream_events
from a2agw.consult.client import PartnerClient
from a2agw.consult.tools import UNTRUSTED_NOTE, PartnerTool, invoke
from a2agw.core.events import AgentEvent, Done
from a2agw.core.spi import InboundContext
from a2agw.serve.agent import AgentSpec, SkillSpec


class CallableAdapter:
    """Wraps ``fn(ctx: InboundContext)``.

    ``fn`` may be sync or async and may return a ``str`` (completes with that text), an
    ``AgentEvent``, ``None`` (completes with no text), or an awaitable of these. It may also
    be, or return, a sync or async iterator yielding ``AgentEvent | str``; plain strings
    stream as one text artifact ("output"), the final one marked ``last``.

    Plain sync functions run in a worker thread. Sync generators are iterated on the event
    loop, so they must not block. Exceptions propagate (the executor marks the task failed).
    """

    def __init__(self, fn: Callable[[InboundContext], Any], *, durable_sessions: bool = False):
        self.fn = fn
        self.durable_sessions = durable_sessions

    async def run(self, ctx: InboundContext) -> AsyncIterator[AgentEvent]:
        fn = self.fn
        if inspect.iscoroutinefunction(fn) or inspect.isasyncgenfunction(fn):
            result = fn(ctx)
        elif inspect.isgeneratorfunction(fn):
            result = fn(ctx)  # creating a generator does not run its body
        else:
            result = await asyncio.to_thread(fn, ctx)
        if inspect.isawaitable(result):
            result = await result

        if result is None:
            yield Done()
        elif isinstance(result, str):
            yield Done(text=result)
        elif isinstance(result, _EVENT_TYPES):
            yield result
        elif hasattr(result, "__aiter__") or hasattr(result, "__next__"):
            async for ev in stream_events(result):
                yield ev
        else:
            raise TypeError(f"callable agent returned unsupported {type(result).__name__}")


def as_functions(
    tools: list[PartnerTool], client: PartnerClient
) -> list[Callable[..., Awaitable[dict]]]:
    """Project partner tools as plain async functions ``fn(**kwargs) -> dict``.

    Inside an inbound run the inbound task and caller come from the T15 contextvars.
    """

    def make(tool: PartnerTool) -> Callable[..., Awaitable[dict]]:
        async def call(**kwargs: Any) -> dict:
            return await invoke(tool, kwargs, client, inbound_task_id=None)

        call.__name__ = tool.name
        call.__qualname__ = tool.name
        call.__doc__ = tool.description + "\n\n" + UNTRUSTED_NOTE
        call.json_schema = tool.parameters  # type: ignore[attr-defined]
        call.tool = tool  # type: ignore[attr-defined]
        return call

    return [make(t) for t in tools]


def agent(
    id: str,
    name: str | None = None,
    description: str | None = None,
    *,
    skills: list[SkillSpec | dict[str, Any]] | None = None,
    durable_sessions: bool = False,
    **spec_kwargs: Any,
) -> Callable[[Callable[[InboundContext], Any]], AgentSpec]:
    """Decorator turning a function into an ``AgentSpec`` backed by ``CallableAdapter``."""

    def deco(fn: Callable[[InboundContext], Any]) -> AgentSpec:
        n = name or fn.__name__.replace("_", " ").title()
        d = description
        if not d:
            doc = inspect.getdoc(fn)
            d = doc.strip().splitlines()[0] if doc and doc.strip() else None
        if not d:
            raise ValueError(f"agent {id!r}: provide a description or a function docstring")
        sk = (
            [s if isinstance(s, SkillSpec) else SkillSpec(**s) for s in skills]
            if skills
            else [SkillSpec(id=id, name=n, description=d)]
        )
        return AgentSpec(
            id=id,
            name=n,
            description=d,
            skills=sk,
            adapter=CallableAdapter(fn, durable_sessions=durable_sessions),
            **spec_kwargs,
        )

    return deco
