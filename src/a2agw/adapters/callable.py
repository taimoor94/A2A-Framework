"""Callable adapter: any plain Python function becomes an A2A agent, and partners become
plain async functions usable as tools in any custom agent loop."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

from a2a.types import Part

from a2agw.consult.client import PartnerClient
from a2agw.consult.tools import UNTRUSTED_NOTE, PartnerTool, invoke
from a2agw.core.events import AgentEvent, ArtifactChunk, Done
from a2agw.core.spi import InboundContext
from a2agw.serve.agent import AgentSpec, SkillSpec

_EVENT_TYPES = tuple(AgentEvent.__args__)  # type: ignore[attr-defined]


def _chunk(text: str, *, first: bool, last: bool) -> ArtifactChunk:
    return ArtifactChunk(
        parts=[Part(text=text)], name="output", artifact_id="output", append=not first, last=last
    )


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
            async for ev in _stream(result):
                yield ev
        else:
            raise TypeError(f"callable agent returned unsupported {type(result).__name__}")


async def _items(source: Any) -> AsyncIterator[Any]:
    if hasattr(source, "__aiter__"):
        async for item in source:
            yield item
    else:
        for item in source:
            yield item


async def _stream(source: Any) -> AsyncIterator[AgentEvent]:
    pending: str | None = None
    first = True
    async for item in _items(source):
        if isinstance(item, str):
            if pending is not None:
                yield _chunk(pending, first=first, last=False)
                first = False
            pending = item
        elif isinstance(item, _EVENT_TYPES):
            if pending is not None:
                yield _chunk(pending, first=first, last=False)
                first = False
                pending = None
            yield item
        else:
            raise TypeError(f"callable agent yielded unsupported {type(item).__name__}")
    if pending is not None:
        yield _chunk(pending, first=first, last=True)


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
