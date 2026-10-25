"""Shared text-streaming helper for adapters: buffer one string so the final chunk can be
marked ``last`` once the source is exhausted."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from a2a.types import Part

from a2agw.core.events import AgentEvent, ArtifactChunk

EVENT_TYPES = tuple(AgentEvent.__args__)  # type: ignore[attr-defined]


def text_chunk(text: str, *, first: bool, last: bool) -> ArtifactChunk:
    return ArtifactChunk(
        parts=[Part(text=text)], name="output", artifact_id="output", append=not first, last=last
    )


async def _items(source: Any) -> AsyncIterator[Any]:
    if hasattr(source, "__aiter__"):
        async for item in source:
            yield item
    else:
        for item in source:
            yield item


async def stream_events(source: Any) -> AsyncIterator[AgentEvent]:
    """Turn an (async) iterable of ``str | AgentEvent`` into events.

    Strings stream as one append-style artifact "output"; one string is held back so the
    final chunk carries ``last=True``. Any other event flushes the held string first.
    """
    pending: str | None = None
    first = True
    async for item in _items(source):
        if isinstance(item, str):
            if pending is not None:
                yield text_chunk(pending, first=first, last=False)
                first = False
            pending = item
        elif isinstance(item, EVENT_TYPES):
            if pending is not None:
                yield text_chunk(pending, first=first, last=False)
                first = False
                pending = None
            yield item
        else:
            raise TypeError(f"agent yielded unsupported {type(item).__name__}")
    if pending is not None:
        yield text_chunk(pending, first=first, last=True)
