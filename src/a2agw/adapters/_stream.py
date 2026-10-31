"""Shared text-streaming helper for adapters: buffer one string so the final chunk can be
marked ``last`` once the source is exhausted."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Any

from a2a.types import Part

from a2agw.core.events import AgentEvent, ArtifactChunk

EVENT_TYPES = tuple(AgentEvent.__args__)


def content_text(content: Any) -> str:
    """Text of LangChain message content (a str, or a list of str / text blocks)."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        out = []
        for block in content:
            if isinstance(block, str):
                out.append(block)
            elif isinstance(block, dict) and block.get("type") == "text":
                out.append(str(block.get("text", "")))
        return "".join(out)
    return ""


MESSAGE_SEPARATOR = "\n\n"


class MessageTexts:
    """Joins the text of consecutive model messages in one streamed answer: the first text
    after a message that had text is prefixed with ``MESSAGE_SEPARATOR``, so a narration and
    the answer after its tool call ("Let me check." / "It is 42.") do not run together.

    Pass every text through ``text``; call ``end_message`` when a model message ends (or a
    new one starts: calling it more than once in a row, or before any text, is harmless)."""

    def __init__(self) -> None:
        self._wrote = False  # some message had text
        self._pending = False  # a message with text ended since the last text

    def end_message(self) -> None:
        if self._wrote:
            self._pending = True

    def text(self, text: str) -> str:
        if not text:
            return text
        if self._pending:
            text = MESSAGE_SEPARATOR + text
            self._pending = False
        self._wrote = True
        return text


def text_chunk(text: str, *, first: bool, last: bool) -> ArtifactChunk:
    return ArtifactChunk(
        parts=[Part(text=text)], name="output", artifact_id="output", append=not first, last=last
    )


async def _items(source: Any) -> AsyncGenerator[Any, None]:
    if hasattr(source, "__aiter__"):
        async for item in source:
            yield item
    else:
        for item in source:
            yield item


async def stream_events(source: Any) -> AsyncGenerator[AgentEvent, None]:
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
