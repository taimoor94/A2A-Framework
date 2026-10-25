"""LangGraph adapter: any compiled graph becomes an A2A agent.

The A2A ``contextId`` is the LangGraph ``thread_id``. A LangGraph ``interrupt()`` becomes the
A2A ``input-required`` state and the next message on the task resumes the graph. Outbound,
LangGraph agents use ``a2agw.adapters.langchain.as_langchain_tools`` (re-exported here).

Importing this module requires ``langgraph``; nothing in the core imports it.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator, Callable
from typing import Any

from langchain_core.messages import AIMessage, AIMessageChunk
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command

from a2agw.adapters._stream import stream_events
from a2agw.adapters.langchain import _content_text, as_langchain_tools
from a2agw.core.events import AgentEvent, Done, NeedInput, Usage
from a2agw.core.spi import InboundContext

__all__ = ["GraphAdapter", "as_langchain_tools"]

logger = logging.getLogger(__name__)

_INTERRUPT = "__interrupt__"


def _default_input(ctx: InboundContext) -> dict:
    return {"messages": [("user", ctx.text)]}


def _question(interrupt: Any) -> str:
    value = getattr(interrupt, "value", interrupt)
    return value if isinstance(value, str) else json.dumps(value, default=str)


def _last_ai_text(update: Any, output_key: str) -> str | None:
    """Text of the last AI message under ``output_key`` in one node update, if any."""
    if not isinstance(update, dict):
        return None
    value = update.get(output_key)
    items = value if isinstance(value, list | tuple) else [value]
    for msg in reversed(items):
        if isinstance(msg, AIMessage):
            return _content_text(msg.content)
    return None


class GraphAdapter:
    """Wraps a compiled LangGraph graph (anything with ``astream``).

    Runs with ``thread_id = ctx.context_id``. On a resumed turn (``ctx.resumed``) the graph is
    continued with ``Command(resume=ctx.text)``, otherwise it gets ``input_mapper(ctx)``
    (default ``{"messages": [("user", ctx.text)]}``).

    Text of AI message chunks streams as the artifact "output" (``stream_nodes`` limits it to
    chunks from those graph nodes). If nothing was streamed, the text of the last AI message
    under ``output_key`` in the node updates is the final ``Done(text)``. Token usage on AI
    chunks is summed (per-chunk deltas) into one ``Usage`` event.

    An ``interrupt()`` ends the turn with ``NeedInput``: the question is the interrupt value
    (a ``str``, else its JSON). With several interrupts the first is used and the rest are
    logged. ``interrupt()`` needs a checkpointer: without one LangGraph raises, the exception
    propagates and the task fails. ``durable_sessions`` is true only for a persistent
    checkpointer (anything but ``InMemorySaver``), so a restarted gateway keeps
    ``input-required`` tasks; with an in-memory one they are failed on restart.
    """

    def __init__(
        self,
        graph: Any,
        *,
        input_mapper: Callable[[InboundContext], dict] | None = None,
        output_key: str = "messages",
        stream_nodes: set[str] | None = None,
    ):
        self.graph = graph
        self.input_mapper = input_mapper or _default_input
        self.output_key = output_key
        self.stream_nodes = stream_nodes

    @property
    def durable_sessions(self) -> bool:
        # ``checkpointer`` may be None, a saver, or a True/False flag (subgraphs).
        cp = getattr(self.graph, "checkpointer", None)
        return isinstance(cp, BaseCheckpointSaver) and not isinstance(cp, InMemorySaver)

    async def run(self, ctx: InboundContext) -> AsyncIterator[AgentEvent]:
        tokens_in = tokens_out = 0
        saw_usage = False
        streamed = False
        final_text: str | None = None
        interrupted = False

        def usage() -> list[AgentEvent]:
            return [Usage(tokens_in=tokens_in, tokens_out=tokens_out)] if saw_usage else []

        async def source() -> AsyncIterator[Any]:
            nonlocal tokens_in, tokens_out, saw_usage, streamed, final_text, interrupted
            payload: Any = Command(resume=ctx.text) if ctx.resumed else self.input_mapper(ctx)
            config = {"configurable": {"thread_id": ctx.context_id}}
            async for mode, data in self.graph.astream(
                payload, config=config, stream_mode=["messages", "updates"]
            ):
                if mode == "messages":
                    chunk, metadata = data
                    if not isinstance(chunk, AIMessage | AIMessageChunk):
                        continue
                    if self.stream_nodes is not None and (
                        (metadata or {}).get("langgraph_node") not in self.stream_nodes
                    ):
                        continue
                    um = getattr(chunk, "usage_metadata", None)
                    if um:
                        saw_usage = True
                        tokens_in += int(um.get("input_tokens", 0) or 0)
                        tokens_out += int(um.get("output_tokens", 0) or 0)
                    text = _content_text(chunk.content)
                    if text:
                        streamed = True
                        yield text
                elif mode == "updates" and isinstance(data, dict):
                    if _INTERRUPT in data:
                        found = list(data[_INTERRUPT])
                        for extra in found[1:]:
                            logger.warning("ignoring extra interrupt: %s", _question(extra))
                        interrupted = True
                        for ev in usage():
                            yield ev
                        yield NeedInput(question=_question(found[0]))
                        return
                    for update in data.values():
                        last = _last_ai_text(update, self.output_key)
                        if last is not None:
                            final_text = last

        async for ev in stream_events(source()):
            yield ev
        if interrupted:
            return
        for ev in usage():
            yield ev
        yield Done() if streamed else Done(text=final_text)
