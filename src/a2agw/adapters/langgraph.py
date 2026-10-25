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

from a2agw.adapters._stream import content_text, stream_events
from a2agw.adapters.langchain import as_langchain_tools
from a2agw.core.events import AgentEvent, Done, Failed, NeedInput, Usage
from a2agw.core.spi import InboundContext

__all__ = ["GraphAdapter", "as_langchain_tools"]

logger = logging.getLogger(__name__)

_INTERRUPT = "__interrupt__"
_NO_SAVER = (
    "graph called interrupt() but has no checkpointer; compile with one to use input-required"
)


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
            return content_text(msg.content)
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
    logged. ``interrupt()`` needs a checkpointer: LangGraph 1.2 does not raise on the first
    turn without one, so the adapter yields ``Failed`` instead of ``NeedInput``. On a resumed
    turn the thread must be paused at an interrupt (checked with ``aget_state``); otherwise
    the message is treated as a fresh follow-up and goes through ``input_mapper``. A graph
    with ``aget_state`` but no ``checkpointer`` attribute (``RemoteGraph``) is assumed to
    keep state; errors from its ``aget_state`` fail the task.

    Each turn replaces the "output" artifact (same artifact id, first chunk not appended). A
    turn interrupted after streaming leaves its last chunk with ``last=False``.
    ``durable_sessions`` is true only for a persistent
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

    def _may_have_state(self) -> bool:
        """True if the graph can keep thread state: a real checkpointer, or ``aget_state``
        without a local ``checkpointer`` attribute (a ``RemoteGraph``: the state lives on the
        server)."""
        if not hasattr(self.graph, "checkpointer"):
            return hasattr(self.graph, "aget_state")
        return isinstance(self.graph.checkpointer, BaseCheckpointSaver)

    async def _has_pending_interrupt(self, config: dict) -> bool:
        """True if the thread is paused at an interrupt, so ``Command(resume=...)`` applies."""
        if not hasattr(self.graph, "aget_state"):
            return True  # cannot tell: assume the executor's resumed flag is right
        if not self._may_have_state():
            return False  # no checkpointer: nothing to resume
        try:
            state = await self.graph.aget_state(config)
        except Exception as e:
            # The state store (local saver or remote server) failed: resuming from fresh
            # input would silently lose the paused thread, so the task fails instead.
            logger.error("checkpointer state read failed: %s", type(e).__name__)
            raise
        if getattr(state, "interrupts", None):
            return True
        return any(getattr(t, "interrupts", None) for t in getattr(state, "tasks", ()) or ())

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
            config = {"configurable": {"thread_id": ctx.context_id}}
            payload: Any = self.input_mapper(ctx)
            if ctx.resumed and await self._has_pending_interrupt(config):
                payload = Command(resume=ctx.text)
            # The (mode, data) unpack below assumes ``subgraphs=False`` (the default); a
            # subgraph interrupt still surfaces as an ``__interrupt__`` update of the parent.
            async for mode, data in self.graph.astream(
                payload, config=config, stream_mode=["messages", "updates"]
            ):
                if mode == "messages":
                    chunk, metadata = data
                    if not isinstance(chunk, AIMessage | AIMessageChunk):
                        continue
                    um = getattr(chunk, "usage_metadata", None)
                    if um:
                        saw_usage = True
                        tokens_in += int(um.get("input_tokens", 0) or 0)
                        tokens_out += int(um.get("output_tokens", 0) or 0)
                    # Usage counts every node; ``stream_nodes`` only limits streamed text.
                    if self.stream_nodes is not None and (
                        (metadata or {}).get("langgraph_node") not in self.stream_nodes
                    ):
                        continue
                    text = content_text(chunk.content)
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
                        if not self._may_have_state():
                            yield Failed(_NO_SAVER)
                        else:
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
