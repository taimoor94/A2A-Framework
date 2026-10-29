"""OpenAI Agents SDK adapter: any ``agents.Agent`` becomes an A2A agent, and partners become
``FunctionTool``s.

Importing this module requires ``openai-agents`` (the ``a2a-gateway[openai]`` extra); nothing
in the core imports it.

Projected tools are not in the SDK's strict JSON-schema mode. Strict mode makes every property
required and closes every object, so it cannot express the optional ``task_id`` /
``context_id`` continuation arguments or the free-form ``data`` object without changing what
they mean. ``invoke`` validates every call against the full schema instead.
"""

from __future__ import annotations

import copy
import json
from collections.abc import AsyncIterator, Callable
from contextlib import aclosing
from dataclasses import dataclass
from typing import Any

OPENAI_EXTRA_HINT = (
    "the OpenAI Agents SDK adapter needs the openai-agents package: "
    "install it with: pip install 'a2a-gateway[openai]'"
)

try:
    from agents import Agent, FunctionTool, RunConfig, Runner
    from agents.memory import Session, SessionABC
    from agents.result import RunResultStreaming
    from agents.tool_context import ToolContext
    from openai.types.responses import ResponseTextDeltaEvent
except ImportError as e:  # pragma: no cover - exercised by a test that hides the package
    raise ImportError(OPENAI_EXTRA_HINT) from e

from a2agw.adapters._contexts import ContextRegistry, context_key
from a2agw.adapters._stream import MessageTexts, stream_events
from a2agw.consult.client import PartnerClient
from a2agw.consult.tools import PartnerTool, invoke, strip_extensions, with_untrusted_note
from a2agw.core.events import AgentEvent, Done, Status, Usage
from a2agw.core.spi import InboundContext
from a2agw.security.principal import Principal

__all__ = ["MemorySession", "OpenAIAgentsAdapter", "as_openai_tools"]

MAX_SESSIONS = 1024  # (caller, context) keys tracked per adapter (least recently used idle go)
MAX_SESSION_ITEMS = 200  # conversation items a default in-memory session keeps per context


class MemorySession(SessionABC):
    """A process-local ``Session``: the conversation items of one A2A context, in memory.

    Keeps the last ``max_items`` items. A trimmed history starts at a user message when the
    window holds one, so it never opens with a tool output whose call was dropped."""

    def __init__(self, session_id: str, *, max_items: int = MAX_SESSION_ITEMS) -> None:
        self.session_id = session_id
        self.max_items = max_items
        self._items: list[Any] = []

    async def get_items(self, limit: int | None = None) -> list[Any]:
        if limit is None and self.session_settings is not None:
            limit = self.session_settings.limit
        items = self._items if limit is None else self._items[-limit:] if limit > 0 else []
        return copy.deepcopy(items)

    async def add_items(self, items: list[Any]) -> None:
        self._items.extend(copy.deepcopy(items))
        if len(self._items) > self.max_items:
            kept = self._items[-self.max_items :]
            start = next((i for i, it in enumerate(kept) if _is_user(it)), 0)
            self._items = kept[start:]

    async def pop_item(self) -> Any | None:
        return self._items.pop() if self._items else None

    async def clear_session(self) -> None:
        self._items.clear()


def _is_user(item: Any) -> bool:
    return isinstance(item, dict) and item.get("role") == "user"


@dataclass
class _Context:
    """Per-context state: its default session (None with a ``session_factory``)."""

    session: MemorySession | None = None


def _final_text(output: Any) -> str | None:
    if output is None or isinstance(output, str):
        return output
    if hasattr(output, "model_dump"):
        output = output.model_dump(mode="json")
    return json.dumps(output, default=str)


class OpenAIAgentsAdapter:
    """Wraps an OpenAI Agents SDK ``Agent``.

    Each turn is ``Runner.run_streamed(agent, ctx.text, session=..., max_turns=...)``.
    Conversations belong to the caller and the A2A context together: the session key is
    ``"<principal id or anonymous>\\x1f<context id>"`` (``_contexts.context_key``), so a
    follow-up message from the same caller on the same context continues the conversation,
    and another caller sending that ``contextId`` does not. The session is
    ``session_factory(key)``; by default a ``MemorySession`` per key (the ``MAX_SESSIONS``
    most recently used keys are kept, each with its last ``MAX_SESSION_ITEMS`` items;
    ``MAX_SESSIONS`` is read when the adapter is constructed). Turns on the same key are
    serialised. Pass a factory returning a persistent session (e.g.
    ``lambda key: agents.SQLiteSession(key, "sessions.db")``) and ``durable_sessions=True``
    to keep conversations across restarts.

    Text deltas from the model stream as the artifact "output" (final chunk marked ``last``);
    each tool call is reported as ``Status("calling <tool>")``. Token usage summed over the
    run's model calls becomes one ``Usage`` event, when non-zero. A run whose model streamed
    no text ends with ``Done(final_output)``. Errors (including ``MaxTurnsExceeded``)
    propagate, so the executor fails the task. Cancelling the turn, or closing its event
    stream, cancels the SDK's background run.

    ``run_config`` is passed to every run. The SDK exports traces to OpenAI by default (when
    an API key is configured); pass ``RunConfig(tracing_disabled=True)`` to keep this agent's
    runs out of it.
    """

    def __init__(
        self,
        agent: Agent[Any],
        *,
        session_factory: Callable[[str], Session] | None = None,
        durable_sessions: bool = False,
        max_turns: int = 10,
        run_config: RunConfig | None = None,
    ):
        self.agent = agent
        self.session_factory = session_factory
        self.durable_sessions = durable_sessions
        self.max_turns = max_turns
        self.run_config = run_config
        # The ``MAX_SESSIONS`` most recently used (caller, context) keys: a key with a turn in
        # flight is never dropped; an idle one goes with its default session.
        self._contexts: ContextRegistry[str, _Context] = ContextRegistry(
            self._new_context, max_size=MAX_SESSIONS
        )

    def _new_context(self, key: str) -> _Context:
        return _Context(MemorySession(key) if self.session_factory is None else None)

    async def run(self, ctx: InboundContext) -> AsyncIterator[AgentEvent]:
        # Turns on one context run one at a time: each sees the history the last one saved.
        async with (
            self._contexts.turn(context_key(ctx)) as entry,
            aclosing(self._turn(ctx, entry)) as turn,
        ):
            # ``aclosing``: closing this stream runs ``_turn``'s cleanup now, not at GC.
            async for ev in turn:
                yield ev

    async def _turn(self, ctx: InboundContext, entry: _Context) -> AsyncIterator[AgentEvent]:
        session = entry.session
        if session is None:
            assert self.session_factory is not None  # no default session only with a factory
            session = self.session_factory(context_key(ctx))
        # The run loop is a task the SDK creates here, so it inherits the inbound contextvars
        # (partner calls from tools are linked to this inbound task).
        result = Runner.run_streamed(
            self.agent,
            ctx.text,
            session=session,
            max_turns=self.max_turns,
            run_config=self.run_config,
        )
        streamed = False

        async def source() -> AsyncIterator[str | AgentEvent]:
            nonlocal streamed
            texts = MessageTexts()  # a new output item, or the response's end, ends a message
            item: str | None = None
            async for ev in result.stream_events():
                if ev.type == "raw_response_event":
                    if isinstance(ev.data, ResponseTextDeltaEvent) and ev.data.delta:
                        if ev.data.item_id != item:
                            texts.end_message()
                            item = ev.data.item_id
                        streamed = True
                        yield texts.text(ev.data.delta)
                    elif getattr(ev.data, "type", None) == "response.completed":
                        texts.end_message()
                elif ev.type == "run_item_stream_event" and ev.name == "tool_called":
                    name = getattr(ev.item, "tool_name", None)
                    if name:
                        yield Status(f"calling {name}")

        try:
            async for item in stream_events(source()):
                yield item
        finally:
            if not result.is_complete:
                # Closed or cancelled mid-run: stop the SDK's background run loop as well.
                result.cancel()
        for ev in _usage(result):
            yield ev
        yield Done() if streamed else Done(text=_final_text(result.final_output))


def _usage(result: RunResultStreaming) -> list[AgentEvent]:
    usage = result.context_wrapper.usage
    tokens_in, tokens_out = int(usage.input_tokens or 0), int(usage.output_tokens or 0)
    return [Usage(tokens_in=tokens_in, tokens_out=tokens_out)] if tokens_in or tokens_out else []


def as_openai_tools(
    tools: list[PartnerTool], client: PartnerClient, *, caller: Principal | None = None
) -> list[FunctionTool]:
    """Project partner tools as ``FunctionTool``s returning the JSON envelope as text.

    The parameters are a copy of the tool's schema without the gateway-only ``x-`` limits,
    in non-strict mode (see the module docstring). Explicit ``null`` arguments are dropped
    (models send them for optional fields); arguments that are not a JSON object are answered
    with ``rejected``. Inside an inbound run the inbound task and caller come from the
    contextvars, as for ``as_langchain_tools``."""

    def make(tool: PartnerTool) -> FunctionTool:
        async def call(_ctx: ToolContext[Any], raw: str) -> str:
            try:
                args: Any = json.loads(raw) if raw else {}
            except ValueError:
                args = None  # ``invoke`` answers a non-object with ``rejected``
            if isinstance(args, dict):
                args = {k: v for k, v in args.items() if v is not None}
            result = await invoke(tool, args, client, inbound_task_id=None, caller=caller)
            return json.dumps(result, default=str)

        return FunctionTool(
            name=tool.name,
            description=with_untrusted_note(tool.description),
            params_json_schema=copy.deepcopy(strip_extensions(tool.parameters)),
            on_invoke_tool=call,
            strict_json_schema=False,
        )

    return [make(t) for t in tools]
