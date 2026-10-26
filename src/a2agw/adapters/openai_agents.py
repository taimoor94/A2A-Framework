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
from collections import OrderedDict
from collections.abc import AsyncIterator, Callable
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

from a2agw.adapters._stream import stream_events
from a2agw.consult.client import PartnerClient
from a2agw.consult.tools import PartnerTool, invoke, strip_extensions, with_untrusted_note
from a2agw.core.events import AgentEvent, Done, Status, Usage
from a2agw.core.spi import InboundContext
from a2agw.security.principal import Principal

__all__ = ["MemorySession", "OpenAIAgentsAdapter", "as_openai_tools"]

MAX_SESSIONS = 1024  # default in-memory sessions kept per adapter (least recently used go)


class MemorySession(SessionABC):
    """A process-local ``Session``: the conversation items of one A2A context, in memory."""

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self._items: list[Any] = []

    async def get_items(self, limit: int | None = None) -> list[Any]:
        if limit is None and self.session_settings is not None:
            limit = self.session_settings.limit
        items = self._items if limit is None else self._items[-limit:] if limit > 0 else []
        return copy.deepcopy(items)

    async def add_items(self, items: list[Any]) -> None:
        self._items.extend(copy.deepcopy(items))

    async def pop_item(self) -> Any | None:
        return self._items.pop() if self._items else None

    async def clear_session(self) -> None:
        self._items.clear()


def _final_text(output: Any) -> str | None:
    if output is None or isinstance(output, str):
        return output
    if hasattr(output, "model_dump"):
        output = output.model_dump(mode="json")
    return json.dumps(output, default=str)


class OpenAIAgentsAdapter:
    """Wraps an OpenAI Agents SDK ``Agent``.

    Each turn is ``Runner.run_streamed(agent, ctx.text, session=..., max_turns=...)``. The
    session is ``session_factory(ctx.context_id)``; by default a ``MemorySession`` per
    context, so a follow-up message on the same A2A context continues the conversation (the
    ``MAX_SESSIONS`` most recently used contexts are kept). Pass a factory returning a
    persistent session (e.g. ``agents.SQLiteSession(context_id, "sessions.db")``) and
    ``durable_sessions=True`` to keep conversations across restarts.

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
        self.session_factory = session_factory or self._memory_session
        self.durable_sessions = durable_sessions
        self.max_turns = max_turns
        self.run_config = run_config
        self._sessions: OrderedDict[str, MemorySession] = OrderedDict()

    def _memory_session(self, context_id: str) -> MemorySession:
        session = self._sessions.get(context_id)
        if session is None:
            session = self._sessions[context_id] = MemorySession(context_id)
            while len(self._sessions) > MAX_SESSIONS:
                self._sessions.popitem(last=False)
        self._sessions.move_to_end(context_id)
        return session

    async def run(self, ctx: InboundContext) -> AsyncIterator[AgentEvent]:
        # The run loop is a task the SDK creates here, so it inherits the inbound contextvars
        # (partner calls from tools are linked to this inbound task).
        result = Runner.run_streamed(
            self.agent,
            ctx.text,
            session=self.session_factory(ctx.context_id),
            max_turns=self.max_turns,
            run_config=self.run_config,
        )
        streamed = False

        async def source() -> AsyncIterator[str | AgentEvent]:
            nonlocal streamed
            async for ev in result.stream_events():
                if ev.type == "raw_response_event":
                    if isinstance(ev.data, ResponseTextDeltaEvent) and ev.data.delta:
                        streamed = True
                        yield ev.data.delta
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
