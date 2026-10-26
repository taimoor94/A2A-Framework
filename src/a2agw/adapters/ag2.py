"""AG2 adapter: any AG2 1.x agent (``ag2.Agent``) becomes an A2A agent, and partners become
AG2 ``FunctionTool``s.

Importing this module requires ``ag2`` 1.x (the ``a2a-gateway[ag2]`` extra; import name
``ag2``); nothing in the core imports it. AG2 Classic (``import autogen``,
``ConversableAgent``) is not supported: serve such an agent through the callable adapter.

Telemetry: AG2 traces only through its opt-in ``TelemetryMiddleware``; this adapter adds none.
"""

from __future__ import annotations

import asyncio
import copy
import json
from collections.abc import AsyncIterator, Callable
from contextlib import aclosing
from typing import Any

AG2_EXTRA_HINT = (
    "the AG2 adapter needs the ag2 package (1.x): install it with: pip install 'a2a-gateway[ag2]'"
)

try:
    from ag2 import Agent, MemoryStream
    from ag2.events import (
        BaseEvent,
        ModelMessageChunk,
        ModelRequest,
        ModelResponse,
        ToolCallEvent,
        ToolResultEvent,
        UsageEvent,
    )
    from ag2.history import close_unanswered_tool_calls
    from ag2.stream import Stream
    from ag2.tools import tool
    from ag2.tools.final import FunctionTool
except ImportError as e:  # pragma: no cover - exercised by a test that hides the package
    raise ImportError(AG2_EXTRA_HINT) from e

from a2agw.adapters._contexts import ContextRegistry, context_key
from a2agw.adapters._stream import stream_events
from a2agw.consult.client import PartnerClient
from a2agw.consult.tools import PartnerTool, invoke, strip_extensions, with_untrusted_note
from a2agw.core.events import AgentEvent, Done, Status, Usage
from a2agw.core.spi import InboundContext
from a2agw.security.principal import Principal

__all__ = ["AG2Adapter", "as_ag2_tools"]

MAX_SESSIONS = 10_000  # (caller, context) conversations kept per adapter (LRU, idle only)
# What a tool call cut short by a cancelled or failed turn is answered with in the history.
UNFINISHED_TOOL_RESULT = "This tool call was not completed: the turn ended before it finished."

_END = object()  # queued once the turn's drive has finished


class AG2Adapter:
    """Runs each turn as ``agent.run(ctx.text, stream=<the conversation's stream>)``.

    An AG2 conversation is a ``Stream``, whose history the agent replays to the model. There
    is one per caller and A2A context (key ``"<principal id or anonymous>\\x1f<context id>"``,
    ``_contexts.context_key``): a follow-up from the same caller on the same context
    continues the conversation, and another caller sending that ``contextId`` does not.
    Turns on one key are serialised. By default each key gets a ``MemoryStream``; the
    ``MAX_SESSIONS`` most recently used keys are kept (read when the adapter is constructed),
    and after each turn the history is trimmed to its last ``history_limit`` messages
    (requests and model responses), cut at a request so a tool call never loses its result.
    Pass ``stream_factory(key)`` returning a stream on persistent ``Storage`` with
    ``durable_sessions=True`` (it is required then) to keep conversations across restarts;
    such streams are never trimmed.

    Text chunks the model streams (``ModelMessageChunk``) become the artifact "output"; a
    model that does not stream answers with ``Done(<reply text>)``. Each tool call is
    reported as ``Status("calling <tool>")``. Token usage summed over the turn's model calls
    becomes one ``Usage`` event, when non-zero; then ``Done``. Errors raised by the agent
    propagate, so the executor fails the task. Cancelling the turn, or closing its event
    stream, cancels AG2's drive of it; tool calls it cut short are answered in the history
    with ``UNFINISHED_TOOL_RESULT``, which keeps the conversation valid for the next turn.
    """

    def __init__(
        self,
        agent: Agent,
        *,
        history_limit: int = 50,
        durable_sessions: bool = False,
        stream_factory: Callable[[str], Stream] | None = None,
    ):
        if history_limit < 1:
            raise ValueError("history_limit must be at least 1")
        if durable_sessions and stream_factory is None:
            raise ValueError(
                "durable_sessions=True needs a stream_factory returning streams on persistent "
                "storage (e.g. ag2.MemoryStream(storage, id=...))"
            )
        self.agent = agent
        self.history_limit = history_limit
        self.durable_sessions = durable_sessions
        self.stream_factory = stream_factory
        # A key with a turn in flight is never dropped; an idle default stream goes with its
        # history (each ``MemoryStream`` keeps its own).
        self._contexts: ContextRegistry[str, Stream] = ContextRegistry(
            stream_factory or (lambda _key: MemoryStream()), max_size=MAX_SESSIONS
        )

    async def run(self, ctx: InboundContext) -> AsyncIterator[AgentEvent]:
        # Turns on one conversation run one at a time: each sees the history the last saved.
        async with (
            self._contexts.turn(context_key(ctx)) as stream,
            aclosing(self._turn(ctx, stream)) as turn,
        ):
            # ``aclosing``: closing this stream runs ``_turn``'s cleanup now, not at GC.
            async for ev in turn:
                yield ev

    async def _turn(self, ctx: InboundContext, stream: Stream) -> AsyncIterator[AgentEvent]:
        queue: asyncio.Queue[Any] = asyncio.Queue()
        tokens_in = tokens_out = 0
        streamed = False

        async def observe(event: BaseEvent) -> None:
            queue.put_nowait(event)

        async def source() -> AsyncIterator[str | AgentEvent]:
            nonlocal tokens_in, tokens_out, streamed
            chunked = False  # chunks streamed for the model response in progress
            while (event := await queue.get()) is not _END:
                if isinstance(event, ModelMessageChunk):
                    if event.content:
                        streamed = chunked = True
                        yield event.content
                elif isinstance(event, ModelResponse):
                    # Once the turn streams, a response that came in one piece streams too.
                    if streamed and not chunked and event.content:
                        yield event.content
                    chunked = False
                elif isinstance(event, ToolCallEvent):
                    yield Status(f"calling {event.name}")
                elif isinstance(event, UsageEvent):
                    tokens_in, tokens_out = _add_usage(event, tokens_in, tokens_out)

        finished = False
        # Subscribed before the run opens its scope, so this sees each event before the
        # run's own subscribers act on it (in the order the turn produced them).
        with stream.sub_scope(observe):
            try:
                async with self.agent.run(ctx.text, stream=stream) as run:
                    # The drive is a task AG2 creates here, so it inherits the inbound
                    # contextvars (partner calls from tools are linked to this inbound task).
                    result = asyncio.ensure_future(run.result())
                    result.add_done_callback(lambda _: queue.put_nowait(_END))
                    try:
                        async for item in stream_events(source()):
                            yield item
                        reply = await result
                    finally:
                        if not result.done():
                            result.cancel()  # cancels AG2's drive of the turn
                        elif not result.cancelled():
                            result.exception()  # retrieved: raised above when it matters
                finished = True
            finally:
                if not finished:
                    # Cut short: a tool call left without a result would make providers
                    # reject the conversation's next turn.
                    await close_unanswered_tool_calls(stream.history, result=UNFINISHED_TOOL_RESULT)
        if self.stream_factory is None:
            await _trim(stream, self.history_limit)
        if tokens_in or tokens_out:
            yield Usage(tokens_in=tokens_in, tokens_out=tokens_out)
        yield Done() if streamed else Done(reply.body)


def _add_usage(event: UsageEvent, tokens_in: int, tokens_out: int) -> tuple[int, int]:
    usage = event.usage
    tokens_in += int(usage.prompt_tokens or 0)
    if event.provider == "anthropic":
        # Anthropic counts cache reads and writes apart from the input tokens (OpenAI-style
        # providers include cached tokens in the prompt count).
        tokens_in += int(usage.cache_read_input_tokens or 0)
        tokens_in += int(usage.cache_creation_input_tokens or 0)
    # Thinking tokens are part of the completion count for every provider.
    return tokens_in, tokens_out + int(usage.completion_tokens or 0)


def _is_message(event: BaseEvent) -> bool:
    # A tuple: ``|`` on AG2 event classes builds a stream condition, not a union.
    return isinstance(event, (ModelRequest, ModelResponse))


async def _trim(stream: Stream, limit: int) -> None:
    """Keep the shortest history suffix that starts at a request and holds at most ``limit``
    messages (or, if even the last request's turn holds more, that turn alone)."""
    events = list(await stream.history.get_events())
    count = sum(1 for e in events if _is_message(e))
    if count <= limit:
        return
    cut = 0
    for i, event in enumerate(events):  # ``count``: the messages from ``i`` on
        if type(event) is ModelRequest:  # a user turn (not a request drained mid-turn)
            cut = i
            if count <= limit:
                break
        if _is_message(event):
            count -= 1
    if cut:
        await stream.history.replace(events[cut:])


class _Target:
    """What a projected tool calls. Shared, not copied, by the deep copies AG2 makes of every
    tool it is given."""

    def __init__(self, ptool: PartnerTool, client: PartnerClient, caller: Principal | None):
        self.ptool = ptool
        self.client = client
        self.caller = caller

    def __copy__(self) -> _Target:
        return self

    def __deepcopy__(self, memo: dict[int, Any]) -> _Target:
        return self


async def _never_called() -> None:  # the tools' declared function: see ``__call__``
    raise NotImplementedError


class _PartnerFunctionTool(FunctionTool):
    """A ``FunctionTool`` advertising the partner tool's JSON schema and running the call
    through ``invoke`` (not a Python signature: the arguments are passed as given)."""

    def __init__(self, ptool: PartnerTool, client: PartnerClient, caller: Principal | None):
        declared = tool(
            _never_called,
            name=ptool.name,
            description=with_untrusted_note(ptool.description),
            schema=copy.deepcopy(strip_extensions(ptool.parameters)),
        )
        function = declared.schema.function
        super().__init__(
            declared.model,
            name=function.name,
            description=function.description,
            schema=function.parameters,
        )
        self._target = _Target(ptool, client, caller)

    async def __call__(self, event: ToolCallEvent, context: Any) -> ToolResultEvent:
        try:
            args = json.loads(event.arguments or "{}")
        except ValueError:
            args = None  # malformed: ``invoke`` answers ``rejected``
        if isinstance(args, dict):
            args = {k: v for k, v in args.items() if v is not None}
        t = self._target
        result = await invoke(t.ptool, args, t.client, inbound_task_id=None, caller=t.caller)
        return ToolResultEvent.from_call(event, result=json.dumps(result, default=str))


def as_ag2_tools(
    tools: list[PartnerTool], client: PartnerClient, *, caller: Principal | None = None
) -> list[FunctionTool]:
    """Project partner tools as AG2 ``FunctionTool``s returning the JSON envelope (text).

    Each tool advertises the partner tool's schema, without the gateway-only ``x-`` limits,
    as its parameters (passed to ``ag2.tools.tool(..., schema=)``, not inferred from a
    signature), and its description ends with the untrusted-data note. Explicit ``null``
    arguments are dropped (models send them for optional fields); ``invoke`` validates the
    rest against the full schema and answers invalid calls with ``rejected``. Inside an
    inbound run the inbound task and caller come from the contextvars, as for
    ``as_langchain_tools``. Give them to the agent: ``Agent(..., tools=as_ag2_tools(...))``."""
    return [_PartnerFunctionTool(t, client, caller) for t in tools]
