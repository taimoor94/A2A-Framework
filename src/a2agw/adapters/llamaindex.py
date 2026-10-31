"""LlamaIndex adapter: a LlamaIndex agent workflow (a ``FunctionAgent``, any other
``BaseWorkflowAgent``, or an ``AgentWorkflow``) becomes an A2A agent, and partners become
LlamaIndex ``FunctionTool``s.

Importing this module requires ``llama-index-core`` (the ``a2a-gateway[llamaindex]`` extra;
import name ``llama_index.core``); nothing in the core imports it.

Telemetry: LlamaIndex's instrumentation dispatcher has no exporter unless the application
adds one; this adapter adds none. Tokenizers come from the copies bundled with
``llama-index-core`` (no download).
"""

from __future__ import annotations

import asyncio
import copy
import json
import keyword
import warnings
from collections.abc import AsyncGenerator, AsyncIterator, Callable
from contextlib import aclosing
from dataclasses import dataclass
from typing import Any, ClassVar, Literal

LLAMAINDEX_EXTRA_HINT = (
    "the LlamaIndex adapter needs llama-index-core: install it with: "
    "pip install 'a2a-gateway[llamaindex]'"
)

try:
    from llama_index.core.agent.workflow import (
        AgentOutput,
        AgentStream,
        AgentWorkflow,
        BaseWorkflowAgent,
        ToolCall,
    )
    from llama_index.core.bridge.pydantic import BaseModel, Field, create_model
    from llama_index.core.memory import BaseMemory, ChatMemoryBuffer
    from llama_index.core.tools import FunctionTool, ToolMetadata
    from llama_index.core.workflow import Context
    from workflows.context.state_store import UnserializableKeyWarning
except ImportError as e:  # pragma: no cover - exercised by a test that hides the package
    raise ImportError(LLAMAINDEX_EXTRA_HINT) from e

from a2agw.adapters._contexts import ContextRegistry, context_key
from a2agw.adapters._stream import MessageTexts, stream_events
from a2agw.consult.client import PartnerClient
from a2agw.consult.tools import PartnerTool, invoke, strip_extensions, with_untrusted_note
from a2agw.core.events import AgentEvent, Done, Status, Usage
from a2agw.core.spi import InboundContext
from a2agw.security.principal import Principal

__all__ = ["LlamaIndexAdapter", "as_llamaindex_tools"]

MAX_SESSIONS = 10_000  # (caller, context) conversations kept per adapter (LRU, idle only)
MAX_HISTORY_MESSAGES = 200  # messages a default memory keeps (cut at a user message)


@dataclass
class _Session:
    """One conversation: the workflow ``Context`` (agent state, current agent) and the chat
    memory, which this adapter holds itself (see ``LlamaIndexAdapter``)."""

    context: Context
    memory: BaseMemory


class LlamaIndexAdapter:
    """Runs each turn as ``workflow.run(user_msg=ctx.text, ctx=<Context>, memory=<memory>)``.

    There is one conversation per caller and A2A context (key ``"<principal id or
    anonymous>\\x1f<context id>"``, ``_contexts.context_key``): a follow-up from the same
    caller on the same context continues it, and another caller sending that ``contextId``
    does not. Turns on one key are serialised; the ``MAX_SESSIONS`` most recently used keys
    are kept (read when the adapter is constructed), idle ones evicted first.

    A conversation is a workflow ``Context`` reused across turns plus its chat memory. The
    memory is passed to every run: a reused ``Context`` restarts from its serialized state,
    and LlamaIndex cannot serialize the chat memory there (it drops the ``memory`` key with
    an ``UnserializableKeyWarning``, silenced around the call), so memory kept only in the
    ``Context`` would be lost after the first turn. By default each key gets a
    ``ChatMemoryBuffer`` sized for the agent's LLM, trimmed after each turn to its last
    ``MAX_HISTORY_MESSAGES`` messages (cut at a user message, so a tool call keeps its
    result). Pass ``memory_factory(key)`` returning memory on a persistent chat store with
    ``durable_sessions=True`` (it is required then) to keep conversations across restarts;
    such memories are never trimmed.

    ``AgentStream`` deltas become the artifact "output"; each ``ToolCall`` is reported as
    ``Status("calling <tool>")``. Token usage is best effort: LlamaIndex has no
    provider-neutral usage, so each model call's ``AgentOutput.raw`` (the provider's raw
    response) is read for a ``usage`` with ``prompt_tokens``/``completion_tokens`` or
    ``input_tokens``/``output_tokens`` (attributes or keys), and the turn's sum, when
    non-zero, is reported as one ``Usage`` (no cost). Providers or integrations that put
    usage elsewhere, or none in ``raw`` (a stream's last chunk often has none unless the
    provider is asked for it), report nothing, and a malformed ``usage`` counts as none.
    The turn ends with ``Done()`` if it streamed, else with ``Done(<final output text>)``.
    Errors raised by the workflow propagate, so the executor fails the task. Cancelling the
    turn, or closing its event stream, cancels the workflow run (``handler.cancel_run()``,
    shielded) so none of its steps keep running; the conversation then gets a fresh
    ``Context`` (the cut-short run's state, such as a half-finished tool-call scratchpad, is
    not carried into the next turn) and keeps its memory.
    """

    def __init__(
        self,
        workflow: BaseWorkflowAgent | AgentWorkflow,
        *,
        durable_sessions: bool = False,
        memory_factory: Callable[[str], BaseMemory] | None = None,
    ):
        if not isinstance(workflow, (BaseWorkflowAgent, AgentWorkflow)):
            raise TypeError(
                "LlamaIndexAdapter serves agent workflows (FunctionAgent, ReActAgent, "
                f"AgentWorkflow, ...), not {type(workflow).__name__}"
            )
        if durable_sessions and memory_factory is None:
            raise ValueError(
                "durable_sessions=True needs a memory_factory returning memory on a "
                "persistent chat store (the default memory lives in this process)"
            )
        self.workflow = workflow
        self.durable_sessions = durable_sessions
        self.memory_factory = memory_factory
        self._contexts: ContextRegistry[str, _Session] = ContextRegistry(
            self._new_session, max_size=MAX_SESSIONS
        )

    def _new_session(self, key: str) -> _Session:
        memory = self.memory_factory(key) if self.memory_factory else self._default_memory()
        return _Session(Context(self.workflow), memory)

    def _default_memory(self) -> BaseMemory:
        # The memory the workflow would make itself, without falling back to
        # ``Settings.llm`` (which would build an OpenAI client).
        llm = getattr(self.workflow, "llm", None)
        if isinstance(self.workflow, AgentWorkflow):
            llm = self.workflow.agents[self.workflow.root_agent].llm
        return ChatMemoryBuffer.from_defaults(llm=llm)

    async def run(self, ctx: InboundContext) -> AsyncIterator[AgentEvent]:
        # Turns on one conversation run one at a time: each sees the memory the last left.
        async with (
            self._contexts.turn(context_key(ctx)) as session,
            aclosing(self._turn(ctx, session)) as turn,
        ):
            # ``aclosing``: closing this stream runs ``_turn``'s cleanup now, not at GC.
            async for ev in turn:
                yield ev

    async def _turn(
        self, ctx: InboundContext, session: _Session
    ) -> AsyncGenerator[AgentEvent, None]:
        streamed = False
        tokens = [0, 0]  # in, out: summed over the turn's model calls

        with warnings.catch_warnings():
            # Synchronous: the reused Context is serialized here, without its memory
            # (passed below instead). ``catch_warnings`` swaps the process-wide filters and
            # is not thread-safe, but it wraps only this one synchronous call: no await
            # runs inside it, so no other coroutine on this loop sees the changed filters.
            warnings.simplefilter("ignore", UnserializableKeyWarning)
            handler = self.workflow.run(
                user_msg=ctx.text, ctx=session.context, memory=session.memory
            )

        async def source() -> AsyncIterator[str | AgentEvent]:
            nonlocal streamed
            texts = MessageTexts()  # one ``AgentOutput`` per model call ends its message
            async with aclosing(handler.stream_events()) as events:
                async for event in events:
                    if isinstance(event, AgentStream):
                        if event.delta:
                            streamed = True
                            yield texts.text(event.delta)
                    elif isinstance(event, ToolCall):
                        yield Status(f"calling {event.tool_name}")
                    elif isinstance(event, AgentOutput):
                        texts.end_message()
                        tokens_in, tokens_out = _raw_usage(event.raw)
                        tokens[0] += tokens_in
                        tokens[1] += tokens_out

        finished = False
        try:
            async with aclosing(stream_events(source())) as items:
                async for item in items:
                    yield item
            result = await handler
            finished = True
        finally:
            if not finished:
                # The run's steps are tasks of their own: stop them now (shielded, so a
                # second cancellation cannot leave them running), and start the next turn
                # from a clean Context.
                if not handler.is_done():
                    await asyncio.shield(handler.cancel_run())
                session.context = Context(self.workflow)
        if self.memory_factory is None:
            await _trim(session.memory, MAX_HISTORY_MESSAGES)
        if tokens[0] or tokens[1]:
            yield Usage(tokens_in=tokens[0], tokens_out=tokens[1])
        yield Done() if streamed else Done(str(result) if result is not None else None)


def _count(source: Any, *names: str) -> int:
    """The first of ``names`` on ``source`` (an attribute or a key) that holds a token
    count, else 0."""
    for name in names:
        value = source.get(name) if isinstance(source, dict) else getattr(source, name, None)
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            return value
    return 0


def _raw_usage(raw: Any) -> tuple[int, int]:
    """(tokens in, tokens out) from a provider's raw response, best effort: its ``usage``
    (attribute or key) in the OpenAI (``prompt_tokens``/``completion_tokens``) or Anthropic
    (``input_tokens``/``output_tokens``) shape; (0, 0) when there is none. Never raises:
    ``raw`` is whatever the provider integration put there, so anything unexpected (a
    property that raises, an odd ``usage`` type) counts as no usage."""
    try:
        usage = raw.get("usage") if isinstance(raw, dict) else getattr(raw, "usage", None)
        if usage is None:
            return 0, 0
        return (
            _count(usage, "prompt_tokens", "input_tokens"),
            _count(usage, "completion_tokens", "output_tokens"),
        )
    except Exception:  # noqa: BLE001 - best effort: a broken shape is no usage
        return 0, 0


async def _trim(memory: BaseMemory, limit: int) -> None:
    """Keep the shortest suffix of the history that starts at a user message and holds at
    most ``limit`` messages (or, if the last user turn alone holds more, that turn)."""
    messages = await memory.aget_all()
    if len(messages) <= limit:
        return
    starts = [i for i, m in enumerate(messages) if m.role == "user"]
    cut = next((i for i in starts if len(messages) - i <= limit), starts[-1] if starts else 0)
    if cut:
        await memory.aset(messages[cut:])


# -- outbound -----------------------------------------------------------------------------

_JSON_TYPES: dict[str, Any] = {
    "string": str,
    "integer": int,
    "number": float,
    "boolean": bool,
    "object": dict[str, Any],
}


def _annotation(schema: Any) -> Any:
    """A Python type for one JSON schema property (enums, primitives, arrays, objects)."""
    if not isinstance(schema, dict):
        return Any
    if isinstance(schema.get("enum"), list) and schema["enum"]:
        return Literal[tuple(schema["enum"])]
    t = schema.get("type")
    if t == "array":
        return list[_annotation(schema.get("items"))]  # type: ignore[misc]
    return _JSON_TYPES.get(t, Any) if isinstance(t, str) else Any


class _PartnerArgs(BaseModel):
    """Base of the projected tools' ``fn_schema`` models: their JSON schema is the partner
    tool's (stripped) schema, verbatim."""

    partner_schema: ClassVar[dict[str, Any]] = {}

    @classmethod
    def model_json_schema(cls, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return copy.deepcopy(cls.partner_schema)


def _args_model(name: str, schema: dict[str, Any]) -> type[_PartnerArgs]:
    """The ``fn_schema`` for one partner tool.

    ``model_json_schema()`` returns ``schema`` exactly, so whatever a LlamaIndex LLM
    integration reads (``get_parameters_dict``, ``to_openai_tool``, or the model's own JSON
    schema) declares the partner tool's parameters, constraints and nesting included. The
    fields are for code that inspects them: each property whose name is a Python identifier
    becomes a field (required ones required, the others ``None`` by default, enums as
    ``Literal``, arrays and objects as lists and dicts); constraints are not repeated there.
    Nothing validates calls with this model: ``invoke`` checks the original schema."""
    required = set(schema.get("required") or ())
    fields: dict[str, Any] = {}
    for prop, sub in (schema.get("properties") or {}).items():
        if not prop.isidentifier() or keyword.iskeyword(prop) or prop.startswith("_"):
            continue
        description = sub.get("description") if isinstance(sub, dict) else None
        ann = _annotation(sub)
        if prop in required:
            fields[prop] = (ann, Field(description=description))
        else:
            fields[prop] = (ann | None, Field(default=None, description=description))
    model = create_model(f"{name}_args", __base__=_PartnerArgs, **fields)
    model.partner_schema = copy.deepcopy(schema)
    return model


@dataclass
class _PartnerToolMetadata(ToolMetadata):
    """Declares the ``fn_schema``'s JSON schema whole: the base ``get_parameters_dict``
    keeps only some top-level keys, which would drop ``additionalProperties: false``."""

    def get_parameters_dict(self) -> dict:
        assert self.fn_schema is not None
        return self.fn_schema.model_json_schema()


def _partner_function_tool(
    ptool: PartnerTool, client: PartnerClient, caller: Principal | None
) -> FunctionTool:
    async def call_partner(**kwargs: Any) -> str:
        args = {k: v for k, v in kwargs.items() if v is not None}
        result = await invoke(ptool, args, client, inbound_task_id=None, caller=caller)
        return json.dumps(result, default=str)

    schema = strip_extensions(ptool.parameters)
    metadata = _PartnerToolMetadata(
        name=ptool.name,
        description=with_untrusted_note(ptool.description),
        fn_schema=_args_model(ptool.name, schema),
    )
    return FunctionTool.from_defaults(async_fn=call_partner, tool_metadata=metadata)


def as_llamaindex_tools(
    tools: list[PartnerTool], client: PartnerClient, *, caller: Principal | None = None
) -> list[FunctionTool]:
    """Project partner tools as LlamaIndex ``FunctionTool``s returning the JSON envelope.

    Each tool declares the partner tool's schema, without the gateway-only ``x-`` limits,
    as its parameters (an explicit ``fn_schema`` whose JSON schema is that schema verbatim,
    not one inferred from a signature), and its description ends with the untrusted-data
    note. Explicit ``null`` arguments are dropped (models send them for optional fields);
    ``invoke`` validates the rest against the full schema and answers invalid calls with
    ``rejected``. Inside an inbound run the inbound task and caller come from the
    contextvars, as for ``as_langchain_tools``. Give them to the agent:
    ``FunctionAgent(tools=as_llamaindex_tools(...), llm=...)``."""
    return [_partner_function_tool(t, client, caller) for t in tools]
