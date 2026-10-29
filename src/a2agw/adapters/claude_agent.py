"""Claude Agent SDK adapter: a Claude Code agent (``claude_agent_sdk.query``) becomes an A2A
agent, and partners become tools of an in-process SDK MCP server.

Importing this module requires ``claude-agent-sdk`` (the ``a2a-gateway[claude]`` extra);
nothing in the core imports it. A real run starts the ``claude`` CLI the SDK bundles, which
needs ``ANTHROPIC_API_KEY`` (or another Claude Code login).

Session continuity: each (caller, A2A context) pair maps to the SDK session its last turn ran
in, and the caller's next turn on that context resumes it (``options.resume``); another caller
sending the same ``contextId`` starts its own session. The map is in memory, bounded to the
``MAX_SESSIONS`` most recently used pairs, unless a ``session_store`` mapping is given.
Durable resumption (``durable_sessions=True``) needs both halves to survive a restart: a
persistent ``session_store`` for the map, and the CLI's transcripts (its local
``~/.claude/projects`` directory, or the SDK's own ``ClaudeAgentOptions.session_store``).
"""

from __future__ import annotations

import copy
import dataclasses
import json
import logging
from collections.abc import AsyncIterator, Callable, MutableMapping
from contextlib import aclosing
from dataclasses import dataclass
from typing import Any

CLAUDE_EXTRA_HINT = (
    "the Claude Agent SDK adapter needs the claude-agent-sdk package: "
    "install it with: pip install 'a2a-gateway[claude]'"
)

try:
    import claude_agent_sdk
    from claude_agent_sdk import (
        AssistantMessage,
        ClaudeAgentOptions,
        McpSdkServerConfig,
        ResultMessage,
        StreamEvent,
        SystemMessage,
        TextBlock,
        ToolUseBlock,
        create_sdk_mcp_server,
        tool,
    )
except ImportError as e:  # pragma: no cover - exercised by a test that hides the package
    raise ImportError(CLAUDE_EXTRA_HINT) from e

from a2agw.adapters._contexts import ContextRegistry, context_key
from a2agw.adapters._stream import MessageTexts, stream_events
from a2agw.consult.client import PartnerClient
from a2agw.consult.tools import PartnerTool, invoke, strip_extensions, with_untrusted_note
from a2agw.core.events import AgentEvent, Done, Failed, Status, Usage
from a2agw.core.spi import InboundContext
from a2agw.security.principal import Principal

__all__ = ["ClaudeAgentAdapter", "as_claude_tools"]

DEFAULT_MAX_SESSIONS = 10_000
MAX_SESSIONS = DEFAULT_MAX_SESSIONS  # (caller, context) keys per adapter (LRU idle ones go)
AGENT_ERROR = "agent error"  # the failure an error result maps to (details are logged)

# Options that choose the session a run continues. The adapter picks it per A2A context
# (``resume``), so any of these set would continue, fork or pin one session across contexts.
# Checked when the installed SDK has the field.
_SESSION_OPTIONS = (
    "continue_conversation",
    "session_id",
    "fork_session",
    "resume",
    "resume_session_at",
)


@dataclass
class _Context:
    """Per-context state: (without a ``session_store``) the id of the SDK session to resume."""

    session_id: str | None = None


class ClaudeAgentAdapter:
    """Runs each turn as ``query(prompt=ctx.text, options=...)`` of the Claude Agent SDK.

    Sessions belong to the caller and the A2A context together, under the key
    ``"<principal id or anonymous>\\x1f<context id>"`` (``_contexts.context_key``).
    ``options`` (default ``ClaudeAgentOptions()``) is copied for every turn with ``resume``
    set to the key's SDK session (None on its first turn) and
    ``include_partial_messages=True``; the caller's object is never changed. Options that
    choose the session themselves (``continue_conversation``, ``session_id``,
    ``fork_session``, ``resume``, ``resume_session_at``) are refused with ``ValueError``, at
    construction and again on every turn: they would carry one conversation across contexts.
    Turns on the same key are serialised. ``query`` defaults to ``claude_agent_sdk.query``.

    ``session_store`` holds the ``key -> session_id`` map instead of the in-memory LRU (the
    ``MAX_SESSIONS`` most recently used keys; ``MAX_SESSIONS`` is read when the adapter is
    constructed); pass a persistent mapping with ``durable_sessions=True`` (it is required
    then) so conversations resume across restarts. Stores written before keys included the
    caller (bare context ids) are not resumed.

    Text streams as the artifact "output": partial-message deltas when the CLI sends them,
    else one chunk per text block. Each tool use is reported as ``Status("calling <tool>")``.
    Subagent messages are not part of the answer. The ``ResultMessage`` ends the turn:
    ``Usage`` (tokens and ``total_cost_usd``, when non-zero), then ``Done`` (with the result
    text when nothing streamed), or ``Failed("agent error")`` for an error result or a run
    without one. Errors raised by ``query`` propagate, so the executor fails the task.
    Cancelling the turn, or closing its event stream, closes ``query`` (which stops the CLI).
    """

    def __init__(
        self,
        options: ClaudeAgentOptions | None = None,
        *,
        query: Callable[..., AsyncIterator[Any]] | None = None,
        durable_sessions: bool = False,
        session_store: MutableMapping[str, str] | None = None,
    ):
        if durable_sessions and session_store is None:
            raise ValueError(
                "durable_sessions=True needs a persistent session_store mapping "
                "(caller and context key -> Claude session id)"
            )
        self.options = options if options is not None else ClaudeAgentOptions()
        _check_options(self.options)
        self.query = query if query is not None else claude_agent_sdk.query
        self.durable_sessions = durable_sessions
        self.session_store = session_store
        # The ``MAX_SESSIONS`` most recently used (caller, context) keys: a key with a turn in
        # flight is never dropped; an idle one goes with its session id.
        self._contexts: ContextRegistry[str, _Context] = ContextRegistry(
            lambda _key: _Context(), max_size=MAX_SESSIONS
        )

    def _session(self, key: str, entry: _Context) -> str | None:
        if self.session_store is not None:
            return self.session_store.get(key)
        return entry.session_id

    def _remember(self, key: str, entry: _Context, session_id: str) -> None:
        if self.session_store is not None:
            if self.session_store.get(key) != session_id:
                self.session_store[key] = session_id
        else:
            entry.session_id = session_id

    async def run(self, ctx: InboundContext) -> AsyncIterator[AgentEvent]:
        # Turns on one context run one at a time: each resumes the session the last one used.
        async with (
            self._contexts.turn(context_key(ctx)) as entry,
            aclosing(self._turn(ctx, entry)) as turn,
        ):
            # ``aclosing``: closing this stream runs ``_turn``'s cleanup now, not at GC.
            async for ev in turn:
                yield ev

    async def _turn(self, ctx: InboundContext, entry: _Context) -> AsyncIterator[AgentEvent]:
        # Checked again here: ``self.options`` may have been changed since construction.
        _check_options(self.options)
        key = context_key(ctx)
        options = dataclasses.replace(
            self.options,
            resume=self._session(key, entry),
            include_partial_messages=True,
        )
        final: ResultMessage | None = None
        streamed = False

        async def source(messages: AsyncIterator[Any]) -> AsyncIterator[str | AgentEvent]:
            nonlocal final, streamed
            partial = False  # deltas streamed for the assistant message in progress
            # The CLI sends one AssistantMessage per content block, and the blocks of one API
            # message share its id: only a new id starts a new message (no id: the same one).
            texts = MessageTexts()
            current: str | None = None

            def message(message_id: Any) -> None:
                nonlocal current
                if not isinstance(message_id, str) or not message_id:
                    return
                if current is not None and message_id != current:
                    texts.end_message()
                current = message_id

            async for msg in messages:
                session_id = _session_id(msg)
                if session_id:
                    self._remember(key, entry, session_id)
                if getattr(msg, "parent_tool_use_id", None):
                    continue  # a subagent's messages are not this agent's answer
                if isinstance(msg, StreamEvent):
                    message(_started_id(msg.event))
                    text = _delta_text(msg.event)
                    if text:
                        partial = streamed = True
                        yield texts.text(text)
                elif isinstance(msg, AssistantMessage):
                    message(msg.message_id)
                    for block in msg.content:
                        if isinstance(block, TextBlock) and block.text and not partial:
                            streamed = True
                            yield texts.text(block.text)
                        elif isinstance(block, ToolUseBlock):
                            yield Status(f"calling {block.name}")
                    partial = False
                elif isinstance(msg, ResultMessage):
                    final = msg

        # ``aclosing``: a closed or cancelled turn closes ``query`` now (the SDK then stops
        # the CLI subprocess), not whenever its generator is garbage collected.
        async with aclosing(self.query(prompt=ctx.text, options=options)) as messages:
            async for item in stream_events(source(messages)):
                yield item
        if final is None:
            _log(ctx).warning("Claude Agent SDK run ended without a result")
            yield Failed(AGENT_ERROR)
            return
        for ev in _usage(final):
            yield ev
        if final.is_error or final.subtype != "success":
            # The result text and ``errors`` may quote the conversation: not logged.
            _log(ctx).warning(
                "Claude Agent SDK run failed: subtype=%s api_error_status=%s",
                final.subtype,
                final.api_error_status,
            )
            yield Failed(AGENT_ERROR)
            return
        yield Done() if streamed else Done(text=final.result)


def _check_options(options: ClaudeAgentOptions) -> None:
    for name in _SESSION_OPTIONS:
        if getattr(options, name, None):
            raise ValueError(
                f"ClaudeAgentOptions.{name} is not supported: the adapter resumes one Claude "
                "session per caller and A2A context itself"
            )


def _log(ctx: InboundContext) -> logging.Logger:
    return logging.getLogger(f"a2agw.agent.{ctx.agent_id}")


def _started_id(event: Any) -> str | None:
    """The API message id a ``message_start`` partial event opens, else None."""
    if not isinstance(event, dict) or event.get("type") != "message_start":
        return None
    message = event.get("message")
    mid = message.get("id") if isinstance(message, dict) else None
    return mid if isinstance(mid, str) else None


def _session_id(msg: Any) -> str | None:
    if isinstance(msg, SystemMessage):
        if msg.subtype != "init":
            return None
        sid = msg.data.get("session_id")
        return sid if isinstance(sid, str) else None
    if isinstance(msg, ResultMessage):
        return msg.session_id or None
    return None


def _delta_text(event: dict[str, Any]) -> str:
    """The text of a raw Anthropic stream event, when it is a text delta."""
    if event.get("type") != "content_block_delta":
        return ""
    delta = event.get("delta") or {}
    if delta.get("type") != "text_delta":
        return ""
    return str(delta.get("text") or "")


def _usage(result: ResultMessage) -> list[AgentEvent]:
    usage = result.usage or {}
    tokens_in = sum(
        int(usage.get(k) or 0)
        for k in ("input_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")
    )
    tokens_out = int(usage.get("output_tokens") or 0)
    cost = float(result.total_cost_usd or 0.0)
    if not (tokens_in or tokens_out or cost):
        return []
    return [Usage(tokens_in=tokens_in, tokens_out=tokens_out, cost=cost)]


def as_claude_tools(
    tools: list[PartnerTool],
    client: PartnerClient,
    *,
    server_name: str = "a2a_partners",
    caller: Principal | None = None,
) -> McpSdkServerConfig:
    """Project partner tools as an in-process SDK MCP server (``create_sdk_mcp_server``).

    Put it in ``ClaudeAgentOptions.mcp_servers`` under ``server_name``; Claude Code names the
    tools ``mcp__<server_name>__<tool>`` (allow them with
    ``allowed_tools=["mcp__<server_name>"]``).
    Each tool returns the JSON envelope as text. The schema is a copy of the tool's without
    the gateway-only ``x-`` limits; the SDK validates arguments against it before the handler
    runs, and ``invoke`` enforces the full schema. Inside an inbound run the inbound task and
    caller come from the contextvars, as for ``as_langchain_tools``."""

    def make(ptool: PartnerTool) -> Any:
        schema = copy.deepcopy(strip_extensions(ptool.parameters))
        # The SDK reads a dict without ``properties`` as a {name: type} map, not a schema.
        schema.setdefault("type", "object")
        schema.setdefault("properties", {})

        @tool(ptool.name, with_untrusted_note(ptool.description), schema)
        async def handler(args: dict[str, Any]) -> dict[str, Any]:
            result = await invoke(ptool, args, client, inbound_task_id=None, caller=caller)
            return {"content": [{"type": "text", "text": json.dumps(result, default=str)}]}

        return handler

    return create_sdk_mcp_server(server_name, tools=[make(t) for t in tools])
