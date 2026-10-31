"""Google ADK adapter: any ADK agent (``google.adk.agents.BaseAgent``, e.g. an ``LlmAgent``)
becomes an A2A agent, and partners become ``FunctionTool``s.

Importing this module requires ``google-adk`` (the ``a2a-gateway[adk]`` extra); nothing in
the core imports it. A real ``LlmAgent`` on Gemini needs ``GOOGLE_API_KEY`` (or Vertex AI
credentials).

Telemetry: ADK records spans through the global OpenTelemetry API only, so they go wherever
the host's tracer provider sends them. It sets up no exporter of its own (that is the ``adk``
CLI's server, which this adapter does not use).
"""

from __future__ import annotations

import copy
import json
import logging
from collections.abc import AsyncGenerator, AsyncIterator
from contextlib import aclosing
from typing import Any

ADK_EXTRA_HINT = (
    "the Google ADK adapter needs the google-adk package: "
    "install it with: pip install 'a2a-gateway[adk]'"
)

try:
    from google.adk.agents import BaseAgent, RunConfig
    from google.adk.agents.run_config import StreamingMode
    from google.adk.events import Event
    from google.adk.runners import Runner
    from google.adk.sessions import BaseSessionService, InMemorySessionService
    from google.adk.tools import FunctionTool
    from google.adk.tools.tool_context import ToolContext
    from google.genai import types
except ImportError as e:  # pragma: no cover - exercised by a test that hides the package
    raise ImportError(ADK_EXTRA_HINT) from e

from a2agw.adapters._contexts import ContextRegistry, owner_id
from a2agw.adapters._stream import stream_events
from a2agw.consult.client import PartnerClient
from a2agw.consult.tools import PartnerTool, invoke, strip_extensions, with_untrusted_note
from a2agw.core.events import AgentEvent, Done, Failed, Status, Usage
from a2agw.core.spi import InboundContext
from a2agw.security.principal import Principal

__all__ = ["AdkAdapter", "as_adk_tools"]

MAX_SESSIONS = 1024  # (caller, context) pairs tracked per adapter (least recently used idle go)
AGENT_ERROR = "agent error"  # the failure an error response maps to (details are logged)


class AdkAdapter:
    """Runs each turn as ``Runner.run_async(user_id=..., session_id=ctx.context_id, ...)``.

    The ADK user is the caller (``ctx.principal.id``, or ``"anonymous"``) and the session is
    the A2A context, created on first use; so a follow-up message on the same context
    continues the conversation, and two callers never share one. Turns on the same context
    (and caller) are serialised. The default ``InMemorySessionService`` keeps the
    ``MAX_SESSIONS`` most recently used sessions (read when the adapter is constructed); an
    evicted user's last session goes with their user-scoped state. A given
    ``session_service`` is never pruned.
    Pass a persistent one (e.g. ``DatabaseSessionService``) with ``durable_sessions=True`` (it
    is required then) to keep conversations across restarts.

    The model is asked to stream (``StreamingMode.SSE``). Partial text streams as the artifact
    "output" (the complete response that follows does not repeat it; a model that sends
    no partials streams each complete response instead; thoughts are left out). Each
    function call is reported as ``Status("calling <tool>")``. Token usage summed over the
    run's model calls becomes one ``Usage`` event, when non-zero; then ``Done()``. An error
    response (``error_code``) ends the turn with ``Failed("agent error")``. Errors raised by
    the agent propagate, so the executor fails the task. Cancelling the turn, or closing its
    event stream, cancels ADK's background run.
    """

    def __init__(
        self,
        agent: BaseAgent,
        *,
        app_name: str = "a2agw",
        session_service: BaseSessionService | None = None,
        durable_sessions: bool = False,
    ):
        if durable_sessions and session_service is None:
            raise ValueError(
                "durable_sessions=True needs a persistent session_service "
                "(e.g. google.adk.sessions.DatabaseSessionService)"
            )
        self.agent = agent
        self.app_name = app_name
        self.durable_sessions = durable_sessions
        self._owns_sessions = session_service is None
        self.session_service = session_service or InMemorySessionService()
        self.runner = Runner(
            agent=agent,
            app_name=app_name,
            session_service=self.session_service,
            auto_create_session=True,
        )
        self.run_config = RunConfig(streaming_mode=StreamingMode.SSE)
        # Keyed by (user id, context id), as ADK keys its sessions. A pair with a turn in
        # flight is never dropped; an idle one goes with its default in-memory session.
        self._contexts: ContextRegistry[tuple[str, str], None] = ContextRegistry(
            lambda _key: None, max_size=MAX_SESSIONS, on_evict=self._evicted
        )

    def _evicted(self, key: tuple[str, str], _value: None) -> None:
        service = self.session_service
        if not self._owns_sessions or not isinstance(service, InMemorySessionService):
            return
        # Synchronous on purpose: nothing may run between the drop and the clean-up (an
        # awaited ``delete_session`` could remove a session a new turn already uses).
        user_id, session_id = key
        users = service.sessions.get(self.app_name, {})
        users.get(user_id, {}).pop(session_id, None)
        if any(user == user_id for user, _ in self._contexts):
            return  # the user still has a tracked session (maybe one being created)
        # Their last one: drop the user with their user-scoped (``user:``) state.
        users.pop(user_id, None)
        service.user_state.get(self.app_name, {}).pop(user_id, None)

    async def run(self, ctx: InboundContext) -> AsyncIterator[AgentEvent]:
        user_id = owner_id(ctx)
        # Turns on one session run one at a time: each sees the events the last one saved.
        async with (
            self._contexts.turn((user_id, ctx.context_id)),
            aclosing(self._turn(ctx, user_id)) as turn,
        ):
            # ``aclosing``: closing this stream runs ``_turn``'s cleanup now, not at GC.
            async for ev in turn:
                yield ev

    async def _turn(self, ctx: InboundContext, user_id: str) -> AsyncGenerator[AgentEvent, None]:
        message = types.Content(role="user", parts=[types.Part(text=ctx.text)])
        tokens_in = tokens_out = 0
        failed: Event | None = None

        async def source(events: AsyncIterator[Event]) -> AsyncIterator[str | AgentEvent]:
            nonlocal tokens_in, tokens_out, failed
            partial = False  # text streamed for the model response in progress
            async for event in events:
                text = _text(event)
                if event.partial:
                    if text:
                        partial = True
                        yield text
                    continue
                usage = event.usage_metadata
                if usage is not None:
                    tokens_in += (usage.prompt_token_count or 0) + (
                        usage.tool_use_prompt_token_count or 0
                    )
                    tokens_out += (usage.candidates_token_count or 0) + (
                        usage.thoughts_token_count or 0
                    )
                for fc in event.get_function_calls():
                    yield Status(f"calling {fc.name}")
                if event.error_code:
                    failed = event
                elif text and not partial:
                    yield text
                partial = False

        # ``aclosing``: ADK runs the agent in a background task that only closing
        # ``run_async`` cancels. A closed or cancelled turn must stop it now, not whenever
        # the generator is garbage collected.
        events = self.runner.run_async(
            user_id=user_id,
            session_id=ctx.context_id,
            new_message=message,
            run_config=self.run_config,
        )
        async with aclosing(events) as stream:
            async for item in stream_events(source(stream)):
                yield item
        if tokens_in or tokens_out:
            yield Usage(tokens_in=tokens_in, tokens_out=tokens_out)
        if failed is not None:
            # The error message may quote the conversation: not logged.
            _log(ctx).warning("ADK agent error response: error_code=%s", failed.error_code)
            yield Failed(AGENT_ERROR)
            return
        yield Done()


def _log(ctx: InboundContext) -> logging.Logger:
    return logging.getLogger(f"a2agw.agent.{ctx.agent_id}")


def _text(event: Event) -> str:
    """The answer text of an event (thoughts left out)."""
    if event.content is None or not event.content.parts:
        return ""
    return "".join(p.text for p in event.content.parts if p.text and not p.thought)


class _PartnerFunctionTool(FunctionTool):
    """A ``FunctionTool`` with an explicit declaration: the partner tool's JSON schema, given
    to the model as ``parameters_json_schema``."""

    def __init__(self, ptool: PartnerTool, client: PartnerClient, caller: Principal | None):
        async def partner_tool(**kwargs: Any) -> dict[str, Any]:  # never called: see run_async
            raise NotImplementedError

        super().__init__(partner_tool)
        self.name = ptool.name
        self.description = with_untrusted_note(ptool.description)
        self._ptool = ptool
        self._client = client
        self._caller = caller
        self._schema = copy.deepcopy(strip_extensions(ptool.parameters))

    def _get_declaration(self) -> types.FunctionDeclaration:
        return types.FunctionDeclaration(
            name=self.name,
            description=self.description,
            parameters_json_schema=copy.deepcopy(self._schema),
        )

    async def run_async(self, *, args: dict[str, Any], tool_context: ToolContext) -> Any:
        if isinstance(args, dict):
            args = {k: v for k, v in args.items() if v is not None}
        result = await invoke(
            self._ptool, args, self._client, inbound_task_id=None, caller=self._caller
        )
        # A function response is a JSON object: round-trip any non-JSON value to text.
        return json.loads(json.dumps(result, default=str))


def as_adk_tools(
    tools: list[PartnerTool], client: PartnerClient, *, caller: Principal | None = None
) -> list[FunctionTool]:
    """Project partner tools as ``FunctionTool``s returning the JSON envelope (a dict).

    Each tool declares the partner tool's schema, without the gateway-only ``x-`` limits, as
    its ``parameters_json_schema``. Explicit ``null`` arguments are dropped (models send them
    for optional fields); ``invoke`` validates the rest against the full schema and answers
    invalid calls with ``rejected``. Inside an inbound run the inbound task and caller come
    from the contextvars, as for ``as_langchain_tools``."""
    return [_PartnerFunctionTool(t, client, caller) for t in tools]
