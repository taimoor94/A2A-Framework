"""CrewAI adapter: a CrewAI ``Crew`` becomes an A2A agent, and partners become CrewAI
``BaseTool``s.

Importing this module requires ``crewai`` (the ``a2a-gateway[crewai]`` extra); nothing in the
core imports it. crewai pins ``mcp<2`` and ``openai<3``, so it cannot be installed next to the
``mcp`` or ``openai`` extras (nor ``all``): give a CrewAI gateway its own environment.

Telemetry: CrewAI sends anonymous usage telemetry (to telemetry.crewai.com) and can collect
traces unless told not to. Importing crewai makes no network call; running a crew does. Set
``CREWAI_DISABLE_TELEMETRY=true`` and ``CREWAI_TRACING_ENABLED=false`` (or
``OTEL_SDK_DISABLED=true``) in the gateway's environment to turn both off.

Files: CrewAI keeps an encryption key for platform credentials
(``<user data dir>/crewai/credentials``), its settings (``~/.config/crewai``) and a database of
the latest kickoff's task outputs (``<user data dir>/<CREWAI_STORAGE_DIR or the current
directory's name>``) under the user's home directory; the user data directory is
``~/Library/Application Support`` on macOS and ``~/.local/share`` (``XDG_DATA_HOME``) on
Linux. The adapter keeps each turn's task outputs in memory instead, but building a crew
still creates that database file. To keep all of it out of the user's home, set
``CREWAI_STORAGE_DIR`` to an absolute directory and run the gateway with ``HOME`` (and
``XDG_CONFIG_HOME``/``XDG_DATA_HOME``) pointing at a directory of its own; ``HOME`` must be
set before crewai is imported (its settings path is fixed at import).
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import copy
import json
import keyword
import threading
from collections.abc import AsyncIterator, Callable, Coroutine
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, ClassVar, Literal

CREWAI_EXTRA_HINT = (
    "the CrewAI adapter needs crewai: install it with: pip install 'a2a-gateway[crewai]' "
    "(in an environment of its own: crewai pins mcp<2 and openai<3)"
)

try:
    from crewai import Crew
    from crewai.llms.base_llm import BaseLLM
    from crewai.tools import BaseTool
    from crewai.utilities.task_output_storage_handler import TaskOutputStorageHandler
    from pydantic import BaseModel, ConfigDict, Field, create_model
except ImportError as e:  # pragma: no cover - exercised by a test that hides the package
    raise ImportError(CREWAI_EXTRA_HINT) from e

from a2agw.adapters._contexts import ContextRegistry, context_key
from a2agw.consult.client import PartnerClient
from a2agw.consult.tools import PartnerTool, invoke, strip_extensions, with_untrusted_note
from a2agw.core.events import AgentEvent, Done, Usage
from a2agw.core.spi import InboundContext
from a2agw.gateway.calls import INBOUND_ENDED
from a2agw.security.principal import Principal

__all__ = ["CrewAIAdapter", "as_crewai_tools"]

MAX_SESSIONS = 10_000  # (caller, context) keys whose turns are serialised (LRU, idle only)
LOOP_CHECK_S = 1.0  # how often a worker thread waiting for a partner call checks the loop runs
LOOP_STOPPED = "gateway event loop stopped"
DATA_JSON = "data_json"  # the string stand-in for ``data`` (see ``as_crewai_tools``)
DATA_JSON_DESCRIPTION = (
    "Optional structured data to send, as a JSON object encoded in a string, for example "
    '{"order": 42}. Pass structured data here, not in data.'
)


# -- the turn a tool call belongs to -------------------------------------------------------


@dataclass
class _Turn:
    """One kickoff, as its partner tools see it. CrewAI runs model and tool calls in worker
    threads that copy the context, so the tools find the turn through ``_current_turn``: the
    loop to run partner calls on, and whether the turn has ended (a worker thread can still
    start a tool call after the kickoff was cancelled)."""

    loop: asyncio.AbstractEventLoop
    ended: bool = False
    calls: set[concurrent.futures.Future[Any]] = field(default_factory=set)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def submit(
        self, make: Callable[[], Coroutine[Any, Any, Any]], loop: asyncio.AbstractEventLoop
    ) -> concurrent.futures.Future[Any] | None:
        """Run ``make()`` on ``loop`` and track it, or None if the turn has ended. The check
        and the submission happen under the lock ``end`` takes, so once ``end`` has run no
        call is submitted (and the coroutine is only made when it is submitted)."""
        with self.lock:
            if self.ended:
                return None
            # ``run_coroutine_threadsafe`` copies this thread's context into the loop's task.
            future = asyncio.run_coroutine_threadsafe(make(), loop)
            self.calls.add(future)
        future.add_done_callback(self._done)
        return future

    def _done(self, future: concurrent.futures.Future[Any]) -> None:
        with self.lock:
            self.calls.discard(future)

    def end(self) -> None:
        """No partner call starts from now on, and those in flight are cancelled."""
        with self.lock:
            self.ended = True
            calls = list(self.calls)
        for future in calls:
            future.cancel()


_current_turn: ContextVar[_Turn | None] = ContextVar("a2agw_crewai_turn", default=None)


class _TurnTaskOutputs(TaskOutputStorageHandler):
    """Keeps one turn's task outputs in memory. CrewAI's default writes every kickoff's inputs
    and task outputs (messages included) to one SQLite file in the user data directory,
    shared by every kickoff in the process and emptied when one starts: other callers' text
    on disk, and concurrent kickoffs erasing each other's records."""

    def __init__(self) -> None:  # no storage
        self.outputs: list[dict[str, Any]] = []

    def update(self, task_index: int, log: dict[str, Any]) -> None:
        self.outputs.append({**log, "task_index": task_index})

    def add(self, task: Any, output: dict[str, Any], task_index: int, *a: Any, **k: Any) -> None:
        self.outputs.append({"task": task, "output": output, "task_index": task_index})

    def reset(self) -> None:
        self.outputs.clear()

    def load(self) -> list[dict[str, Any]] | None:
        return list(self.outputs) or None


def _uses_memory(crew: Crew) -> bool:
    agents = [*crew.agents, *([crew.manager_agent] if crew.manager_agent else [])]
    return bool(crew.memory) or any(getattr(a, "memory", None) for a in agents)


def _mentions(crew: Crew, placeholder: str) -> bool:
    texts = [t for task in crew.tasks for t in (task.description, task.expected_output)]
    texts += [t for a in crew.agents for t in (a.role, a.goal, a.backstory)]
    return any(placeholder in (t or "") for t in texts)


def _own_counters(llm: Any) -> Any:
    """``llm`` with token counters of its own. CrewAI's per-LLM counters are cumulative, and
    a crew copy's LLMs share them with the original's (a shallow copy keeps the dict)."""
    if not isinstance(llm, BaseLLM):
        return llm
    fresh = copy.copy(llm)
    fresh._token_usage = dict.fromkeys(llm._token_usage, 0)
    return fresh


class CrewAIAdapter:
    """Runs each turn as ``await crew.akickoff(inputs={input_key: ctx.text, "context_id":
    ctx.context_id})`` on a copy of ``crew``, and answers ``Done(str(result))``.

    The crew is a template: its tasks or agents name ``{input}`` (or ``{<input_key>}``), which
    CrewAI fills with the message text, and may name ``{context_id}``. Each turn kicks off its
    own copy (``crew.copy()``, as ``kickoff_for_each`` does), so turns on different contexts
    run at once without sharing task outputs or interpolated text. A crew holds nothing
    between kickoffs: every turn is a fresh run, and a follow-up on the same context does not
    see the previous one (put what it needs in the message). Turns on one caller and context
    (``_contexts.context_key``) still run one at a time. CrewAI memory (``memory=`` on the crew
    or an agent) is refused: it is one store shared by every kickoff, so callers and contexts
    would read each other's memories. ``durable_sessions`` is accepted as given: there is no
    conversation state to lose.

    Token usage is ``crew.usage_metrics`` after the kickoff (prompt and completion tokens),
    reported as one ``Usage`` before ``Done`` when non-zero; each turn's copy counts its own
    model calls. Text is not streamed: CrewAI's stream (``Crew(stream=True)``) carries the raw
    model output of every task and agent (intermediate tasks' answers and, for models without
    native tool calling, the "Thought:/Action:" scaffolding) without telling the final
    task's apart, so the result is sent whole. Errors raised by the crew propagate, so the
    executor fails the task.

    Cancellation: ``akickoff`` runs CrewAI's steps (each model or tool call) in worker
    threads. Cancelling the turn stops the kickoff at the next step; the step in flight
    finishes in its thread and its result is dropped. Partner calls in flight are cancelled,
    and a tool call that starts after the turn ended is answered ``unavailable`` without
    reaching the partner. (``kickoff_async`` would run the whole kickoff in one thread that
    cancelling does not stop, so the adapter does not use it.)
    """

    def __init__(self, crew: Crew, *, input_key: str = "input", durable_sessions: bool = False):
        if not isinstance(crew, Crew):
            raise TypeError(f"CrewAIAdapter serves a crewai.Crew, not {type(crew).__name__}")
        if _uses_memory(crew):
            raise ValueError(
                "CrewAIAdapter does not serve crews with memory: CrewAI memory is one store "
                "shared by every kickoff, so callers and contexts would see each other's "
                "memories"
            )
        if not _mentions(crew, "{" + input_key + "}"):
            raise ValueError(
                f"no task or agent of the crew mentions {{{input_key}}}: the message text "
                "would never reach the crew"
            )
        self.crew = crew
        self.input_key = input_key
        self.durable_sessions = durable_sessions
        self._contexts: ContextRegistry[str, None] = ContextRegistry(
            lambda key: None, max_size=MAX_SESSIONS
        )

    def _turn_crew(self) -> Crew:
        crew = self.crew.copy()
        crew._task_output_handler = _TurnTaskOutputs()
        for agent in [*crew.agents, *([crew.manager_agent] if crew.manager_agent else [])]:
            agent.llm = _own_counters(agent.llm)
        crew.manager_llm = _own_counters(crew.manager_llm)
        crew.stream = False
        return crew

    async def run(self, ctx: InboundContext) -> AsyncIterator[AgentEvent]:
        async with self._contexts.turn(context_key(ctx)):
            crew = self._turn_crew()
            result = await self._kickoff(crew, ctx)
        usage = crew.usage_metrics
        if usage is not None and (usage.prompt_tokens or usage.completion_tokens):
            yield Usage(tokens_in=usage.prompt_tokens, tokens_out=usage.completion_tokens)
        yield Done(str(result))

    async def _kickoff(self, crew: Crew, ctx: InboundContext) -> Any:
        turn = _Turn(asyncio.get_running_loop())
        token = _current_turn.set(turn)  # no yield until reset: the turn's context only
        try:
            return await crew.akickoff(
                inputs={self.input_key: ctx.text, "context_id": ctx.context_id}
            )
        finally:
            turn.end()
            _current_turn.reset(token)


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
        return Literal[tuple(schema["enum"])]  # type: ignore[valid-type]
    t = schema.get("type")
    if t == "array":
        return list[_annotation(schema.get("items"))]  # type: ignore[misc]
    return _JSON_TYPES.get(t, Any) if isinstance(t, str) else Any


def _nullable_optionals(schema: dict[str, Any]) -> dict[str, Any]:
    """``schema`` with each optional top-level property also accepting ``null``, the way
    pydantic declares ``x: T | None = None``. CrewAI's native tool calling declares tools in
    OpenAI strict mode, which lists every property as required: a model must then send each
    one, and ``null`` is how it leaves an optional one out (nulls are dropped before
    ``invoke``)."""
    out = copy.deepcopy(schema)
    required = set(schema.get("required") or ())
    props = out.get("properties")
    if isinstance(props, dict):
        for name, prop in props.items():
            if name in required or not isinstance(prop, dict):
                continue
            outer = {k: prop.pop(k) for k in ("description", "default") if k in prop}
            props[name] = {"anyOf": [prop, {"type": "null"}], **outer}
    return out


class _PartnerArgs(BaseModel):
    """Base of the projected tools' ``args_schema`` models: their JSON schema is the partner
    tool's (stripped, optional properties nullable). Extra arguments are kept, so ``invoke``
    sees and rejects them."""

    model_config = ConfigDict(extra="allow")
    partner_schema: ClassVar[dict[str, Any]] = {}

    @classmethod
    def model_json_schema(cls, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return copy.deepcopy(cls.partner_schema)


def _args_model(name: str, schema: dict[str, Any]) -> type[_PartnerArgs]:
    """The ``args_schema`` for one partner tool.

    ``model_json_schema()`` returns ``schema`` exactly; CrewAI derives what the model is given
    from it (in strict form for native tool calling). CrewAI also validates each call with
    this model before the tool runs, so its fields follow the schema loosely: each property
    whose name is a Python identifier becomes a field (required ones required, the others
    ``None`` by default, enums as ``Literal``, arrays and objects as lists and dicts);
    constraints are left to ``invoke``, which checks the original schema."""
    required = set(schema.get("required") or ())
    fields: dict[str, Any] = {}
    for prop, sub in (schema.get("properties") or {}).items():
        if not prop.isidentifier() or keyword.iskeyword(prop) or prop.startswith("_"):
            continue
        description = sub.get("description") if isinstance(sub, dict) else None
        ann = _annotation(sub.get("anyOf", [sub])[0] if isinstance(sub, dict) else sub)
        if prop in required:
            fields[prop] = (ann, Field(description=description))
        else:
            fields[prop] = (ann | None, Field(default=None, description=description))
    model = create_model(f"{name}_args", __base__=_PartnerArgs, **fields)
    model.partner_schema = copy.deepcopy(schema)
    return model


def _turn_ended() -> str:
    return json.dumps({"state": "unavailable", "reason": INBOUND_ENDED})


def _loop_stopped() -> str:
    return json.dumps({"state": "unavailable", "reason": LOOP_STOPPED})


def _with_data_json(schema: dict[str, Any]) -> dict[str, Any]:
    """``schema`` plus a nullable ``data_json`` string next to its ``data`` object. CrewAI's
    strict mode closes every object, so ``data`` can only be sent empty; ``data_json`` carries
    the structured data as a JSON string instead (parsed before ``invoke``)."""
    props = schema.get("properties")
    if not isinstance(props, dict) or "data" not in props or DATA_JSON in props:
        return schema
    out = copy.deepcopy(schema)
    out["properties"][DATA_JSON] = {
        "anyOf": [{"type": "string"}, {"type": "null"}],
        "description": DATA_JSON_DESCRIPTION,
    }
    return out


class _PartnerTool(BaseTool):
    """A partner tool as a CrewAI tool. CrewAI calls ``_run`` in a worker thread; the partner
    call itself runs on the gateway's event loop (the turn's, else the one the tools were
    made on), with the worker's context, so the inbound task and caller contextvars reach
    ``invoke``. Answers are never cached: the same question may get a new answer."""

    ptool: PartnerTool
    client: Any  # PartnerClient (not validated by pydantic)
    caller: Any = None  # Principal | None
    loop: Any = None  # the event loop the tools were made on, if any
    takes_data_json: bool = False  # ``data_json`` was added to the declared schema

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        self.cache_function = lambda _args, _result: False

    async def _call(self, kwargs: dict[str, Any]) -> str:
        args = {k: v for k, v in kwargs.items() if v is not None}
        if self.takes_data_json and DATA_JSON in args:
            raw = args.pop(DATA_JSON)
            try:
                data = json.loads(raw) if isinstance(raw, str) else None
            except ValueError:
                data = None
            if not isinstance(data, dict) or args.get("data"):
                # Not a JSON object, or ``data`` given as well: nothing is sent.
                reason = f"invalid arguments: {DATA_JSON}"
                return json.dumps({"state": "rejected", "reason": reason})
            args["data"] = data
        result = await invoke(
            self.ptool, args, self.client, inbound_task_id=None, caller=self.caller
        )
        return json.dumps(result, default=str)

    def _target(self) -> tuple[asyncio.AbstractEventLoop, _Turn | None]:
        turn = _current_turn.get()
        loop = turn.loop if turn is not None else self.loop
        if loop is None or loop.is_closed():
            raise RuntimeError(
                f"partner tool {self.name!r} has no event loop to run on: make the tools "
                "(as_crewai_tools) inside the gateway's event loop"
            )
        return loop, turn

    def _run(self, **kwargs: Any) -> str:
        loop, turn = self._target()
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is loop:
            raise RuntimeError(
                f"partner tool {self.name!r} was called synchronously on the gateway's event "
                "loop thread, which it would block; CrewAI calls tools from worker threads"
            )
        if not loop.is_running():
            return _loop_stopped()
        future = self._submit(kwargs, loop, turn)
        if future is None:
            return _turn_ended()
        while True:
            try:
                return future.result(timeout=LOOP_CHECK_S)
            except concurrent.futures.CancelledError:
                return _turn_ended()
            except concurrent.futures.TimeoutError:
                # A loop that stopped will never run the call: do not wait for it forever
                # (a thread blocked here would keep the process from exiting).
                if not loop.is_running():
                    future.cancel()
                    return _loop_stopped()

    def _submit(
        self, kwargs: dict[str, Any], loop: asyncio.AbstractEventLoop, turn: _Turn | None
    ) -> concurrent.futures.Future[Any] | None:
        if turn is None:
            return asyncio.run_coroutine_threadsafe(self._call(kwargs), loop)
        return turn.submit(lambda: self._call(kwargs), loop)

    async def _arun(self, **kwargs: Any) -> str:
        loop, turn = self._target()
        if turn is not None and turn.ended:
            return _turn_ended()
        if asyncio.get_running_loop() is loop:
            return await self._call(kwargs)  # on the loop thread: ``end`` cannot interleave
        future = self._submit(kwargs, loop, turn)
        if future is None:
            return _turn_ended()
        try:
            return await asyncio.wrap_future(future)
        except asyncio.CancelledError:
            future.cancel()
            raise


def as_crewai_tools(
    tools: list[PartnerTool], client: PartnerClient, *, caller: Principal | None = None
) -> list[BaseTool]:
    """Project partner tools as CrewAI ``BaseTool``s returning the JSON envelope.

    Each tool's ``args_schema`` declares the partner tool's schema without the gateway-only
    ``x-`` limits, its optional properties also accepting ``null`` (CrewAI's native tool
    calling makes every property required), and its description ends with the
    untrusted-data note. Explicit ``null`` arguments are dropped; ``invoke`` validates the rest
    against the full schema and answers invalid calls with ``rejected``. Strict mode also
    closes the free-form ``data`` object, so tools that take ``data`` declare a nullable
    ``data_json`` string as well: a JSON object passed there is parsed and sent as ``data``
    (anything else, or ``data`` given too, is answered ``rejected``). Inside an inbound run
    the inbound task and caller come from the contextvars, as for ``as_langchain_tools``.

    Make the tools inside the gateway's event loop (once the host has started, for example
    ``agent.tools = as_crewai_tools(host.partner_tools("crew"), host.client)``): partner calls
    run on that loop. Give them to the agents of the crew a ``CrewAIAdapter`` serves."""
    try:
        loop: asyncio.AbstractEventLoop | None = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    out: list[BaseTool] = []
    for t in tools:
        stripped = _nullable_optionals(strip_extensions(t.parameters))
        schema = _with_data_json(stripped)
        out.append(
            _PartnerTool(
                name=t.name,
                description=with_untrusted_note(t.description),
                args_schema=_args_model(t.name, schema),
                ptool=t,
                client=client,
                caller=caller,
                loop=loop,
                takes_data_json=schema is not stripped,
            )
        )
    return out
