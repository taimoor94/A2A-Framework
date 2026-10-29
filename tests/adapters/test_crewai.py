"""CrewAI adapter tests. They run in their own environment (``scripts/test-crewai.sh``):
crewai pins ``mcp<2`` and ``openai<3``, so it is not in the dev environment, and the main
suite skips this module. The script sets ``A2AGW_CREWAI_TESTS=1``, which turns a missing
crewai into a failure instead of a skip."""

from __future__ import annotations

import asyncio
import atexit
import concurrent.futures
import importlib.util
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import warnings
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

# CrewAI's anonymous telemetry and trace collection: off before crewai is imported.
os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")

# CrewAI writes under the user's home: a credentials key and its settings (crewai_core; the
# settings path is fixed when crewai is imported) and its kickoff database. The real home
# (the script passes it as A2AGW_REAL_HOME, having pointed HOME elsewhere) is snapshotted
# here, and HOME is pointed at a temporary directory before crewai is imported.
REAL_HOME = os.environ.get("A2AGW_REAL_HOME") or os.path.expanduser("~")


def crewai_paths(home: str) -> dict[str, tuple[int, int]]:
    """Every file under the places CrewAI writes in ``home``: (mtime, size) by path."""
    roots = [
        Path(home, "Library", "Application Support", "crewai"),
        Path(home, "Library", "Application Support", Path.cwd().name),
        Path(home, ".config", "crewai"),
        Path(home, ".local", "share", "crewai"),
        Path(home, ".local", "share", Path.cwd().name),
    ]
    found: dict[str, tuple[int, int]] = {}
    for root in roots:
        if root.exists():
            found[str(root)] = (0, 0)
            for f in root.rglob("*"):
                st = f.stat()
                found[str(f)] = (st.st_mtime_ns, st.st_size)
    return found


REAL_HOME_BEFORE = crewai_paths(REAL_HOME)

if os.environ.get("A2AGW_CREWAI_TESTS") or importlib.util.find_spec("crewai") is not None:
    _home = tempfile.mkdtemp(prefix="a2agw-crewai-home-")
    atexit.register(shutil.rmtree, _home, True)
    os.environ["HOME"] = _home
    os.environ["XDG_CONFIG_HOME"] = os.path.join(_home, ".config")
    os.environ["XDG_DATA_HOME"] = os.path.join(_home, ".local", "share")
    os.environ.setdefault("CREWAI_STORAGE_DIR", os.path.join(_home, "storage"))

# ``crewai.rag`` is a module object that refuses attributes, so importing its submodules
# raises ``ImportWarning("Cannot set an attribute on 'crewai.rag' for child module ...")``
# (ignored by default; ``-W error`` turns it into an error). Library noise: only that message
# is ignored, around the import and in the tests (submodules also load lazily).
RAG_IMPORT_NOISE = r"Cannot set an attribute on 'crewai\.rag' for child module"
with warnings.catch_warnings():
    warnings.filterwarnings("ignore", message=RAG_IMPORT_NOISE, category=ImportWarning)
    if os.environ.get("A2AGW_CREWAI_TESTS"):
        import crewai  # noqa: F401 - in the CrewAI environment a missing crewai is a failure
    else:
        pytest.importorskip("crewai")

# CrewAI's ``Agent`` reads its own deprecated fields (``function_calling_llm``,
# ``allow_code_execution``, ...) when it is built or copied; pydantic warns, and crewai's
# ``warnings.warn`` wrapper reports it from module ``crewai``. Library noise: only those
# messages from that module are ignored.
pytestmark = [
    pytest.mark.filterwarnings(f"ignore:{RAG_IMPORT_NOISE}:ImportWarning"),
    pytest.mark.filterwarnings(
        "ignore:function_calling_llm is deprecated and will be removed:DeprecationWarning:crewai"
    ),
    pytest.mark.filterwarnings("ignore:deprecated$:DeprecationWarning:crewai"),
]

from adapters.contract import (
    FakePartnerClient,
    assert_cancellable,
    assert_failure_maps,
    assert_projection,
    assert_text_stream,
    caller,
    drive,
    make_ctx,
)
from crewai import Agent, Crew, Task
from crewai.llms.base_llm import BaseLLM
from crewai.tools import BaseTool
from pydantic import PrivateAttr

import a2agw.adapters.crewai as crewai_mod
from a2agw.adapters._contexts import context_key
from a2agw.adapters.crewai import CrewAIAdapter, as_crewai_tools
from a2agw.consult.tools import UNTRUSTED_NOTE, strip_extensions
from a2agw.context.call_context import current_inbound_task, use_inbound
from a2agw.core.events import Done, Usage


@pytest.fixture(autouse=True)
def _offline(monkeypatch, tmp_path):
    """No test here may reach the network (CrewAI telemetry and tracing, provider clients):
    name resolution and outbound connections fail and are recorded, which fails the test
    even where CrewAI swallows the error. CrewAI's home, config, data and storage
    directories are the test's own."""
    attempts: list[Any] = []

    def refuse(*args: Any, **kwargs: Any) -> Any:
        attempts.append(args[:1])
        raise OSError("a CrewAI test tried to use the network")

    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    for var in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    isolate_home(monkeypatch.setenv, tmp_path)
    yield
    assert attempts == [], f"network attempts: {attempts}"


def isolate_home(setenv: Any, tmp_path: Path) -> None:
    """Point HOME, XDG_CONFIG_HOME, XDG_DATA_HOME and CREWAI_STORAGE_DIR (absolute) at
    ``tmp_path``. ``setenv(name, value)``: ``monkeypatch.setenv`` or a dict's ``__setitem__``."""
    home = tmp_path / "home"
    setenv("HOME", str(home))
    setenv("XDG_CONFIG_HOME", str(home / ".config"))
    setenv("XDG_DATA_HOME", str(home / ".local" / "share"))
    setenv("CREWAI_STORAGE_DIR", str((tmp_path / "crewai").resolve()))


# -- a scripted fake model ----------------------------------------------------------------

USAGE = {"prompt_tokens": 7, "completion_tokens": 3}  # what each model call reports


def call(name: str, args: dict[str, Any], *, call_id: str = "call-1") -> list[dict[str, Any]]:
    """One native tool call, as provider integrations hand it to CrewAI."""
    return [
        {
            "id": call_id,
            "type": "function",
            "function": {"name": name, "arguments": json.dumps(args)},
        }
    ]


ECHO = ("echo",)  # answers "heard: <every task the model was given>"


def block(then: Any = ECHO) -> tuple:
    return ("block", then)  # signals ``started``, waits for ``release``, then plays ``then``


def tasks_seen(messages: Sequence[dict[str, Any]]) -> list[str]:
    """The task texts (the interpolated task descriptions) in the messages."""
    found: list[str] = []
    for m in messages:
        if m.get("role") == "user" and isinstance(m.get("content"), str):
            found += re.findall(r"Current Task: (.*)", m["content"])
    return found


class Script:
    """What the fake model answers, across turns (calls past the script echo). Model calls run
    in CrewAI's worker threads: the script records each call's messages and declared tools,
    and signals the test's loop through ``started`` (an ``asyncio.Event``)."""

    def __init__(self, *steps: Any) -> None:
        self.steps = list(steps)
        self.calls: list[list[dict[str, Any]]] = []
        self.declared: list[list[dict[str, Any]] | None] = []
        self.loop = asyncio.get_running_loop()
        self.started = asyncio.Event()
        self.release = threading.Event()
        self.returned = threading.Event()  # a blocked call has returned
        self._lock = threading.Lock()

    def play(self, messages: Sequence[dict[str, Any]], tools: Any) -> Any:
        with self._lock:
            self.calls.append([dict(m) for m in messages])
            self.declared.append(json.loads(json.dumps(tools)) if tools else None)
            step = self.steps.pop(0) if self.steps else ECHO
        if isinstance(step, tuple) and step[0] == "block":
            self.loop.call_soon_threadsafe(self.started.set)
            try:
                assert self.release.wait(10), "a blocked model call was never released"
            finally:
                self.returned.set()
            step = step[1]
        if isinstance(step, BaseException):
            raise step
        if step == ECHO:
            return "heard: " + ", ".join(tasks_seen(messages))
        return step


class ScriptedLLM(BaseLLM):
    """A CrewAI ``BaseLLM`` playing a ``Script`` with native tool calling. Each call reports
    ``USAGE`` through CrewAI's own token accounting."""

    _script: Script = PrivateAttr()

    def __init__(self, script: Script) -> None:
        super().__init__(model="scripted")
        self._script = script

    def supports_function_calling(self) -> bool:
        return True

    def get_input_tokens_count(self, messages: Any, tools: Any = None, **kw: Any) -> int:
        return 1  # the base class logs a warning for its estimate

    def call(self, messages: Any, tools: Any = None, *args: Any, **kwargs: Any) -> Any:
        if isinstance(messages, str):
            messages = [{"role": "user", "content": messages}]
        self._track_token_usage_internal(dict(USAGE))
        return self._script.play(messages, tools)

    async def acall(self, messages: Any, tools: Any = None, *args: Any, **kwargs: Any) -> Any:
        return self.call(messages, tools)


def make_crew(
    script: Script, tools: Sequence[BaseTool] = (), *, description: str = "{input}", **kw: Any
) -> Crew:
    agent = Agent(
        role="helper",
        goal="help",
        backstory="You help.",
        llm=ScriptedLLM(script),
        tools=list(tools),
    )
    task = Task(description=description, expected_output="an answer", agent=agent)
    return Crew(agents=[agent], tasks=[task], **kw)


# -- inbound ------------------------------------------------------------------------------


async def test_kickoff_completes():
    script = Script()
    crew = make_crew(script, description="{input} (conversation {context_id})")
    evs = await drive(CrewAIAdapter(crew), "hi there", context_id="c-42")
    assert evs[-1] == Done("heard: hi there (conversation c-42)")
    assert_text_stream(evs, "heard: hi there (conversation c-42)")
    # The user's crew is a template: each turn runs a copy, so the original is untouched.
    assert crew.tasks[0].description == "{input} (conversation {context_id})"
    assert crew.usage_metrics is None


async def test_input_key():
    script = Script()
    crew = make_crew(script, description="Question: {question}")
    evs = await drive(CrewAIAdapter(crew, input_key="question"), "why?")
    assert evs[-1] == Done("heard: Question: why?")
    with pytest.raises(ValueError, match=r"\{input\}"):
        CrewAIAdapter(crew)  # no task or agent mentions {input}


async def test_usage_metrics_reported():
    client = FakePartnerClient()
    script = Script(call("ask_pinger", {"message": "hi"}), "done")
    crew = make_crew(script, as_crewai_tools(client.tools(), client))
    adapter = CrewAIAdapter(crew)
    evs = await drive(adapter, "go")
    # Two model calls in the turn; one Usage, just before Done.
    assert evs == [Usage(tokens_in=14, tokens_out=6), Done("done")]
    # Each turn reports its own calls only (CrewAI's counters are per LLM object and shared
    # by its copies), and the user's crew keeps no count of the turns.
    evs = await drive(adapter, "again", task_id="t2")
    assert evs == [Usage(tokens_in=7, tokens_out=3), Done("heard: again")]
    assert crew.agents[0].llm.get_token_usage_summary().total_tokens == 0


async def test_concurrent_turns_are_independent():
    # Turns on different contexts run at once, each on its own copy of the crew.
    script = Script(block())
    adapter = CrewAIAdapter(make_crew(script))
    one = asyncio.create_task(drive(adapter, "one", context_id="c-a"))
    await asyncio.wait_for(script.started.wait(), 5)
    two = await drive(adapter, "two", context_id="c-b")  # not blocked by "one"
    assert two == [Usage(tokens_in=7, tokens_out=3), Done("heard: two")]
    script.release.set()
    assert await one == [Usage(tokens_in=7, tokens_out=3), Done("heard: one")]


async def test_turns_on_one_context_are_serialised():
    script = Script(block())
    adapter = CrewAIAdapter(make_crew(script))
    one = asyncio.create_task(drive(adapter, "one", context_id="c-ser"))
    await asyncio.wait_for(script.started.wait(), 5)
    two = asyncio.create_task(drive(adapter, "two", context_id="c-ser", task_id="t2"))
    other = await drive(adapter, "elsewhere", context_id="c-other")  # a third context runs
    assert other[-1] == Done("heard: elsewhere")
    for _ in range(20):
        await asyncio.sleep(0)
    assert not two.done() and len(script.calls) == 2  # "two" waits for "one"
    script.release.set()
    await one
    assert (await two)[-1] == Done("heard: two")
    assert context_key(make_ctx("x", context_id="c-ser")) in list(adapter._contexts)


async def test_no_memory_between_turns():
    # A crew holds nothing between kickoffs: a follow-up on the same context is a new run.
    script = Script()
    adapter = CrewAIAdapter(make_crew(script))
    await drive(adapter, "apples", context_id="c-mt")
    evs = await drive(adapter, "pears", context_id="c-mt", task_id="t2", principal=caller("k:a"))
    assert evs[-1] == Done("heard: pears")
    assert tasks_seen(script.calls[1]) == ["pears"]


async def test_refuses_memory():
    # CrewAI memory is one store shared by every kickoff: callers and contexts would read
    # each other's memories.
    crew = make_crew(Script())
    crew.memory = True
    with pytest.raises(ValueError, match="memory"):
        CrewAIAdapter(crew)
    crew.memory = False
    crew.agents[0].memory = True
    with pytest.raises(ValueError, match="memory"):
        CrewAIAdapter(crew)


def test_rejects_non_crews():
    with pytest.raises(TypeError, match="Crew"):
        CrewAIAdapter(object())  # type: ignore[arg-type]


async def test_task_outputs_stay_in_memory(tmp_path):
    # CrewAI would write every kickoff's inputs and task outputs to one SQLite file shared by
    # all kickoffs (and reset at each start): the adapter's copies keep them per turn.
    script = Script()
    await drive(CrewAIAdapter(make_crew(script)), "a secret question")
    for db in (tmp_path / "crewai").rglob("*.db"):
        with sqlite3.connect(db) as conn:
            tables = [
                r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
            ]
            for table in tables:
                assert conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone() == (0,), db


async def test_failure_propagates():
    script = Script(*[RuntimeError("model down")] * 10)
    await assert_failure_maps(CrewAIAdapter(make_crew(script)), match="model down")


async def test_cancellable():
    # The kickoff runs CrewAI's steps in worker threads: cancelling stops it at the next step.
    # The model call in flight finishes in its thread; nothing after it runs.
    client = FakePartnerClient()
    script = Script(block(then=call("ask_pinger", {"message": "hi"})))
    adapter = CrewAIAdapter(make_crew(script, as_crewai_tools(client.tools(), client)))
    await assert_cancellable(adapter, started=script.started, within_s=5)
    script.release.set()
    assert await asyncio.to_thread(script.returned.wait, 5)
    # A full turn afterwards (a barrier for anything the first one could still schedule).
    assert (await drive(adapter, "next", context_id="c-next"))[-1] == Done("heard: next")
    assert client.consults == [] and len(script.calls) == 2


async def test_cancel_mid_tool_call_cancels_the_partner_call():
    entered, cancelled = asyncio.Event(), asyncio.Event()

    class Hanging(FakePartnerClient):
        async def consult(self, partner_id: str, message: str, **kwargs: Any) -> Any:
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

    client = Hanging()
    script = Script(call("ask_pinger", {"message": "hi"}))
    adapter = CrewAIAdapter(make_crew(script, as_crewai_tools(client.tools(), client)))
    await assert_cancellable(adapter, started=entered, stopped=cancelled, within_s=5)


async def test_tool_call_after_cancel_is_refused(monkeypatch):
    # A tool call CrewAI's worker thread starts after the turn was cancelled never reaches
    # the partner client.
    client = FakePartnerClient()
    [tool] = [t for t in as_crewai_tools(client.tools(), client) if t.name == "ask_pinger"]
    loop = asyncio.get_running_loop()
    entered, release, finished = asyncio.Event(), threading.Event(), threading.Event()
    results: list[Any] = []
    validate, run = type(tool)._validate_kwargs, type(tool)._run

    def slow_validate(self: BaseTool, kwargs: dict[str, Any]) -> dict[str, Any]:
        loop.call_soon_threadsafe(entered.set)
        release.wait(10)
        return validate(self, kwargs)

    def recording_run(self: BaseTool, **kwargs: Any) -> Any:
        try:
            results.append(run(self, **kwargs))
        finally:
            finished.set()
        return results[-1]

    monkeypatch.setattr(type(tool), "_validate_kwargs", slow_validate)
    monkeypatch.setattr(type(tool), "_run", recording_run)
    script = Script(call("ask_pinger", {"message": "hi"}))
    adapter = CrewAIAdapter(make_crew(script, [tool]))
    await assert_cancellable(adapter, started=entered, within_s=5)
    release.set()
    assert await asyncio.to_thread(finished.wait, 5)
    assert json.loads(results[0]) == {"state": "unavailable", "reason": "inbound task ended"}
    assert client.consults == []


async def test_tool_reaches_partner_client():
    client = FakePartnerClient()
    script = Script(call("ask_pinger", {"message": "hi"}), "pinger said pong")
    adapter = CrewAIAdapter(make_crew(script, as_crewai_tools(client.tools(), client)))
    evs = await drive(adapter, "ping the pinger")
    assert evs[-1] == Done("pinger said pong")
    assert [c["message"] for c in client.consults] == ["hi"]
    # The model's second call is given the envelope as the tool result.
    [result] = [m for m in script.calls[1] if m.get("role") == "tool"]
    assert result["tool_call_id"] == "call-1"
    envelope = json.loads(result["content"])
    assert (envelope["state"], envelope["text"]) == ("completed", "pong:hi")


async def test_tool_calls_run_under_the_inbound_task():
    seen: list[str | None] = []

    class Recording(FakePartnerClient):
        async def consult(self, partner_id: str, message: str, **kwargs: Any) -> Any:
            seen.append(current_inbound_task.get())
            return await super().consult(partner_id, message, **kwargs)

    client = Recording()
    script = Script(call("ask_pinger", {"message": "hi"}), "ok")
    adapter = CrewAIAdapter(make_crew(script, as_crewai_tools(client.tools(), client)))
    # CrewAI's worker threads copy the context, and the partner call is run on the loop with
    # the worker's context: the contextvars reach ``invoke``.
    with use_inbound("inbound-1", None):
        await drive(adapter, "go")
    assert seen == ["inbound-1"]


def strict_form(schema: dict[str, Any]) -> dict[str, Any]:
    """The partner schema as CrewAI's native tool calling declares it (OpenAI strict mode):
    every property required, the optional ones nullable, every object closed; a tool taking
    ``data`` also takes the nullable ``data_json`` string."""
    out = json.loads(json.dumps(schema))
    required = set(schema.get("required", ()))
    data_json = "data" in out["properties"]
    for name, prop in out["properties"].items():
        if prop.get("type") == "object":
            prop.update(additionalProperties=False, properties={}, required=[])
        if name not in required:
            outer = {k: prop.pop(k) for k in ("description", "default") if k in prop}
            out["properties"][name] = {"anyOf": [prop, {"type": "null"}], **outer}
    if data_json:
        out["properties"]["data_json"] = {
            "anyOf": [{"type": "string"}, {"type": "null"}],
            "description": crewai_mod.DATA_JSON_DESCRIPTION,
        }
    out["required"] = list(out["properties"])
    return out


async def test_tools_reach_the_model():
    # What the model is actually given, through CrewAI's own conversion.
    client = FakePartnerClient()
    ptools = client.tools()
    script = Script("ok")
    await drive(CrewAIAdapter(make_crew(script, as_crewai_tools(ptools, client))), "hi")
    [declared] = script.declared
    assert declared is not None
    functions = [d["function"] for d in declared]
    assert [f["name"] for f in functions] == [p.name for p in ptools]
    for f, p in zip(functions, ptools, strict=True):
        assert f["description"].endswith(UNTRUSTED_NOTE)
        assert f["description"].count(UNTRUSTED_NOTE) == 1
        assert f["parameters"] == strict_form(strip_extensions(p.parameters))
        assert "x-max-json-bytes" not in json.dumps(f["parameters"])
    # Structured data goes as a JSON string: strict mode closes the ``data`` object.
    ask = functions[0]["parameters"]["properties"]
    closed = ask["data"]["anyOf"][0]
    assert closed["type"] == "object" and closed["properties"] == {}
    assert closed["additionalProperties"] is False
    assert "JSON" in ask["data_json"]["description"]


# -- outbound -----------------------------------------------------------------------------


async def run_tool(tool: BaseTool, args: dict[str, Any]) -> str:
    """Call a tool the way CrewAI does: ``run`` (validation, then ``_run``) in a worker
    thread."""
    return await asyncio.to_thread(tool.run, **args)


async def test_projection_contract():
    client = FakePartnerClient()
    tools = as_crewai_tools(client.tools(), client)
    assert all(isinstance(t, BaseTool) for t in tools)
    await assert_projection(tools, run_tool, client=client)
    # Explicit nulls for optional arguments are dropped before validation.
    ok = json.loads(await run_tool(tools[0], {"message": "yo", "task_id": None}))
    assert ok["state"] == "completed" and client.consults[-1]["task_id"] is None
    # ``invoke`` validates against the original schema: unknown arguments and the
    # gateway-only ``x-`` limits the model never sees are answered with ``rejected``.
    assert json.loads(await run_tool(tools[0], {"message": "hi", "bogus": 1}))["state"] == (
        "rejected"
    )
    big = {"message": "hi", "data": {"blob": "x" * 40_000}}
    assert json.loads(await run_tool(tools[0], big))["state"] == "rejected"
    # ``_arun`` (CrewAI's async tool path) reaches the client too, on or off the loop.
    out = json.loads(await tools[0].arun(message="async"))
    assert out["text"] == "pong:async"


async def test_tool_on_the_loop_thread_refuses():
    # A synchronous call on the event loop's own thread would deadlock waiting for the loop.
    client = FakePartnerClient()
    [tool] = as_crewai_tools(client.tools()[:1], client)
    with pytest.raises(RuntimeError, match="event loop"):
        tool.run(message="hi")
    assert client.consults == []


def test_tool_without_a_loop_refuses():
    client = FakePartnerClient()
    [tool] = as_crewai_tools(client.tools()[:1], client)  # built outside any event loop
    with pytest.raises(RuntimeError, match="event loop"):
        tool.run(message="hi")


def test_tool_on_a_stopped_loop_does_not_hang(monkeypatch):
    # A worker thread waiting for a partner call never waits on a loop that no longer runs
    # (it would keep the process from exiting).
    monkeypatch.setattr(crewai_mod, "LOOP_CHECK_S", 0.05)
    client = FakePartnerClient()
    [tool] = as_crewai_tools(client.tools()[:1], client)
    loop = asyncio.new_event_loop()  # never run
    tool.loop = loop
    try:
        out: list[Any] = []
        worker = threading.Thread(target=lambda: out.append(tool.run(message="hi")))
        worker.start()
        worker.join(5)
        assert not worker.is_alive(), "the tool call is still waiting"
        assert json.loads(out[0]) == {
            "state": "unavailable",
            "reason": "gateway event loop stopped",
        }
    finally:
        loop.close()
    assert client.consults == []


def test_projected_tool_schemas():
    client = FakePartnerClient()
    ptools = client.tools()
    tools = as_crewai_tools(ptools, client)
    assert [t.name for t in tools] == [p.name for p in ptools]
    for t, p in zip(tools, ptools, strict=True):
        assert t.description.count(UNTRUSTED_NOTE) == 1
        stripped = strip_extensions(p.parameters)
        schema = t.args_schema.model_json_schema()
        # The stripped schema, with optional properties nullable (CrewAI's strict
        # conversion makes every property required).
        required = set(stripped.get("required", ()))
        assert schema["required"] == stripped.get("required", [])
        for name, prop in stripped["properties"].items():
            if name in required:
                assert schema["properties"][name] == prop
            else:
                assert {"type": "null"} in schema["properties"][name]["anyOf"]
        assert t.cache_function({}, "") is False  # partner answers are never cached
        assert ("data_json" in schema["properties"]) == ("data" in stripped["properties"])
    assert "x-max-json-bytes" in json.dumps(ptools[0].parameters)  # the original is untouched


async def test_data_json_reaches_invoke_as_data():
    client = FakePartnerClient()
    [tool] = as_crewai_tools(client.tools()[:1], client)
    out = json.loads(await run_tool(tool, {"message": "hi", "data_json": '{"order": 42}'}))
    assert out["state"] == "completed"
    assert client.consults[-1]["data"] == {"order": 42}
    # ``invoke`` still validates the parsed data (here its gateway-only size limit).
    big = json.dumps({"blob": "x" * 40_000})
    assert json.loads(await run_tool(tool, {"message": "hi", "data_json": big}))["state"] == (
        "rejected"
    )
    sent = len(client.consults)
    rejected = {"state": "rejected", "reason": "invalid arguments: data_json"}
    for bad in ("{not json", "[1, 2]", '"text"'):
        assert json.loads(await run_tool(tool, {"message": "hi", "data_json": bad})) == rejected
    both = {"message": "hi", "data": {"a": 1}, "data_json": '{"b": 2}'}
    assert json.loads(await run_tool(tool, both)) == rejected
    assert len(client.consults) == sent  # nothing was sent for those
    # The model's strict-mode empty ``data`` next to ``data_json`` is fine.
    out = json.loads(await run_tool(tool, {"message": "hi", "data": {}, "data_json": '{"c": 3}'}))
    assert out["state"] == "completed" and client.consults[-1]["data"] == {"c": 3}


async def test_deeply_nested_data_json_is_rejected():
    # json.loads raises RecursionError (not ValueError) on deep nesting: still an answer.
    client = FakePartnerClient()
    [tool] = as_crewai_tools(client.tools()[:1], client)
    deep = "[" * 100_000 + "]" * 100_000
    out = json.loads(await run_tool(tool, {"message": "hi", "data_json": deep}))
    assert out == {"state": "rejected", "reason": "invalid arguments: data_json"}
    assert client.consults == []


def test_turn_submits_under_the_end_lock(monkeypatch):
    # No partner call is ever submitted after the turn ended: ``submit`` checks ``ended`` and
    # submits while holding the lock ``end`` takes, and only makes the coroutine then.
    loop = asyncio.new_event_loop()
    turn = crewai_mod._Turn(loop)
    held: list[bool] = []
    submitted: list[concurrent.futures.Future[Any]] = []

    def fake_submit(coro: Any, target: Any) -> concurrent.futures.Future[Any]:
        held.append(turn.lock.locked())
        coro.close()
        submitted.append(concurrent.futures.Future())
        return submitted[-1]

    async def work() -> None:
        return None

    monkeypatch.setattr(crewai_mod.asyncio, "run_coroutine_threadsafe", fake_submit)
    made: list[int] = []

    def make() -> Any:
        made.append(1)
        return work()

    try:
        assert turn.submit(make, loop) is submitted[0]
        assert held == [True]
        turn.end()
        assert submitted[0].cancelled()  # the call in flight is cancelled
        assert turn.submit(make, loop) is None  # and none starts afterwards
        assert made == [1] and len(submitted) == 1
    finally:
        loop.close()


async def test_contract_kit():
    script = Script("Hello")
    assert_text_stream(await drive(CrewAIAdapter(make_crew(script)), "hi"), "Hello")
    # No memory between kickoffs: ``assert_multi_turn`` / ``assert_isolated_callers`` do not
    # apply (``test_no_memory_between_turns``).
    await assert_failure_maps(
        CrewAIAdapter(make_crew(Script(*[RuntimeError("boom")] * 10))), match="boom"
    )
    blocking = Script(block())
    await assert_cancellable(CrewAIAdapter(make_crew(blocking)), started=blocking.started)
    blocking.release.set()
    client = FakePartnerClient()
    await assert_projection(as_crewai_tools(client.tools(), client), run_tool, client=client)


async def test_served_end_to_end(tmp_path):
    import uuid

    import httpx
    from a2a.client import ClientConfig, ClientFactory
    from a2a.types import Message, Part, Role, SendMessageRequest, TaskState
    from streaming_asgi import StreamingASGITransport

    from a2agw.serve.agent import AgentSpec, SkillSpec
    from a2agw.serve.host import AgentHost

    spec = AgentSpec(
        id="crew",
        name="CrewAI",
        description="A CrewAI crew",
        skills=[SkillSpec(id="crew", name="CrewAI", description="Echoes")],
        adapter=CrewAIAdapter(make_crew(Script("served fine"))),
    )
    host = AgentHost("http://t", db_url=f"sqlite+aiosqlite:///{tmp_path / 'h.db'}")
    host.add(spec)
    await host.startup()
    hc = httpx.AsyncClient(transport=StreamingASGITransport({"t": host.app()}), base_url="http://t")
    try:
        client = ClientFactory(ClientConfig(httpx_client=hc, streaming=False)).create(
            host.cards["crew"]
        )
        msg = Message(message_id=uuid.uuid4().hex, role=Role.ROLE_USER, parts=[Part(text="x")])
        events = [ev async for ev in client.send_message(SendMessageRequest(message=msg))]
        task = events[-1].task
        assert task.status.state == TaskState.TASK_STATE_COMPLETED
        assert "".join(p.text for a in task.artifacts for p in a.parts) == "served fine"
    finally:
        await host.shutdown()
        await hc.aclose()


# -- packaging ----------------------------------------------------------------------------


def test_missing_extra_message(monkeypatch):
    # ``import crewai...`` raises ImportError (submodules already loaded included).
    for name in [m for m in sys.modules if m == "crewai" or m.startswith("crewai.")]:
        monkeypatch.setitem(sys.modules, name, None)
    spec = importlib.util.spec_from_file_location("_crewai_probe", crewai_mod.__file__)
    module = importlib.util.module_from_spec(spec)
    with pytest.raises(ImportError, match=r"a2a-gateway\[crewai\]"):
        spec.loader.exec_module(module)


def test_core_does_not_import_crewai(tmp_path):
    env = dict(os.environ)
    isolate_home(env.__setitem__, tmp_path)
    code = (
        "import sys, a2agw, a2agw.serve.host, a2agw.adapters.callable, a2agw.cli, a2agw.config,"
        " a2agw.gateway.rest;"
        "print([m for m in sys.modules if m.split('.')[0] in ('crewai', 'crewai_core')])"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True, env=env
    )
    assert out.stdout.strip() == "[]"


def test_importing_crewai_is_offline(tmp_path):
    # Importing crewai (and the adapter) makes no network call, telemetry left on.
    code = (
        "import socket\n"
        "tried = []\n"
        "def refuse(*a, **k):\n"
        "    tried.append(a[:1]); raise OSError('offline')\n"
        "socket.getaddrinfo = refuse\n"
        "socket.socket.connect = refuse\n"
        "import a2agw.adapters.crewai\n"
        "print(tried)\n"
    )
    env = {k: v for k, v in os.environ.items() if not k.startswith(("CREWAI_", "OTEL_"))}
    isolate_home(env.__setitem__, tmp_path)
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True, env=env
    )
    assert out.stdout.strip() == "[]"


async def test_example_runs():
    from examples.adapters import crewai_example

    assert await crewai_example.main() == "echo: hello from A2A"


async def test_real_home_untouched(tmp_path):
    # Last in the module: after every other test (and one more crew run here), nothing new
    # or changed under the real home's CrewAI paths.
    client = FakePartnerClient()
    script = Script(call("ask_pinger", {"message": "hi"}), "done")
    crew = make_crew(script, as_crewai_tools(client.tools(), client))
    await drive(CrewAIAdapter(crew), "go")
    assert os.path.realpath(os.path.expanduser("~")) != os.path.realpath(REAL_HOME)
    assert crewai_paths(REAL_HOME) == REAL_HOME_BEFORE


async def test_owned_tasks_only():
    # Partner tasks belong to whoever started them: a foreign task id answers "unknown task".
    from adapters.contract import FakePartnerClient, assert_owned_tasks_only

    client = FakePartnerClient()
    await assert_owned_tasks_only(as_crewai_tools(client.tools(), client), run_tool, client)
