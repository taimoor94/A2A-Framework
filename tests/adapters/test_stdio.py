"""StdioAdapter against a real subprocess (``stdio_agent.py``, run with ``python -I``)."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sys
import time
import types
from pathlib import Path

import pytest
from a2a.types import Message, Part, Role

from a2agw.adapters import _sidecar
from a2agw.adapters import stdio as stdio_mod
from a2agw.adapters.stdio import StdioAdapter
from a2agw.core.events import ArtifactChunk, Done, Failed, Status, Usage
from a2agw.core.spi import InboundContext, LifecycleAdapter
from a2agw.gateway.protocol import MAX_LINE_BYTES, PROTOCOL, ConsultGrant

AGENT = str(Path(__file__).with_name("stdio_agent.py"))
LOGGER = "a2agw.agent.coder"


def cmd(mode: str, *extra: str) -> list[str]:
    return [sys.executable, "-I", AGENT, mode, *extra]


@pytest.fixture
async def make():
    made: list[StdioAdapter] = []

    def factory(mode: str, *extra: str, **kw) -> StdioAdapter:
        a = StdioAdapter(cmd(mode, *extra), agent_id="coder", **kw)
        made.append(a)
        return a

    yield factory
    for a in made:
        await a.stop()


def ctx(text: str = "hello", task_id: str = "t1") -> InboundContext:
    msg = Message(message_id="m1", role=Role.ROLE_USER, parts=[Part(text=text)])
    return InboundContext.from_message("coder", msg, task_id=task_id, context_id="c1")


async def collect(a: StdioAdapter, text: str = "hello", task_id: str = "t1") -> list:
    return [ev async for ev in a.run(ctx(text, task_id))]


def chunk(text: str, *, first: bool, last: bool) -> ArtifactChunk:
    return ArtifactChunk(
        [Part(text=text)], name="output", artifact_id="output", append=not first, last=last
    )


def echo(text: str) -> list:
    return [
        Status("on it"),
        chunk("echo: ", first=True, last=False),
        chunk(text, first=False, last=False),
        Usage(1, 2, 0.5),
        Done(),
    ]


def ops(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def grandchildren(rec: Path) -> list[int]:
    path = Path(f"{rec}.gc")
    return [int(x) for x in path.read_text().split()] if path.exists() else []


async def until(pred, timeout: float = 5.0):
    """Poll ``pred`` (something the agent process does on its own) until it is truthy."""
    end = time.monotonic() + timeout
    while not (result := pred()):
        if time.monotonic() > end:
            raise AssertionError("condition not reached")
        await asyncio.sleep(0.02)
    return result


async def test_invoke_streams_events(make, tmp_path):
    rec = tmp_path / "ops.jsonl"
    a = make("serve", str(rec))
    assert isinstance(a, LifecycleAdapter)
    assert await collect(a) == echo("hello")
    [op] = ops(rec)
    assert op["op"] == "invoke" and len(op["id"]) == 32 and int(op["id"], 16) >= 0
    req = op["request"]
    assert req["protocol"] == PROTOCOL and req["text"] == "hello" and req["task_id"] == "t1"
    assert req["consult"] is None
    assert req["deadline"] == pytest.approx(time.time() + 300.0, abs=5)
    assert await collect(a, "again") == echo("again")  # same process, next run
    assert len({o["id"] for o in ops(rec)}) == 2


async def test_concurrent_runs_are_multiplexed(make):
    a = make("gather:8")
    texts = [f"r{i}" for i in range(8)]
    results = await asyncio.wait_for(
        asyncio.gather(*(collect(a, t, task_id=t) for t in texts)), 10.0
    )
    assert results == [[Done(f"reply-{t}")] for t in texts]


async def test_cancel_sends_cancel_op(make, tmp_path):
    rec = tmp_path / "ops.jsonl"
    a = make("serve", str(rec))
    events = a.run(ctx("block"))
    assert await anext(events) == Status("working")
    await events.aclose()
    [inv] = [o for o in ops(rec) if o["op"] == "invoke"]
    await until(lambda: any(o["op"] == "cancel" for o in ops(rec)))
    [cancel] = [o for o in ops(rec) if o["op"] == "cancel"]
    assert cancel == {"op": "cancel", "id": inv["id"]}
    assert await collect(a) == echo("hello")  # the process is still serving


async def test_timeout_fails_and_cancels(make, tmp_path):
    rec = tmp_path / "ops.jsonl"
    a = make("serve", str(rec), timeout_s=0.3)
    start = time.monotonic()
    assert await collect(a, "block") == [Status("working"), Failed("agent timed out")]
    assert time.monotonic() - start < 3.0
    await until(lambda: any(o["op"] == "cancel" for o in ops(rec)))


async def test_crash_fails_inflight_and_restarts(make, tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(stdio_mod, "BACKOFF_MIN_S", 0.05)
    rec = tmp_path / "ops.jsonl"
    a = make("crash-after-first", str(rec))
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        results = await asyncio.wait_for(
            asyncio.gather(*(collect(a, f"r{i}", task_id=f"t{i}") for i in range(3))), 10.0
        )
    assert results == [[Failed("agent process exited")]] * 3
    assert "agent process exited" in caplog.text
    assert await asyncio.wait_for(collect(a), 10.0) == echo("hello")  # restarted


async def test_env_is_not_inherited(make, tmp_path, monkeypatch):
    monkeypatch.setenv("A2AGW_TEST_SECRET", "s3cret")
    monkeypatch.setenv("A2AGW_TEST_OTHER", "x")
    a = make("serve", env={"GIVEN": "given-value"}, cwd=tmp_path)
    [done] = await collect(a, "env")
    report = json.loads(done.text)
    assert report["secret"] is False and report["other"] is False
    assert report["given"] == "given-value"
    assert os.path.realpath(report["cwd"]) == os.path.realpath(tmp_path)
    assert "given-value" not in repr(a)


def test_child_env_allowlist(monkeypatch):
    for k, v in {"PATH": "/p", "HOME": "/h", "LANG": "C", "TZ": "UTC", "PYTHONPATH": "/pp"}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("A2AGW_TEST_SECRET", "s3cret")
    a = StdioAdapter(["agent"], env={"GIVEN": "g", "PATH": "/override"})
    assert a._child_env() == {
        "PATH": "/override",
        "HOME": "/h",
        "LANG": "C",
        "TZ": "UTC",
        "PYTHONPATH": "/pp",
        "GIVEN": "g",
    }


async def test_stderr_forwarded_and_capped(make, caplog):
    a = make("serve")
    with caplog.at_level(logging.INFO, logger=LOGGER):
        assert await collect(a, "stderr") == [Done()]
        await until(lambda: "hello-stderr" in caplog.text)
    lines = [r for r in caplog.records if r.name == LOGGER and r.levelno == logging.INFO]
    long = [r.getMessage() for r in lines if r.getMessage().startswith("x")]
    assert long == ["x" * 4096 + " [truncated]"]
    assert any(r.getMessage() == "hello-stderr" for r in lines)


async def test_shutdown_terminates_process(make, tmp_path):
    rec = tmp_path / "ops.jsonl"
    a = make("serve", str(rec))
    await a.start()
    pid = a.pid
    assert pid is not None
    os.kill(pid, 0)  # running
    await a.stop()
    assert a.pid is None
    with pytest.raises(ProcessLookupError):  # exited and reaped: no zombie
        os.kill(pid, 0)
    assert ops(rec)[-1] == {"op": "shutdown"}
    assert await collect(a) == echo("hello")  # a later invoke starts it again


async def test_stubborn_process_is_killed(make, monkeypatch):
    monkeypatch.setattr(stdio_mod, "SHUTDOWN_GRACE_S", 0.2)
    monkeypatch.setattr(stdio_mod, "TERMINATE_GRACE_S", 0.2)
    a = make("stubborn")
    await a.start()
    pid = a.pid
    assert pid is not None
    start = time.monotonic()
    await a.stop()
    assert time.monotonic() - start < 3.0
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


async def test_inflight_runs_fail_on_stop(make):
    a = make("serve")
    events = a.run(ctx("block"))
    assert await anext(events) == Status("working")
    await a.stop()
    assert [ev async for ev in events] == [Failed("agent process exited")]


async def test_malformed_line_fails_only_that_run(make, tmp_path, caplog):
    rec = tmp_path / "ops.jsonl"
    a = make("serve", str(rec))
    blocked = a.run(ctx("block", task_id="tb"))
    assert await anext(blocked) == Status("working")
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        assert await collect(a, "malformed") == [Failed("agent protocol error")]
        # Unparseable lines and a line without an id are logged and ignored.
        assert await collect(a, "garbage") == echo("garbage")
    assert "unknown event type" in caplog.text
    assert "invalid JSON" in caplog.text and "without a run id" in caplog.text
    invokes = {o["request"]["text"]: o["id"] for o in ops(rec) if o["op"] == "invoke"}
    await until(lambda: any(o["op"] == "cancel" for o in ops(rec)))
    cancels = [o["id"] for o in ops(rec) if o["op"] == "cancel"]
    assert cancels == [invokes["malformed"]]  # the blocked run is untouched
    await blocked.aclose()


async def test_per_run_event_limit(make, monkeypatch):
    monkeypatch.setattr(stdio_mod, "MAX_EVENTS", 3)
    a = make("serve")
    events = await collect(a)
    assert events[0] == Status("on it") and events[-1] == Failed("agent protocol error")
    assert len(events) == 4
    monkeypatch.setattr(stdio_mod, "MAX_EVENTS", 100)
    monkeypatch.setattr(stdio_mod, "MAX_RESPONSE_BYTES", 150)
    events = await collect(a)
    assert events[-1] == Failed("agent protocol error")


async def test_max_concurrency_bounds_runs(make, tmp_path):
    rec = tmp_path / "ops.jsonl"
    a = make("serve", str(rec), max_concurrency=1, timeout_s=0.3)
    blocked = a.run(ctx("block"))
    assert await anext(blocked) == Status("working")
    assert await collect(a) == [Failed("agent timed out")]
    assert [o["request"]["text"] for o in ops(rec) if o["op"] == "invoke"] == ["block"]
    await blocked.aclose()


async def test_spawn_failure_is_unavailable(tmp_path, caplog):
    a = StdioAdapter([str(tmp_path / "missing-agent")], agent_id="coder", timeout_s=0.3)
    try:
        with caplog.at_level(logging.WARNING, logger=LOGGER):
            assert await collect(a) == [Failed("agent unavailable")]
        assert "FileNotFoundError" in caplog.text
    finally:
        await a.stop()


async def test_backoff_invokes_fail_unavailable(make, monkeypatch):
    monkeypatch.setattr(stdio_mod, "BACKOFF_MIN_S", 30.0)
    a = make("exit", timeout_s=0.3)
    await a.start()
    await until(lambda: a.pid is None)  # exited; now backing off
    start = time.monotonic()
    assert await collect(a) == [Failed("agent unavailable")]
    assert time.monotonic() - start < 3.0
    start = time.monotonic()
    await a.stop()  # does not wait out the back-off
    assert time.monotonic() - start < 3.0


def test_backoff_schedule():
    b = stdio_mod._Backoff()
    assert [b.next(uptime=0.0) for _ in range(7)] == [1, 2, 4, 8, 16, 30, 30]
    assert b.next(uptime=60.0) == 1  # a long enough run resets it
    assert b.next(uptime=1.0) == 2


async def test_consult_grant_and_deadline(make, tmp_path, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(_sidecar, "time", types.SimpleNamespace(time=lambda: clock[0]))
    rec = tmp_path / "ops.jsonl"

    async def grant(c: InboundContext) -> ConsultGrant:
        clock[0] += 50.0  # the grant takes a while
        return ConsultGrant(url="http://gw/consult", token="g-tok", expires_at=42.0)

    a = make("serve", str(rec), consult=grant, timeout_s=300.0)
    assert await collect(a) == echo("hello")
    [op] = ops(rec)
    assert op["request"]["deadline"] == 1300.0  # captured when the turn started
    assert op["request"]["consult"] == {
        "url": "http://gw/consult",
        "token": "g-tok",
        "expires_at": 42.0,
    }


async def test_consult_setup_failure(make, tmp_path, caplog):
    rec = tmp_path / "ops.jsonl"

    async def boom(_c: InboundContext):
        raise RuntimeError("SECRET-MARKER")

    a = make("serve", str(rec), consult=boom)
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        assert await collect(a) == [Failed("agent consult setup failed")]
    assert "RuntimeError" in caplog.text and "SECRET-MARKER" not in caplog.text
    assert ops(rec) == []


def test_constructor_validates():
    a = StdioAdapter(["agent", "--flag"], durable_sessions=True)
    assert a.durable_sessions is True and a.command == ["agent", "--flag"]
    assert (a.max_concurrency, a.timeout_s, a.cwd, a.consult) == (16, 300.0, None, None)
    for bad in ([], [""], ["ok", 3], "agent"):
        with pytest.raises(ValueError):
            StdioAdapter(bad)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        StdioAdapter(["a"], max_concurrency=0)
    with pytest.raises(ValueError):
        StdioAdapter(["a"], timeout_s=0)
    with pytest.raises(ValueError):
        StdioAdapter(["a"], env={"BAD=NAME": "x"})


async def test_crash_with_live_grandchild_fails_promptly_and_restarts(make, tmp_path, monkeypatch):
    # The grandchild holds the agent's pipes open: the exit is still seen at once, the rest
    # of the process group is killed, and the agent is restarted.
    monkeypatch.setattr(stdio_mod, "BACKOFF_MIN_S", 0.05)
    rec = tmp_path / "ops.jsonl"
    a = make("grandchild", str(rec), timeout_s=30)
    assert await collect(a) == echo("hello")
    [gc] = grandchildren(rec)
    assert alive(gc)
    start = time.monotonic()
    assert await collect(a, "crash") == [Failed("agent process exited")]
    assert time.monotonic() - start < 5.0  # not the 30 s deadline
    await until(lambda: not alive(gc))
    assert await asyncio.wait_for(collect(a), 10.0) == echo("hello")  # restarted
    assert len(grandchildren(rec)) == 2


async def test_stop_leaves_no_descendant(make, tmp_path):
    rec = tmp_path / "ops.jsonl"
    a = make("grandchild", str(rec))
    await a.start()
    [gc] = await until(lambda: grandchildren(rec))
    pid = a.pid
    assert pid is not None
    start = time.monotonic()
    await a.stop()
    assert time.monotonic() - start < 3.0
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
    await until(lambda: not alive(gc))  # killed with the group, not orphaned


async def test_oversized_line_fails_its_run_promptly(make, tmp_path):
    rec = tmp_path / "ops.jsonl"
    a = make("serve", str(rec), timeout_s=30)
    start = time.monotonic()
    assert await collect(a, "huge") == [Failed("agent protocol error")]
    assert time.monotonic() - start < 5.0  # its run id was read from the line's start
    await until(lambda: any(o["op"] == "cancel" for o in ops(rec)))
    # Exactly MAX_LINE_BYTES plus "\r\n", the "\r" arriving before the "\n": accepted.
    status, done = await collect(a, "big")
    assert isinstance(status, Status) and done == Done()
    assert len(status.text) > MAX_LINE_BYTES - 100


async def test_stderr_sanitized_and_rate_limited(make, caplog):
    a = make("serve")
    with caplog.at_level(logging.INFO, logger=LOGGER):
        assert await collect(a, "noisy") == [Done()]
        await a.stop()  # the end of stderr reports what was suppressed
    msgs = [r.getMessage() for r in caplog.records if r.name == LOGGER]
    lines = [m for m in msgs if m.startswith("red")]
    assert lines[0] == "red line 0"  # no escapes, no control characters
    assert all(re.fullmatch(r"red line \d+", m) for m in lines)
    [note] = [m for m in msgs if "suppressed" in m]
    suppressed = int(re.search(r"suppressed (\d+) lines", note).group(1))
    assert 100 <= len(lines) <= 200 and len(lines) + suppressed == 300


def test_env_names_must_match_fully():
    with pytest.raises(ValueError):
        StdioAdapter(["a"], env={"FOO\n": "x"})
