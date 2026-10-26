"""Stdio adapter: an external agent, in any language, run as a supervised local process that
speaks JSON lines (spec 7.7, ``docs/sidecar.md``).

One long-lived process serves every turn of the agent; turns are multiplexed by a run id
(``uuid4().hex``):

- The gateway writes to the agent's stdin ``{"op":"invoke","id":<run id>,"request":<invoke
  body>}`` (the ``a2agw.invoke/1`` body, ``a2agw.gateway.protocol.build_invoke``),
  ``{"op":"cancel","id":<run id>}`` and ``{"op":"shutdown"}``, one per line.
- The agent writes to stdout ``{"id":<run id>,"event":<wire event>}``, one per line. A run
  ends at its first terminal event, or when the process exits.
- Stdout carries the protocol only. Stderr is forwarded to the ``a2agw.agent.<agent id>``
  logger at INFO: control characters and ANSI escapes removed, each line capped at 4 KiB, at
  most STDERR_LINES_PER_S lines a second (the rest are counted and reported as suppressed).

Supervision: the process starts at ``start()`` (or lazily, on the first invoke), in a process
group of its own (``start_new_session``), and is always signalled as a group, so helpers it
starts (a wrapper's child, a tool server) cannot outlive it or hold its pipes open. Its exit
is detected from the process itself, not from stdout closing: when it exits, what remains of
its group is killed, every run in flight fails with "agent process exited", and it is
restarted after a back-off of 1, 2, 4 ... up to 30 s (reset once a process stayed up 60 s).
Invokes during the back-off wait for it up to their deadline, then fail with "agent
unavailable". ``stop()`` sends ``shutdown`` and closes stdin, then terminates the group (after
5 s) and kills it (after 2 more). Every wait after an exit is bounded.

The process gets only ``PATH``, ``HOME``, ``LANG``, ``TZ`` and ``PYTHONPATH`` (those that are
set) from the gateway's environment, plus ``env``: the parent environment is never passed
through wholesale.

Failure handling matches the webhook adapter: fixed failure reasons (``a2agw.adapters._sidecar``),
details at WARNING on the agent's logger (an error class or a protocol rule, never a value).
Per run, the same limits apply as to one webhook response (``MAX_LINE_BYTES``,
``MAX_RESPONSE_BYTES``, ``MAX_EVENTS``). A malformed line fails only the run it names (a line
over ``MAX_LINE_BYTES`` names its run when it starts with ``{"id":"<run id>"``); a line that
names no run is logged and ignored. A run that ends on the gateway's side (cancelled, timed
out, a protocol error) is sent ``cancel``.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import re
import signal
from collections.abc import AsyncIterator, Awaitable, Mapping
from contextlib import aclosing
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

from a2agw.adapters._sidecar import (
    EXITED,
    PROTOCOL_ERROR,
    TIMED_OUT,
    UNAVAILABLE,
    ConsultFn,
    TurnDeadline,
    TurnFailure,
    check_line,
    consult_grant,
    loads,
    partial_line_too_long,
    run_turn,
)
from a2agw.core.events import AgentEvent, Failed
from a2agw.core.spi import InboundContext
from a2agw.gateway.protocol import (
    MAX_EVENTS,
    MAX_RESPONSE_BYTES,
    TERMINAL,
    ProtocolError,
    build_invoke,
    parse_event,
)

__all__ = ["StdioAdapter"]

INHERITED_ENV = ("PATH", "HOME", "LANG", "TZ", "PYTHONPATH")
STDERR_LINE_MAX = 4096
STDERR_LINES_PER_S = 100
BACKOFF_MIN_S = 1.0
BACKOFF_MAX_S = 30.0
BACKOFF_RESET_S = 60.0  # uptime after which the back-off starts again at BACKOFF_MIN_S
SHUTDOWN_GRACE_S = 5.0  # after "shutdown" and stdin closed, before SIGTERM to the group
TERMINATE_GRACE_S = 2.0  # after SIGTERM, before SIGKILL to the group
KILL_WAIT_S = 2.0  # for the process to exit after SIGKILL
DRAIN_S = 1.0  # for the pipes' last bytes once the group is gone
_READ_SIZE = 1 << 16
_PEEK = 64  # bytes of an oversized line searched for its run id
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_RUN_ID_PREFIX = re.compile(rb'\s*\{\s*"id"\s*:\s*"([0-9a-f]{32})"')
_ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)?|[@-Z\\-_])")
_CONTROL = re.compile(r"[\x00-\x08\x0a-\x1f\x7f-\x9f]")


@dataclass
class _Run:
    """A run in flight: its events (``AgentEvent | str``, or a ``_End``) and its budget."""

    queue: asyncio.Queue[Any] = field(default_factory=asyncio.Queue)
    bytes: int = 0
    events: int = 0


@dataclass(frozen=True)
class _End:
    """The run ended without a terminal event: fail it, and tell the agent when it still
    runs it (``cancel``)."""

    reason: str
    cancel: bool


@dataclass
class _Child:
    """A spawned process; ``exited`` is set when the process itself exits (its pipes may
    still be held open by descendants)."""

    proc: asyncio.subprocess.Process
    transport: asyncio.SubprocessTransport
    exited: asyncio.Event


class _Protocol(asyncio.subprocess.SubprocessStreamProtocol):
    """The standard stream protocol, plus an event set at process exit. (On 3.12,
    ``Process.wait()`` resolves only once every pipe is closed as well.)"""

    def __init__(self, exited: asyncio.Event, loop: asyncio.AbstractEventLoop) -> None:
        super().__init__(limit=_READ_SIZE, loop=loop)
        self.exited_event = exited

    def process_exited(self) -> None:
        super().process_exited()
        self.exited_event.set()


class _Backoff:
    """Restart delays: BACKOFF_MIN_S doubling up to BACKOFF_MAX_S; reset by a long uptime."""

    def __init__(self) -> None:
        self._next = BACKOFF_MIN_S

    def next(self, *, uptime: float) -> float:
        if uptime >= BACKOFF_RESET_S:
            self._next = BACKOFF_MIN_S
        delay = self._next
        self._next = min(delay * 2, BACKOFF_MAX_S)
        return delay


def _signal_group(pid: int, sig: int) -> None:
    """Signal the process group led by ``pid`` (the agent runs in a session of its own)."""
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(pid, sig)


async def _within(aw: Awaitable[Any], timeout: float) -> bool:
    """Await ``aw`` for at most ``timeout`` seconds; False when it timed out."""
    try:
        await asyncio.wait_for(aw, timeout)
    except TimeoutError:
        return False
    return True


def _clean(line: bytes) -> str:
    """A stderr line for the log: capped, decoded, without escapes or control characters."""
    text = line[:STDERR_LINE_MAX].decode("utf-8", "replace")
    return _CONTROL.sub("", _ANSI.sub("", text))


class StdioAdapter:
    """Inbound adapter for an external agent run as ``command`` (see the module docstring).

    ``agent_id`` names the logger (``a2agw.agent.<agent_id>``); without it, the id of the
    first turn is used (stderr read before that goes to ``a2agw.agent``)."""

    def __init__(
        self,
        command: list[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        max_concurrency: int = 16,
        timeout_s: float = 300.0,
        durable_sessions: bool = False,
        consult: ConsultFn | None = None,
        agent_id: str | None = None,
    ) -> None:
        if (
            not isinstance(command, list)
            or not command
            or not all(isinstance(c, str) and c for c in command)
        ):
            raise ValueError("command must be a non-empty list of non-empty strings")
        env = dict(env or {})
        for name, value in env.items():
            if not (isinstance(name, str) and _ENV_NAME.fullmatch(name) and isinstance(value, str)):
                raise ValueError("env must map environment variable names to strings")
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be at least 1")
        if not timeout_s > 0:
            raise ValueError("timeout_s must be positive")
        self.command = list(command)
        self.cwd = cwd
        self.env = env
        self.max_concurrency = max_concurrency
        self.timeout_s = float(timeout_s)
        self.durable_sessions = durable_sessions
        self.consult = consult
        self.agent_id = agent_id
        self._sem = asyncio.Semaphore(max_concurrency)
        self._write_lock = asyncio.Lock()
        self._runs: dict[str, _Run] = {}
        self._child: _Child | None = None
        self._up = asyncio.Event()  # set while a process is running
        self._tried = asyncio.Event()  # set once the supervisor tried to spawn
        self._supervisor: asyncio.Task[None] | None = None
        self._stopping = False

    def __repr__(self) -> str:  # never env values, nor the arguments
        return (
            f"StdioAdapter(command={self.command[0]!r}, max_concurrency={self.max_concurrency}, "
            f"timeout_s={self.timeout_s})"
        )

    @property
    def pid(self) -> int | None:
        """The running process's pid (also its process group id), or None."""
        return self._child.proc.pid if self._child is not None else None

    def _log(self) -> logging.Logger:
        return logging.getLogger(f"a2agw.agent.{self.agent_id}" if self.agent_id else "a2agw.agent")

    def _child_env(self) -> dict[str, str]:
        env = {k: os.environ[k] for k in INHERITED_ENV if k in os.environ}
        env.update(self.env)
        return env

    # -- lifecycle (``a2agw.core.spi.LifecycleAdapter``) --------------------------------

    async def start(self) -> None:
        """Start the supervisor and return once it tried to spawn the process. A process
        that fails to start is logged and retried with back-off; this does not raise."""
        if not self._ensure_supervisor():
            raise RuntimeError("StdioAdapter is stopping")
        await self._tried.wait()

    async def stop(self) -> None:
        """Shut the process group down (``shutdown``, stdin closed, SIGTERM, SIGKILL) and
        stop supervising it; runs in flight fail with "agent process exited". A later
        invoke (or ``start()``) starts it again."""
        supervisor = self._supervisor
        if supervisor is None:
            return
        self._stopping = True
        try:
            child = self._child
            if child is not None:
                if not child.exited.is_set():
                    await _shut_down(child)
                # The supervisor reaps what is left of the group, ends the runs and returns.
                await asyncio.wait({supervisor}, timeout=KILL_WAIT_S + 2 * DRAIN_S)
        finally:
            supervisor.cancel()  # still spawning, backing off, or past its bound
            await asyncio.gather(supervisor, return_exceptions=True)
            self._supervisor = None
            self._stopping = False

    def _ensure_supervisor(self) -> bool:
        """Start the supervisor unless it runs; False while ``stop()`` is in progress."""
        if self._stopping:
            return False
        if self._supervisor is None or self._supervisor.done():
            self._tried = asyncio.Event()
            self._supervisor = asyncio.create_task(
                self._supervise(), name=f"a2agw:stdio:{self.agent_id or self.command[0]}"
            )
        return True

    async def _supervise(self) -> None:
        try:
            await self._supervise_loop()
        except Exception as e:  # noqa: BLE001 - a bug here must not go unnoticed
            self._log().error("agent supervisor failed: %s", type(e).__name__)
            self._end_all(_End(EXITED, cancel=False))
        finally:
            self._tried.set()  # a start() waiting on a supervisor that ended never hangs

    async def _supervise_loop(self) -> None:
        loop = asyncio.get_running_loop()
        backoff = _Backoff()
        while not self._stopping:
            log = self._log()
            uptime = 0.0
            child = None
            try:
                child = await self._spawn(loop)
            except (OSError, ValueError) as e:  # e.g. FileNotFoundError, PermissionError
                log.warning("agent process failed to start: %s", type(e).__name__)
            finally:
                self._tried.set()
            if child is not None:
                started = loop.time()
                await self._serve(child, log)
                uptime = loop.time() - started
            if self._stopping:
                return
            await asyncio.sleep(backoff.next(uptime=uptime))

    async def _spawn(self, loop: asyncio.AbstractEventLoop) -> _Child:
        exited = asyncio.Event()
        transport, protocol = await loop.subprocess_exec(
            lambda: _Protocol(exited, loop),
            *self.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=self.cwd,
            env=self._child_env(),
            start_new_session=True,  # its own process group: signalled, and killed, as one
        )
        child = _Child(asyncio.subprocess.Process(transport, protocol, loop), transport, exited)
        self._child = child
        self._up.set()
        return child

    async def _serve(self, child: _Child, log: logging.Logger) -> None:
        """Route the process's output until it exits; then kill what is left of its group
        and fail the runs it left."""
        proc = child.proc
        assert proc.stdout is not None and proc.stderr is not None
        pid = proc.pid
        log.info("agent process started (pid %d)", pid)
        out = asyncio.create_task(self._read_stdout(proc.stdout))
        err = asyncio.create_task(self._forward_stderr(proc.stderr))
        exit_wait = asyncio.create_task(child.exited.wait())
        try:
            await asyncio.wait({out, exit_wait}, return_when=asyncio.FIRST_COMPLETED)
            # stdout closed, yet the process runs on: give it a moment, then kill it.
            if not child.exited.is_set() and not await _within(
                child.exited.wait(), SHUTDOWN_GRACE_S
            ):
                log.warning("agent process closed stdout but kept running; killing it")
        finally:
            # No await until no run can register with this process any more.
            self._child = None
            self._up.clear()
            try:
                if not child.exited.is_set():  # cancelled, or still running: kill it
                    _signal_group(pid, signal.SIGKILL)
                    await _within(child.exited.wait(), KILL_WAIT_S)
                # The process is gone: so is the rest of its group, which may hold its pipes.
                _signal_group(pid, signal.SIGKILL)
                await asyncio.wait({out}, timeout=DRAIN_S)  # route the lines it wrote
            finally:
                child.transport.close()  # whatever still holds the pipes, they are closed
                self._end_all(_End(EXITED, cancel=False))
                try:
                    await asyncio.wait({err}, timeout=DRAIN_S)
                    if self._stopping:
                        log.info("agent process stopped (code %s)", proc.returncode)
                    else:
                        log.warning("%s (code %s)", EXITED, proc.returncode)
                finally:
                    for task in (out, err, exit_wait):
                        task.cancel()
                    await asyncio.gather(out, err, exit_wait, return_exceptions=True)
                    await _within(proc.wait(), DRAIN_S)  # the transport has finished

    # -- stdout: the protocol ---------------------------------------------------------

    async def _read_stdout(self, stream: asyncio.StreamReader) -> None:
        log = self._log()
        buf = bytearray()
        skipping = False  # inside a line longer than MAX_LINE_BYTES
        while chunk := await stream.read(_READ_SIZE):
            buf += chunk
            while (i := buf.find(b"\n")) >= 0:
                line = bytes(buf[:i])
                del buf[: i + 1]
                if skipping:
                    skipping = False
                elif line.strip():
                    self._route(line, log)
            if skipping:
                buf.clear()
            elif partial_line_too_long(buf):
                self._oversized(bytes(buf[:_PEEK]), log)
                skipping = True
                buf.clear()
        if buf.strip() and not skipping:
            self._route(bytes(buf), log)

    def _oversized(self, head: bytes, log: logging.Logger) -> None:
        """A line over MAX_LINE_BYTES: fail its run when its start names one."""
        m = _RUN_ID_PREFIX.match(head)
        rid = m.group(1).decode() if m else None
        if rid is not None and rid in self._runs:
            log.warning("%s: line longer than MAX_LINE_BYTES", PROTOCOL_ERROR)
            self._end(rid, _End(PROTOCOL_ERROR, cancel=True))
        else:
            log.warning("%s: line longer than MAX_LINE_BYTES; ignored", PROTOCOL_ERROR)

    def _route(self, line: bytes, log: logging.Logger) -> None:
        """One stdout line to its run's queue (or the run's end, when it breaks the rules)."""
        try:
            line = check_line(line)
        except ProtocolError:
            self._oversized(line[:_PEEK], log)
            return
        try:
            obj = loads(line)
        except ProtocolError as e:
            log.warning("%s: %s; line ignored", PROTOCOL_ERROR, e)
            return
        rid = obj.get("id") if isinstance(obj, dict) else None
        if not isinstance(rid, str):
            log.warning("%s: line without a run id; ignored", PROTOCOL_ERROR)
            return
        run = self._runs.get(rid)
        if run is None:  # a run that has ended (or never was)
            log.debug("line for an unknown or ended run; ignored")
            return
        run.bytes += len(line) + 1
        run.events += 1
        try:
            if run.bytes > MAX_RESPONSE_BYTES:
                raise ProtocolError("run output larger than MAX_RESPONSE_BYTES")
            if run.events > MAX_EVENTS:
                raise ProtocolError("more than MAX_EVENTS events")
            if set(obj) != {"id", "event"}:
                raise ProtocolError("line needs exactly id and event")
            item = parse_event(obj["event"])
        except ProtocolError as e:
            log.warning("%s: %s", PROTOCOL_ERROR, e)
            self._end(rid, _End(PROTOCOL_ERROR, cancel=True))
            return
        if isinstance(item, TERMINAL):
            del self._runs[rid]  # the run ends at its first terminal event
        run.queue.put_nowait(item)

    def _end(self, rid: str, end: _End) -> None:
        run = self._runs.pop(rid, None)
        if run is not None:
            run.queue.put_nowait(end)

    def _end_all(self, end: _End) -> None:
        for rid in list(self._runs):
            self._end(rid, end)

    # -- stderr: forwarded to the log -------------------------------------------------

    async def _forward_stderr(self, stream: asyncio.StreamReader) -> None:
        log = self._log()
        loop = asyncio.get_running_loop()
        window = loop.time()
        emitted = suppressed = 0

        def note_suppressed() -> None:
            nonlocal suppressed
            if suppressed:
                log.warning("agent stderr: suppressed %d lines (rate limit)", suppressed)
                suppressed = 0

        def emit(line: bytes, truncated: bool = False) -> None:
            nonlocal window, emitted, suppressed
            now = loop.time()
            if now - window >= 1.0:
                note_suppressed()
                window, emitted = now, 0
            if emitted >= STDERR_LINES_PER_S:
                suppressed += 1
                return
            emitted += 1
            log.info("%s [truncated]" if truncated else "%s", _clean(line))

        buf = bytearray()
        skipping = False
        try:
            while chunk := await stream.read(_READ_SIZE):
                buf += chunk
                while (i := buf.find(b"\n")) >= 0:
                    line = bytes(buf[:i])
                    del buf[: i + 1]
                    if skipping:
                        skipping = False
                    else:
                        emit(line, truncated=len(line) > STDERR_LINE_MAX)
                if len(buf) > STDERR_LINE_MAX and not skipping:
                    emit(bytes(buf), truncated=True)
                    skipping = True
                if skipping:
                    buf.clear()
            if buf and not skipping:
                emit(bytes(buf))
        finally:
            note_suppressed()

    # -- turns ------------------------------------------------------------------------

    async def run(self, ctx: InboundContext) -> AsyncIterator[AgentEvent]:
        if self.agent_id is None:
            self.agent_id = ctx.agent_id
        async with aclosing(run_turn(self._turn(ctx, self._log()))) as events:
            async for ev in events:
                yield ev

    async def _turn(
        self, ctx: InboundContext, log: logging.Logger
    ) -> AsyncIterator[AgentEvent | str]:
        """Wire events (a ``str`` is a text delta), then possibly one ``Failed``."""
        deadline = TurnDeadline(self.timeout_s)
        try:
            grant = await consult_grant(self.consult, ctx, deadline, log)
        except TurnFailure as e:
            yield Failed(e.reason)
            return
        invoke = build_invoke(ctx, consult=grant, deadline=deadline.wall)
        try:
            await deadline.within(self._sem.acquire())
        except TimeoutError:
            log.warning("%s after %ss (waiting for a free slot)", TIMED_OUT, self.timeout_s)
            yield Failed(TIMED_OUT)
            return
        rid = uuid4().hex
        child: _Child | None = None
        ended = False  # by the agent (a terminal event) or by the process exiting
        try:
            try:
                child, run = await self._register(rid, deadline)
            except TurnFailure as e:
                yield Failed(e.reason)
                return
            try:
                await deadline.within(
                    self._write(child, {"op": "invoke", "id": rid, "request": invoke})
                )
                while True:
                    item = await deadline.within(run.queue.get())
                    if isinstance(item, _End):
                        ended = not item.cancel
                        yield Failed(item.reason)
                        return
                    ended = isinstance(item, TERMINAL)
                    yield item
                    if ended:
                        return
            except TimeoutError:
                log.warning("%s after %ss", TIMED_OUT, self.timeout_s)
                yield Failed(TIMED_OUT)
        finally:
            self._sem.release()
            self._runs.pop(rid, None)
            if child is not None and not ended:  # ended on our side: the agent may still run it
                self._send_nowait(child, {"op": "cancel", "id": rid})

    async def _register(self, rid: str, deadline: TurnDeadline) -> tuple[_Child, _Run]:
        """Wait (within the deadline) for a running process and register the run with it."""
        while True:
            if not self._ensure_supervisor():
                raise TurnFailure(UNAVAILABLE)
            try:
                await deadline.within(self._up.wait())
            except TimeoutError:
                self._log().warning("%s after %ss", UNAVAILABLE, self.timeout_s)
                raise TurnFailure(UNAVAILABLE) from None
            child = self._child
            if child is not None:  # no await since the check: the process is still served
                run = self._runs[rid] = _Run()
                return child, run

    async def _write(self, child: _Child, msg: dict[str, Any]) -> None:
        """One line to stdin. A broken pipe is not an error here: the process is exiting,
        and its runs end with "agent process exited"."""
        data = json.dumps(msg, separators=(",", ":")).encode() + b"\n"
        stdin = child.proc.stdin
        assert stdin is not None
        async with self._write_lock:
            if child.exited.is_set() or stdin.is_closing():
                return
            try:
                stdin.write(data)
                await stdin.drain()
            except (BrokenPipeError, ConnectionResetError):
                self._log().debug("agent stdin closed")

    def _send_nowait(self, child: _Child, msg: dict[str, Any]) -> None:
        """Best effort, without waiting (e.g. from a closing generator)."""
        stdin = child.proc.stdin
        if child.exited.is_set() or stdin is None or stdin.is_closing():
            return
        with contextlib.suppress(BrokenPipeError, ConnectionResetError, RuntimeError):
            stdin.write(json.dumps(msg, separators=(",", ":")).encode() + b"\n")


async def _shut_down(child: _Child) -> None:
    """``shutdown`` and stdin closed; SIGTERM to the group after SHUTDOWN_GRACE_S; SIGKILL
    after TERMINATE_GRACE_S more. Returns once the process has exited (or KILL_WAIT_S)."""
    stdin = child.proc.stdin
    if stdin is not None and not stdin.is_closing():
        with contextlib.suppress(BrokenPipeError, ConnectionResetError, RuntimeError):
            stdin.write(b'{"op":"shutdown"}\n')
        stdin.close()
    pid = child.proc.pid
    for grace, sig in ((SHUTDOWN_GRACE_S, signal.SIGTERM), (TERMINATE_GRACE_S, signal.SIGKILL)):
        if await _within(child.exited.wait(), grace):
            return
        _signal_group(pid, sig)
    await _within(child.exited.wait(), KILL_WAIT_S)
