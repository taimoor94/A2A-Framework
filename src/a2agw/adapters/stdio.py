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
  logger at INFO, each line capped at 4 KiB.

Supervision: the process starts at ``start()`` (or lazily, on the first invoke). When it
exits, every run in flight fails with "agent process exited" and it is restarted after a
back-off of 1, 2, 4 ... up to 30 s (reset once a process stayed up 60 s); invokes during the
back-off wait for it up to their deadline, then fail with "agent unavailable". ``stop()`` sends
``shutdown`` and closes stdin, then terminates (after 5 s) and kills (after 2 more).

The process gets only ``PATH``, ``HOME``, ``LANG``, ``TZ`` and ``PYTHONPATH`` (those that are
set) from the gateway's environment, plus ``env``: the parent environment is never passed
through wholesale.

Failure handling matches the webhook adapter: fixed failure reasons, details at WARNING on the
agent's logger (an error class or a protocol rule, never a value). Per run, the same limits
apply as to one webhook response (``MAX_LINE_BYTES``, ``MAX_RESPONSE_BYTES``, ``MAX_EVENTS``).
A malformed line fails only the run it names; a line that names no run is logged and ignored.
A run that ends on the gateway's side (cancelled, timed out, a protocol error) is sent
``cancel``.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import re
from collections.abc import AsyncIterator, Mapping
from contextlib import aclosing
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

from a2agw.adapters._sidecar import (
    ConsultFn,
    TurnDeadline,
    TurnFailure,
    check_line,
    consult_grant,
    loads,
    run_turn,
)
from a2agw.core.events import AgentEvent, Failed
from a2agw.core.spi import InboundContext
from a2agw.gateway.protocol import (
    MAX_EVENTS,
    MAX_LINE_BYTES,
    MAX_RESPONSE_BYTES,
    TERMINAL,
    ProtocolError,
    build_invoke,
    parse_event,
)

__all__ = ["StdioAdapter"]

INHERITED_ENV = ("PATH", "HOME", "LANG", "TZ", "PYTHONPATH")
STDERR_LINE_MAX = 4096
BACKOFF_MIN_S = 1.0
BACKOFF_MAX_S = 30.0
BACKOFF_RESET_S = 60.0  # uptime after which the back-off starts again at BACKOFF_MIN_S
SHUTDOWN_GRACE_S = 5.0  # after "shutdown" and stdin closed, before terminate()
TERMINATE_GRACE_S = 2.0  # after terminate(), before kill()
_READ_SIZE = 1 << 16
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

EXITED = "agent process exited"
UNAVAILABLE = "agent unavailable"


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
            if not (isinstance(name, str) and _ENV_NAME.match(name) and isinstance(value, str)):
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
        self._proc: asyncio.subprocess.Process | None = None
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
        """The running process's pid, or None."""
        return self._proc.pid if self._proc is not None else None

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
        """Shut the process down (``shutdown``, stdin closed, terminate, kill) and stop
        supervising it; runs in flight fail with "agent process exited". A later invoke (or
        ``start()``) starts it again."""
        supervisor = self._supervisor
        if supervisor is None:
            return
        self._stopping = True
        try:
            proc = self._proc
            if proc is not None and proc.returncode is None:
                await _shut_down(proc)
        finally:
            supervisor.cancel()
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
            self._tried.set()

    async def _supervise_loop(self) -> None:
        loop = asyncio.get_running_loop()
        backoff = _Backoff()
        while True:
            log = self._log()
            uptime = 0.0
            try:
                proc = await asyncio.create_subprocess_exec(
                    *self.command,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=self.cwd,
                    env=self._child_env(),
                )
            except (OSError, ValueError) as e:  # e.g. FileNotFoundError, PermissionError
                log.warning("agent process failed to start: %s", type(e).__name__)
                self._tried.set()
            else:
                self._tried.set()
                started = loop.time()
                await self._serve(proc, log)
                uptime = loop.time() - started
            await asyncio.sleep(backoff.next(uptime=uptime))

    async def _serve(self, proc: asyncio.subprocess.Process, log: logging.Logger) -> None:
        """Route the process's output until it exits; then fail the runs it left."""
        assert proc.stdout is not None and proc.stderr is not None
        self._proc = proc
        self._up.set()
        log.info("agent process started (pid %d)", proc.pid)
        stderr = asyncio.create_task(self._forward_stderr(proc.stderr))
        try:
            await self._read_stdout(proc.stdout)
            try:  # stdout closed: the process is exiting (or misbehaving)
                await asyncio.wait_for(proc.wait(), SHUTDOWN_GRACE_S)
            except TimeoutError:
                log.warning("agent process closed stdout but kept running; killing it")
        finally:
            # No await until the runs are ended: a run registers only while ``_proc`` is set,
            # and a cancelled supervisor (``stop()``) still ends them all.
            if proc.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
            self._proc = None
            self._up.clear()
            self._end_all(_End(EXITED, cancel=False))
            try:
                await proc.wait()  # reaped: no zombie
                if self._stopping:
                    log.info("agent process stopped (code %s)", proc.returncode)
                else:
                    log.warning("agent process exited (code %s)", proc.returncode)
                await asyncio.wait({stderr}, timeout=1.0)  # its last lines, unless held open
            finally:
                stderr.cancel()
                await asyncio.gather(stderr, return_exceptions=True)

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
            if len(buf) > MAX_LINE_BYTES:
                if not skipping:
                    log.warning("agent protocol error: line longer than MAX_LINE_BYTES; ignored")
                skipping = True
                buf.clear()
        if buf.strip() and not skipping:
            self._route(bytes(buf), log)

    def _route(self, line: bytes, log: logging.Logger) -> None:
        """One stdout line to its run's queue (or the run's end, when it breaks the rules)."""
        try:
            obj = loads(check_line(line))
        except ProtocolError as e:
            log.warning("agent protocol error: %s; line ignored", e)
            return
        rid = obj.get("id") if isinstance(obj, dict) else None
        if not isinstance(rid, str):
            log.warning("agent protocol error: line without a run id; ignored")
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
            log.warning("agent protocol error: %s", e)
            self._end(rid, _End("agent protocol error", cancel=True))
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

    async def _forward_stderr(self, stream: asyncio.StreamReader) -> None:
        log = self._log()

        def emit(line: bytes, truncated: bool = False) -> None:
            text = line[:STDERR_LINE_MAX].decode("utf-8", "replace").removesuffix("\r")
            log.info("%s [truncated]" if truncated else "%s", text)

        buf = bytearray()
        skipping = False
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
            log.warning("agent timed out after %ss (waiting for a free slot)", self.timeout_s)
            yield Failed("agent timed out")
            return
        rid = uuid4().hex
        proc: asyncio.subprocess.Process | None = None
        ended = False  # by the agent (a terminal event) or by the process exiting
        try:
            try:
                proc, run = await self._register(rid, deadline)
            except TurnFailure as e:
                yield Failed(e.reason)
                return
            try:
                await deadline.within(
                    self._write(proc, {"op": "invoke", "id": rid, "request": invoke})
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
                log.warning("agent timed out after %ss", self.timeout_s)
                yield Failed("agent timed out")
        finally:
            self._sem.release()
            self._runs.pop(rid, None)
            if proc is not None and not ended:  # ended on our side: the agent may still run it
                self._send_nowait(proc, {"op": "cancel", "id": rid})

    async def _register(
        self, rid: str, deadline: TurnDeadline
    ) -> tuple[asyncio.subprocess.Process, _Run]:
        """Wait (within the deadline) for a running process and register the run with it."""
        while True:
            if not self._ensure_supervisor():
                raise TurnFailure(UNAVAILABLE)
            try:
                await deadline.within(self._up.wait())
            except TimeoutError:
                self._log().warning("agent unavailable after %ss", self.timeout_s)
                raise TurnFailure(UNAVAILABLE) from None
            proc = self._proc
            if proc is not None:  # no await since the check: the process is still running
                run = self._runs[rid] = _Run()
                return proc, run

    async def _write(self, proc: asyncio.subprocess.Process, msg: dict[str, Any]) -> None:
        """One line to stdin. A broken pipe is not an error here: the process is exiting,
        and its runs end with "agent process exited"."""
        data = json.dumps(msg, separators=(",", ":")).encode() + b"\n"
        stdin = proc.stdin
        assert stdin is not None
        async with self._write_lock:
            if stdin.is_closing():
                return
            try:
                stdin.write(data)
                await stdin.drain()
            except (BrokenPipeError, ConnectionResetError):
                self._log().debug("agent stdin closed")

    def _send_nowait(self, proc: asyncio.subprocess.Process, msg: dict[str, Any]) -> None:
        """Best effort, without waiting (e.g. from a closing generator)."""
        stdin = proc.stdin
        if proc.returncode is not None or stdin is None or stdin.is_closing():
            return
        with contextlib.suppress(BrokenPipeError, ConnectionResetError, RuntimeError):
            stdin.write(json.dumps(msg, separators=(",", ":")).encode() + b"\n")


async def _shut_down(proc: asyncio.subprocess.Process) -> None:
    """``shutdown``, stdin closed; terminate after SHUTDOWN_GRACE_S; kill after
    TERMINATE_GRACE_S more. Returns once the process has exited and been reaped."""
    stdin = proc.stdin
    if stdin is not None and not stdin.is_closing():
        with contextlib.suppress(BrokenPipeError, ConnectionResetError, RuntimeError):
            stdin.write(b'{"op":"shutdown"}\n')
        stdin.close()
    for grace, signal_next in ((SHUTDOWN_GRACE_S, proc.terminate), (TERMINATE_GRACE_S, proc.kill)):
        try:
            await asyncio.wait_for(proc.wait(), grace)
            return
        except TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                signal_next()
    await proc.wait()
