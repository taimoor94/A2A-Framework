"""Ranked executable verification of a worker's change: verification by execution.

Every check is a real subprocess (never a shell) in its own session, so a timeout or an output
overflow kills the whole process group. Output is read through a shared 4 MiB cap; the result
keeps only the SHA-256 of what was captured and the last 2 KiB of stderr with secrets masked.

Acceptance files (``AcceptanceTest.files``) are paths relative to the *workspace root*; the test
command itself runs in the system's ``path`` sub-tree of that root.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import os
import re
import signal
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal

from a2agw.vsc.config import CheckConfig, SystemConfig
from a2agw.vsc.spec import AcceptanceTest, ExecutableSpec
from a2agw.vsc.workspace import Workspace, WorkspaceManager

CheckKind = Literal[
    "gate",
    "reproduction_before",
    "reproduction_after",
    "regression",
    "contract",
    "path_confinement",
    "whole_system",
    "review",
]

MAX_OUTPUT_BYTES = 4 * 1024 * 1024
STDERR_TAIL_BYTES = 2048
_CHUNK = 64 * 1024
_KILL_GRACE_S = 2.0

_SECRET_PATTERNS = [
    re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}"),
    re.compile(
        r"(?i)\b([\w.-]*(?:token|secret|passw(?:or)?d|api[_-]?key|auth|credential)[\w.-]*)"
        r"(\s*[=:]\s*)\S+"
    ),
    re.compile(r"\b(?:gh[pousr]_|github_pat_|sk-|xox[abprs]-|AKIA|AIza)[A-Za-z0-9_-]{8,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"),
    re.compile(r"(?i)(://[^/\s:@]+:)[^@\s/]+@"),
]


def _redact(text: str) -> str:
    text = _SECRET_PATTERNS[0].sub(lambda m: f"{m.group(1)} [redacted]", text)
    text = _SECRET_PATTERNS[1].sub(lambda m: f"{m.group(1)}{m.group(2)}[redacted]", text)
    text = _SECRET_PATTERNS[2].sub("[redacted]", text)
    text = _SECRET_PATTERNS[3].sub("[redacted]", text)
    return _SECRET_PATTERNS[4].sub(lambda m: f"{m.group(1)}[redacted]@", text)


@dataclass(frozen=True)
class CheckResult:
    kind: CheckKind
    id: str
    command: list[str]
    exit_code: int | None
    passed: bool
    duration_s: float
    log_sha256: str
    stderr_tail: str
    reason: str = ""


def _kill_group(pid: int) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(pid, signal.SIGKILL)


def _tail_text(data: bytes) -> str:
    tail = data[-STDERR_TAIL_BYTES:].decode(errors="replace")
    return _redact(tail).encode()[-STDERR_TAIL_BYTES:].decode(errors="replace")


def _result(
    kind: CheckKind,
    id: str,
    command: list[str],
    *,
    exit_code: int | None,
    passed: bool,
    started: float,
    digest: str = "",
    stderr: bytes = b"",
    reason: str = "",
) -> CheckResult:
    return CheckResult(
        kind=kind,
        id=id,
        command=list(command),
        exit_code=exit_code,
        passed=passed,
        duration_s=round(time.monotonic() - started, 3),
        log_sha256=digest or hashlib.sha256(b"").hexdigest(),
        stderr_tail=_tail_text(stderr),
        reason=reason,
    )


async def run_check(
    kind: CheckKind,
    id: str,
    command: list[str],
    cwd: Path,
    *,
    timeout_s: float,
    env: Mapping[str, str] | None = None,
) -> CheckResult:
    started = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(
            *command,
            cwd=cwd,
            env={**os.environ, **(env or {})},
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
    except (OSError, ValueError) as e:
        return _result(
            kind, id, command, exit_code=None, passed=False, started=started, reason=f"spawn: {e}"
        )

    digest = hashlib.sha256()
    total = 0
    stderr_tail = b""
    truncated = False
    lock = asyncio.Lock()

    async def pump(stream: asyncio.StreamReader, is_err: bool) -> None:
        nonlocal total, stderr_tail, truncated
        while not truncated:
            chunk = await stream.read(_CHUNK)
            if not chunk:
                return
            async with lock:
                room = MAX_OUTPUT_BYTES - total
                if len(chunk) > room:
                    chunk = chunk[:room]
                    truncated = True
                total += len(chunk)
                digest.update(chunk)
                if is_err:
                    stderr_tail = (stderr_tail + chunk)[-STDERR_TAIL_BYTES:]
            if truncated:
                _kill_group(proc.pid)

    assert proc.stdout is not None and proc.stderr is not None
    readers = asyncio.gather(pump(proc.stdout, False), pump(proc.stderr, True))
    timed_out = False
    try:
        await asyncio.wait_for(readers, timeout_s)
        await asyncio.wait_for(proc.wait(), _KILL_GRACE_S if truncated else timeout_s)
    except TimeoutError:
        timed_out = True
    finally:
        _kill_group(proc.pid)  # reap stragglers that outlived the leader
        readers.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await readers
        with contextlib.suppress(Exception):
            await asyncio.wait_for(proc.wait(), _KILL_GRACE_S)

    code = proc.returncode
    if timed_out:
        reason, passed = "timeout", False
    elif truncated:
        reason, passed = "truncated", False
    else:
        passed = code == 0
        reason = "" if passed else f"exit {code}"
    return _result(
        kind,
        id,
        command,
        exit_code=code,
        passed=passed,
        started=started,
        digest=digest.hexdigest(),
        stderr=stderr_tail,
        reason=reason,
    )


def _skipped(kind: CheckKind, id: str, reason: str, passed: bool = True) -> CheckResult:
    return CheckResult(
        kind=kind,
        id=id,
        command=[],
        exit_code=None,
        passed=passed,
        duration_s=0.0,
        log_sha256=hashlib.sha256(b"").hexdigest(),
        stderr_tail="",
        reason=reason,
    )


def _write_files(root: Path, files: Mapping[str, str]) -> str | None:
    """Write relative files under ``root``; an error text if one escapes it."""
    base = root.resolve()
    for rel, content in files.items():
        target = (base / rel).resolve()
        if not target.is_relative_to(base) or target == base:
            return f"acceptance file outside the workspace: {rel}"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    return None


def _test_command(test: AcceptanceTest, system: SystemConfig) -> list[str] | None:
    return test.run or system.tests


async def reproduction_before(
    manager: WorkspaceManager,
    ws: Workspace,
    test: AcceptanceTest,
    system: SystemConfig,
    *,
    timeout_s: float,
) -> CheckResult:
    """The acceptance test must FAIL on the base: ``passed`` means "failed as required"."""
    command = _test_command(test, system)
    if command is None:
        return _skipped("reproduction_before", test.id, "no test command", passed=False)
    async with manager.throwaway(ws) as tmp:
        err = _write_files(tmp, test.files)
        if err:
            return _skipped("reproduction_before", test.id, err, passed=False)
        res = await run_check(
            "reproduction_before", test.id, command, tmp / system.path, timeout_s=timeout_s
        )
    if res.reason in ("timeout", "truncated"):
        return res  # inconclusive, not "failed as required"
    if res.exit_code == 0:
        return replace(res, passed=False, reason="passed on base")
    return replace(res, passed=True, reason="failed on base")


async def verify_step(
    ws: Workspace,
    system: SystemConfig,
    spec: ExecutableSpec,
    *,
    manager: WorkspaceManager,
    timeout_s: float,
) -> list[CheckResult]:
    """Run the ranked checks for one system's workspace; stop at the first failure."""
    results: list[CheckResult] = []
    cwd = ws.path / system.path

    def push(res: CheckResult) -> bool:
        results.append(res)
        return res.passed

    changed = await manager.changed_paths(ws)
    outside = manager.confine(ws, system.id, changed)
    if outside:
        shown = ", ".join(outside[:10])
        push(_skipped("path_confinement", system.id, f"outside {system.path}: {shown}", False))
        return results
    push(_skipped("path_confinement", system.id, ""))

    if system.gate is None:
        push(_skipped("gate", system.id, "no gate"))
    elif not push(await run_check("gate", system.id, system.gate, cwd, timeout_s=timeout_s)):
        return results

    for test in spec.acceptance:
        if test.system != system.id:
            continue
        command = _test_command(test, system)
        if command is None:
            push(_skipped("reproduction_after", test.id, "no test command", False))
            return results
        err = _write_files(ws.path, test.files)
        if err:
            push(_skipped("reproduction_after", test.id, err, False))
            return results
        res = await run_check("reproduction_after", test.id, command, cwd, timeout_s=timeout_s)
        if not push(res):
            return results

    if system.tests is None:
        push(_skipped("regression", system.id, "no tests"))
    elif not push(await run_check("regression", system.id, system.tests, cwd, timeout_s=timeout_s)):
        return results

    for contract in spec.contracts:
        if system.id not in contract.systems or contract.path is None:
            continue
        target = (ws.path / contract.path).resolve()
        if not target.is_relative_to(ws.path.resolve()) or not target.is_file():
            push(_skipped("contract", contract.name, "contract file not present"))
            continue
        if system.tests is None:
            push(_skipped("contract", contract.name, "no tests command"))
            continue
        res = await run_check(
            "contract",
            contract.name,
            [*system.tests, contract.path],
            cwd,
            timeout_s=timeout_s,
        )
        if not push(res):
            return results
    return results


async def verify_whole(
    check: CheckConfig, workspaces: dict[str, Workspace], *, timeout_s: float
) -> CheckResult:
    """Run a cross-system check from the first workspace; ``VSC_WS_<ID>`` names every workspace."""
    env = {
        "VSC_WS_" + re.sub(r"[^A-Za-z0-9]", "_", sid).upper(): str(ws.path.resolve())
        for sid, ws in workspaces.items()
    }
    first = next(iter(workspaces.values()))
    return await run_check(
        "whole_system", check.id, check.run, first.path, timeout_s=timeout_s, env=env
    )


def all_passed(results: Iterable[CheckResult]) -> bool:
    items = list(results)
    return bool(items) and all(r.passed for r in items)
