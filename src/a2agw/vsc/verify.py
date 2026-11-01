"""Ranked executable verification of a worker's change: verification by execution.

Every check is a real subprocess (never a shell) in its own session, so a timeout or an output
overflow kills the whole process group. Output is read through a shared 4 MiB cap; the result
keeps only the SHA-256 of what was captured and the last 2 KiB of stderr with secrets masked.

Child processes get an allowlisted environment, never the full gateway environment
(``a2agw.vsc._env``): the names ``PATH, HOME, USER, SHELL, LANG, TERM, TMPDIR, TZ, VIRTUAL_ENV,
CI`` and the prefixes ``LC_, PYTHON, UV_, NODE_, npm_config_, GIT_`` taken from ``os.environ``,
merged with the caller's ``env`` (the caller wins). Redaction of the stderr tail is a best-effort second layer.

Acceptance files (``AcceptanceTest.files``) are paths relative to the *workspace root*; the test
command itself runs in the system's ``path`` sub-tree of that root. They are only ever written
into throwaway checkouts (``verify_step``, ``reproduction_before``), never into a job's
workspace, so they cannot reach the job branch. A whole-system test's
(``system`` unset) files instead start with a repository id (``contract/tests/test_x.py``): each
is written into that repository's workspace, without the id (``write_whole_files``).
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import os
import re
import signal
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal

from a2agw.vsc._env import child_env
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
    "worker",  # the worker itself failed (crash, timeout, gave up); no check ran
]

MAX_OUTPUT_BYTES = 4 * 1024 * 1024
STDERR_TAIL_BYTES = 2048
_CHUNK = 64 * 1024
_KILL_GRACE_S = 2.0

_SECRET_NAME = re.compile(
    r"(?i)(token|secret|password|passwd|api_?key|auth|credential|private_key)"
)
_MIN_SECRET_LEN = 8


def _secret_values(extra: Mapping[str, str] | None) -> list[str]:
    values = {
        v
        for k, v in {**os.environ, **(extra or {})}.items()
        if _SECRET_NAME.search(k) and len(v) >= _MIN_SECRET_LEN
    }
    return sorted(values, key=len, reverse=True)


_SECRET_PATTERNS = [
    re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}"),
    re.compile(
        r"(?i)\b([\w.-]*(?:token|secret|passw(?:or)?d|api[_-]?key|auth|credential)[\w.-]*)"
        r"(\s*[=:]\s*)\S+"
    ),
    re.compile(r"\b(?:gh[pousr]_|github_pat_|sk-|xox[abprs]-|AKIA|AIza)[A-Za-z0-9_-]{8,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"),
    re.compile(r"(?i)(://[^/\s:@]+:)[^@\s/]+@"),
    re.compile(r"(?i)\b(authorization\s*[=:]\s*)(?:[A-Za-z][\w-]*\s+)?[^\s\"',;]+"),
    re.compile(
        r"(?i)([\"'][\w.-]*(?:token|secret|passw(?:or)?d|api[_-]?key|auth|credential|private_key)"
        r"[\w.-]*[\"']\s*:\s*)([\"'])(?:\\.|(?!\2).)*\2"
    ),
    re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.DOTALL
    ),
]


def _redact(text: str) -> str:
    text = _SECRET_PATTERNS[7].sub("[redacted]", text)
    text = _SECRET_PATTERNS[6].sub(lambda m: f'{m.group(1)}"[redacted]"', text)
    text = _SECRET_PATTERNS[5].sub(lambda m: f"{m.group(1)}[redacted]", text)
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


def _tail_text(data: bytes, secrets: Iterable[str] = ()) -> str:
    # callers may pass one byte more than the tail so that a cut is detectable
    cut = len(data) > STDERR_TAIL_BYTES
    tail = data[-STDERR_TAIL_BYTES:].decode(errors="replace")
    if cut and "\n" in tail:
        tail = tail.split("\n", 1)[1]  # the first line may be partial: drop it
    for value in secrets:
        tail = tail.replace(value, "[redacted]")
    return _redact(tail)


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
    secrets: Iterable[str] = (),
) -> CheckResult:
    return CheckResult(
        kind=kind,
        id=id,
        command=list(command),
        exit_code=exit_code,
        passed=passed,
        duration_s=round(time.monotonic() - started, 3),
        log_sha256=digest or hashlib.sha256(b"").hexdigest(),
        stderr_tail=_tail_text(stderr, secrets),
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
    """Run ``command`` as a subprocess in ``cwd``.

    The child sees only an allowlisted slice of ``os.environ`` (see the module docstring) plus
    ``env``, which wins. Values of secret-named parent variables are scrubbed from the stderr tail.
    """
    started = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(
            *command,
            cwd=cwd,
            env=child_env(env),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
    except (OSError, ValueError) as e:
        return _result(
            kind, id, command, exit_code=None, passed=False, started=started, reason=f"spawn: {e}"
        )
    secrets = _secret_values(env)

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
                    stderr_tail = (stderr_tail + chunk)[-(STDERR_TAIL_BYTES + 1) :]
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
        secrets=secrets,
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


def write_whole_files(
    acceptance: Iterable[AcceptanceTest], check_id: str, workspaces: Mapping[str, Workspace]
) -> str | None:
    """Write the files of every whole-system acceptance test of ``check_id`` into the workspace
    of the repository each path names by its first segment (``workspaces`` maps repository id
    to workspace); an error text if a path names no workspace of the check or escapes it."""
    for test in acceptance:
        if test.system is not None or test.check != check_id:
            continue
        groups: dict[str, dict[str, str]] = {}
        for rel, content in test.files.items():
            repo_id, _, rest = rel.partition("/")
            if repo_id not in workspaces or not rest:
                return f"acceptance file names no repository of the check: {rel}"
            groups.setdefault(repo_id, {})[rest] = content
        for repo_id, files in groups.items():
            err = _write_files(workspaces[repo_id].path, files)
            if err:
                return err
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
    if res.exit_code is None:
        return replace(res, passed=False)  # spawn error, timeout, truncated: inconclusive
    if res.exit_code == 0:
        return replace(res, passed=False, reason="passed on base")
    return replace(res, passed=True, reason="failed on base")


# The kinds of check that execute something (a check of one of these kinds with a command ran).
_EXECUTED_KINDS = frozenset({"gate", "reproduction_after", "regression", "contract"})


def executable_checks(
    system: SystemConfig, spec: ExecutableSpec, checks: Iterable[CheckConfig] = ()
) -> bool:
    """Whether verifying ``system`` under ``spec`` executes at least one check that is about
    it: a gate, a tests command, a per-system acceptance test of the system with its own
    command, or (given the configured ``checks``) a whole-system acceptance test of a check
    that names the system. The last kind runs in the whole-system phase, not per step."""
    if (
        system.gate is not None
        or system.tests is not None
        or any(t.system == system.id and t.run for t in spec.acceptance)
    ):
        return True
    covering = {c.id for c in checks if system.id in c.systems}
    return any(t.system is None and t.check in covering for t in spec.acceptance)


async def verify_step(
    ws: Workspace,
    system: SystemConfig,
    spec: ExecutableSpec,
    *,
    manager: WorkspaceManager,
    timeout_s: float,
    candidate: str | None = None,
    whole_covered: bool = False,
) -> list[CheckResult]:
    """Run the ranked checks for one system's change; stop at the first failure.

    The change is the commit ``candidate`` (default: a ``snapshot`` of the worker's tree on
    ``ws.base_ref``), compared with ``ws.base_ref``. Every check runs in a detached throwaway
    checkout of that commit (``WorkspaceManager.throwaway``, cleaned with ``clean -fdx``); the
    acceptance files are written there, never into the worker's tree. A verification that
    executed no check at all fails (``no checks``), unless ``whole_covered``: a whole-system
    acceptance test of a check over the system runs later (``executable_checks``)."""
    results: list[CheckResult] = []

    def push(res: CheckResult) -> bool:
        results.append(res)
        return res.passed

    if candidate is None:
        candidate = await manager.snapshot(ws, f"vsc candidate {ws.job_id}")
    changed = await manager.changed_between(ws, ws.base_ref, candidate)
    outside = manager.confine(ws, system.id, changed)
    if outside:
        shown = ", ".join(outside[:10])
        push(_skipped("path_confinement", system.id, f"outside {system.path}: {shown}", False))
        return results
    push(_skipped("path_confinement", system.id, ""))
    async with manager.throwaway(ws, candidate) as root:
        await _checks_in(root, system, spec, timeout_s, push)
    if (
        all_passed(results)
        and not whole_covered
        and not any(r.kind in _EXECUTED_KINDS and r.command for r in results)
    ):
        push(_skipped("regression", system.id, "no checks", False))
    return results


async def _checks_in(
    root: Path,
    system: SystemConfig,
    spec: ExecutableSpec,
    timeout_s: float,
    push: Callable[[CheckResult], bool],
) -> None:
    cwd = root / system.path
    if system.gate is None:
        push(_skipped("gate", system.id, "no gate"))
    elif not push(await run_check("gate", system.id, system.gate, cwd, timeout_s=timeout_s)):
        return

    for test in spec.acceptance:
        if test.system != system.id:
            continue
        command = _test_command(test, system)
        if command is None:
            push(_skipped("reproduction_after", test.id, "no test command", False))
            return
        err = _write_files(root, test.files)
        if err:
            push(_skipped("reproduction_after", test.id, err, False))
            return
        res = await run_check("reproduction_after", test.id, command, cwd, timeout_s=timeout_s)
        if not push(res):
            return

    if system.tests is None:
        push(_skipped("regression", system.id, "no tests"))
    elif not push(await run_check("regression", system.id, system.tests, cwd, timeout_s=timeout_s)):
        return

    for contract in spec.contracts:
        if system.id not in contract.systems:
            continue
        if contract.path is None:
            push(_skipped("contract", contract.name, "no contract test"))
            continue
        base = root.resolve()
        target = (base / contract.path).resolve()
        if not target.is_relative_to(base) or not target.is_file():
            push(_skipped("contract", contract.name, "contract file missing", False))
            return
        if system.tests is None:
            push(_skipped("contract", contract.name, "no tests command", False))
            return
        res = await run_check(
            "contract",
            contract.name,
            [*system.tests, contract.path],
            root,
            timeout_s=timeout_s,
        )
        if not push(res):
            return


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


async def run_whole(
    manager: WorkspaceManager,
    check: CheckConfig,
    workspaces: Mapping[str, Workspace],
    refs: Mapping[str, str],
    acceptance: Iterable[AcceptanceTest],
    *,
    timeout_s: float,
) -> CheckResult:
    """Run the whole-system ``check`` over detached throwaway checkouts: of ``refs[repo_id]``
    for each repository of ``workspaces`` (system id -> workspace). The files of the check's
    whole-system acceptance tests are written into those checkouts first, never into the
    job's workspaces."""
    by_repo = {ws.repo_id: ws for ws in workspaces.values()}
    async with contextlib.AsyncExitStack() as stack:
        tmp: dict[str, Workspace] = {}
        for rid, ws in by_repo.items():
            path = await stack.enter_async_context(manager.throwaway(ws, refs[rid]))
            tmp[rid] = replace(ws, path=path)
        err = write_whole_files(acceptance, check.id, tmp)
        if err:
            return _skipped("whole_system", check.id, err, False)
        views = {sid: tmp[ws.repo_id] for sid, ws in workspaces.items()}
        return await verify_whole(check, views, timeout_s=timeout_s)


async def reproduction_before_whole(
    manager: WorkspaceManager,
    check: CheckConfig,
    workspaces: Mapping[str, Workspace],
    acceptance: Iterable[AcceptanceTest],
    *,
    timeout_s: float,
) -> CheckResult | None:
    """The whole-system acceptance tests of ``check`` must make it FAIL on the base (every
    repository at its workspace's ``base_ref``): ``passed`` means "failed as required". None
    when the check has no whole-system acceptance test."""
    tests = [t for t in acceptance if t.system is None and t.check == check.id]
    if not tests:
        return None
    refs = {ws.repo_id: ws.base_ref for ws in workspaces.values()}
    res = await run_whole(manager, check, workspaces, refs, tests, timeout_s=timeout_s)
    res = replace(res, kind="reproduction_before")
    if res.exit_code is None:
        return replace(res, passed=False, reason=res.reason or "inconclusive")
    if res.exit_code == 0:
        return replace(res, passed=False, reason="passed on base")
    return replace(res, passed=True, reason="failed on base")


def all_passed(results: Iterable[CheckResult]) -> bool:
    items = list(results)
    return bool(items) and all(r.passed for r in items)
