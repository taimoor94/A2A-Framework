"""Throwaway PostgreSQL 16 server for tests marked ``@pytest.mark.postgres``.

Usage: take the ``pg_url`` fixture (a fresh, empty database per test) or the dual-backend
``db_url`` fixture (``tests/conftest.py``) as a test argument. One server is started per test
session (``initdb`` into a temporary directory, ``pg_ctl start`` on a free localhost port)
and stopped at the end. Tests are skipped when the binaries are not found.

Binaries are looked up in ``A2AGW_PG_BIN``, then on ``PATH`` (``pg_ctl``), then in
``/opt/homebrew/opt/postgresql@16/bin``.
"""

from __future__ import annotations

import os
import shutil
import signal
import socket
import subprocess
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

HOMEBREW_BIN = Path("/opt/homebrew/opt/postgresql@16/bin")
START_ATTEMPTS = 3
_TOOLS = ("initdb", "pg_ctl", "createdb", "dropdb")

# postgres refuses to start ("postmaster became multithreaded") without a valid locale.
_ENV = {**os.environ, "LC_ALL": "C", "LANG": "C"}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _has_tools(directory: Path) -> bool:
    return all((directory / tool).is_file() for tool in _TOOLS)


def find_pg_bin() -> Path | None:
    """A2AGW_PG_BIN, else the directory of ``pg_ctl`` on PATH, else Homebrew's postgresql@16."""
    env = os.environ.get("A2AGW_PG_BIN")
    if env:
        candidate = Path(env)
        return candidate if _has_tools(candidate) else None
    found = shutil.which("pg_ctl")
    if found and _has_tools(Path(found).resolve().parent):
        return Path(found).resolve().parent
    return HOMEBREW_BIN if _has_tools(HOMEBREW_BIN) else None


def _stop(bin_dir: Path, data: Path) -> None:
    """Stop a postmaster that may be half-started: immediate stop, then kill the pid."""
    subprocess.run(
        [str(bin_dir / "pg_ctl"), "-D", str(data), "-m", "immediate", "-w", "stop"],
        check=False,
        capture_output=True,
        env=_ENV,
        timeout=60,
    )
    pidfile = data / "postmaster.pid"
    try:
        pid = int(pidfile.read_text().split()[0])
    except (OSError, ValueError, IndexError):
        return
    try:
        os.kill(pid, 0)
    except OSError:
        return
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


@pytest.fixture(scope="session")
def _pg_server(tmp_path_factory) -> Iterator[tuple[int, Path, Path]]:
    bin_dir = find_pg_bin()
    if bin_dir is None:
        pytest.skip("PostgreSQL binaries not found (set A2AGW_PG_BIN)")
    base = tmp_path_factory.mktemp("pg")
    data = base / "data"
    try:
        # The server is stopped by the finally block even if initdb or start fails midway.
        subprocess.run(
            [
                str(bin_dir / "initdb"),
                "-D",
                str(data),
                "-U",
                "postgres",
                "-A",
                "trust",
                "--no-sync",
                "--locale=C",
            ],
            check=True,
            capture_output=True,
            env=_ENV,
        )
        port = 0
        last: subprocess.CalledProcessError | None = None
        for _ in range(START_ATTEMPTS):
            port = _free_port()  # a new port per attempt: another process may grab it first
            # TCP only: macOS caps Unix socket paths at 103 bytes, which temp dirs exceed.
            opts = (
                f"-p {port} -c unix_socket_directories='' "
                "-c listen_addresses=127.0.0.1 -c fsync=off -c max_connections=200"
            )
            try:
                subprocess.run(
                    [
                        str(bin_dir / "pg_ctl"),
                        "-D",
                        str(data),
                        "-o",
                        opts,
                        "-l",
                        str(base / "log"),
                        "-w",
                        "start",
                    ],
                    check=True,
                    capture_output=True,
                    env=_ENV,
                )
                last = None
                break
            except subprocess.CalledProcessError as exc:
                last = exc
                _stop(bin_dir, data)  # a timed-out start may still have left a postmaster
        if last is not None:
            raise last
        yield port, base, bin_dir
    finally:
        _stop(bin_dir, data)
        shutil.rmtree(base, ignore_errors=True)


@pytest.fixture
def pg_url_factory(_pg_server) -> Iterator[Callable[[], str]]:
    """Calls return a fresh, empty database each (all dropped after the test), as
    SQLAlchemy asyncpg URLs."""
    port, _, bin_dir = _pg_server
    common = ["-h", "127.0.0.1", "-p", str(port), "-U", "postgres"]
    made: list[str] = []

    def make() -> str:
        name = f"t_{uuid.uuid4().hex}"
        subprocess.run(
            [str(bin_dir / "createdb"), *common, name], check=True, capture_output=True, env=_ENV
        )
        made.append(name)
        return f"postgresql+asyncpg://postgres@127.0.0.1:{port}/{name}"

    try:
        yield make
    finally:
        for name in made:
            subprocess.run(
                [str(bin_dir / "dropdb"), *common, "--force", "--if-exists", name],
                check=False,
                capture_output=True,
                env=_ENV,
            )


@pytest.fixture
def pg_url(pg_url_factory) -> str:
    """A fresh, empty database on the session's server (dropped afterwards), as a
    SQLAlchemy asyncpg URL."""
    return pg_url_factory()
