"""Throwaway PostgreSQL 16 server for tests marked ``@pytest.mark.postgres``.

Usage: take the ``pg_url`` fixture as a test argument (``tests/conftest.py`` imports it). One server is started per test session (``initdb``
into a temporary directory, ``pg_ctl start`` on a free localhost port) and torn down at the
end. Tests are skipped when the binaries are not installed. Set ``A2AGW_PG_BIN`` to use
binaries from another directory.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

PG_BIN = Path(os.environ.get("A2AGW_PG_BIN", "/opt/homebrew/opt/postgresql@16/bin"))


# postgres refuses to start ("postmaster became multithreaded") without a valid locale.
_ENV = {**os.environ, "LC_ALL": "C", "LANG": "C"}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _available() -> bool:
    return all((PG_BIN / tool).is_file() for tool in ("initdb", "pg_ctl", "createdb"))


@pytest.fixture(scope="session")
def _pg_server(tmp_path_factory) -> Iterator[tuple[int, Path]]:
    if not _available():
        pytest.skip(f"PostgreSQL binaries not found in {PG_BIN}")
    base = tmp_path_factory.mktemp("pg")
    data = base / "data"
    port = _free_port()
    subprocess.run(
        [
            str(PG_BIN / "initdb"),
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
    # TCP only: macOS caps Unix socket paths at 103 bytes, which temp dirs easily exceed.
    opts = f"-p {port} -c unix_socket_directories='' -c listen_addresses=127.0.0.1 -c fsync=off"
    subprocess.run(
        [
            str(PG_BIN / "pg_ctl"),
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
    try:
        yield port, base
    finally:
        subprocess.run(
            [str(PG_BIN / "pg_ctl"), "-D", str(data), "-m", "immediate", "-w", "stop"],
            check=False,
            capture_output=True,
        )
        shutil.rmtree(base, ignore_errors=True)


@pytest.fixture
def pg_url(_pg_server) -> str:
    """A fresh, empty database on the session's server, as a SQLAlchemy asyncpg URL."""
    port, _ = _pg_server
    name = f"t_{uuid.uuid4().hex[:12]}"
    subprocess.run(
        [str(PG_BIN / "createdb"), "-h", "127.0.0.1", "-p", str(port), "-U", "postgres", name],
        check=True,
        capture_output=True,
        env=_ENV,
    )
    return f"postgresql+asyncpg://postgres@127.0.0.1:{port}/{name}"
