"""Fail the test that leaks a database connection, not whichever test the GC happens to hit.

A pooled connection that is never checked in surfaces much later, when the garbage collector
finalizes it (SQLAlchemy's "non-checked-in connection" warning, aiosqlite's "deleted before
being closed" ResourceWarning), inside an unrelated test. This guard checks the two
deterministic preconditions instead, at the end of the test that created them:

- an engine was disposed while some of its connections were still checked out (whatever
  holds them outlives the engine: when it finally returns or drops them, they land in a
  dead pool or reach the garbage collector);
- a connection checked out during the test was never checked in by the end of its teardown
  (its event loop is gone, so nothing can return it any more).

The bookkeeping is two dict operations per checkout. Set ``A2AGW_LEAK_STACKS=1`` to also
record where each connection was checked out (slow; for debugging a report).

A test that hands a live connection to a later test on purpose opts out with
``@pytest.mark.leaves_db_connections``.
"""

from __future__ import annotations

import asyncio
import os
import traceback
import weakref
from typing import Any

import pytest
from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlalchemy.pool import Pool

_STACKS = os.environ.get("A2AGW_LEAK_STACKS") == "1"
_current = {"node": "<collection>"}
# id(record) -> (weakref(record), creating test, holder description)
_open: dict[int, tuple[Any, str, str]] = {}
_problems: dict[str, list[str]] = {}


def _holder() -> str:
    try:
        task = asyncio.current_task()
    except RuntimeError:
        task = None
    where = f"task {task.get_name()!r}" if task is not None else "no task"
    if _STACKS:
        where += "\n" + "".join(traceback.format_stack(limit=30)[:-3])
    return where


@event.listens_for(Pool, "checkout")
def _on_checkout(_dbapi_conn: Any, record: Any, _proxy: Any) -> None:
    _open[id(record)] = (weakref.ref(record), _current["node"], _holder())


@event.listens_for(Pool, "checkin")
def _on_checkin(_dbapi_conn: Any, record: Any) -> None:
    _open.pop(id(record), None)


_engine_dispose = Engine.dispose


def _checked_dispose(self: Engine, close: bool = True) -> None:
    checked_out = self.pool.checkedout() if hasattr(self.pool, "checkedout") else 0
    if checked_out:
        holders = sorted({h for _, node, h in _open.values() if node == _current["node"]})
        _problems.setdefault(_current["node"], []).append(
            f"engine {self.url.render_as_string(hide_password=True)} was disposed with "
            f"{checked_out} connection(s) still checked out; held by: "
            + ("; ".join(holders) or "unknown (checked out by an earlier test)")
        )
    _engine_dispose(self, close)


Engine.dispose = _checked_dispose  # type: ignore[method-assign]


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_logstart(nodeid: str, location: Any) -> None:
    _current["node"] = nodeid


@pytest.hookimpl(wrapper=True)
def pytest_runtest_teardown(item: pytest.Item, nextitem: pytest.Item | None):
    result = yield  # every fixture of this test is finalized (its event loop is closed)
    node = item.nodeid
    problems = _problems.pop(node, [])
    for key, (_ref, owner, holder) in list(_open.items()):
        if owner != node:
            continue
        del _open[key]
        problems.append(f"a connection checked out by {holder} was never checked in")
    if problems and item.get_closest_marker("leaves_db_connections") is None:
        pytest.fail(
            "database connection leak (see tests/db_leak_guard.py):\n- " + "\n- ".join(problems),
            pytrace=False,
        )
    return result
