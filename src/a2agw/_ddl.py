"""Schema creation that survives several gateways starting against one empty database.

``CREATE TABLE IF NOT EXISTS`` is not atomic on PostgreSQL: two sessions creating the same
table can fail with a duplicate-object or ``pg_type`` unique violation, and sqlite reports
"already exists" when two processes race. Each creation runs in its own transaction (DDL is
transactional on PostgreSQL, so the loser leaves nothing behind); on a duplicate-object error
it is simply run again, and ``checkfirst`` then sees the winner's table.
"""

from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable
from typing import TypeVar

from sqlalchemy.exc import DBAPIError

T = TypeVar("T")

ATTEMPTS = 6
# duplicate_table, duplicate_column, duplicate_object, unique_violation (pg_type race),
# deadlock_detected, serialization_failure
_PG_SQLSTATES = frozenset({"42P07", "42701", "42710", "23505", "40P01", "40001"})
_MESSAGES = ("already exists", "duplicate column")


def is_duplicate_object(exc: BaseException) -> bool:
    """Whether ``exc`` is a database error meaning another session created the object first."""
    if not isinstance(exc, DBAPIError):
        return False
    orig = exc.orig
    code = getattr(orig, "sqlstate", None) or getattr(orig, "pgcode", None)
    if isinstance(code, str) and code in _PG_SQLSTATES:
        return True
    return any(m in str(exc).lower() for m in _MESSAGES)


async def retry_ddl(work: Callable[[], Awaitable[T]], attempts: int = ATTEMPTS) -> T:
    """Run ``work`` (a complete, re-runnable schema step), retrying duplicate-object errors."""
    for attempt in range(1, attempts + 1):
        try:
            return await work()
        except DBAPIError as exc:
            if attempt == attempts or not is_duplicate_object(exc):
                raise
            await asyncio.sleep(random.uniform(0.01, 0.05) * attempt)
    raise AssertionError("unreachable")  # pragma: no cover
