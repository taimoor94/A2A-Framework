"""The allowlisted environment of every child process VSC starts (checks and git).

Never the full gateway environment: the names ``PATH, HOME, USER, SHELL, LANG, TERM, TMPDIR,
TZ, VIRTUAL_ENV, CI`` and the prefixes ``LC_, PYTHON, UV_, NODE_, npm_config_, GIT_`` taken
from ``os.environ``, merged with the caller's ``extra`` (the caller wins)."""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping

ENV_NAMES = frozenset(
    {"PATH", "HOME", "USER", "SHELL", "LANG", "TERM", "TMPDIR", "TZ", "VIRTUAL_ENV", "CI"}
)
ENV_PREFIXES = ("LC_", "PYTHON", "UV_", "NODE_", "npm_config_", "GIT_")


def child_env(
    extra: Mapping[str, str] | None = None, *, drop: Iterable[str] = ()
) -> dict[str, str]:
    """The allowlisted slice of ``os.environ`` without the names in ``drop``, plus ``extra``."""
    dropped = set(drop)
    env = {
        k: v
        for k, v in os.environ.items()
        if (k in ENV_NAMES or k.startswith(ENV_PREFIXES)) and k not in dropped
    }
    env.update(extra or {})
    return env
