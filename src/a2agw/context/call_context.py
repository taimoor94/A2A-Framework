"""Call-context extension: hop, cycle, deadline and budget limits for agent-to-agent calls."""

from __future__ import annotations

import math
import time
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from a2agw.security.principal import Principal

EXTENSION_URI = "https://a2agw.dev/ext/call-context/v1"
METADATA_KEY = EXTENSION_URI


MAX_STR = 256
MAX_PATH = 64


class CallContextViolation(Exception):
    """Base class for call-context limit violations."""


class HopLimitExceeded(CallContextViolation):
    pass


class CycleDetected(CallContextViolation):
    pass


class DeadlineExceeded(CallContextViolation):
    pass


class BudgetExceeded(CallContextViolation):
    pass


def _str(d: Mapping, key: str, *, required: bool = False) -> str | None:
    v = d.get(key)
    if v is None:
        if required:
            raise ValueError(f"call-context: missing required field {key!r}")
        return None
    if not isinstance(v, str) or (required and not v) or len(v) > MAX_STR:
        raise ValueError(f"call-context: {key!r} must be a string of at most {MAX_STR} chars")
    return v


def _int(d: Mapping, key: str, default: int | None) -> int | None:
    v = d.get(key)
    if v is None:
        return default
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise ValueError(f"call-context: {key!r} must be an integer")  # noqa: TRY004
    if isinstance(v, float):
        if not v.is_integer():
            raise ValueError(f"call-context: {key!r} must be an integer")
        v = int(v)
    return v


@dataclass(frozen=True)
class CallContext:
    origin: str
    root_agent: str
    hop: int = 0
    max_hops: int = 8
    path: tuple[str, ...] = ()
    deadline: float | None = None
    traceparent: str | None = None
    on_behalf_of: str | None = None
    max_calls: int | None = None
    calls_used: int = 0

    @classmethod
    def new(cls, agent_id: str, *, deadline_s: float | None = None) -> CallContext:
        deadline = time.time() + deadline_s if deadline_s is not None else None
        return cls(
            origin=uuid.uuid4().hex,
            root_agent=agent_id,
            path=(agent_id,),
            deadline=deadline,
            traceparent=None,
        )

    @classmethod
    def from_metadata(cls, md: Mapping) -> CallContext | None:
        if not isinstance(md, Mapping):
            raise ValueError("call-context: metadata must be a mapping")  # noqa: TRY004
        raw = md.get(METADATA_KEY)
        if raw is None:
            return None
        if not isinstance(raw, Mapping):
            raise ValueError("call-context: metadata value must be an object")  # noqa: TRY004
        path = raw.get("path", [])
        if (
            not isinstance(path, (list, tuple))
            or len(path) > MAX_PATH
            or not all(isinstance(p, str) and len(p) <= MAX_STR for p in path)
        ):
            raise ValueError(
                f"call-context: 'path' must be a list of at most {MAX_PATH} short strings"
            )
        deadline = raw.get("deadline")
        if deadline is not None:
            if isinstance(deadline, bool) or not isinstance(deadline, (int, float)):
                raise ValueError("call-context: 'deadline' must be a number")
            try:
                deadline = float(deadline)
            except OverflowError:
                raise ValueError("call-context: 'deadline' out of range") from None
            if not math.isfinite(deadline):
                raise ValueError("call-context: 'deadline' must be finite")
        max_calls = _int(raw, "max_calls", None)
        if max_calls is not None and max_calls < 0:
            raise ValueError("call-context: 'max_calls' must be non-negative")
        return cls(
            origin=_str(raw, "origin", required=True),  # type: ignore[arg-type]
            root_agent=_str(raw, "root_agent", required=True),  # type: ignore[arg-type]
            hop=_int(raw, "hop", 0),  # type: ignore[arg-type]
            max_hops=_int(raw, "max_hops", 8),  # type: ignore[arg-type]
            path=tuple(path),
            deadline=deadline,
            traceparent=_str(raw, "traceparent"),
            on_behalf_of=_str(raw, "on_behalf_of"),
            max_calls=max_calls,
            calls_used=_int(raw, "calls_used", 0),  # type: ignore[arg-type]
        )

    def to_metadata(self) -> dict[str, Any]:
        return {
            METADATA_KEY: {
                "origin": self.origin,
                "root_agent": self.root_agent,
                "hop": self.hop,
                "max_hops": self.max_hops,
                "path": list(self.path),
                "deadline": self.deadline,
                "traceparent": self.traceparent,
                "on_behalf_of": self.on_behalf_of,
                "max_calls": self.max_calls,
                "calls_used": self.calls_used,
            }
        }

    def clamp(
        self,
        *,
        local_max_hops: int,
        local_max_deadline_s: float,
        now: float,
        local_max_calls: int | None = None,
    ) -> CallContext:
        """Cap untrusted inbound values to local policy (fails closed on non-finite deadlines)."""
        limit = now + local_max_deadline_s
        if self.deadline is None or not math.isfinite(self.deadline):
            deadline = limit
        else:
            deadline = min(self.deadline, limit)
        max_calls = self.max_calls
        if local_max_calls is not None:
            max_calls = min(
                max_calls if max_calls is not None else local_max_calls, local_max_calls
            )
        return replace(
            self,
            hop=max(self.hop, 0),
            max_hops=min(self.max_hops, local_max_hops),
            deadline=deadline,
            max_calls=max_calls,
            calls_used=max(self.calls_used, 0),
        )

    def child(self, next_agent: str) -> CallContext:
        return replace(
            self,
            hop=self.hop + 1,
            calls_used=self.calls_used + 1,
            path=(*self.path, next_agent),
        )

    def remaining(self, now: float | None = None) -> float | None:
        if self.deadline is None:
            return None
        return self.deadline - (time.time() if now is None else now)

    def check_admit(
        self, agent_id: str, *, allow_reentry: bool = False, now: float | None = None
    ) -> None:
        if self.hop >= self.max_hops:
            raise HopLimitExceeded(f"hop {self.hop} reached max_hops {self.max_hops}")
        if agent_id in self.path and not allow_reentry:
            raise CycleDetected(f"agent {agent_id!r} already in path {list(self.path)}")
        rem = self.remaining(now)
        if rem is not None and not rem > 0:  # also rejects NaN
            raise DeadlineExceeded("call deadline exceeded")
        if self.max_calls is not None and self.calls_used > self.max_calls:
            raise BudgetExceeded(f"calls_used {self.calls_used} exceeds max_calls {self.max_calls}")


current_call: ContextVar[CallContext | None] = ContextVar("a2agw_current_call", default=None)


@contextmanager
def use_call(cc: CallContext | None) -> Iterator[CallContext | None]:
    token = current_call.set(cc)
    try:
        yield cc
    finally:
        current_call.reset(token)


# Set by the inbound executor while an adapter runs, so outbound calls made by that adapter
# (e.g. through partner tools) are linked to the inbound task and made on behalf of its caller.
current_inbound_task: ContextVar[str | None] = ContextVar(
    "a2agw_current_inbound_task", default=None
)
current_principal: ContextVar[Principal | None] = ContextVar(
    "a2agw_current_principal", default=None
)


@contextmanager
def use_inbound(task_id: str | None, principal: Principal | None) -> Iterator[None]:
    task_token = current_inbound_task.set(task_id)
    principal_token = current_principal.set(principal)
    try:
        yield
    finally:
        current_principal.reset(principal_token)
        current_inbound_task.reset(task_token)


# The inbound caller's raw bearer JWT, set by the executor while an adapter runs so that an
# RFC 8693 token exchange (a2agw.consult.oauth.OAuthTokenExchange) can act on the caller's
# behalf. Only JWT callers have one. A secret: never log it or put it in a repr or a span.
current_inbound_token: ContextVar[str | None] = ContextVar(
    "a2agw_current_inbound_token", default=None
)


@contextmanager
def use_inbound_token(token: str | None) -> Iterator[None]:
    reset = current_inbound_token.set(token)
    try:
        yield
    finally:
        current_inbound_token.reset(reset)
