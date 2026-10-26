"""Run-scoped consult tokens (spec 7.7): how an external agent consults partners through the
gateway while it serves an inbound turn.

For each turn of a webhook or stdio agent the host issues a ``ConsultGrant``: the gateway's
REST URL (``/a2agw/v1``) and a bearer token bound to that agent and that inbound task. A call
made with the token (``a2agw.gateway.rest``) runs as if the agent were embedded: linked to
the inbound task (cascade cancel, the fan-out cap), with its call context and its caller.

A token is ``secrets.token_urlsafe(32)``. Only its SHA-256 digest is kept; the token itself is
never logged, audited or echoed. It stops resolving at the earliest of the end of its run
(``revoke``, ``revoke_task``), the inbound call's deadline and ``ttl_s``.
"""

from __future__ import annotations

import asyncio
import hashlib
import secrets
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING

from a2agw.gateway.protocol import ConsultGrant

if TYPE_CHECKING:
    from a2agw.context.call_context import CallContext
    from a2agw.core.spi import InboundContext
    from a2agw.security.principal import Principal

__all__ = ["Binding", "ConsultTokens", "GrantIssuer", "token_digest"]

DEFAULT_TTL_S = 3600.0


def token_digest(token: str) -> str:
    """The SHA-256 hex digest a token is stored (and looked up) as."""
    return hashlib.sha256(token.encode()).hexdigest()


@dataclass(frozen=True)
class Binding:
    """What a live token stands for: the agent it acts as, the inbound task (and its call
    context and caller) its calls link to, and when it expires (epoch seconds)."""

    agent_id: str
    inbound_task_id: str
    call: CallContext | None
    caller: Principal | None
    expires_at: float


class ConsultTokens:
    """The host's live consult tokens, in memory (a restart ends every run anyway).

    ``track`` registers a REST call in flight; revoking its token cancels it, so a call does
    not outlive the run it belongs to."""

    def __init__(self, ttl_s: float = DEFAULT_TTL_S, *, url: str = "") -> None:
        if not ttl_s > 0:
            raise ValueError("ttl_s must be positive")
        self.ttl_s = ttl_s
        self.url = url  # ConsultGrant.url: the host's ``.../a2agw/v1``
        self._live: dict[str, Binding] = {}  # digest -> binding
        self._by_task: dict[str, set[str]] = {}  # inbound task id -> digests
        self._inflight: dict[str, set[asyncio.Task[object]]] = {}  # digest -> calls

    def __repr__(self) -> str:  # counts only
        return f"ConsultTokens(live={len(self._live)}, ttl_s={self.ttl_s})"

    def issue(
        self,
        agent_id: str,
        inbound_task_id: str,
        call: CallContext | None,
        caller: Principal | None,
    ) -> ConsultGrant:
        now = time.time()
        self._sweep(now)
        expires_at = now + self.ttl_s
        if call is not None and call.deadline is not None:
            expires_at = min(expires_at, call.deadline)
        token = secrets.token_urlsafe(32)
        digest = token_digest(token)
        self._live[digest] = Binding(agent_id, inbound_task_id, call, caller, expires_at)
        self._by_task.setdefault(inbound_task_id, set()).add(digest)
        return ConsultGrant(url=self.url, token=token, expires_at=expires_at)

    def resolve(self, token: str, *, now: float | None = None) -> Binding | None:
        """The binding of a live token, else None (unknown, revoked or expired)."""
        if not isinstance(token, str) or not token:
            return None
        digest = token_digest(token)
        binding = self._live.get(digest)
        if binding is None:
            return None
        if (time.time() if now is None else now) >= binding.expires_at:
            self._drop(digest)
            return None
        return binding

    def revoke(self, grant: ConsultGrant) -> None:
        """End one grant (its run ended) and cancel its calls in flight."""
        self._drop(token_digest(grant.token))

    def revoke_task(self, inbound_task_id: str) -> None:
        """End every grant of an inbound task and cancel their calls in flight."""
        for digest in list(self._by_task.get(inbound_task_id, ())):
            self._drop(digest)

    @contextmanager
    def track(self, binding: Binding, task: asyncio.Task[object]) -> Iterator[bool]:
        """Register ``task`` as a call made under ``binding`` for the duration of the block:
        revoking the binding's token cancels it. Yields False (and registers nothing) when
        the binding's token is no longer live."""
        digest = next(
            (
                d
                for d in self._by_task.get(binding.inbound_task_id, ())
                if self._live.get(d) is binding
            ),
            None,
        )
        if digest is None:
            yield False
            return
        calls = self._inflight.setdefault(digest, set())
        calls.add(task)
        try:
            yield True
        finally:
            calls.discard(task)
            if not calls and self._inflight.get(digest) is calls:
                del self._inflight[digest]

    def _drop(self, digest: str) -> None:
        binding = self._live.pop(digest, None)
        if binding is not None:
            digests = self._by_task.get(binding.inbound_task_id)
            if digests is not None:
                digests.discard(digest)
                if not digests:
                    del self._by_task[binding.inbound_task_id]
        for task in self._inflight.pop(digest, ()):
            task.cancel()

    def _sweep(self, now: float) -> None:
        """Forget expired tokens (their runs normally revoke them first)."""
        for digest in [d for d, b in self._live.items() if now >= b.expires_at]:
            self._drop(digest)


class GrantIssuer:
    """The ``consult`` callable the host gives its webhook and stdio adapters: one grant per
    turn, revoked by the adapter when the turn ends (``revoke``)."""

    def __init__(self, tokens: ConsultTokens) -> None:
        self.tokens = tokens

    def __repr__(self) -> str:
        return f"GrantIssuer({self.tokens!r})"

    async def __call__(self, ctx: InboundContext) -> ConsultGrant:
        return self.tokens.issue(ctx.agent_id, ctx.task_id, ctx.call, ctx.principal)

    def revoke(self, grant: ConsultGrant) -> None:
        self.tokens.revoke(grant)
