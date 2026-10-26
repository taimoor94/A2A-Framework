"""Per-caller inbound concurrency cap (spec 7.2 "Limits", 7.5, 11a item 4).

``CallerLimiter`` counts the running agent turns of each principal across every agent of one
``AgentHost``. The request handler reserves a slot before a send runs the agent (a refused
reservation is an A2A error); the executor adopts the slot when the turn starts and releases
it when the turn ends (completed, failed, cancelled or interrupted for input). A send that
never reaches the executor releases its slot in the handler.

The slot travels from handler to executor in a context variable: the SDK runs
``AgentExecutor.execute`` in the context of the request that sent the message. A send
answered without running the agent (a duplicate of an open task) takes no slot.

All principals without credentials share the one ``anonymous`` count.
"""

from __future__ import annotations

from contextvars import ContextVar

DEFAULT_MAX_CONCURRENT_TASKS_PER_CALLER = 32


class CallerSlot:
    """One reserved unit of a principal's concurrency budget. ``release`` is idempotent;
    ``adopt`` (by the executor) takes the slot back if the handler already let it go."""

    __slots__ = ("adopted", "held", "limiter", "owner")

    def __init__(self, limiter: CallerLimiter, owner: str) -> None:
        self.limiter = limiter
        self.owner = owner
        self.held = True
        self.adopted = False

    def adopt(self) -> None:
        self.adopted = True
        if not self.held:  # the send returned before the turn started (return_immediately)
            self.limiter._add(self.owner, 1)
            self.held = True

    def release(self) -> None:
        if self.held:
            self.held = False
            self.limiter._add(self.owner, -1)


class CallerLimiter:
    def __init__(self, max_per_caller: int = DEFAULT_MAX_CONCURRENT_TASKS_PER_CALLER) -> None:
        if max_per_caller < 1:
            raise ValueError("max_concurrent_tasks_per_caller must be at least 1")
        self.max_per_caller = max_per_caller
        self._counts: dict[str, int] = {}

    def count(self, owner: str) -> int:
        return self._counts.get(owner, 0)

    def reserve(self, owner: str) -> CallerSlot | None:
        """A slot for ``owner``, or None when it already has ``max_per_caller`` running."""
        if self.count(owner) >= self.max_per_caller:
            return None
        self._add(owner, 1)
        return CallerSlot(self, owner)

    def _add(self, owner: str, delta: int) -> None:
        n = self._counts.get(owner, 0) + delta
        if n > 0:
            self._counts[owner] = n
        else:
            self._counts.pop(owner, None)


current_slot: ContextVar[CallerSlot | None] = ContextVar("a2agw_caller_slot", default=None)
