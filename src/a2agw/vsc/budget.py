"""Job budgets and the retry policy of the job runner.

A budget is the tighter of the configured one and the spec's (a request can never raise its own
budget). Tokens and cost are charged after every worker and planner turn; the deadline is
event-loop time, set from the job's remaining *active* time (time awaiting approval never
counts). The ``attempts`` budget is per step and is the retry policy's ``max_attempts``; the
runner counts a step's attempts from its stored rows. Exceeding any raises
``BudgetExceeded(what)``.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

from a2agw.vsc.config import BudgetConfig
from a2agw.vsc.workers import WorkerSpec

_RANK = {"cheap": 0, "standard": 1, "strong": 2}


class BudgetExceeded(Exception):
    def __init__(self, what: str) -> None:
        super().__init__(f"budget exceeded: {what}")
        self.what = what


@dataclass
class Budget:
    tokens: int
    cost_usd: float
    deadline: float  # event-loop (monotonic) time
    used_tokens: int = 0
    used_cost: float = 0.0

    @classmethod
    def from_config(
        cls,
        cfg: BudgetConfig,
        *,
        deadline: float,
        used_tokens: int = 0,
        used_cost: float = 0.0,
    ) -> Budget:
        return cls(cfg.tokens, cfg.cost_usd, deadline, used_tokens, used_cost)

    def charge(self, tokens_in: int, tokens_out: int, cost: float) -> None:
        self.used_tokens += tokens_in + tokens_out
        self.used_cost += cost
        if self.used_tokens > self.tokens:
            raise BudgetExceeded("tokens")
        if self.used_cost > self.cost_usd:
            raise BudgetExceeded("cost")

    def check_deadline(self, now: float) -> None:
        if now >= self.deadline:
            raise BudgetExceeded("deadline")


def stronger(workers: list[WorkerSpec], current: WorkerSpec) -> WorkerSpec:
    """The first registered worker of a stronger cost class than ``current``, else ``current``."""
    for w in workers:
        if _RANK[w.cost_class] > _RANK[current.cost_class]:
            return w
    return current


@dataclass
class RetryPolicy:
    max_attempts: int = 3
    escalate_after: int = 2

    def next_worker(
        self, workers: list[WorkerSpec], attempt: int, current: WorkerSpec
    ) -> WorkerSpec:
        """The worker for the attempt after ``attempt`` (counted from 1) failed."""
        return stronger(workers, current) if attempt >= self.escalate_after else current


def tighter(a: BudgetConfig, b: BudgetConfig) -> BudgetConfig:
    return BudgetConfig(
        tokens=min(a.tokens, b.tokens),
        cost_usd=min(a.cost_usd, b.cost_usd),
        attempts=min(a.attempts, b.attempts),
        deadline_s=min(a.deadline_s, b.deadline_s),
    )


@asynccontextmanager
async def deadline(when: float) -> AsyncIterator[None]:
    """Run the body until loop time ``when``; expiry raises ``BudgetExceeded("deadline")``."""
    cm = asyncio.timeout_at(when)
    try:
        async with cm:
            yield
    except TimeoutError:
        if cm.expired():
            raise BudgetExceeded("deadline") from None
        raise
