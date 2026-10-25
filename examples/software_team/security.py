"""Security agent: a plain callable running a long task (three status updates, then a verdict)."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

from a2agw.adapters.callable import agent
from a2agw.core.events import AgentEvent, Done, Status
from a2agw.core.spi import InboundContext
from a2agw.serve.agent import AgentSpec

STEP_DELAY_S = 0.7  # module constant so tests can shorten the "long task"
STEPS = ("scanning dependencies", "checking authz", "writing report")
FINDING = "No critical findings. Recommend rate limiting on POST /todos."


async def review(ctx: InboundContext) -> AsyncIterator[AgentEvent]:
    """Reviews a system design for security issues (a long-running task)."""
    for step in STEPS:
        yield Status(step)
        await asyncio.sleep(STEP_DELAY_S)
    yield Done(FINDING)


def security_agent() -> AgentSpec:
    return agent(
        "security",
        name="Security",
        skills=[
            {
                "id": "review",
                "name": "Security review",
                "description": "Reviews a system design for security issues.",
                "examples": ["Review the design: ..."],
            }
        ],
    )(review)
