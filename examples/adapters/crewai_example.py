"""A CrewAI crew served over A2A.

Runs offline: ``EchoLLM`` is a tiny CrewAI LLM that answers with the task it was given, so no
API key or network is needed. For a real crew, use a model instead, such as
``crewai.LLM(model="openai/gpt-5-mini")`` with ``OPENAI_API_KEY`` set.

CrewAI needs an environment of its own (it pins ``mcp<2`` and ``openai<3``):
``pip install 'a2a-gateway[crewai]'``, or in this repository ``scripts/test-crewai.sh``. Turn
CrewAI's telemetry and trace collection off with ``CREWAI_DISABLE_TELEMETRY=true`` and
``CREWAI_TRACING_ENABLED=false``.

Run one turn: ``python -m examples.adapters.crewai_example``. Serve it with the gateway by
listing ``examples.adapters.crewai_example:assistant`` under ``agents`` in ``a2agw.yaml``.

To let the crew consult partners, give its agents projected partner tools once the host has
started (``host.client`` exists from then on), inside the gateway's event loop::

    from a2agw.adapters.crewai import as_crewai_tools

    crew.agents[0].tools = as_crewai_tools(host.partner_tools("assistant"), host.client)
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

from a2a.types import Message, Part, Role
from crewai import Agent, Crew, Task
from crewai.llms.base_llm import BaseLLM

from a2agw.adapters.crewai import CrewAIAdapter
from a2agw.core.events import Done
from a2agw.core.spi import InboundContext
from a2agw.serve.agent import AgentSpec, SkillSpec


class EchoLLM(BaseLLM):
    """Answers ``"echo: <the task>"``."""

    def call(self, messages: Any, *args: Any, **kwargs: Any) -> str:
        text = messages if isinstance(messages, str) else str(messages[-1].get("content"))
        task = re.search(r"Current Task: (.*)", text)
        return f"echo: {task.group(1) if task else text}"

    def get_input_tokens_count(self, messages: Any, *args: Any, **kwargs: Any) -> int:
        return 0  # no estimate (the base class logs a warning for its own)


helper = Agent(
    role="Assistant", goal="Answer helpfully", backstory="You help.", llm=EchoLLM(model="echo")
)
# ``{input}`` is filled with the A2A message text on each turn.
answer = Task(description="{input}", expected_output="A helpful answer", agent=helper)
crew = Crew(agents=[helper], tasks=[answer])

assistant = AgentSpec(
    id="assistant",
    name="Assistant",
    description="A CrewAI crew.",
    skills=[SkillSpec(id="chat", name="Chat", description="Answers questions")],
    # Each turn kicks off a copy of the crew; nothing is kept between turns.
    adapter=CrewAIAdapter(crew),
)


async def main(text: str = "hello from A2A") -> str:
    """Run one turn through the adapter, as the gateway would, and return the answer."""
    message = Message(message_id="m1", role=Role.ROLE_USER, parts=[Part(text=text)])
    ctx = InboundContext.from_message("assistant", message, task_id="t1", context_id="c1")
    async for ev in assistant.adapter.run(ctx):
        if isinstance(ev, Done):
            return ev.text or ""
    return ""


if __name__ == "__main__":
    print(asyncio.run(main()))
