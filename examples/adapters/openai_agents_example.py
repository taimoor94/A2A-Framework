"""An OpenAI Agents SDK agent served over A2A.

Runs offline: ``EchoModel`` is a tiny scripted ``agents.models.interface.Model`` that streams
the user's message back, so no API key or network is needed. To use a real model, drop
``model=EchoModel()`` (the SDK default model) or pass a model name such as
``model="gpt-5-mini"``, set ``OPENAI_API_KEY``, and remove ``tracing_disabled`` if you want
the SDK's traces.

Run one turn: ``uv run python -m examples.adapters.openai_agents_example``. Serve it with the
gateway by listing ``examples.adapters.openai_agents_example:assistant`` under ``agents`` in
``a2agw.yaml``.

To let the agent consult partners, add projected partner tools once the host has started
(``host.client`` exists from then on)::

    from a2agw.adapters.openai_agents import as_openai_tools

    agent.tools = as_openai_tools(host.partner_tools("assistant"), host.client)
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

from a2a.types import Message, Part, Role
from agents import Agent, RunConfig
from agents.models.interface import Model
from openai.types.responses import (
    Response,
    ResponseCompletedEvent,
    ResponseOutputMessage,
    ResponseOutputText,
    ResponseTextDeltaEvent,
)

from a2agw.adapters.openai_agents import OpenAIAgentsAdapter
from a2agw.core.events import ArtifactChunk
from a2agw.core.spi import InboundContext
from a2agw.serve.agent import AgentSpec, SkillSpec


class EchoModel(Model):
    """Streams ``"echo: <last user message>"`` word by word."""

    async def get_response(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError("this example only streams")

    async def stream_response(
        self, system_instructions: str | None, input: Any, *args: Any, **kwargs: Any
    ) -> AsyncIterator[Any]:
        if isinstance(input, str):
            last = input
        else:
            users = [i for i in input if isinstance(i, dict) and i.get("role") == "user"]
            last = str(users[-1]["content"]) if users else ""
        words = f"echo: {last}".split(" ")
        chunks = [w if n == 0 else " " + w for n, w in enumerate(words)]
        for n, chunk in enumerate(chunks):
            yield ResponseTextDeltaEvent(
                type="response.output_text.delta",
                item_id="msg",
                output_index=0,
                content_index=0,
                delta=chunk,
                logprobs=[],
                sequence_number=n,
            )
        text = ResponseOutputText(
            text="".join(chunks), type="output_text", annotations=[], logprobs=[]
        )
        message = ResponseOutputMessage(
            id="msg", type="message", role="assistant", status="completed", content=[text]
        )
        response = Response(
            id="resp",
            created_at=0,
            model="echo",
            object="response",
            output=[message],
            tool_choice="auto",
            tools=[],
            top_p=None,
            parallel_tool_calls=False,
            status="completed",
        )
        yield ResponseCompletedEvent(
            type="response.completed", response=response, sequence_number=len(chunks)
        )


agent = Agent(name="assistant", instructions="Answer helpfully.", model=EchoModel())

assistant = AgentSpec(
    id="assistant",
    name="Assistant",
    description="An OpenAI Agents SDK agent.",
    skills=[SkillSpec(id="chat", name="Chat", description="Answers questions")],
    # Each A2A context gets its own in-memory SDK session. ``tracing_disabled`` keeps runs out
    # of the SDK's trace export (on by default when OPENAI_API_KEY is set).
    adapter=OpenAIAgentsAdapter(agent, run_config=RunConfig(tracing_disabled=True)),
)


async def main(text: str = "hello from A2A") -> str:
    """Run one turn through the adapter, as the gateway would, and return the answer."""
    message = Message(message_id="m1", role=Role.ROLE_USER, parts=[Part(text=text)])
    ctx = InboundContext.from_message("assistant", message, task_id="t1", context_id="c1")
    out = []
    async for ev in assistant.adapter.run(ctx):
        if isinstance(ev, ArtifactChunk):
            out += [p.text for p in ev.parts]
    return "".join(out)


if __name__ == "__main__":
    print(asyncio.run(main()))
