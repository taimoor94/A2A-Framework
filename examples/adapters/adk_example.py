"""A Google ADK agent served over A2A.

Runs offline: ``EchoLlm`` is a tiny scripted ``google.adk.models.BaseLlm`` that streams the
user's message back, so no API key or network is needed. For a real agent, use a model name
instead, such as ``model="gemini-2.5-flash"``, and set ``GOOGLE_API_KEY`` (or the Vertex AI
variables).

Run one turn: ``uv run python -m examples.adapters.adk_example``. Serve it with the gateway by
listing ``examples.adapters.adk_example:assistant`` under ``agents`` in ``a2agw.yaml``.

To let the agent consult partners, add projected partner tools once the host has started
(``host.client`` exists from then on)::

    from a2agw.adapters.adk import as_adk_tools

    agent.tools = as_adk_tools(host.partner_tools("assistant"), host.client)
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator

from a2a.types import Message, Part, Role
from google.adk.agents import LlmAgent
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.genai import types

from a2agw.adapters.adk import AdkAdapter
from a2agw.core.events import ArtifactChunk
from a2agw.core.spi import InboundContext
from a2agw.serve.agent import AgentSpec, SkillSpec


class EchoLlm(BaseLlm):
    """Answers ``"echo: <last user message>"`` word by word, as a streaming model would."""

    model: str = "echo"

    async def generate_content_async(
        self, llm_request: LlmRequest, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        last = llm_request.contents[-1]
        prompt = "".join(p.text or "" for p in last.parts or ())
        words = f"echo: {prompt}".split(" ")
        chunks = [w if n == 0 else " " + w for n, w in enumerate(words)]
        if stream:
            for chunk in chunks:
                part = types.Part(text=chunk)
                yield LlmResponse(content=types.Content(role="model", parts=[part]), partial=True)
        whole = types.Content(role="model", parts=[types.Part(text="".join(chunks))])
        usage = types.GenerateContentResponseUsageMetadata(  # one "token" per word
            prompt_token_count=len(prompt.split()), candidates_token_count=len(words)
        )
        yield LlmResponse(content=whole, usage_metadata=usage, turn_complete=True)


agent = LlmAgent(name="assistant", instruction="Answer helpfully.", model=EchoLlm())

assistant = AgentSpec(
    id="assistant",
    name="Assistant",
    description="A Google ADK agent.",
    skills=[SkillSpec(id="chat", name="Chat", description="Answers questions")],
    # Each A2A context is its own ADK session (in memory here).
    adapter=AdkAdapter(agent),
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
