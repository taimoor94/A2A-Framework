"""A LlamaIndex agent served over A2A.

Runs offline: ``EchoLLM`` is a tiny function-calling LLM that streams the user's message
back, so no API key or network is needed. For a real agent, use an LLM integration instead,
such as ``llama_index.llms.openai.OpenAI(model="gpt-5-mini")`` with ``OPENAI_API_KEY`` set
(``pip install llama-index-llms-openai``).

Run one turn: ``uv run python -m examples.adapters.llamaindex_example``. Serve it with the
gateway by listing ``examples.adapters.llamaindex_example:assistant`` under ``agents`` in
``a2agw.yaml``.

To let the agent consult partners, give it projected partner tools once the host has
started (``host.client`` exists from then on)::

    from a2agw.adapters.llamaindex import as_llamaindex_tools

    agent.tools = as_llamaindex_tools(host.partner_tools("assistant"), host.client)
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Sequence
from typing import Any

from a2a.types import Message, Part, Role
from llama_index.core.agent.workflow import FunctionAgent
from llama_index.core.base.llms.types import ChatResponse
from llama_index.core.llms import ChatMessage
from llama_index.core.llms.mock import MockFunctionCallingLLM

from a2agw.adapters.llamaindex import LlamaIndexAdapter
from a2agw.core.events import ArtifactChunk
from a2agw.core.spi import InboundContext
from a2agw.serve.agent import AgentSpec, SkillSpec


class EchoLLM(MockFunctionCallingLLM):
    """Answers ``"echo: <last user message>"`` word by word, as a streaming model would."""

    async def astream_chat(self, messages: Sequence[ChatMessage], **kwargs: Any) -> Any:
        prompt = next(m.content or "" for m in reversed(messages) if m.role == "user")
        words = f"echo: {prompt}".split(" ")

        async def gen() -> AsyncIterator[ChatResponse]:
            text = ""
            for n, word in enumerate(words):
                delta = word if n == 0 else " " + word
                text += delta
                yield ChatResponse(message=ChatMessage(role="assistant", content=text), delta=delta)

        return gen()


agent = FunctionAgent(name="assistant", system_prompt="Answer helpfully.", llm=EchoLLM())

assistant = AgentSpec(
    id="assistant",
    name="Assistant",
    description="A LlamaIndex agent.",
    skills=[SkillSpec(id="chat", name="Chat", description="Answers questions")],
    # Each A2A context (per caller) is its own conversation (in memory here).
    adapter=LlamaIndexAdapter(agent),
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
