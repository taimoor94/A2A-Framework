"""An AG2 agent served over A2A.

Runs offline: ``EchoConfig`` is a tiny AG2 model config whose client streams the user's
message back, so no API key or network is needed. For a real agent, use a provider config
instead, such as ``ag2.config.OpenAIConfig(model="gpt-5-mini", streaming=True)`` with
``OPENAI_API_KEY`` set (and its extra: ``pip install 'ag2[openai]'``).

Run one turn: ``uv run python -m examples.adapters.ag2_example``. Serve it with the gateway by
listing ``examples.adapters.ag2_example:assistant`` under ``agents`` in ``a2agw.yaml``.

To let the agent consult partners, add projected partner tools once the host has started
(``host.client`` exists from then on)::

    from a2agw.adapters.ag2 import as_ag2_tools

    for t in as_ag2_tools(host.partner_tools("assistant"), host.client):
        agent.add_tool(t)
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from typing import Any

from a2a.types import Message, Part, Role
from ag2 import Agent
from ag2.events import (
    BaseEvent,
    ModelMessage,
    ModelMessageChunk,
    ModelRequest,
    ModelResponse,
    TextInput,
    Usage,
)

from a2agw.adapters.ag2 import AG2Adapter
from a2agw.core.events import ArtifactChunk
from a2agw.core.spi import InboundContext
from a2agw.serve.agent import AgentSpec, SkillSpec


class EchoClient:
    """Answers ``"echo: <last user message>"`` word by word, as a streaming model would."""

    async def __call__(
        self, messages: Sequence[BaseEvent], context: Any, **kwargs: Any
    ) -> ModelResponse:
        last = next(m for m in reversed(messages) if isinstance(m, ModelRequest))
        prompt = "".join(p.content for p in last.parts if isinstance(p, TextInput))
        words = f"echo: {prompt}".split(" ")
        chunks = [w if n == 0 else " " + w for n, w in enumerate(words)]
        for chunk in chunks:
            await context.send(ModelMessageChunk(chunk))
        message = ModelMessage("".join(chunks))
        await context.send(message)
        usage = Usage(prompt_tokens=len(prompt.split()), completion_tokens=len(words))
        return ModelResponse(message, usage=usage)  # one "token" per word


class EchoConfig:
    """An AG2 ``ModelConfig`` for ``EchoClient``."""

    provider = "echo"
    model = "echo"

    def copy(self) -> EchoConfig:
        return self

    def create(self) -> EchoClient:
        return EchoClient()


agent = Agent("assistant", "Answer helpfully.", config=EchoConfig())

assistant = AgentSpec(
    id="assistant",
    name="Assistant",
    description="An AG2 agent.",
    skills=[SkillSpec(id="chat", name="Chat", description="Answers questions")],
    # Each A2A context (per caller) is its own AG2 conversation stream (in memory here).
    adapter=AG2Adapter(agent),
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
