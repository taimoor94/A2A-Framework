"""A Claude Agent SDK agent served over A2A.

Runs offline: ``echo_query`` stands in for ``claude_agent_sdk.query`` and streams the user's
message back as the SDK's own message types, so neither the Claude Code CLI nor an API key is
needed. For a real agent, drop ``query=echo_query``: the adapter then calls
``claude_agent_sdk.query``, which starts the ``claude`` CLI bundled with the SDK and needs
``ANTHROPIC_API_KEY`` (or another Claude Code login).

Run one turn: ``uv run python -m examples.adapters.claude_agent_example``. Serve it with the
gateway by listing ``examples.adapters.claude_agent_example:assistant`` under ``agents`` in
``a2agw.yaml``.

To let the agent consult partners, add the projected partner tools once the host has started
(``host.client`` exists from then on)::

    from a2agw.adapters.claude_agent import as_claude_tools

    server = as_claude_tools(host.partner_tools("assistant"), host.client)
    options.mcp_servers = {"a2a_partners": server}
    options.allowed_tools = ["mcp__a2a_partners"]
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from typing import Any

from a2a.types import Message, Part, Role
from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ResultMessage,
    StreamEvent,
    SystemMessage,
    TextBlock,
)

from a2agw.adapters.claude_agent import ClaudeAgentAdapter
from a2agw.core.events import ArtifactChunk
from a2agw.core.spi import InboundContext
from a2agw.serve.agent import AgentSpec, SkillSpec


async def echo_query(*, prompt: str, options: ClaudeAgentOptions) -> AsyncIterator[Any]:
    """Answers ``"echo: <prompt>"`` word by word, as the CLI would stream it."""
    session_id = options.resume or str(uuid.uuid4())
    yield SystemMessage(subtype="init", data={"subtype": "init", "session_id": session_id})
    words = f"echo: {prompt}".split(" ")
    chunks = [w if n == 0 else " " + w for n, w in enumerate(words)]
    for chunk in chunks:
        event = {"type": "content_block_delta", "delta": {"type": "text_delta", "text": chunk}}
        yield StreamEvent(uuid=str(uuid.uuid4()), session_id=session_id, event=event)
    text = "".join(chunks)
    yield AssistantMessage(content=[TextBlock(text=text)], model="echo")
    yield ResultMessage(
        subtype="success",
        duration_ms=0,
        duration_api_ms=0,
        is_error=False,
        num_turns=1,
        session_id=session_id,
        result=text,
    )


options = ClaudeAgentOptions(system_prompt="Answer helpfully.", max_turns=10)

assistant = AgentSpec(
    id="assistant",
    name="Assistant",
    description="A Claude Agent SDK agent.",
    skills=[SkillSpec(id="chat", name="Chat", description="Answers questions")],
    # Each A2A context resumes its own Claude session (kept in memory here).
    adapter=ClaudeAgentAdapter(options, query=echo_query),
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
