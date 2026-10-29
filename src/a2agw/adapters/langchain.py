"""LangChain adapter: any Runnable becomes an A2A agent, and partners become StructuredTools.

Importing this module requires ``langchain-core``; nothing in the core imports it.
"""

from __future__ import annotations

import copy
import json
from collections.abc import AsyncIterator
from typing import Any

from a2a.helpers import new_data_part
from langchain_core.messages import BaseMessage
from langchain_core.runnables import Runnable
from langchain_core.runnables.utils import AddableDict
from langchain_core.tools import StructuredTool

from a2agw.adapters._contexts import context_key
from a2agw.adapters._stream import content_text, stream_events
from a2agw.consult.client import PartnerClient
from a2agw.consult.tools import PartnerTool, invoke, strip_extensions, with_untrusted_note
from a2agw.core.events import AgentEvent, ArtifactChunk, Usage
from a2agw.core.spi import InboundContext
from a2agw.security.principal import Principal


class RunnableAdapter:
    """Wraps a LangChain ``Runnable``.

    The input is the inbound text, or ``{input_key: text}`` when ``input_key`` is set. Chunks
    may be ``str``, message chunks (their text content is used) or dicts. Text streams as the
    artifact "output" (final chunk marked ``last``). If the runnable yields dicts, the partial
    dicts are merged and published as a data artifact named "result". Token usage found on
    message chunks is summed (chunk usage is a per-chunk delta, the ``AIMessageChunk``
    convention) and reported as one ``Usage`` event at the end.

    The run config's ``thread_id`` (what a runnable with memory keys it on) is
    ``"<principal id or anonymous>\\x1f<context id>"`` (``_contexts.context_key``), so
    another caller sending the same ``contextId`` gets its own thread.
    """

    def __init__(
        self, runnable: Runnable, *, input_key: str | None = None, durable_sessions: bool = False
    ):
        self.runnable = runnable
        self.input_key = input_key
        self.durable_sessions = durable_sessions

    async def run(self, ctx: InboundContext) -> AsyncIterator[AgentEvent]:
        tokens_in = tokens_out = 0
        saw_usage = False
        final: dict | None = None

        async def texts() -> AsyncIterator[str]:
            nonlocal tokens_in, tokens_out, saw_usage, final
            payload: Any = {self.input_key: ctx.text} if self.input_key else ctx.text
            config = {"configurable": {"thread_id": context_key(ctx)}}
            async for chunk in self.runnable.astream(payload, config=config):  # type: ignore[arg-type]
                if isinstance(chunk, dict):
                    # Merge partial dicts the way Runnable.ainvoke does.
                    if final is None:
                        final = chunk
                    elif isinstance(final, AddableDict) and isinstance(chunk, AddableDict):
                        final = final + chunk
                    else:
                        final = {**final, **chunk}
                    continue
                if isinstance(chunk, str):
                    text = chunk
                elif isinstance(chunk, BaseMessage):
                    text = content_text(chunk.content)
                    um = getattr(chunk, "usage_metadata", None)
                    if um:
                        saw_usage = True
                        tokens_in += int(um.get("input_tokens", 0) or 0)
                        tokens_out += int(um.get("output_tokens", 0) or 0)
                else:
                    raise TypeError(f"runnable yielded unsupported {type(chunk).__name__}")
                if text:
                    yield text

        async for ev in stream_events(texts()):
            yield ev
        if final is not None:
            data = json.loads(json.dumps(final, default=str))
            yield ArtifactChunk(
                parts=[new_data_part(data)], name="result", artifact_id="result", last=True
            )
        if saw_usage:
            yield Usage(tokens_in=tokens_in, tokens_out=tokens_out)


def as_langchain_tools(
    tools: list[PartnerTool], client: PartnerClient, *, caller: Principal | None = None
) -> list[StructuredTool]:
    """Project partner tools as LangChain ``StructuredTool``s returning the JSON envelope."""

    def make(tool: PartnerTool) -> StructuredTool:
        async def call(**kwargs: Any) -> str:
            result = await invoke(tool, kwargs, client, inbound_task_id=None, caller=caller)
            return json.dumps(result, default=str)

        return StructuredTool.from_function(
            coroutine=call,
            name=tool.name,
            description=with_untrusted_note(tool.description),
            # A dict args_schema is not validated by LangChain; ``invoke`` validates instead
            # (gateway-only ``x-`` limits included). A copy: LangChain may change it.
            args_schema=copy.deepcopy(strip_extensions(tool.parameters)),
            handle_tool_error=True,
        )

    return [make(t) for t in tools]
