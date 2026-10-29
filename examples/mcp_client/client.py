"""An MCP-only agent: consults ``pm`` through the gateway's MCP server, as Claude Code or
Cursor would.

It connects to ``{base}/a2agw/mcp/pm-desk`` over streamable HTTP with an API key whose
principal has the ``a2agw:sidecar`` scope (``sidecar.clients`` maps it to ``pm-desk``), lists
the tools, consults ``pm`` with a short wait, and calls ``a2a_wait`` on the handle until
the PM's task is done. It has no A2A code of its own: the gateway does the A2A side.

A2AGW_API_KEY=... uv run python examples/mcp_client/client.py http://127.0.0.1:8765 "Build X"

Needs the ``mcp`` extra (``pip install 'a2a-gateway[mcp]'``).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any

import httpx2
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client

AGENT_ID = "pm-desk"
PARTNER = "pm"
FIRST_WAIT_S = 1.0  # short on purpose: the PM's work outlasts it, so a handle comes back
WAIT_SECONDS = 30.0
MAX_WAITS = 10
TIMEOUT_S = 120.0


@dataclass
class Outcome:
    tools: list[str] = field(default_factory=list)
    first: dict[str, Any] = field(default_factory=dict)  # the consult's answer
    final: dict[str, Any] = field(default_factory=dict)  # the PM task's last state


def mcp_url(base_url: str, agent_id: str = AGENT_ID) -> str:
    return f"{base_url.rstrip('/')}/a2agw/mcp/{agent_id}"


class ToolError(RuntimeError):
    """A tool call the gateway could not answer with a partner envelope."""


def _envelope(tool: str, result: Any) -> dict[str, Any]:
    """The JSON answer of a tool call (``structuredContent``, else its text content).

    An ``isError`` result with an envelope (``failed``, ``rejected``, ``unavailable``) is
    returned as is, so the caller sees its ``state`` and ``reason``; one without an envelope
    raises ``ToolError``, as does content that is neither."""
    if result.structured_content is not None:
        return dict(result.structured_content)
    texts = [c.text for c in result.content if getattr(c, "type", None) == "text"]
    if len(texts) == 1:
        try:
            value = json.loads(texts[0])
        except ValueError:
            value = None
        if isinstance(value, dict):
            return value
    kinds = ", ".join(sorted({str(getattr(c, "type", "?")) for c in result.content})) or "none"
    what = "an error" if result.is_error else "no JSON envelope"
    raise ToolError(f"{tool}: the gateway answered {what} (content: {kinds})")


def _wait_result(waited: dict[str, Any]) -> dict[str, Any]:
    """The first result of an ``a2a_wait`` answer. An envelope instead of results (say
    ``unavailable``: the task is unknown) is returned as is, so the caller sees its
    ``state`` and ``reason``; anything else raises ``ToolError``, like ``_envelope``."""
    results = waited.get("results")
    if isinstance(results, list) and results and isinstance(results[0], dict):
        return results[0]
    if "results" not in waited and isinstance(waited.get("state"), str):
        return waited
    raise ToolError("a2a_wait: the gateway answered no JSON envelope (content: results)")


async def consult_pm(base_url: str, api_key: str, goal: str) -> Outcome:
    """List the tools, ask ``pm`` for ``goal``, then ``a2a_wait`` until it is done."""
    out = Outcome()
    http = httpx2.AsyncClient(headers={"X-API-Key": api_key}, timeout=TIMEOUT_S)
    async with (
        http,
        streamable_http_client(mcp_url(base_url), http_client=http) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        out.tools = [t.name for t in (await session.list_tools()).tools]
        ask = f"ask_{PARTNER}"
        result = _envelope(
            ask, await session.call_tool(ask, {"message": goal, "wait_seconds": FIRST_WAIT_S})
        )
        out.first = result
        for _ in range(MAX_WAITS):
            if result.get("state") != "working":
                break
            handle = {"partner_id": PARTNER, "task_id": result["task_id"]}
            waited = _envelope(
                "a2a_wait",
                await session.call_tool("a2a_wait", {"tasks": [handle], "seconds": WAIT_SECONDS}),
            )
            result = _wait_result(waited)
        out.final = result
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("base_url", help="the gateway's base URL, e.g. http://127.0.0.1:8765")
    p.add_argument("goal", nargs="?", default="Build a todo API")
    args = p.parse_args(argv)
    api_key = os.environ.get("A2AGW_API_KEY")
    if not api_key:
        print("set A2AGW_API_KEY to an API key with the a2agw:sidecar scope", file=sys.stderr)
        return 2
    out = asyncio.run(consult_pm(args.base_url, api_key, args.goal))
    print("tools:", ", ".join(out.tools))
    print(f"{PARTNER}: {out.final.get('state')}")
    print(out.final.get("text") or out.final.get("reason") or "")
    return 0 if out.final.get("state") == "completed" else 1


if __name__ == "__main__":
    sys.exit(main())
