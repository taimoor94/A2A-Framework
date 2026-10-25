"""Run the software-team demo: serve the three agents and ask pm to build a todo API.

uv run python examples/software_team/run_demo.py [--port 8765] [--no-trace]
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import tempfile
import uuid
from pathlib import Path

if not __package__:  # run as a script: make ``examples.software_team`` importable
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import httpx
import uvicorn
from a2a.client import A2ACardResolver, ClientConfig, ClientFactory
from a2a.types import Message, Part, Role, SendMessageRequest, TaskState
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    ConsoleSpanExporter,
    SimpleSpanProcessor,
)
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)

from a2agw.ops.telemetry import setup_telemetry
from examples.software_team.team import build_team

GOAL = "Build a todo API"
STARTUP_TIMEOUT_S = 10.0


def _parse(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--no-trace", action="store_true", help="do not set up OpenTelemetry")
    return p.parse_args(argv)


class GatewayConsoleExporter(ConsoleSpanExporter):
    """Prints only the gateway's ``a2agw.*`` spans, not the a2a-sdk's internal ones."""

    def export(self, spans):
        return super().export([s for s in spans if s.name.startswith("a2agw.")])


def _tracing() -> tuple[TracerProvider, InMemorySpanExporter]:
    provider = setup_telemetry("software-team", exporter=GatewayConsoleExporter(), json_logs=False)
    memory = InMemorySpanExporter()  # second processor: read the trace id back at the end
    provider.add_span_processor(SimpleSpanProcessor(memory))
    return provider, memory


async def _serve_until_started(server: uvicorn.Server) -> asyncio.Task:
    task = asyncio.create_task(server.serve())
    async with asyncio.timeout(STARTUP_TIMEOUT_S):
        while not server.started:
            if task.done():
                task.result()  # surface the startup error
                raise RuntimeError("server exited during startup")
            await asyncio.sleep(0.05)
    return task


def _text(task) -> str:
    return "".join(p.text for a in task.artifacts for p in a.parts if p.text)


def _timeline(host) -> list[str]:
    lines = []
    t0 = None
    for ev in host.bus.recent():
        t0 = ev.ts if t0 is None else t0
        who = ev.agent_id
        if ev.kind == "partner.call":
            who = f"{ev.agent_id}->{ev.data.get('partner_id')}"
        lines.append(f"  +{ev.ts - t0:6.2f}s  {ev.kind:<12}  {who:<20}  {ev.data.get('state')}")
    return lines


async def _run(args: argparse.Namespace) -> int:
    provider = memory = None
    if not args.no_trace:
        provider, memory = _tracing()
    base = f"http://127.0.0.1:{args.port}"
    with tempfile.TemporaryDirectory() as tmp:
        host = await build_team(base, db_url=f"sqlite+aiosqlite:///{Path(tmp) / 'demo.db'}")
        config = uvicorn.Config(host.app(), host="127.0.0.1", port=args.port, log_level="warning")
        server = uvicorn.Server(config)
        serving = await _serve_until_started(server)
        try:
            async with httpx.AsyncClient(timeout=60.0) as hc:
                card = await A2ACardResolver(hc, f"{base}/agents/pm").get_agent_card()
                client = ClientFactory(ClientConfig(httpx_client=hc, streaming=False)).create(card)
                message = Message(
                    message_id=uuid.uuid4().hex, role=Role.ROLE_USER, parts=[Part(text=GOAL)]
                )
                events = [
                    ev async for ev in client.send_message(SendMessageRequest(message=message))
                ]
        finally:
            server.should_exit = True
            await serving

    if provider is not None:
        provider.force_flush()  # console spans first, then the summary
    task = events[-1].task
    state = TaskState.Name(task.status.state)
    print(f"\n=== pm task {task.id}: {state} ===\n")
    print(_text(task))
    print("\n=== timeline ===")
    print("\n".join(_timeline(host)))
    if memory is not None:
        spans = [s for s in memory.get_finished_spans() if s.name.startswith("a2agw.")]
        root = next(
            (
                s
                for s in spans
                if s.name == "a2agw.inbound" and s.attributes.get("a2agw.agent_id") == "pm"
            ),
            None,
        )
        traces = {s.context.trace_id for s in spans}
        if root is not None:
            print(
                f"\ntrace id: {root.context.trace_id:032x} "
                f"({len(spans)} a2agw spans in {len(traces)} trace(s))"
            )
    return 0 if task.status.state == TaskState.TASK_STATE_COMPLETED else 1


def main(argv: list[str] | None = None) -> int:
    return asyncio.run(_run(_parse(argv)))


if __name__ == "__main__":
    sys.exit(main())
