"""Run the software-team demo: serve the agents and ask pm to build a todo API.

By default this is the Phase 3 network: the Node ``coder`` (a webhook agent,
``examples/node_coder``, started here with ``node``) joins pm, architect and security, and the
request comes from an MCP-only agent (``examples/mcp_client``) through the gateway's MCP
server. ``--phase1`` runs the Python-only network with an A2A client instead.

Runs signed (cards, partner cards and call contexts, with a throwaway Ed25519 key) and with
the audit log on; prints the signing key id and the audit chain check at the end.

uv run python examples/software_team/run_demo.py [--port 8765] [--no-trace] [--phase1]
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import json
import os
import secrets
import shutil
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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
NODE_STARTUP_TIMEOUT_S = 30.0  # first start of node can be slow (virus scanners, cold cache)
NODE_STOP_GRACE_S = 5.0
CODER_JS = Path(__file__).resolve().parents[1] / "node_coder" / "agent.mjs"
CODER_SECRET_ENV = "CODER_SECRET"


def _parse(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--no-trace", action="store_true", help="do not set up OpenTelemetry")
    p.add_argument(
        "--phase1", action="store_true", help="Python agents only, asked by an A2A client"
    )
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


class NodeCoder:
    """The Node coder as a subprocess on an ephemeral loopback port.

    ``start`` waits for its ``{"listening": port}`` line, then probes ``/healthz`` until it
    answers; ``stop`` sends SIGTERM and, after a grace period, SIGKILL. Its stdout and stderr
    lines are kept in ``output``."""

    def __init__(self, secret: str) -> None:
        self._secret = secret
        self.proc: asyncio.subprocess.Process | None = None
        self.output: list[str] = []
        self._drains: list[asyncio.Task[None]] = []

    async def start(self) -> str:
        node = shutil.which("node")
        if node is None:
            raise RuntimeError("node is not on PATH (the coder needs Node 24); try --phase1")
        env = {
            "PATH": os.environ.get("PATH", ""),
            "PORT": "0",
            "HOST": "127.0.0.1",
            "SECRET_ENV": CODER_SECRET_ENV,
            CODER_SECRET_ENV: self._secret,
        }
        self.proc = await asyncio.create_subprocess_exec(
            node,
            str(CODER_JS),
            env=env,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        assert self.proc.stdout is not None and self.proc.stderr is not None
        self._drains.append(asyncio.create_task(self._drain(self.proc.stderr)))
        async with asyncio.timeout(NODE_STARTUP_TIMEOUT_S):
            line = await self.proc.stdout.readline()
            if not line:
                await self.proc.wait()
                await asyncio.gather(*self._drains)
                raise RuntimeError(
                    f"the coder exited during startup ({self.proc.returncode}): "
                    + " | ".join(self.output[-5:])
                )
            port = int(json.loads(line)["listening"])
            self._drains.append(asyncio.create_task(self._drain(self.proc.stdout)))
            base = f"http://127.0.0.1:{port}"
            async with httpx.AsyncClient(timeout=2.0) as hc:
                while True:  # readiness probe
                    with contextlib.suppress(httpx.HTTPError):
                        if (await hc.get(f"{base}/healthz")).status_code == 200:
                            break
                    await asyncio.sleep(0.1)
        return f"{base}/a2agw/invoke"

    async def _drain(self, stream: asyncio.StreamReader) -> None:
        async for raw in stream:
            self.output.append(raw.decode("utf-8", "replace").rstrip("\n"))

    async def stop(self) -> None:
        proc = self.proc
        if proc is None:
            return
        if proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), NODE_STOP_GRACE_S)
            except TimeoutError:
                proc.kill()
                await proc.wait()
        for task in self._drains:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(task, NODE_STOP_GRACE_S)


@dataclass
class DemoResult:
    """What one run produced, read from the host before it shut down."""

    host: Any
    pm_task: Any = None  # --phase1: the PM's A2A task
    mcp: Any = None  # Phase 3: the MCP client's ``Outcome``
    coder_tasks: list[str] = field(default_factory=list)
    coder_handles: list[dict[str, Any]] = field(default_factory=list)
    coder_output: list[str] = field(default_factory=list)
    audit_rows: list[dict[str, Any]] = field(default_factory=list)
    chain_ok: bool = False
    # Throwaway secrets of this run (the webhook secret and API keys). Never printed; tests
    # check that none of them reaches a log.
    secrets: list[str] = field(default_factory=list)

    @property
    def completed(self) -> bool:
        if self.mcp is not None:
            return self.mcp.final.get("state") == "completed"
        return self.pm_task is not None and (
            self.pm_task.status.state == TaskState.TASK_STATE_COMPLETED
        )


async def _ask_pm_over_a2a(base: str) -> Any:
    async with httpx.AsyncClient(timeout=60.0) as hc:
        card = await A2ACardResolver(hc, f"{base}/agents/pm").get_agent_card()
        client = ClientFactory(ClientConfig(httpx_client=hc, streaming=False)).create(card)
        message = Message(message_id=uuid.uuid4().hex, role=Role.ROLE_USER, parts=[Part(text=GOAL)])
        events = [ev async for ev in client.send_message(SendMessageRequest(message=message))]
    return events[-1].task


async def run_network(*, port: int, phase3: bool = True) -> DemoResult:
    """Serve the team on ``127.0.0.1:port``, ask pm for :data:`GOAL`, and collect the facts.

    Phase 3: the Node coder runs as a subprocess (killed on the way out, whatever happens)
    and the MCP client asks pm through ``/a2agw/mcp/pm-desk``."""
    from examples.mcp_client.client import consult_pm

    base = f"http://127.0.0.1:{port}"
    coder_secret, team_key, mcp_key = (secrets.token_urlsafe(32) for _ in range(3))
    result = DemoResult(host=None)
    node = NodeCoder(coder_secret) if phase3 else None
    with tempfile.TemporaryDirectory() as tmp:
        try:
            team: dict[str, Any] = {}
            if node is not None:
                team = {
                    "coder_url": await node.start(),
                    "coder_secret": coder_secret,
                    "mcp_key": mcp_key,
                    "team_key": team_key,
                }
                result.secrets = [coder_secret, team_key, mcp_key]
            host = result.host = await build_team(
                base,
                db_url=f"sqlite+aiosqlite:///{Path(tmp) / 'demo.db'}",
                signing_dir=Path(tmp) / "keys",
                **team,
            )
            config = uvicorn.Config(host.app(), host="127.0.0.1", port=port, log_level="warning")
            server = uvicorn.Server(config)
            serving = await _serve_until_started(server)
            try:
                if node is not None:
                    result.mcp = await consult_pm(base, mcp_key, GOAL)
                    rows, _ = await host.index.list(agent_id="coder")
                    result.coder_tasks = [r["task_id"] for r in rows]
                    for task_id in result.coder_tasks:
                        result.coder_handles += await host.handles.by_inbound(task_id)
                else:
                    result.pm_task = await _ask_pm_over_a2a(base)
                assert host.audit is not None
                result.audit_rows, _ = await host.audit.query({}, 1000, None)
                result.chain_ok = await host.audit.verify_chain() is None
            finally:
                await host.end_streams()  # end the MCP sessions before uvicorn stops
                server.should_exit = True
                await serving
        finally:
            if node is not None:
                await node.stop()
                result.coder_output = node.output
    return result


def _text(task) -> str:
    return "".join(p.text for a in task.artifacts for p in a.parts if p.text)


def _kids(host) -> set[str]:
    kids = set()
    for card in host.cards.values():
        for sig in card.signatures:
            header = json.loads(
                base64.urlsafe_b64decode(sig.protected + "=" * (-len(sig.protected) % 4))
            )
            kids.add(header.get("kid", "?"))
    return kids


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


def _report(result: DemoResult) -> None:
    host = result.host
    if result.mcp is not None:
        final = result.mcp.final
        print(f"\n=== MCP client (pm-desk) tools: {', '.join(result.mcp.tools)} ===")
        print(
            f"first answer: {result.mcp.first.get('state')}; after a2a_wait: {final.get('state')}"
        )
        print(f"\n=== pm task {final.get('task_id')}: {final.get('state')} ===\n")
        print(final.get("text") or final.get("reason") or "")
    else:
        task = result.pm_task
        print(f"\n=== pm task {task.id}: {TaskState.Name(task.status.state)} ===\n")
        print(_text(task))
    print("\n=== timeline ===")
    print("\n".join(_timeline(host)))
    if result.coder_tasks:
        print("\n=== coder (Node) ===")
        for h in result.coder_handles:
            print(
                f"partner call {h['partner_id']} {h['state']}, "
                f"linked to inbound task {h['inbound_task_id']}"
            )
        print("\n".join(f"  {line}" for line in result.coder_output))
    print("\n=== security ===")
    signed = sum(1 for card in host.cards.values() if card.signatures)
    print(f"signed cards: {signed} (kid {', '.join(sorted(_kids(host)))})")
    chain = "ok" if result.chain_ok else "BROKEN"
    print(f"audit rows: {len(result.audit_rows)}; audit chain: {chain}")


async def _run(args: argparse.Namespace) -> int:
    provider = memory = None
    if not args.no_trace:
        provider, memory = _tracing()
    result = await run_network(port=args.port, phase3=not args.phase1)
    if provider is not None:
        provider.force_flush()  # console spans first, then the summary
    _report(result)
    if memory is not None:
        spans = [s for s in memory.get_finished_spans() if s.name.startswith("a2agw.")]
        traces = {s.context.trace_id for s in spans}
        if len(traces) == 1:
            print(f"\ntrace id: {next(iter(traces)):032x} ({len(spans)} a2agw spans in 1 trace)")
        else:
            print(f"\n{len(spans)} a2agw spans in {len(traces)} traces")
    return 0 if result.completed and result.chain_ok else 1


def main(argv: list[str] | None = None) -> int:
    return asyncio.run(_run(_parse(argv)))


if __name__ == "__main__":
    sys.exit(main())
