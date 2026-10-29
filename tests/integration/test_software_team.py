"""The "software team" demo network (Phase 1 acceptance): three frameworks over A2A."""

from __future__ import annotations

import socket
import uuid

import httpx
from a2a.client import ClientConfig, ClientFactory
from a2a.types import Message, Part, Role, SendMessageRequest, TaskState
from streaming_asgi import StreamingASGITransport

from examples.software_team import run_demo, security
from examples.software_team.team import build_team

COMPLETED = TaskState.Name(TaskState.TASK_STATE_COMPLETED)
INPUT_REQUIRED = TaskState.Name(TaskState.TASK_STATE_INPUT_REQUIRED)


def _text(task) -> str:
    return "".join(p.text for a in task.artifacts for p in a.parts if p.text)


async def test_pm_delegates_handles_input_and_long_task(tmp_path, fast, spans, monkeypatch):
    monkeypatch.setattr(security, "STEP_DELAY_S", 0.3)  # 0.9 s total, past PM's 0.5 s wait
    transport = StreamingASGITransport({})
    partner_hc = httpx.AsyncClient(transport=transport, base_url="http://t")
    host = await build_team(
        "http://t",
        db_url=f"sqlite+aiosqlite:///{tmp_path / 'team.db'}",
        partner_http=partner_hc,
        signing_dir=tmp_path / "keys",
    )
    transport.apps["t"] = host.app()
    await host.startup()
    hc = httpx.AsyncClient(transport=StreamingASGITransport({"t": host.app()}), base_url="http://t")
    try:
        client = ClientFactory(ClientConfig(httpx_client=hc, streaming=False)).create(
            host.cards["pm"]
        )
        req = SendMessageRequest(
            message=Message(
                message_id=uuid.uuid4().hex,
                role=Role.ROLE_USER,
                parts=[Part(text="Build a todo API")],
            )
        )
        events = [ev async for ev in client.send_message(req)]
        task = events[-1].task

        # PM completed, with both sections assembled from the partners' answers.
        assert TaskState.Name(task.status.state) == COMPLETED
        text = _text(task)
        assert "## Architecture" in text and "## Security review" in text
        architecture = text.split("## Security review")[0]
        assert "PostgreSQL" in architecture
        assert security.FINDING in text.split("## Security review")[1]

        recent = host.bus.recent()
        # The architect asked a question, then finished on the answer.
        arch_states = [
            e.data["state"] for e in recent if e.kind == "task.state" and e.agent_id == "architect"
        ]
        assert INPUT_REQUIRED in arch_states
        assert arch_states.index(INPUT_REQUIRED) < len(arch_states) - 1
        assert arch_states[-1] == COMPLETED

        # The security review is a long task: the first consult returned a working handle.
        sec_calls = [
            e.data
            for e in recent
            if e.kind == "partner.call" and e.data["partner_id"] == "security"
        ]
        assert sec_calls[0]["state"] == "working"
        assert sec_calls[0]["task_id"]

        # One distributed trace for the whole run.
        a2a_spans = [s for s in spans.get_finished_spans() if s.name.startswith("a2agw.")]
        assert {s.attributes.get("a2agw.agent_id") for s in a2a_spans} >= {
            "pm",
            "architect",
            "security",
        }
        assert len({s.context.trace_id for s in a2a_spans}) == 1

        # Signing: every served card is signed, the partners were registered from signed
        # cards (internal tier requires it here), and calls carried signed call contexts.
        assert all(card.signatures for card in host.cards.values())
        for pid in ("architect", "security"):
            assert host.partners.get(pid).signed_key_id
        assert host.partners.require_signed == frozenset({"internal"})

        # Audit: partner calls and signed inbound admissions, on an intact chain.
        rows, _ = await host.audit.query({}, 500, None)
        actions = {r["action"] for r in rows}
        assert {"partner.call", "inbound.admit"} <= actions, actions
        assert any(
            r["action"] == "inbound.admit" and (r.get("detail") or {}).get("context") == "signed"
            for r in rows
        )
        assert await host.audit.verify_chain() is None

        # The task index holds tasks for every agent.
        for agent_id in ("pm", "architect", "security"):
            rows, _ = await host.index.list(agent_id=agent_id)
            assert rows, agent_id
    finally:
        await host.shutdown()
        await hc.aclose()
        await partner_hc.aclose()


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_run_demo_smoke(capsys, monkeypatch):
    monkeypatch.setattr(security, "STEP_DELAY_S", 0.3)
    code = run_demo.main(["--phase1", "--no-trace", "--port", str(_free_port())])
    out = capsys.readouterr().out
    assert code == 0
    assert "COMPLETED" in out
    assert "## Security review" in out
    assert "signed cards: 3" in out and "audit chain: ok" in out
