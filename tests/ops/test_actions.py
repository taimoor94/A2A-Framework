"""Gateway write operations shared by the admin API, the CLI and the control plane."""

from __future__ import annotations

import asyncio
import copy
import json

import httpx
import pytest
import respx

from a2agw.consult import netguard
from a2agw.consult.credentials import StaticCredentials
from a2agw.ops import actions
from a2agw.serve.agent import AgentSpec, SkillSpec
from a2agw.serve.host import AgentHost, PartnersInUse

URL = "https://partner.example.com"
CARD_URL = URL + "/.well-known/agent-card.json"
CARD = {
    "name": "Partner",
    "description": "does things",
    "version": "1.0",
    "supportedInterfaces": [
        {
            "url": "https://partner.example.com/rpc",
            "protocolBinding": "JSONRPC",
            "protocolVersion": "1.0",
        }
    ],
    "capabilities": {},
    "defaultInputModes": ["text/plain"],
    "defaultOutputModes": ["text/plain"],
    "skills": [{"id": "s1", "name": "S1", "description": "d", "tags": ["a"]}],
}
EVIL = {**copy.deepcopy(CARD), "description": "now evil"}
ACTOR = "key:tester"
SECRET = "Bearer SECRET-VALUE-123"


class Echo:
    durable_sessions = False

    async def run(self, ctx):
        from a2agw.core.events import Done

        yield Done(text="ok")


@pytest.fixture(autouse=True)
def public_dns(monkeypatch):
    async def fake(host):
        return ["93.184.216.34"]

    monkeypatch.setattr(netguard, "_resolve", fake)


@pytest.fixture
async def gw(tmp_path):
    """A started host with partner p1 (fetched from CARD_URL) registered."""
    with respx.mock(assert_all_called=False) as router:
        route = router.get(CARD_URL).respond(200, json=CARD)
        http = httpx.AsyncClient()
        host = AgentHost(
            "http://t",
            db_url=f"sqlite+aiosqlite:///{tmp_path / 'h.db'}",
            partners_path=tmp_path / "partners.yaml",
            partner_http=http,
            credentials=StaticCredentials({"acme-cred": {"Authorization": SECRET}}),
        )
        host.add(
            AgentSpec(
                id="alpha",
                name="Alpha",
                description="d",
                skills=[SkillSpec(id="s", name="S", description="d")],
                adapter=Echo(),
            )
        )
        await host.startup()
        await actions.add_partner(
            host, id="p1", card_url=URL, tier="public", credential_ref="acme-cred", actor="setup"
        )
        host.test_route = route  # type: ignore[attr-defined]
        try:
            yield host
        finally:
            await host.shutdown()
            await http.aclose()


async def _quarantine(host: AgentHost) -> None:
    host.test_route.respond(200, json=EVIL)  # type: ignore[attr-defined]
    assert (await actions.refresh_partner(host, "p1", actor="setup"))["result"] == "quarantined"


async def _disable(host: AgentHost) -> None:
    await actions.disable_partner(host, "p1", actor="setup")


async def _none(host: AgentHost) -> None:
    return None


def _pending_hash(host: AgentHost) -> str:
    from a2agw.consult.registry import card_hash

    return card_hash(host.partners.get("p1").pending_card)


CASES = {
    "add_partner": (
        _none,
        lambda h: actions.add_partner(h, id="p2", card=CARD, tier="public", actor=ACTOR),
        "partner.add",
    ),
    "approve_partner": (
        _quarantine,
        lambda h: actions.approve_partner(h, "p1", expected_hash=_pending_hash(h), actor=ACTOR),
        "partner.approve",
    ),
    "reject_partner": (
        _quarantine,
        lambda h: actions.reject_partner(h, "p1", actor=ACTOR),
        "partner.reject",
    ),
    "disable_partner": (
        _none,
        lambda h: actions.disable_partner(h, "p1", actor=ACTOR),
        "partner.disable",
    ),
    "enable_partner": (
        _disable,
        lambda h: actions.enable_partner(h, "p1", actor=ACTOR),
        "partner.enable",
    ),
    "remove_partner": (
        _none,
        lambda h: actions.remove_partner(h, "p1", actor=ACTOR),
        "partner.remove",
    ),
    "refresh_partner": (
        lambda h: _set_card(h, EVIL),
        lambda h: actions.refresh_partner(h, "p1", actor=ACTOR),
        "partner.quarantine",
    ),
    "update_partner": (
        _none,
        lambda h: actions.update_partner(h, "p1", tags=["eu"], actor=ACTOR),
        "partner.update",
    ),
    "reload_partners": (
        _none,
        lambda h: actions.reload_partners(h, actor=ACTOR),
        "partner.reload",
    ),
    "reap": (
        _none,
        lambda h: actions.reap(h, "ghost", confirm=False, force=False, actor=ACTOR),
        "task.reap",
    ),
    "set_policy": (
        _none,
        lambda h: actions.set_policy(h, {"version": 1}, actor=ACTOR),
        "policy.update",
    ),
}


async def _set_card(host: AgentHost, card: dict) -> None:
    host.test_route.respond(200, json=card)  # type: ignore[attr-defined]


@pytest.mark.parametrize("name", sorted(CASES))
async def test_every_action_audits_with_actor(gw, name):
    setup, call, action = CASES[name]
    await setup(gw)
    out = await call(gw)
    json.dumps(out)  # every action returns a JSON-able dict
    assert isinstance(out, dict)
    await gw.audit.drain()
    rows, _ = await gw.audit.query({"action": action})
    assert ACTOR in [r["actor"] for r in rows], rows


async def test_actions_return_shapes(gw):
    assert await actions.update_partner(gw, "p1", tags=["eu"], actor=ACTOR) == {
        "id": "p1",
        "fields": ["tags"],
    }
    disabled = await actions.disable_partner(gw, "p1", actor=ACTOR)
    assert disabled["id"] == "p1" and disabled["status"] == "disabled"
    assert await actions.reap(gw, "ghost", confirm=False, force=False, actor=ACTOR) == {
        "dry_run": True,
        "tasks": 0,
        "handles": 0,
        "recent": 0,
    }
    with pytest.raises(ValueError, match="exactly one of card_url or card"):
        await actions.add_partner(gw, id="p3", tier="public", actor=ACTOR)


async def test_partner_detail_has_diff_and_no_secrets(gw):
    await _quarantine(gw)
    detail = await actions.partner_detail(gw, "p1", actor=ACTOR)
    text = json.dumps(detail)
    assert "SECRET-VALUE" not in text
    assert detail["credential_ref"] == "acme-cred"  # the ref name only
    assert detail["status"] == "quarantined"
    assert detail["card"]["description"] == "does things"
    assert detail["pending_card"]["description"] == "now evil"
    assert detail["diff"] == [
        {
            "path": "description",
            "kind": "changed",
            "old": "does things",
            "new": "now evil",
            "significant": True,
        }
    ]
    await actions.approve_partner(gw, "p1", expected_hash=_pending_hash(gw), actor=ACTOR)
    detail = await actions.partner_detail(gw, "p1", actor=ACTOR)
    assert detail["pending_card"] is None and detail["diff"] == []
    with pytest.raises(KeyError):
        await actions.partner_detail(gw, "ghost", actor=ACTOR)


async def test_remove_with_open_handles_needs_force(gw):
    await gw.handles.record("t1", "p1", "c1", None, None, "TASK_STATE_WORKING")
    await gw.handles.record("t2", "p1", "c1", None, None, "TASK_STATE_COMPLETED")
    with pytest.raises(PartnersInUse) as exc:
        await actions.remove_partner(gw, "p1", actor=ACTOR)
    assert exc.value.open_handles == 1
    assert [r.id for r in gw.partners.all()] == ["p1"]  # unchanged
    rows, _ = await gw.audit.query({"action": "partner.remove"})
    assert [(r["actor"], r["outcome"]) for r in rows] == [(ACTOR, "refused")]

    out = await actions.remove_partner(gw, "p1", force=True, actor=ACTOR)
    assert out["removed"] is True and out["open_handles"] == 1
    assert gw.partners.all() == []
    await gw.audit.drain()
    rows, _ = await gw.audit.query({"action": "partner.remove"})
    rows = [r for r in rows if r["task_id"] is None]  # one row per cancelled task besides
    assert [(r["actor"], r["outcome"]) for r in rows] == [(ACTOR, "active"), (ACTOR, "refused")]


async def test_set_policy_action_validates_without_echoing_values(gw):
    from a2agw.security.policy import PolicyError

    with pytest.raises(PolicyError) as exc:
        await actions.set_policy(
            gw, {"version": 1, "authz": [{"principal": "s3cret"}]}, actor=ACTOR
        )
    assert "s3cret" not in str(exc.value) and "authz.0" in str(exc.value)
    assert gw.policy is None  # unchanged
    out = await actions.set_policy(gw, {"version": 1}, actor=ACTOR)
    assert out["applied"] is True and len(out["hash"]) == 64
    assert gw.policy is not None
    assert await actions.set_policy(gw, None, actor=ACTOR) == {"applied": True, "hash": None}
    assert gw.policy is None


# -- forced removal cancels the partner's open tasks ----------------------------------------


class Blocker:
    durable_sessions = False

    async def run(self, ctx):
        from a2agw.core.events import Done

        await asyncio.Event().wait()
        yield Done(text="never")


@pytest.fixture
async def linked(tmp_path):
    """A gateway whose partner "blk" (a real in-process host) has one open task."""
    from google.protobuf.json_format import MessageToDict
    from streaming_asgi import StreamingASGITransport

    partner = AgentHost("http://p", db_url=f"sqlite+aiosqlite:///{tmp_path / 'p.db'}")
    partner.add(
        AgentSpec(
            id="blk",
            name="Blk",
            description="d",
            skills=[SkillSpec(id="s", name="S", description="d")],
            adapter=Blocker(),
        )
    )
    await partner.startup()
    outbound = httpx.AsyncClient(transport=StreamingASGITransport({"p": partner.app()}))
    pf = tmp_path / "partners.yaml"
    host = AgentHost(
        "http://t",
        db_url=f"sqlite+aiosqlite:///{tmp_path / 'h.db'}",
        partners_path=pf,
        partner_http=outbound,
    )
    await host.startup()
    try:
        await host.partners.add_from_card("blk", MessageToDict(partner.cards["blk"]), "internal")
        res = await host.client.consult("blk", "go", wait_seconds=0.2)
        assert res.state == "working", res
        host.test_partner = partner  # type: ignore[attr-defined]
        host.test_task = res.task_id  # type: ignore[attr-defined]
        yield host
    finally:
        await host.shutdown()
        await outbound.aclose()
        await partner.shutdown()


async def _partner_task_state(host: AgentHost) -> str:
    rows, _ = await host.test_partner.index.list(limit=10)  # type: ignore[attr-defined]
    (row,) = [r for r in rows if r["task_id"] == host.test_task]  # type: ignore[attr-defined]
    return row["state"]


async def test_remove_force_cancels_open_partner_tasks(linked):
    out = await actions.remove_partner(linked, "blk", force=True, actor=ACTOR)
    assert out == {
        "id": "blk",
        "removed": True,
        "open_handles": 1,
        "cancelled": 1,
        "cancel_errors": 0,
    }
    assert linked.partners.all() == []
    h = await linked.handles.get("blk", linked.test_task)
    assert (h["state"], h["end_reason"]) == ("TASK_STATE_CANCELED", "partner removed")
    assert await _partner_task_state(linked) == "TASK_STATE_CANCELED"  # the partner got it
    rows, _ = await linked.audit.query({"action": "partner.remove"})
    cancels = [r for r in rows if r["task_id"] == linked.test_task]
    assert [(r["actor"], r["outcome"], r["detail"]["reason"]) for r in cancels] == [
        (ACTOR, "canceled", "partner removed")
    ]


async def test_reload_force_cancels_open_partner_tasks(linked):
    linked.partners.path.write_text("partners: []\n")
    with pytest.raises(PartnersInUse):
        await linked.reload_partners()
    out = await linked.reload_partners(force=True)
    assert out == {
        "added": [],
        "updated": [],
        "removed": ["blk"],
        "open_handles": 1,
        "cancelled": 1,
        "cancel_errors": 0,
    }
    h = await linked.handles.get("blk", linked.test_task)
    assert (h["state"], h["end_reason"]) == ("TASK_STATE_CANCELED", "partner removed")
    assert await _partner_task_state(linked) == "TASK_STATE_CANCELED"


async def test_remove_force_cancel_error_still_removes(gw):
    # p1's endpoint is not served (respx has no route for it): the cancel fails.
    await gw.handles.record("t9", "p1", "c1", None, None, "TASK_STATE_WORKING")
    out = await actions.remove_partner(gw, "p1", force=True, actor=ACTOR)
    assert out["open_handles"] == 1 and out["cancelled"] == 0 and out["cancel_errors"] == 1
    assert gw.partners.all() == []
    h = await gw.handles.get("p1", "t9")
    assert (h["state"], h["end_reason"]) == ("TASK_STATE_CANCELED", "partner removed")
    rows, _ = await gw.audit.query({"action": "partner.remove"})
    assert ("cancel_failed", "t9") in [(r["outcome"], r["task_id"]) for r in rows]
