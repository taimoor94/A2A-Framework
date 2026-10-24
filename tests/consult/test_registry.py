import copy

import httpx
import pytest
import respx
import yaml

from a2agw.consult import netguard
from a2agw.consult.registry import CardFetchError, PartnerRegistry, card_hash

URL = "https://partner.example.com"
CARD_URL = URL + "/.well-known/agent-card.json"

CARD = {
    "name": "Partner",
    "description": "does things",
    "version": "1.0",
    "supportedInterfaces": [
        {"url": "https://partner.example.com/rpc", "protocolBinding": "JSONRPC",
         "protocolVersion": "1.0"}
    ],
    "capabilities": {},
    "defaultInputModes": ["text/plain"],
    "defaultOutputModes": ["text/plain"],
    "skills": [{"id": "s1", "name": "S1", "description": "d", "tags": ["a"]}],
}


@pytest.fixture(autouse=True)
def public_dns(monkeypatch):
    async def fake(host):
        return ["93.184.216.34"]

    monkeypatch.setattr(netguard, "_resolve", fake)


def variant(**kw):
    c = copy.deepcopy(CARD)
    c.update(kw)
    return c


@respx.mock
async def test_add_from_url_parses_card():
    respx.get(CARD_URL).respond(200, json=CARD)
    events = []
    reg = PartnerRegistry()
    reg.on_change = lambda r, e: events.append(e)
    rec = await reg.add_from_url("p1", URL, "public", credential_ref="cred", tags=["x"])
    assert rec.status == "active" and rec.card_url == URL
    assert rec.agent_card.name == "Partner"
    assert rec.agent_card.skills[0].id == "s1"
    assert rec.card_hash == card_hash(rec.card)
    assert rec.credential_ref == "cred" and rec.tags == ["x"]
    assert reg.active() == [rec] and events == ["added"]


@respx.mock
async def test_full_card_url_used_as_is():
    respx.get("https://partner.example.com/c/card.json").respond(200, json=CARD)
    reg = PartnerRegistry()
    await reg.add_from_url("p1", "https://partner.example.com/c/card.json", "public")


@respx.mock
async def test_injected_client_used():
    respx.get(CARD_URL).respond(200, json=CARD)
    async with httpx.AsyncClient() as hc:
        reg = PartnerRegistry(http=hc)
        await reg.add_from_url("p1", URL, "public")


@respx.mock
async def test_card_too_large_rejected():
    big = b"{" + b" " * (1024 * 1024 + 10) + b"}"
    respx.get(CARD_URL).respond(200, content=big)
    with pytest.raises(CardFetchError, match="1 MiB"):
        await PartnerRegistry().add_from_url("p1", URL, "public")


@respx.mock
async def test_redirect_not_followed():
    respx.get(CARD_URL).respond(302, headers={"location": "http://169.254.169.254/"})
    with pytest.raises(CardFetchError, match="redirect"):
        await PartnerRegistry().add_from_url("p1", URL, "public")


@respx.mock
async def test_bad_json_and_status():
    respx.get(CARD_URL).respond(200, content=b"nope")
    with pytest.raises(CardFetchError):
        await PartnerRegistry().add_from_url("p1", URL, "public")
    respx.get(CARD_URL).respond(500)
    with pytest.raises(CardFetchError):
        await PartnerRegistry().add_from_url("p1", URL, "public")


async def test_unsafe_card_url_rejected():
    with pytest.raises(CardFetchError):
        await PartnerRegistry().add_from_url("p1", "http://partner.example.com", "public")


async def test_metadata_endpoint_in_card_rejected():
    bad = variant(supportedInterfaces=[
        {"url": "https://169.254.169.254/", "protocolBinding": "JSONRPC",
         "protocolVersion": "1.0"}])
    reg = PartnerRegistry()
    with pytest.raises(CardFetchError, match="unsafe"):
        await reg.add_from_card("p1", bad, "public")
    assert reg.active() == []


async def test_ids_and_duplicates():
    reg = PartnerRegistry()
    await reg.add_from_card("p1", CARD, "partner")
    with pytest.raises(ValueError):
        await reg.add_from_card("p1", CARD, "partner")
    with pytest.raises(ValueError):
        await reg.add_from_card("Bad_ID", CARD, "partner")


@respx.mock
async def test_refresh_unchanged():
    respx.get(CARD_URL).respond(200, json=CARD)
    reg = PartnerRegistry()
    await reg.add_from_url("p1", URL, "public")
    assert await reg.refresh("p1") == "unchanged"
    assert reg.get("p1").status == "active"


@respx.mock
async def test_refresh_skill_change_quarantines():
    route = respx.get(CARD_URL).respond(200, json=CARD)
    reg = PartnerRegistry()
    events = []
    await reg.add_from_url("p1", URL, "public")
    reg.on_change = lambda r, e: events.append(e)
    new = variant(skills=[{"id": "s2", "name": "S2", "description": "d", "tags": []}])
    route.respond(200, json=new)
    assert await reg.refresh("p1") == "quarantined"
    rec = reg.get("p1")
    assert rec.status == "quarantined" and rec.pending_card["skills"][0]["id"] == "s2"
    assert rec.card["skills"][0]["id"] == "s1"
    assert reg.active() == [] and events == ["quarantined"]


@respx.mock
async def test_refresh_description_change_applies():
    route = respx.get(CARD_URL).respond(200, json=CARD)
    reg = PartnerRegistry()
    old = (await reg.add_from_url("p1", URL, "public")).card_hash
    route.respond(200, json=variant(description="new words"))
    assert await reg.refresh("p1") == "unchanged"
    rec = reg.get("p1")
    assert rec.status == "active" and rec.card["description"] == "new words"
    assert rec.card_hash != old and rec.pending_card is None


@respx.mock
async def test_approve_promotes_pending():
    route = respx.get(CARD_URL).respond(200, json=CARD)
    reg = PartnerRegistry()
    await reg.add_from_url("p1", URL, "public")
    route.respond(200, json=variant(skills=[]))
    await reg.refresh("p1")
    reg.approve("p1")
    rec = reg.get("p1")
    assert rec.status == "active" and rec.pending_card is None
    assert "skills" not in rec.card and rec.card_hash == card_hash(rec.card)


@respx.mock
async def test_refresh_disabled_noop():
    route = respx.get(CARD_URL).respond(200, json=CARD)
    reg = PartnerRegistry()
    await reg.add_from_url("p1", URL, "public")
    reg.disable("p1")
    calls = route.call_count
    assert await reg.refresh("p1") == "unchanged"
    assert route.call_count == calls and reg.active() == []


async def test_yaml_persistence_roundtrip(tmp_path):
    p = tmp_path / "partners.yaml"
    reg = PartnerRegistry(p)
    await reg.add_from_card("p1", CARD, "partner", credential_ref="ref", tags=["t"])
    await reg.add_from_card("p2", CARD, "public")
    reg.disable("p2")
    assert not list(tmp_path.glob("*.tmp"))
    assert yaml.safe_load(p.read_text())["partners"][0]["credential_ref"] == "ref"
    reg2 = PartnerRegistry(p)
    reg2.load()
    assert reg2.get("p1") == reg.get("p1")
    assert reg2.get("p2").status == "disabled"
    assert [r.id for r in reg2.active()] == ["p1"]
