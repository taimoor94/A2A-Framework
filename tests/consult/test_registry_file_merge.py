"""N1: a registry never overwrites changes another process made to the partners file.

The host's registry and the CLI's share ``partners.yaml``. A save re-reads the file under a
lock and writes back only the records this registry changed; a record also changed on disk
since this registry last read or wrote it is left as it is on disk (WARNING: reload).
"""

from __future__ import annotations

import logging

import httpx
import yaml

from a2agw.consult.registry import PartnerRegistry
from a2agw.serve.agent import AgentSpec, SkillSpec
from a2agw.serve.host import AgentHost

CARD = {
    "name": "P",
    "description": "d",
    "version": "1",
    "supportedInterfaces": [
        {"url": "http://10.0.0.5/rpc", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
    ],
    "capabilities": {},
    "defaultInputModes": ["text/plain"],
    "defaultOutputModes": ["text/plain"],
    "skills": [{"id": "s", "name": "s", "description": "d", "tags": []}],
}
CHANGED = {**CARD, "description": "changed: now does something else"}


class Echo:
    durable_sessions = False

    async def run(self, ctx):  # pragma: no cover - never called
        if False:
            yield None


def _spec() -> AgentSpec:
    return AgentSpec(
        id="aa",
        name="A",
        description="d",
        skills=[SkillSpec(id="s", name="s", description="d")],
        adapter=Echo(),
    )


def _file(path) -> dict[str, dict]:
    return {p["id"]: p for p in yaml.safe_load(path.read_text())["partners"]}


def _http(cards: dict[str, dict]) -> httpx.AsyncClient:
    """Serves a card per host name (p1.internal -> cards["p1"])."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=cards[request.url.host.split(".")[0]])

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def _host(tmp_path, http) -> AgentHost:
    host = AgentHost(
        "http://a",
        db_url=f"sqlite+aiosqlite:///{tmp_path / 'g.db'}",
        partners_path=tmp_path / "partners.yaml",
        partner_http=http,
    )
    host.add(_spec())
    await host.partners.add_from_url("p1", "http://p1.internal", "internal")
    await host.startup()
    return host


def _cli(tmp_path, http) -> PartnerRegistry:
    reg = PartnerRegistry(tmp_path / "partners.yaml", http=http)
    reg.load()
    return reg


async def test_partner_added_by_the_cli_survives_a_host_maintenance_pass(tmp_path):
    cards = {"p1": CARD, "p2": CARD}
    async with _http(cards) as http:
        host = await _host(tmp_path, http)
        try:
            await _cli(tmp_path, http).add_from_url("p2", "http://p2.internal", "internal")
            await host.maintain(now=10**10)  # p1 is due for a refresh
            assert set(_file(tmp_path / "partners.yaml")) == {"p1", "p2"}
            cards["p1"] = CHANGED  # now the host has something to write for p1
            await host.maintain(now=10**10)
            on_disk = _file(tmp_path / "partners.yaml")
            assert set(on_disk) == {"p1", "p2"}
            assert on_disk["p1"]["status"] == "quarantined"
        finally:
            await host.shutdown()


async def test_unchanged_refresh_does_not_write_the_file(tmp_path):
    async with _http({"p1": CARD}) as http:
        host = await _host(tmp_path, http)
        try:
            path = tmp_path / "partners.yaml"
            before = path.stat().st_mtime_ns, path.read_bytes()
            await host.maintain(now=10**10)
            assert (path.stat().st_mtime_ns, path.read_bytes()) == before
        finally:
            await host.shutdown()


async def test_cli_approval_survives_a_host_maintenance_pass(tmp_path):
    cards = {"p1": CARD, "p2": CARD}
    async with _http(cards) as http:
        host = await _host(tmp_path, http)
        try:
            cli = _cli(tmp_path, http)
            await cli.add_from_url("p2", "http://p2.internal", "internal")
            cards["p2"] = CHANGED
            assert await cli.refresh("p2") == "quarantined"
            cli.approve("p2")
            cards["p1"] = CHANGED  # the host quarantines p1 and saves
            await host.maintain(now=10**10)
            on_disk = _file(tmp_path / "partners.yaml")
            assert on_disk["p2"]["status"] == "active"
            assert on_disk["p2"]["card"]["description"] == CHANGED["description"]
            assert on_disk["p1"]["status"] == "quarantined"
        finally:
            await host.shutdown()


async def test_host_change_is_written_and_other_records_are_left_byte_identical(tmp_path):
    cards = {"p1": CARD, "p2": CARD}
    async with _http(cards) as http:
        host = await _host(tmp_path, http)
        try:
            cli = _cli(tmp_path, http)
            await cli.add_from_url("p2", "http://p2.internal", "internal", tags=["from-cli"])
            p2_before = _file(tmp_path / "partners.yaml")["p2"]
            cards["p1"] = CHANGED
            await host.maintain(now=10**10)
            on_disk = _file(tmp_path / "partners.yaml")
            assert on_disk["p1"]["status"] == "quarantined"
            assert on_disk["p2"] == p2_before
            assert "p2" not in {r.id for r in host.partners.all()}  # not loaded by the host
        finally:
            await host.shutdown()


async def test_record_changed_on_both_sides_keeps_the_disk_version(tmp_path, caplog):
    cards = {"p1": CARD}
    async with _http(cards) as http:
        host = await _host(tmp_path, http)
        try:
            _cli(tmp_path, http).disable("p1")  # the operator disables p1 on disk
            cards["p1"] = CHANGED  # meanwhile the host's refresh quarantines it
            with caplog.at_level(logging.WARNING, logger="a2agw.consult.registry"):
                await host.maintain(now=10**10)
            assert _file(tmp_path / "partners.yaml")["p1"]["status"] == "disabled"
            assert any(
                "p1" in r.getMessage() and "reload" in r.getMessage() for r in caplog.records
            )
            # After a reload the host sees the operator's version.
            await host.reload_partners()
            assert host.partners.get("p1").status == "disabled"
        finally:
            await host.shutdown()


def test_saves_take_the_sidecar_lock(tmp_path, monkeypatch):
    from a2agw.consult import registry as registry_mod

    taken: list[str] = []
    real = registry_mod._file_lock

    def spy(path):
        taken.append(path.name)
        return real(path)

    monkeypatch.setattr(registry_mod, "_file_lock", spy)
    reg = PartnerRegistry(tmp_path / "partners.yaml")
    reg._records["p1"] = registry_mod.PartnerRecord(
        id="p1", card=CARD, card_hash=registry_mod.card_hash(CARD), tier="internal"
    )
    reg.save()
    assert taken == ["partners.yaml"]  # the lock is taken on <file>.lock
    assert (tmp_path / "partners.yaml.lock").exists()
    assert set(_file(tmp_path / "partners.yaml")) == {"p1"}
