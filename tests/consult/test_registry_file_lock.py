"""Saving the partners file never blocks the gateway on a held lock, and keeps the file's
mode and durability (a crash never leaves an empty or truncated file)."""

from __future__ import annotations

import fcntl
import logging
import os
import stat
import time
from contextlib import contextmanager

import httpx
import pytest
import yaml

from a2agw.consult import registry as registry_mod
from a2agw.consult.registry import PartnerRecord, PartnerRegistry, PartnersFileBusy, card_hash
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


class _Idle:
    durable_sessions = False

    async def run(self, ctx):  # pragma: no cover - never called
        if False:
            yield None


def _seed(path):
    reg = PartnerRegistry(path)
    reg._records["p1"] = PartnerRecord(
        id="p1", card=CARD, card_hash=card_hash(CARD), tier="internal"
    )
    reg.save()


def _status(path) -> str:
    return yaml.safe_load(path.read_text())["partners"][0]["status"]


@contextmanager
def _held(path):
    """Another process's lock on ``<file>.lock`` (flock locks are per open file)."""
    with open(path.with_name(path.name + ".lock"), "a") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def test_held_lock_raises_busy_after_the_timeout_by_default(tmp_path):
    path = tmp_path / "partners.yaml"
    _seed(path)
    reg = PartnerRegistry(path, lock_timeout_s=0.1)
    reg.load()
    with _held(path):
        t0 = time.monotonic()
        with pytest.raises(PartnersFileBusy):
            reg.disable("p1")
        assert time.monotonic() - t0 < 2.0
        assert _status(path) == "active"  # nothing written
    reg.flush()  # the change was kept and is written once the lock is free
    assert _status(path) == "disabled"


def test_deferring_registry_skips_the_save_and_flushes_later(tmp_path, caplog):
    path = tmp_path / "partners.yaml"
    _seed(path)
    reg = PartnerRegistry(path, lock_timeout_s=0.1, defer_busy_saves=True)
    reg.load()
    with _held(path):
        with caplog.at_level(logging.WARNING, logger="a2agw.consult.registry"):
            t0 = time.monotonic()
            reg.disable("p1")  # does not raise, does not block for long
            assert time.monotonic() - t0 < 2.0
        assert reg.get("p1").status == "disabled"
        assert _status(path) == "active"
        assert any("busy" in r.getMessage() for r in caplog.records)
        assert reg.unsaved
    reg.flush()
    assert _status(path) == "disabled"
    assert not reg.unsaved


def test_flush_on_a_deferring_registry_does_not_raise_while_busy(tmp_path):
    path = tmp_path / "partners.yaml"
    _seed(path)
    reg = PartnerRegistry(path, lock_timeout_s=0.05, defer_busy_saves=True)
    reg.load()
    with _held(path):
        reg.disable("p1")
        reg.flush()  # still busy: deferred again, no exception
        assert reg.unsaved


async def test_host_defers_a_busy_save_and_its_maintenance_pass_writes_it(tmp_path):
    path = tmp_path / "partners.yaml"
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=CARD))
    async with httpx.AsyncClient(transport=transport) as http:
        host = AgentHost(
            "http://a",
            db_url=f"sqlite+aiosqlite:///{tmp_path / 'g.db'}",
            partners_path=path,
            partner_http=http,
        )
        host.add(
            AgentSpec(
                id="aa",
                name="A",
                description="d",
                skills=[SkillSpec(id="s", name="s", description="d")],
                adapter=_Idle(),
            )
        )
        await host.partners.add_from_url("p1", "http://p1.internal", "internal")
        await host.startup()
        try:
            assert host.partners.defer_busy_saves is True
            assert host.partners.lock_timeout_s <= 0.5
            with _held(path):
                t0 = time.monotonic()
                host.partners.disable("p1")  # on the event loop: must not stall it
                assert time.monotonic() - t0 < 2.0
                assert _status(path) == "active"
                assert host.partners.unsaved
            await host.maintain()
            assert _status(path) == "disabled"
            assert not host.partners.unsaved
        finally:
            await host.shutdown()


def test_save_keeps_the_file_mode(tmp_path):
    path = tmp_path / "partners.yaml"
    _seed(path)
    os.chmod(path, 0o600)
    reg = PartnerRegistry(path)
    reg.load()
    reg.disable("p1")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _status(path) == "disabled"


def test_save_fsyncs_before_replacing(tmp_path, monkeypatch):
    path = tmp_path / "partners.yaml"
    _seed(path)
    calls: list[str] = []
    real_fsync, real_replace = os.fsync, os.replace
    monkeypatch.setattr(
        registry_mod.os, "fsync", lambda fd: (calls.append("fsync"), real_fsync(fd))[1]
    )
    monkeypatch.setattr(
        registry_mod.os, "replace", lambda a, b: (calls.append("replace"), real_replace(a, b))[1]
    )
    reg = PartnerRegistry(path)
    reg.load()
    reg.disable("p1")
    assert "fsync" in calls and "replace" in calls
    assert calls.index("fsync") < calls.index("replace")


def test_symlinked_temp_file_is_not_followed(tmp_path):
    path = tmp_path / "partners.yaml"
    _seed(path)
    target = tmp_path / "elsewhere.txt"
    target.write_text("keep")
    (tmp_path / "partners.yaml.tmp").symlink_to(target)
    reg = PartnerRegistry(path)
    reg.load()
    reg.disable("p1")
    assert target.read_text() == "keep"
    assert _status(path) == "disabled"
