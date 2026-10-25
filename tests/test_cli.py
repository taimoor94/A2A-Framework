import json
from pathlib import Path

import httpx
import pytest
import respx
from typer.testing import CliRunner

from a2agw import cli
from a2agw.consult import netguard
from a2agw.consult.registry import PartnerRegistry

runner = CliRunner()
URL = "https://partner.example.com"
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


@pytest.fixture(autouse=True)
def public_dns(monkeypatch):
    async def fake(host):
        return ["93.184.216.34"]

    monkeypatch.setattr(netguard, "_resolve", fake)


@pytest.fixture
def pf(tmp_path):
    return str(tmp_path / "partners.yaml")


def run(*args):
    return runner.invoke(cli.app, list(args))


def test_init_scaffolds_files(tmp_path):
    d = tmp_path / "proj"
    r = run("init", str(d))
    assert r.exit_code == 0, r.output
    assert {p.name for p in d.iterdir()} == {"a2agw.yaml", "agent.py", ".env.example"}
    # the scaffold must load and build
    from a2agw.config import build_host, load_config

    cfg = load_config(d / "a2agw.yaml", env={})
    host = build_host(cfg, config_dir=d)
    assert "echo" in host.specs
    import sys

    sys.modules.pop("agent", None)


def test_init_refuses_overwrite_unless_force(tmp_path):
    (tmp_path / "agent.py").write_text("keep")
    r = run("init", str(tmp_path))
    assert r.exit_code == 1 and "refusing" in r.output
    assert (tmp_path / "agent.py").read_text() == "keep"
    assert run("init", str(tmp_path), "--force").exit_code == 0
    assert (tmp_path / "agent.py").read_text() != "keep"


def test_card_validate_file_ok_and_bad(tmp_path):
    good = tmp_path / "card.json"
    good.write_text(json.dumps(CARD))
    r = run("card", "validate", str(good))
    assert r.exit_code == 0 and "OK Partner" in r.output and "s1" in r.output
    assert "JSONRPC" in r.output
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    r = run("card", "validate", str(bad))
    assert r.exit_code == 1 and "Traceback" not in r.output
    r = run("card", "validate", str(tmp_path / "missing.json"))
    assert r.exit_code == 1


@respx.mock
def test_card_validate_url_and_unsafe():
    respx.get(URL + "/.well-known/agent-card.json").respond(200, json=CARD)
    assert "OK Partner" in run("card", "validate", URL).output
    r = run("card", "validate", "http://127.0.0.1:9/")
    assert r.exit_code == 1 and "error:" in r.output


@respx.mock
def test_partners_add_list_with_respx(pf):
    respx.get(URL + "/.well-known/agent-card.json").respond(200, json=CARD)
    r = run(
        "partners", "add", "acme", URL, "--tier", "partner", "--tag", "x", "--partners-file", pf
    )
    assert r.exit_code == 0, r.output
    r = run("partners", "list", "--partners-file", pf)
    assert r.exit_code == 0
    line = next(ln for ln in r.output.splitlines() if ln.startswith("acme"))
    assert "partner" in line and "active" in line and "pending" not in line
    reg = PartnerRegistry(Path(pf))
    reg.load()
    assert line.split()[3] == reg.get("acme").card_hash[:12]
    r = run("partners", "add", "acme", URL, "--tier", "partner", "--partners-file", pf)
    assert r.exit_code == 1 and "duplicate" in r.output
    r = run("partners", "add", "z", URL, "--tier", "weird", "--partners-file", pf)
    assert r.exit_code == 1


@respx.mock
def test_verify_quarantine_approve_flow(pf):
    route = respx.get(URL + "/.well-known/agent-card.json").respond(200, json=CARD)
    run("partners", "add", "acme", URL, "--tier", "partner", "--partners-file", pf)
    assert "acme: unchanged" in run("partners", "verify", "--partners-file", pf).output
    changed = {**CARD, "description": "now evil"}
    route.respond(200, json=changed)
    assert "acme: quarantined" in run("partners", "verify", "acme", "--partners-file", pf).output
    out = run("partners", "list", "--partners-file", pf).output
    assert "quarantined" in out and "pending" in out
    r = run("partners", "approve", "acme", "--hash", "deadbeef", "--partners-file", pf)
    assert r.exit_code == 1 and "changed" in r.output
    from a2a.client.card_resolver import parse_agent_card
    from google.protobuf.json_format import MessageToDict

    from a2agw.consult.registry import card_hash

    good = card_hash(MessageToDict(parse_agent_card(dict(changed))))
    r = run("partners", "approve", "acme", "--hash", good, "--partners-file", pf)
    assert r.exit_code == 0, r.output
    assert " active " in run("partners", "list", "--partners-file", pf).output
    assert run("partners", "verify", "ghost", "--partners-file", pf).exit_code == 1


@respx.mock
def test_disable_enable(pf):
    respx.get(URL + "/.well-known/agent-card.json").respond(200, json=CARD)
    run("partners", "add", "acme", URL, "--tier", "partner", "--partners-file", pf)
    assert run("partners", "enable", "acme", "--partners-file", pf).exit_code == 1
    assert run("partners", "disable", "acme", "--partners-file", pf).exit_code == 0
    assert "disabled" in run("partners", "list", "--partners-file", pf).output
    assert run("partners", "enable", "acme", "--partners-file", pf).exit_code == 0
    assert " active " in run("partners", "list", "--partners-file", pf).output
    assert run("partners", "disable", "nope", "--partners-file", pf).exit_code == 1


def test_partners_uses_config_partners_file(tmp_path):
    (tmp_path / "a2agw.yaml").write_text("base_url: http://x\npartners_file: sub/p.yaml\n")
    r = run("partners", "list", "-c", str(tmp_path / "a2agw.yaml"))
    assert r.exit_code == 0
    assert run("partners", "list", "-c", str(tmp_path / "nope.yaml")).exit_code == 1


@respx.mock
def test_call_prints_state_and_text_without_leaking_key():
    respx.get(URL + "/.well-known/agent-card.json").respond(200, json=CARD)
    seen = {}

    def rpc(request: httpx.Request) -> httpx.Response:
        seen["key"] = request.headers.get("x-api-key")
        body = json.loads(request.content)
        task = {
            "id": "t1",
            "contextId": "c1",
            "status": {"state": "TASK_STATE_COMPLETED"},
            "artifacts": [{"artifactId": "a", "parts": [{"text": "pong"}]}],
        }
        return httpx.Response(
            200, json={"jsonrpc": "2.0", "id": body["id"], "result": {"task": task}}
        )

    respx.post(URL + "/rpc").mock(side_effect=rpc)
    r = run("call", URL, "ping", "--api-key", "sekret-key-123")
    assert r.exit_code == 0, r.output
    assert "TASK_STATE_COMPLETED" in r.output and "pong" in r.output
    assert seen["key"] == "sekret-key-123"
    assert "sekret-key-123" not in r.output


@respx.mock
def test_call_failure_hides_key():
    respx.get(URL + "/.well-known/agent-card.json").respond(404)
    r = run("call", URL, "ping", "--api-key", "sekret-key-123")
    assert r.exit_code == 1 and "sekret-key-123" not in r.output
    r = run("call", "http://169.254.169.254/", "x", "--api-key", "sekret-key-123")
    assert r.exit_code == 1 and "sekret-key-123" not in r.output


def test_serve_registers_and_runs(tmp_path, monkeypatch):
    (tmp_path / "t20_serve_agent.py").write_text(
        "from a2agw.adapters.callable import agent\n"
        "@agent(id='s', description='d')\n"
        "async def s(ctx):\n    return 'x'\n"
    )
    (tmp_path / "a2agw.yaml").write_text(
        "base_url: http://x\nagents:\n  - spec: t20_serve_agent:s\n"
    )
    calls = {}
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: calls.update(kw, app=app))
    r = run("serve", "-c", str(tmp_path / "a2agw.yaml"), "--port", "9123")
    assert r.exit_code == 0, r.output
    assert calls["port"] == 9123 and calls["host"] == "0.0.0.0"
    import sys

    sys.modules.pop("t20_serve_agent", None)


def test_serve_bad_config_is_one_line_error(tmp_path):
    (tmp_path / "a2agw.yaml").write_text("base_url: ${MISSING_T20}\n")
    r = run("serve", "-c", str(tmp_path / "a2agw.yaml"))
    assert r.exit_code == 1 and "MISSING_T20" in r.output and "Traceback" not in r.output


def test_init_refuses_symlink_even_with_force(tmp_path):
    target = tmp_path / "elsewhere.txt"
    target.write_text("orig")
    d = tmp_path / "proj"
    d.mkdir()
    (d / "agent.py").symlink_to(target)
    r = run("init", str(d), "--force")
    assert r.exit_code == 1 and "symlink" in r.output
    assert target.read_text() == "orig"


def test_card_validate_file_too_large(tmp_path):
    big = tmp_path / "big.json"
    big.write_text(" " * (1024 * 1024 + 10))
    r = run("card", "validate", str(big))
    assert r.exit_code == 1 and "1 MiB" in r.output


def _mock_rpc(text, seen, card=CARD):
    respx.get(URL + "/.well-known/agent-card.json").respond(200, json=card)

    def rpc(request: httpx.Request) -> httpx.Response:
        seen["key"] = request.headers.get("x-api-key")
        seen["host"] = request.url.host
        body = json.loads(request.content)
        task = {
            "id": "t1",
            "contextId": "c1",
            "status": {"state": "TASK_STATE_COMPLETED"},
            "artifacts": [{"artifactId": "a", "parts": [{"text": text}]}],
        }
        return httpx.Response(
            200, json={"jsonrpc": "2.0", "id": body["id"], "result": {"task": task}}
        )

    respx.post(url__regex=r"https://.*/rpc").mock(side_effect=rpc)


EVIL = {
    **CARD,
    "supportedInterfaces": [
        {
            "url": "https://evil.example.com/rpc",
            "protocolBinding": "JSONRPC",
            "protocolVersion": "1.0",
        }
    ],
}


@respx.mock
def test_call_cross_origin_endpoint_refuses_api_key():
    seen = {}
    _mock_rpc("x", seen, EVIL)
    r = run("call", URL, "hi", "--api-key", "sekret-key-123")
    assert r.exit_code == 1 and "origin differs" in r.output
    assert "sekret-key-123" not in r.output and seen == {}


@respx.mock
def test_call_cross_origin_without_key_warns_and_strips_escapes():
    seen = {}
    _mock_rpc("ok\x1b[31mred\x07\ttab", seen, EVIL)
    r = run("call", URL, "hi")
    assert r.exit_code == 0, r.output
    assert "warning" in r.output and seen["host"] == "evil.example.com"
    assert "\x1b" not in r.output and "\x07" not in r.output and "ok[31mred\ttab" in r.output


def test_serve_registers_partners_before_uvicorn(tmp_path, monkeypatch):
    import uvicorn

    (tmp_path / "a2agw.yaml").write_text("base_url: http://x\n")
    order = []

    async def fake_register(host, cfg, **kw):
        order.append("register")

    monkeypatch.setattr(cli, "register_partners", fake_register)
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: order.append("run"))
    assert run("serve", "-c", str(tmp_path / "a2agw.yaml")).exit_code == 0
    assert order == ["register", "run"]
