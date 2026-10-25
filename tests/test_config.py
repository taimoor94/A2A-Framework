import sys
import textwrap

import pytest

from a2agw.config import ConfigError, GatewayConfig, build_host, interpolate, load_config
from a2agw.serve.agent import AgentSpec


def write(tmp_path, text, name="a2agw.yaml"):
    p = tmp_path / name
    p.write_text(textwrap.dedent(text))
    return p


def test_env_interpolation():
    env = {"A": "x", "EMPTY": ""}
    assert interpolate("${A}-${B:-dflt}-${EMPTY:-d2}-${EMPTY}", env) == "x-dflt--"
    assert interpolate("cost $$5 and $${A}", env) == "cost $5 and ${A}"


def test_missing_env_errors_clearly(tmp_path):
    p = write(tmp_path, "base_url: ${NOPE_URL}\nauth:\n  jwt: ${SECRET_VALUE}\n")
    with pytest.raises(ConfigError) as ei:
        load_config(p, env={"SECRET_VALUE": "hunter2"})
    msg = str(ei.value)
    assert "NOPE_URL" in msg and str(p) in msg and "hunter2" not in msg


def test_load_config_defaults_and_validation(tmp_path):
    p = write(tmp_path, "base_url: ${U:-http://x}\n")
    cfg = load_config(p, env={})
    assert cfg.base_url == "http://x" and cfg.partners_file == "partners.yaml"
    assert cfg.db_url == "sqlite+aiosqlite:///a2agw.db" and cfg.auth is None
    bad = write(tmp_path, "base_url: http://x\npartners:\n  - {id: p, tier: partner}\n", "b.yaml")
    with pytest.raises(ConfigError, match="exactly one of url or card_file"):
        load_config(bad, env={})
    unknown = write(tmp_path, "base_url: http://x\nbogus: 1\n", "c.yaml")
    with pytest.raises(ConfigError, match="bogus"):
        load_config(unknown, env={})


def test_build_host_imports_agent(tmp_path, monkeypatch):
    (tmp_path / "t20_agent_mod.py").write_text(
        "from a2agw.adapters.callable import agent\n"
        "@agent(id='e1', description='d')\n"
        "async def e1(ctx):\n    return ctx.text\n"
        "def factory():\n    return e1\n"
        "NOT_SPEC = 3\n"
    )
    cfg = GatewayConfig.model_validate(
        {
            "base_url": "http://x",
            "db_url": f"sqlite+aiosqlite:///{tmp_path / 'g.db'}",
            "agents": [{"spec": "t20_agent_mod:e1"}],
            "credentials": {"r": {"header": "Authorization", "env": "TOK"}},
        }
    )
    try:
        host = build_host(cfg, config_dir=tmp_path)
        assert isinstance(host.specs["e1"], AgentSpec)
        assert host.partners.path == (tmp_path / "partners.yaml").resolve()
        assert "r" in repr(host.credentials)
        assert str(tmp_path) not in sys.path

        cfg2 = GatewayConfig.model_validate(
            {**cfg.model_dump(), "agents": [{"spec": "t20_agent_mod:factory"}]}
        )
        assert "e1" in build_host(cfg2, config_dir=tmp_path).specs

        cfg3 = GatewayConfig.model_validate(
            {**cfg.model_dump(), "agents": [{"spec": "t20_agent_mod:NOT_SPEC"}]}
        )
        with pytest.raises(ConfigError, match="not an AgentSpec"):
            build_host(cfg3, config_dir=tmp_path)
        cfg4 = GatewayConfig.model_validate(
            {**cfg.model_dump(), "agents": [{"spec": "nonexistent_mod_t20:x"}]}
        )
        with pytest.raises(ConfigError, match="cannot import"):
            build_host(cfg4, config_dir=tmp_path)
    finally:
        sys.modules.pop("t20_agent_mod", None)


def test_otlp_endpoint_requires_exporter(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "opentelemetry.exporter.otlp.proto.http.trace_exporter", None)
    cfg = GatewayConfig.model_validate(
        {
            "base_url": "http://x",
            "telemetry": {"service_name": "s", "otlp_endpoint": "http://collector:4318"},
        }
    )
    with pytest.raises(ConfigError, match="install opentelemetry-exporter-otlp"):
        build_host(cfg, config_dir=tmp_path)


@pytest.mark.parametrize("variant", ["new", "existing_changed"])
async def test_register_partners(tmp_path, variant):
    import json

    import respx
    from test_cli import CARD, URL

    from a2agw.config import register_partners
    from a2agw.consult import netguard

    async def fake(host):
        return ["93.184.216.34"]

    netguard._resolve, saved = fake, netguard._resolve
    try:
        (tmp_path / "card.json").write_text(json.dumps(CARD))
        cfg = GatewayConfig.model_validate(
            {
                "base_url": "http://x",
                "partners": [
                    {"id": "web", "url": URL, "tier": "partner", "tags": ["t"]},
                    {"id": "filed", "card_file": "card.json", "tier": "partner"},
                ],
            }
        )
        host = build_host(cfg, config_dir=tmp_path)
        with respx.mock:
            route = respx.get(URL + "/.well-known/agent-card.json").respond(200, json=CARD)
            await register_partners(host, cfg, config_dir=tmp_path)
            assert {r.id for r in host.partners.all()} == {"web", "filed"}
            assert host.partners.get("web").tags == ["t"]
            if variant == "existing_changed":
                route.respond(200, json={**CARD, "description": "changed"})
                await register_partners(host, cfg, config_dir=tmp_path)
                assert host.partners.get("web").status == "quarantined"
                assert host.partners.get("web").pending_card is not None
        assert (tmp_path / "partners.yaml").exists()
    finally:
        netguard._resolve = saved
