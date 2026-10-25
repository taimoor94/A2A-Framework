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
        with pytest.raises(ConfigError, match="failed to import agent module"):
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


def test_interpolation_cannot_inject_yaml_structure(tmp_path):
    p = write(tmp_path, "base_url: ${K}\n")
    evil = "x\nadmin_without_auth: true"
    cfg = load_config(p, env={"K": evil})
    assert cfg.base_url == evil and cfg.admin_without_auth is False


def test_interpolation_comments_hash_and_multiline(tmp_path):
    p = write(
        tmp_path,
        """\
        # uses ${UNSET_IN_COMMENT}
        base_url: ${U}
        db_url: ${D}
        auth:
          jwt:
            issuer: i
            audience: a
            public_key_pem: ${PEM}
        admin_without_auth: ${FLAG:-false}
        """,
    )
    pem = "-----BEGIN PUBLIC KEY-----\nAAA\nBBB\n-----END PUBLIC KEY-----\n"
    cfg = load_config(p, env={"U": "http://x/#frag", "D": "sqlite:///a#b", "PEM": pem})
    assert cfg.base_url == "http://x/#frag" and cfg.db_url == "sqlite:///a#b"
    assert cfg.auth.jwt.public_key_pem == pem
    assert load_config(p, env={"U": "u", "D": "d", "PEM": pem, "FLAG": "true"}).admin_without_auth


def test_unknown_credential_ref_rejected(tmp_path):
    p = write(
        tmp_path,
        "base_url: http://x\npartners:\n  - {id: a, url: 'https://a.example', tier: partner,"
        " credential_ref: nope}\n",
    )
    with pytest.raises(ConfigError, match="credential_ref"):
        load_config(p, env={})


def test_agent_import_failures_wrapped(tmp_path):
    (tmp_path / "t20_syntax_mod.py").write_text("def broken(:\n")
    (tmp_path / "t20_fac_mod.py").write_text(
        "def needs_arg(x):\n    return x\ndef boom():\n    raise RuntimeError('secret')\n"
    )
    base = {"base_url": "http://x"}
    try:
        for spec, pat in [
            ("t20_syntax_mod:x", "failed to import agent module t20_syntax_mod: SyntaxError"),
            ("t20_fac_mod:needs_arg", "zero-argument"),
            ("t20_fac_mod:boom", "raised RuntimeError"),
        ]:
            cfg = GatewayConfig.model_validate({**base, "agents": [{"spec": spec}]})
            with pytest.raises(ConfigError, match=pat) as ei:
                build_host(cfg, config_dir=tmp_path)
            assert "secret" not in str(ei.value)
    finally:
        for m in ("t20_syntax_mod", "t20_fac_mod"):
            sys.modules.pop(m, None)


async def test_register_partners_unreachable_continues(tmp_path, caplog):
    import respx

    from a2agw.config import register_partners

    cfg = GatewayConfig.model_validate(
        {
            "base_url": "http://x",
            "partners": [{"id": "dead", "url": "http://127.0.0.1:9", "tier": "partner"}],
        }
    )
    host = build_host(cfg, config_dir=tmp_path)
    with respx.mock, caplog.at_level("WARNING"):
        await register_partners(host, cfg, config_dir=tmp_path)
    assert host.partners.all() == [] and "dead" in caplog.text
