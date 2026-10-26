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


def test_outbound_ttl_config_reaches_the_host(tmp_path):
    cfg = load_config(write(tmp_path, "base_url: http://x\noutbound_ttl_s: 600\n"), env={})
    assert cfg.outbound_ttl_s == 600
    assert build_host(cfg, config_dir=tmp_path).outbound_ttl_s == 600
    default = load_config(write(tmp_path, "base_url: http://x\n", "d.yaml"), env={})
    assert build_host(default, config_dir=tmp_path).outbound_ttl_s == 86400
    with pytest.raises(ConfigError, match="outbound_ttl_s"):
        load_config(write(tmp_path, "base_url: http://x\noutbound_ttl_s: 0\n", "z.yaml"), env={})


# -- external (sidecar) agents ---------------------------------------------------------

EXTERNAL = """\
base_url: http://gw
db_url: sqlite+aiosqlite:///{db}
agents:
  - id: coder
    name: Coder
    description: Writes code
    skills:
      - {{id: code, name: Code, description: Writes code, tags: [dev]}}
    output_modes: [text/plain]
    durable_sessions: true
    webhook:
      url: http://127.0.0.1:9000/a2agw/invoke
      secret_env: CODER_SECRET
      timeout_s: 30
"""


def test_external_webhook_agent_builds_spec(tmp_path, monkeypatch):
    from a2agw.adapters.webhook import WebhookAdapter

    p = write(tmp_path, EXTERNAL.format(db=tmp_path / "g.db"))
    cfg = load_config(p, env={})
    monkeypatch.delenv("CODER_SECRET", raising=False)
    with pytest.raises(ConfigError, match="CODER_SECRET") as ei:
        build_host(cfg, config_dir=tmp_path)
    assert "agents.0.webhook.secret_env" in str(ei.value)

    monkeypatch.setenv("CODER_SECRET", "s3cret-value")
    host = build_host(cfg, config_dir=tmp_path)
    assert host.specs["coder"].adapter.secret == "s3cret-value"
    spec = host.specs["coder"]
    assert (spec.name, spec.description) == ("Coder", "Writes code")
    assert [s.id for s in spec.skills] == ["code"] and spec.skills[0].tags == ["dev"]
    assert spec.output_modes == ["text/plain"]
    assert spec.input_modes == ["text/plain", "application/json"]  # the default
    a = spec.adapter
    assert isinstance(a, WebhookAdapter) and a.durable_sessions is True
    assert a.url == "http://127.0.0.1:9000/a2agw/invoke" and a.timeout_s == 30.0
    assert a.tier == "internal"
    assert "s3cret-value" not in repr(a)

    # A module agent and an external agent side by side; no secret is fine.
    (tmp_path / "t1_ext_mod.py").write_text(
        "from a2agw.adapters.callable import agent\n"
        "@agent(id='local', description='d')\n"
        "async def local(ctx):\n    return ctx.text\n"
    )
    cfg2 = GatewayConfig.model_validate(
        {
            "base_url": "http://gw",
            "db_url": f"sqlite+aiosqlite:///{tmp_path / 'g2.db'}",
            "agents": [
                {"spec": "t1_ext_mod:local"},
                {
                    "id": "ext",
                    "name": "Ext",
                    "description": "d",
                    "skills": [{"id": "s", "name": "S", "description": "d"}],
                    "webhook": {"url": "http://localhost:1/a2agw/invoke"},
                },
            ],
        }
    )
    host2 = build_host(cfg2, config_dir=tmp_path)
    assert set(host2.specs) == {"local", "ext"}
    ext = host2.specs["ext"].adapter
    assert isinstance(ext, WebhookAdapter) and ext.secret is None and ext.timeout_s == 300.0


def _ext(**over):
    entry = {
        "id": "ext",
        "name": "Ext",
        "description": "d",
        "skills": [{"id": "s", "name": "S", "description": "d"}],
    }
    entry.update(over)
    return {"base_url": "http://gw", "agents": [entry]}


def test_external_agent_needs_exactly_one_transport(tmp_path):
    with pytest.raises(ValueError, match="exactly one transport"):
        GatewayConfig.model_validate(_ext())
    p = write(
        tmp_path,
        "base_url: http://gw\nagents:\n  - {id: ext, name: E, description: d,\n"
        "     skills: [{id: s, name: S, description: d}]}\n",
    )
    with pytest.raises(ConfigError, match="exactly one transport"):
        load_config(p, env={})
    # Other shape problems are rejected at load time too.
    for bad in (
        _ext(webhook={"url": "http://x/"}, skills=[]),
        _ext(webhook={"url": "http://x/"}, id="Bad_ID"),
        _ext(webhook={"url": "http://x/", "bogus": 1}),
        _ext(webhook={"url": "ftp://x/"}),
        _ext(webhook={"url": "http://x/", "timeout_s": 0}),
        _ext(webhook={"url": "http://x.example.com/", "tier": "public"}),  # needs https
        _ext(webhook={"url": "http://x/"}, spec="m:a"),
        _ext(
            webhook={"url": "http://x/"},
            skills=[{"id": "s", "name": "S", "description": "d", "extra": 1}],
        ),
    ):
        with pytest.raises(ValueError):
            GatewayConfig.model_validate(bad)
    ok = GatewayConfig.model_validate(
        _ext(webhook={"url": "https://x.example.com/", "tier": "public"})
    )
    assert ok.agents[0].webhook.tier == "public"


def test_webhook_inline_secret_rejected(tmp_path):
    p = write(
        tmp_path,
        "base_url: http://gw\nagents:\n  - id: ext\n    name: E\n    description: d\n"
        "    skills: [{id: s, name: S, description: d}]\n"
        "    webhook: {url: 'http://x/', secret: hunter2-inline}\n",
    )
    with pytest.raises(ConfigError) as ei:
        load_config(p, env={})
    msg = str(ei.value)
    assert "agents.0.webhook.secret" in msg and "secret_env" in msg and "hunter2" not in msg
