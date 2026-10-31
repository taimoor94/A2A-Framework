"""Control-plane settings: the gateway's interpolation and inline-secret rules, extra=forbid."""

from __future__ import annotations

import textwrap

import pytest

from a2agw.config import ConfigError
from a2agw.control.settings import ControlSettings, load_control_settings


def write(tmp_path, text, name="control.yaml"):
    p = tmp_path / name
    p.write_text(textwrap.dedent(text))
    return p


def test_inline_client_secret_rejected(tmp_path):
    p = write(
        tmp_path,
        """\
        base_url: https://cp.example
        oidc:
          issuer: https://idp.example
          client_id: console
          client_secret: hunter2-inline
        """,
    )
    with pytest.raises(ConfigError) as ei:
        load_control_settings(p, env={})
    msg = str(ei.value)
    assert "oidc.client_secret" in msg and "client_secret_env" in msg
    assert "hunter2" not in msg


def test_inline_db_password_rejected(tmp_path):
    p = write(tmp_path, "base_url: https://cp.example\ndb_url: postgresql+asyncpg://u:pw@h/db\n")
    with pytest.raises(ConfigError, match="db_url") as ei:
        load_control_settings(p, env={})
    assert "pw@" not in str(ei.value)


def test_role_map_keys_are_operator_names(tmp_path):
    """A group called "token" is a name, not an inline secret."""
    p = write(
        tmp_path,
        """\
        base_url: https://cp.example
        oidc:
          issuer: https://idp.example
          client_id: console
          client_secret_env: CP_OIDC_SECRET
          role_map: {token: viewer, sec-team: security}
        """,
    )
    s = load_control_settings(p, env={})
    assert s.oidc is not None and s.oidc.role_map == {"token": "viewer", "sec-team": "security"}


def test_env_interpolation(tmp_path):
    p = write(
        tmp_path,
        """\
        base_url: ${CP_URL}
        db_url: ${CP_DB:-sqlite+aiosqlite:///x.db}
        oidc:
          issuer: ${IDP}
          client_id: console
          client_secret_env: CP_OIDC_SECRET
        retention: {events_days: 3}
        """,
    )
    s = load_control_settings(p, env={"CP_URL": "https://cp.example", "IDP": "https://idp.x"})
    assert isinstance(s, ControlSettings)
    assert s.base_url == "https://cp.example" and s.db_url == "sqlite+aiosqlite:///x.db"
    assert s.oidc is not None and s.oidc.issuer == "https://idp.x"
    assert s.oidc.scopes == ["openid", "profile", "email"] and s.oidc.roles_claim == "groups"
    assert s.retention.events_days == 3 and s.retention.commands_days == 7
    assert s.session.absolute_s == 28800 and s.session.idle_s == 3600 and s.session.cookie_secure
    assert s.limits.report_max_bytes == 1048576 and s.limits.report_max_items == 1000
    assert s.limits.stream_keepalive_s == 15 and s.trust is None
    with pytest.raises(ConfigError, match="CP_URL"):
        load_control_settings(p, env={})


def test_defaults(tmp_path):
    s = load_control_settings(write(tmp_path, "base_url: https://cp.example\n"), env={})
    assert s.db_url == "sqlite+aiosqlite:///a2agw-control.db" and s.oidc is None


def test_unknown_key_rejected_with_path(tmp_path):
    p = write(
        tmp_path,
        """\
        base_url: https://cp.example
        session: {idle_s: 60, bogus_key: s3cr3t-value}
        """,
    )
    with pytest.raises(ConfigError) as ei:
        load_control_settings(p, env={})
    msg = str(ei.value)
    assert "session.bogus_key" in msg and "s3cr3t" not in msg
    with pytest.raises(ConfigError, match="base_url"):
        load_control_settings(write(tmp_path, "db_url: sqlite+aiosqlite:///x.db\n", "b.yaml"))
    bad_role = write(
        tmp_path,
        """\
        base_url: https://cp.example
        oidc: {issuer: https://i, client_id: c, client_secret_env: E, role_map: {g: root}}
        """,
        "c.yaml",
    )
    with pytest.raises(ConfigError, match=r"oidc\.role_map\.g") as ei:
        load_control_settings(bad_role, env={})
    assert "'root'" not in str(ei.value)


def test_trust_section_uses_gateway_shape(tmp_path):
    p = write(
        tmp_path,
        """\
        base_url: https://cp.example
        trust: {require_signed: [public]}
        """,
    )
    with pytest.raises(ConfigError, match="require_signed needs card_keys"):
        load_control_settings(p, env={})
