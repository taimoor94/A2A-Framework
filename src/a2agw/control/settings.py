"""Control-plane settings (``control.yaml``), loaded with the gateway's config rules.

The same rules as ``a2agw.config`` apply, through its shared ``read_config_tree``: ``${VAR}``
interpolation in string scalars after parsing, inline secrets (``client_secret: ...``, a
literal password in ``db_url``) rejected with a hint to use ``*_env``, ``extra="forbid"`` at
every level, and errors that name dotted field paths, never values.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from a2agw.config import ConfigError, TrustConfig, read_config_tree, validation_message
from a2agw.consult.netguard import UnsafeURL, require_https

_FORBID = ConfigDict(extra="forbid")
_ENV_NAME = r"^[A-Za-z_][A-Za-z0-9_]*$"

# Console roles (permissions per role: a2agw.control.rbac, Task 5).
Role = Literal["viewer", "operator", "security", "admin"]
ROLES: tuple[Role, ...] = ("viewer", "operator", "security", "admin")

# Mappings in control.yaml whose keys are names chosen by the operator (a group called
# "token" is not an inline secret).
_NAME_MAPS = frozenset({"oidc.role_map"})


class OidcSettings(BaseModel):
    """Sign-in through an OpenID Connect provider (authorization code flow with PKCE)."""

    model_config = _FORBID
    issuer: str = Field(min_length=1)
    client_id: str = Field(min_length=1)
    client_secret_env: str = Field(pattern=_ENV_NAME)
    scopes: list[str] = Field(default_factory=lambda: ["openid", "profile", "email"])
    roles_claim: str = Field(default="groups", min_length=1)
    role_map: dict[str, Role] = Field(default_factory=dict)  # IdP group -> Console role

    @field_validator("issuer")
    @classmethod
    def _https_issuer(cls, v: str) -> str:
        try:
            require_https(v)  # plain http only with A2AGW_DEV=1
        except UnsafeURL as e:
            raise ValueError(str(e)) from None
        return v


class SessionSettings(BaseModel):
    model_config = _FORBID
    absolute_s: int = Field(default=28800, gt=0)
    idle_s: int = Field(default=3600, gt=0)
    cookie_secure: bool = True


class RetentionSettings(BaseModel):
    model_config = _FORBID
    events_days: float = Field(default=7, gt=0)
    commands_days: float = Field(default=7, gt=0)


class LimitsSettings(BaseModel):
    model_config = _FORBID
    report_max_bytes: int = Field(default=1048576, gt=0)
    report_max_items: int = Field(default=1000, gt=0)
    # a gateway counts as connected while seen within two keepalives; under 3 s the
    # keepalives are mostly overhead, over 60 s a lost gateway shows connected too long
    stream_keepalive_s: float = Field(default=15, ge=3, le=60)


class ControlSettings(BaseModel):
    model_config = _FORBID
    base_url: str = Field(min_length=1)  # the public URL of the control plane
    db_url: str = "sqlite+aiosqlite:///a2agw-control.db"
    oidc: OidcSettings | None = None
    session: SessionSettings = Field(default_factory=SessionSettings)
    retention: RetentionSettings = Field(default_factory=RetentionSettings)
    limits: LimitsSettings = Field(default_factory=LimitsSettings)
    trust: TrustConfig | None = None  # the gateway's shape: keys for card signature checks


def load_control_settings(path: str | Path, env: dict[str, str] | None = None) -> ControlSettings:
    """Load ``control.yaml``. ``env`` replaces ``os.environ`` for interpolation (tests)."""
    data = read_config_tree(path, env, name_maps=_NAME_MAPS)
    try:
        return ControlSettings.model_validate(data)
    except ValidationError as e:
        raise ConfigError(validation_message(Path(path), e)) from None
