"""Gateway configuration: YAML with ``${ENV}`` interpolation, and the host builder.

Partner registration: config-listed partners are registered by ``register_partners(host, cfg)``,
which ``a2agw serve`` awaits before ``uvicorn.run``. Partners already in the registry are not
overwritten; URL partners are refreshed instead, so a changed card goes through quarantine.
"""

from __future__ import annotations

import importlib
import inspect
import logging
import os
import re
import sys
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from a2agw.consult.credentials import EnvCredentials
from a2agw.consult.netguard import UnsafeURL
from a2agw.consult.registry import CardFetchError
from a2agw.security.auth import AuthConfig
from a2agw.serve.agent import AgentSpec
from a2agw.serve.host import AgentHost

logger = logging.getLogger(__name__)


class ConfigError(Exception):
    """Invalid or unusable configuration. Messages never contain config values."""


_VAR = re.compile(r"\$\$|\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def interpolate(text: str, env: dict[str, str], *, source: str = "config") -> str:
    """Replace ``${VAR}`` / ``${VAR:-default}``; ``$$`` is a literal ``$``."""

    def sub(m: re.Match[str]) -> str:
        if m.group(0) == "$$":
            return "$"
        name, default = m.group(1), m.group(2)
        if name in env:
            return env[name]
        if default is not None:
            return default
        raise ConfigError(f"{source}: environment variable {name} is not set")

    return _VAR.sub(sub, text)


class AgentRef(BaseModel):
    model_config = ConfigDict(extra="forbid")
    spec: str = Field(pattern=r"^[A-Za-z_][\w.]*:[A-Za-z_]\w*$")


class PartnerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    url: str | None = None
    card_file: str | None = None
    tier: Literal["internal", "partner", "public"]
    credential_ref: str | None = None
    tags: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _one_source(self) -> PartnerConfig:
        if (self.url is None) == (self.card_file is None):
            raise ValueError("partner needs exactly one of url or card_file")
        return self


class CredentialConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    header: str
    env: str


class TelemetryConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    service_name: str
    otlp_endpoint: str | None = None


class GatewayConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    base_url: str
    db_url: str = "sqlite+aiosqlite:///a2agw.db"
    auth: AuthConfig | None = None
    admin_without_auth: bool = False
    partners_file: str = "partners.yaml"
    agents: list[AgentRef] = Field(default_factory=list)
    partners: list[PartnerConfig] = Field(default_factory=list)
    credentials: dict[str, CredentialConfig] = Field(default_factory=dict)
    telemetry: TelemetryConfig | None = None
    # Spec 8.2: outbound partner tasks still open after this many seconds are cancelled.
    outbound_ttl_s: float = Field(default=86400.0, gt=0)

    @model_validator(mode="after")
    def _credential_refs_exist(self) -> GatewayConfig:
        for p in self.partners:
            if p.credential_ref is not None and p.credential_ref not in self.credentials:
                raise ValueError(f"partner {p.id!r}: unknown credential_ref {p.credential_ref!r}")
        return self


def _interpolate_tree(node: Any, env: dict[str, str], source: str) -> Any:
    if isinstance(node, str):
        return interpolate(node, env, source=source)
    if isinstance(node, list):
        return [_interpolate_tree(x, env, source) for x in node]
    if isinstance(node, dict):
        return {k: _interpolate_tree(v, env, source) for k, v in node.items()}
    return node


def load_config(path: str | Path, env: dict[str, str] | None = None) -> GatewayConfig:
    p = Path(path)
    try:
        text = p.read_text()
    except OSError:
        raise ConfigError(f"cannot read config file {p}") from None
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        raise ConfigError(f"{p}: invalid YAML") from None
    # Interpolate string scalars only, after parsing: env values can never add YAML structure.
    data = _interpolate_tree(data, dict(os.environ) if env is None else env, str(p))
    if not isinstance(data, dict):
        raise ConfigError(f"{p}: config must be a mapping")
    try:
        return GatewayConfig.model_validate(data)
    except ValidationError as e:
        # Field locations and messages only; never echo input values.
        problems = "; ".join(
            f"{'.'.join(str(x) for x in err['loc'])}: {err['msg']}" for err in e.errors()
        )
        raise ConfigError(f"{p}: {problems}") from None


def partners_path(cfg: GatewayConfig, config_dir: Path) -> Path:
    return (config_dir / cfg.partners_file).resolve()


def _load_agent(ref: str, config_dir: Path) -> AgentSpec:
    module_name, attr = ref.split(":")
    added = str(config_dir)
    sys.path.insert(0, added)
    try:
        module = importlib.import_module(module_name)
    except Exception as e:  # noqa: BLE001 - any failure in user code, incl. SyntaxError
        raise ConfigError(
            f"failed to import agent module {module_name}: {type(e).__name__}"
        ) from None
    finally:
        if added in sys.path:
            sys.path.remove(added)
    try:
        obj: Any = getattr(module, attr)
    except AttributeError:
        raise ConfigError(f"agent {ref!r}: module has no attribute {attr}") from None
    if not isinstance(obj, AgentSpec) and callable(obj):
        try:
            required = [
                p
                for p in inspect.signature(obj).parameters.values()
                if p.default is p.empty
                and p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY)
            ]
        except (TypeError, ValueError):
            required = []
        if required:
            raise ConfigError(f"agent {ref!r} must be an AgentSpec or a zero-argument callable")
        try:
            obj = obj()
        except Exception as e:  # noqa: BLE001
            raise ConfigError(f"agent factory {ref!r} raised {type(e).__name__}") from None
    if not isinstance(obj, AgentSpec):
        raise ConfigError(f"agent {ref!r} is not an AgentSpec or a factory returning one")
    return obj


def _setup_telemetry(cfg: TelemetryConfig) -> None:
    from a2agw.ops.telemetry import setup_telemetry

    exporter = None
    if cfg.otlp_endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        except ImportError:
            raise ConfigError("install opentelemetry-exporter-otlp to use otlp_endpoint") from None
        exporter = OTLPSpanExporter(endpoint=cfg.otlp_endpoint)
    setup_telemetry(cfg.service_name, exporter=exporter)


def build_host(cfg: GatewayConfig, *, config_dir: Path | str = ".") -> AgentHost:
    config_dir = Path(config_dir).resolve()
    if cfg.telemetry is not None:
        _setup_telemetry(cfg.telemetry)
    host = AgentHost(
        cfg.base_url,
        auth=cfg.auth,
        db_url=cfg.db_url,
        partners_path=partners_path(cfg, config_dir),
        credentials=EnvCredentials({k: (v.header, v.env) for k, v in cfg.credentials.items()}),
        admin_without_auth=cfg.admin_without_auth,
        outbound_ttl_s=cfg.outbound_ttl_s,
    )
    for ref in cfg.agents:
        host.add(_load_agent(ref.spec, config_dir))
    return host


def _read_card(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text())  # JSON is a YAML subset
    except (OSError, yaml.YAMLError):
        raise ConfigError(f"cannot read card file {path}") from None
    if not isinstance(data, dict):
        raise ConfigError(f"card file {path} must contain an object")
    return data


async def register_partners(
    host: AgentHost, cfg: GatewayConfig, *, config_dir: Path | str = "."
) -> None:
    """Register config-listed partners that are not yet in the registry.

    Existing URL partners are refreshed (a changed card is quarantined, never overwritten).
    Existing card_file partners are left alone.
    An unreachable or unsafe URL partner logs a warning and startup continues; its state is unchanged.
    """
    config_dir = Path(config_dir).resolve()
    reg = host.partners
    reg.load()
    known = {r.id for r in reg.all()}
    for p in cfg.partners:
        if p.id in known:
            if p.url is not None:
                try:
                    await reg.refresh(p.id)
                except (CardFetchError, UnsafeURL) as e:
                    logger.warning("partner %s: refresh failed (%s); state unchanged", p.id, e)
            continue
        if p.url is not None:
            try:
                await reg.add_from_url(
                    p.id, p.url, p.tier, credential_ref=p.credential_ref, tags=p.tags
                )
            except (CardFetchError, UnsafeURL) as e:
                logger.warning("partner %s: not registered (%s); continuing", p.id, e)
        else:
            assert p.card_file is not None
            card = _read_card(config_dir / p.card_file)
            await reg.add_from_card(
                p.id, card, p.tier, credential_ref=p.credential_ref, tags=p.tags
            )


__all__ = [
    "ConfigError",
    "GatewayConfig",
    "build_host",
    "interpolate",
    "load_config",
    "partners_path",
    "register_partners",
]
