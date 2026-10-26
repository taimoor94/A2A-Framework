"""Gateway configuration: YAML with ``${ENV}`` interpolation, and the host builder.

Partner registration: config-listed partners are registered by ``register_partners(host, cfg)``,
which ``a2agw serve`` awaits before ``uvicorn.run``. Partners already in the registry are not
overwritten; URL partners are refreshed instead, so a changed card goes through quarantine.

Rules for every section (``extra="forbid"`` at every level):

- Unknown keys and wrong types are rejected with the dotted path of the field
  (``push.timeout_s: ...``), never with the offending value.
- Secrets never appear inline. Key material comes from files (``*_file``, resolved relative to
  the config file's directory); other secrets from environment variables named in ``*_env``
  fields. An inline secret-looking key (``client_secret``, ``password``, ``token``, ...) or a
  literal password in ``db_url`` is a ``ConfigError`` with a hint to use ``*_env`` / ``${VAR}``.
- ``${VAR}`` interpolation applies to string scalars after YAML parsing, so an environment
  value can never add YAML structure.
- A key, certificate or policy file that is missing or unreadable is a ``ConfigError`` naming
  the file, never its contents.
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
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from a2agw.consult.credentials import ChainCredentials, CredentialProvider, EnvCredentials
from a2agw.consult.netguard import Tier, UnsafeURL, require_https
from a2agw.consult.oauth import OAuthClientCredentials, OAuthTokenExchange
from a2agw.consult.registry import CardFetchError, PartnerRegistry
from a2agw.consult.tls import TlsClientConfig
from a2agw.context.signing import CallContextSigner, CallContextVerifier
from a2agw.security.auth import AuthConfig
from a2agw.security.cardsign import CardSigner, CardVerifier, load_public_key
from a2agw.security.classify import RegexPiiClassifier
from a2agw.security.policy import PolicyEngine, PolicyError, load_policy
from a2agw.serve.agent import AgentSpec
from a2agw.serve.host import AgentHost
from a2agw.serve.push import PushSettings

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


_FORBID = ConfigDict(extra="forbid")
Alg = Literal["ES256", "RS256", "EdDSA"]
TierName = Literal["internal", "partner", "public"]
# Keys whose value would be a secret written inline. Each has an ``*_env`` / ``*_file`` form.
_SECRET_KEYS = frozenset(
    {
        "secret",
        "client_secret",
        "password",
        "passwd",
        "token",
        "access_token",
        "refresh_token",
        "bearer",
        "api_key",
        "apikey",
        "private_key",
        "encryption_key",
        "signing_key",
    }
)
# Mappings whose keys are names chosen by the operator (a ref named "token" is fine).
_NAME_MAPS = frozenset(
    {"oauth", "credentials", "tls", "trust.card_keys", "trust.context_issuers", "auth.api_keys"}
)
# userinfo password in a URL: scheme://user:PASSWORD@host
_URL_PASSWORD = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://[^/@:]*:([^/@]*)@")
_WHOLE_VAR = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*(?::-[^}]*)?\}")
# The default part of ${VAR:-default} (as ``interpolate`` reads it: up to the first "}").
_VAR_DEFAULT = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*:-([^}]*)\}")


def _https_only(url: str) -> str:
    """Config-load check: an https URL (plain http only with ``A2AGW_DEV=1``)."""
    try:
        require_https(url)
    except UnsafeURL as e:
        raise ValueError(str(e)) from None
    return url


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
    tls_ref: str | None = None  # a key of the top-level ``tls`` section: mTLS for this partner
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


class SigningConfig(BaseModel):
    """The gateway's private key: signs its agent cards, push JWTs and call contexts."""

    model_config = _FORBID
    key_file: str  # PEM private key (EC P-256, RSA >= 2048 or Ed25519), unencrypted
    kid: str = Field(min_length=1)
    alg: Alg
    jku: str | None = None  # JWKS URL advertised in the card signature header
    issuer: str | None = None  # call-context ``iss``; defaults to base_url


class ContextIssuerConfig(BaseModel):
    model_config = _FORBID
    issuer: str = Field(min_length=1)
    key_file: str  # PEM public key


class TrustConfig(BaseModel):
    """Keys trusted for partner card signatures and for signed call contexts."""

    model_config = _FORBID
    card_keys: dict[str, str] = Field(default_factory=dict)  # kid -> PEM public key file
    jwks_urls: list[str] = Field(default_factory=list)  # allowlisted jku URLs (https)
    jwks_tier: TierName = "public"  # netguard tier the JWKS hosts are vetted with
    require_signed: list[TierName] = Field(default_factory=list)
    context_issuers: dict[str, ContextIssuerConfig] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _keys_for_required(self) -> TrustConfig:
        if self.require_signed and not (self.card_keys or self.jwks_urls):
            raise ValueError("require_signed needs card_keys or jwks_urls")
        return self

    @field_validator("jwks_urls")
    @classmethod
    def _https_jwks(cls, v: list[str]) -> list[str]:
        for url in v:
            _https_only(url)
        return v


class OAuthConfig(BaseModel):
    """An OAuth2 credential for the partners whose ``credential_ref`` is this entry's key."""

    model_config = _FORBID
    type: Literal["client_credentials", "token_exchange"]
    token_url: str  # https on every tier (plain http only with A2AGW_DEV=1)
    token_tier: TierName = "public"  # netguard tier the token endpoint is vetted with
    client_id: str
    client_secret_env: str  # name of the env var holding the client secret
    scope: str | None = None
    audience: str | None = None  # required for token_exchange
    # token_exchange only: a client_credentials entry used for maintenance calls (cascade
    # cancels, recovery) when there is no inbound caller token to exchange.
    fallback: str | None = None

    @field_validator("token_url")
    @classmethod
    def _https_token_url(cls, v: str) -> str:
        return _https_only(v)

    @model_validator(mode="after")
    def _shape(self) -> OAuthConfig:
        if self.type == "token_exchange" and not self.audience:
            raise ValueError("token_exchange needs audience")
        if self.type == "client_credentials" and self.fallback is not None:
            raise ValueError("fallback is only for token_exchange")
        return self


class TlsConfig(BaseModel):
    """A client certificate for mTLS to partners whose ``tls_ref`` is this entry's key."""

    model_config = _FORBID
    cert_file: str
    key_file: str
    ca_file: str | None = None


class PushConfig(BaseModel):
    """Push notifications (``a2agw.serve.push.PushSettings``). Push JWTs are signed with the
    ``signing`` key when that section is set."""

    model_config = _FORBID
    allow_private: bool = False
    timeout_s: float = Field(default=10.0, gt=0)
    max_attempts: int = Field(default=3, ge=1)
    encryption_key_env: str | None = None
    max_configs_per_task: int = Field(default=10, ge=1)
    max_concurrent_deliveries: int = Field(default=32, ge=1)
    max_pending_tasks: int = Field(default=1000, ge=1)


class LimitsConfig(BaseModel):
    """Per-caller caps (spec 7.2, 11a.4): agent turns running at once per principal, and
    new partner tasks one inbound task may start."""

    model_config = _FORBID
    max_concurrent_tasks_per_caller: int = Field(default=32, ge=1)
    max_consults_per_task: int = Field(default=16, ge=1)


class ServerTlsConfig(BaseModel):
    """HTTPS for ``a2agw serve`` (the ``--ssl-*`` flags override it)."""

    model_config = _FORBID
    cert_file: str
    key_file: str
    ca_file: str | None = None
    require_client_cert: bool = False

    @model_validator(mode="after")
    def _ca_for_client_certs(self) -> ServerTlsConfig:
        if self.require_client_cert and not self.ca_file:
            raise ValueError("require_client_cert needs ca_file")
        return self


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
    # How often the maintenance pass runs (TTL expiry, message-id purge, card refresh).
    maintenance_interval_s: float = Field(default=300.0, gt=0)
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    signing: SigningConfig | None = None
    trust: TrustConfig | None = None
    oauth: dict[str, OAuthConfig] = Field(default_factory=dict)
    tls: dict[str, TlsConfig] = Field(default_factory=dict)
    policy_file: str | None = None
    classifier: Literal["regex_pii"] | None = None  # egress classifier for the policy
    push: PushConfig | None = None
    audit: bool = True
    server_tls: ServerTlsConfig | None = None

    @model_validator(mode="after")
    def _refs_exist(self) -> GatewayConfig:
        both = sorted(set(self.credentials) & set(self.oauth))
        if both:
            raise ValueError(f"refs defined in both credentials and oauth: {', '.join(both)}")
        for ref, o in self.oauth.items():
            if o.fallback is not None:
                fb = self.oauth.get(o.fallback)
                if fb is None or fb.type != "client_credentials":
                    raise ValueError(
                        f"oauth {ref!r}: fallback must name a client_credentials oauth entry"
                    )
        for p in self.partners:
            ref = p.credential_ref
            if ref is not None and ref not in self.credentials and ref not in self.oauth:
                raise ValueError(f"partner {p.id!r}: unknown credential_ref {ref!r}")
            if p.tls_ref is not None and p.tls_ref not in self.tls:
                raise ValueError(f"partner {p.id!r}: unknown tls_ref {p.tls_ref!r}")
        if self.classifier is not None and self.policy_file is None:
            raise ValueError("classifier needs policy_file")
        return self


def _interpolate_tree(node: Any, env: dict[str, str], source: str) -> Any:
    if isinstance(node, str):
        return interpolate(node, env, source=source)
    if isinstance(node, list):
        return [_interpolate_tree(x, env, source) for x in node]
    if isinstance(node, dict):
        return {k: _interpolate_tree(v, env, source) for k, v in node.items()}
    return node


def _reject_inline_secrets(node: Any, source: str, path: str = "") -> None:
    """Before interpolation: no secret-looking key anywhere, no literal password in db_url."""
    if isinstance(node, dict):
        for k, v in node.items():
            key = str(k)
            where = f"{path}.{key}" if path else key
            if path not in _NAME_MAPS and key.lower() in _SECRET_KEYS:
                raise ConfigError(
                    f"{source}: {where}: inline secrets are not allowed in config; name an "
                    f"environment variable with {key}_env (or put key material in a *_file)"
                )
            _reject_inline_secrets(v, source, where)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _reject_inline_secrets(v, source, f"{path}.{i}")
    if path == "db_url" and isinstance(node, str) and _inline_password(node):
        raise ConfigError(
            f"{source}: db_url: inline database password; use ${{VAR}} for it "
            "(or for the whole URL)"
        )


def _inline_password(url: str) -> bool:
    """A literal userinfo password in ``url``, or in the ``:-default`` part of any
    ``${VAR:-default}`` in it (the default is used whenever the variable is unset)."""
    m = _URL_PASSWORD.match(url)
    if m and m.group(1) and not _WHOLE_VAR.fullmatch(m.group(1)):
        return True
    return any(
        default is not None and _inline_password(default)
        for default in (d.group(1) for d in _VAR_DEFAULT.finditer(url))
    )


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
    _reject_inline_secrets(data, str(p))
    # Interpolate string scalars only, after parsing: env values can never add YAML structure.
    data = _interpolate_tree(data, dict(os.environ) if env is None else env, str(p))
    if not isinstance(data, dict):
        raise ConfigError(f"{p}: config must be a mapping")
    try:
        return GatewayConfig.model_validate(data)
    except ValidationError as e:
        # Field locations and messages only; never echo input values.
        problems = "; ".join(
            f"{'.'.join(str(x) for x in err['loc']) or '<root>'}: "
            f"{err['msg'].removeprefix('Value error, ')}"
            for err in e.errors(include_input=False, include_url=False)
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


def config_file(config_dir: Path, value: str, where: str) -> Path:
    """``value`` resolved against the config dir; ConfigError (naming the file, never its
    contents) unless it is a readable regular file."""
    p = (Path(config_dir) / value).resolve()
    if not p.is_file() or not os.access(p, os.R_OK):
        raise ConfigError(f"{where}: file {value} is missing or unreadable")
    return p


def _public_key(config_dir: Path, value: str, where: str) -> Any:
    p = config_file(config_dir, value, where)
    try:
        return load_public_key(p)
    except (ValueError, OSError):
        raise ConfigError(f"{where}: cannot load a public key from {value}") from None


def tls_configs(cfg: GatewayConfig, config_dir: Path | str) -> dict[str, TlsClientConfig]:
    """The ``tls`` section as one mapping, shared by the registry and the partner client."""
    config_dir = Path(config_dir).resolve()
    out: dict[str, TlsClientConfig] = {}
    for ref, t in cfg.tls.items():
        where = f"tls.{ref}"
        try:
            out[ref] = TlsClientConfig(
                config_file(config_dir, t.cert_file, f"{where}.cert_file"),
                config_file(config_dir, t.key_file, f"{where}.key_file"),
                config_file(config_dir, t.ca_file, f"{where}.ca_file") if t.ca_file else None,
            )
            out[ref].ssl_context()
        except (ValueError, OSError) as e:
            # TlsClientConfig's messages name the file and the problem only.
            raise ConfigError(f"{where}: {type(e).__name__}: {e}") from None
    return out


def card_verifier(cfg: GatewayConfig, config_dir: Path | str) -> CardVerifier | None:
    """The partner card verifier from ``trust`` (None without card keys or JWKS URLs)."""
    t = cfg.trust
    if t is None or not (t.card_keys or t.jwks_urls):
        return None
    config_dir = Path(config_dir).resolve()
    keys = {
        kid: _public_key(config_dir, f, f"trust.card_keys.{kid}") for kid, f in t.card_keys.items()
    }
    try:
        return CardVerifier(trusted=keys, jwks_urls=list(t.jwks_urls), jwks_tier=t.jwks_tier)
    except (ValueError, UnsafeURL) as e:
        raise ConfigError(f"trust: {e}") from None


def registry_options(cfg: GatewayConfig, config_dir: Path | str) -> dict[str, Any]:
    """Keyword arguments for a ``PartnerRegistry`` (and ``AgentHost``) from the config:
    the card verifier, the tiers that require signed cards and the mTLS configs."""
    require: frozenset[Tier] = frozenset(cfg.trust.require_signed if cfg.trust else ())
    return {
        "verifier": card_verifier(cfg, config_dir),
        "require_signed": require,
        "tls": tls_configs(cfg, config_dir),
    }


def partner_registry(cfg: GatewayConfig, config_dir: Path | str) -> PartnerRegistry:
    """The configured partner registry (not loaded), as ``a2agw partners ...`` uses it."""
    return PartnerRegistry(
        partners_path(cfg, Path(config_dir).resolve()), **registry_options(cfg, config_dir)
    )


def credentials_provider(cfg: GatewayConfig) -> CredentialProvider:
    """Static env credentials, then one OAuth provider per ``oauth`` entry (each applies only
    to partners whose ``credential_ref`` is its key)."""
    env = EnvCredentials({k: (v.header, v.env) for k, v in cfg.credentials.items()})
    if not cfg.oauth:
        return env
    providers: list[CredentialProvider] = [env]
    try:
        for ref, o in cfg.oauth.items():
            if o.type == "client_credentials":
                providers.append(_client_credentials(o, ref))
            else:
                assert o.audience is not None
                fallback = None
                if o.fallback is not None:
                    fallback = _client_credentials(cfg.oauth[o.fallback], ref)
                providers.append(
                    OAuthTokenExchange(
                        o.token_url,
                        o.client_id,
                        o.client_secret_env,
                        o.audience,
                        {ref},
                        fallback=fallback,
                        tier=o.token_tier,
                    )
                )
    except (ValueError, UnsafeURL) as e:
        raise ConfigError(f"oauth: {e}") from None
    return ChainCredentials(*providers)


def _client_credentials(o: OAuthConfig, ref: str) -> OAuthClientCredentials:
    return OAuthClientCredentials(
        o.token_url,
        o.client_id,
        o.client_secret_env,
        scope=o.scope,
        audience=o.audience,
        refs={ref},
        tier=o.token_tier,
    )


def _signers(
    cfg: GatewayConfig, config_dir: Path
) -> tuple[CardSigner | None, CallContextSigner | None]:
    s = cfg.signing
    if s is None:
        return None, None
    key = config_file(config_dir, s.key_file, "signing.key_file")
    try:
        card = CardSigner(key, s.kid, s.alg, s.jku)
        context = CallContextSigner(key, s.kid, s.alg, s.issuer or cfg.base_url)
    except (ValueError, UnsafeURL) as e:
        # Messages name the key file and the problem, never key material.
        raise ConfigError(f"signing: {e}") from None
    return card, context


def _context_verifier(
    cfg: GatewayConfig, config_dir: Path, signer: CallContextSigner | None
) -> CallContextVerifier | None:
    issuers = cfg.trust.context_issuers if cfg.trust is not None else {}
    if not issuers and signer is None:
        return None
    trusted = {
        kid: (c.issuer, _public_key(config_dir, c.key_file, f"trust.context_issuers.{kid}"))
        for kid, c in issuers.items()
    }
    try:
        # With a signer, AgentHost adds its own key, so a loop back to us verifies.
        return CallContextVerifier(trusted)
    except ValueError as e:
        raise ConfigError(f"trust.context_issuers: {e}") from None


def _policy(cfg: GatewayConfig, config_dir: Path) -> PolicyEngine | None:
    if cfg.policy_file is None:
        return None
    path = config_file(config_dir, cfg.policy_file, "policy_file")
    try:
        policy = load_policy(path)
    except PolicyError as e:
        raise ConfigError(f"policy_file: {e}") from None
    classifier = RegexPiiClassifier() if cfg.classifier == "regex_pii" else None
    return PolicyEngine(policy, classifier=classifier)


def server_run_kwargs(cfg: GatewayConfig, *, config_dir: Path | str = ".") -> dict[str, Any]:
    """``AgentHost.run`` keyword arguments for the config's ``server_tls`` (HTTPS, and mTLS
    with ``require_client_cert``); empty without it. ``a2agw serve`` uses this; code that
    builds the host with ``build_host`` passes it on: ``host.run(**server_run_kwargs(cfg))``.
    ConfigError (naming the file) for a missing certificate or key file."""
    tls = cfg.server_tls
    if tls is None:
        return {}
    config_dir = Path(config_dir).resolve()
    return {
        "ssl_certfile": str(config_file(config_dir, tls.cert_file, "server_tls.cert_file")),
        "ssl_keyfile": str(config_file(config_dir, tls.key_file, "server_tls.key_file")),
        "ssl_ca_certs": (
            str(config_file(config_dir, tls.ca_file, "server_tls.ca_file"))
            if tls.ca_file is not None
            else None
        ),
        "require_client_cert": tls.require_client_cert,
    }


def build_host(cfg: GatewayConfig, *, config_dir: Path | str = ".") -> AgentHost:
    """An ``AgentHost`` for the config, agents added (partners are registered separately,
    by ``register_partners``).

    ``server_tls`` is not part of the host: it applies when the server starts. ``a2agw
    serve`` applies it; with ``build_host``, run the host with
    ``host.run(**server_run_kwargs(cfg, config_dir=...))`` (a WARNING says so)."""
    config_dir = Path(config_dir).resolve()
    if cfg.server_tls is not None:
        logger.warning(
            "server_tls is applied when the server starts: pass "
            "server_run_kwargs(cfg) to host.run() (a2agw serve does this)"
        )
    card_signer, context_signer = _signers(cfg, config_dir)
    reg = registry_options(cfg, config_dir)
    push = None
    if cfg.push is not None:
        push = PushSettings(**cfg.push.model_dump(), jwt_signer=card_signer)
    policy = _policy(cfg, config_dir)
    context_verifier = _context_verifier(cfg, config_dir, context_signer)
    credentials = credentials_provider(cfg)
    if cfg.telemetry is not None:
        _setup_telemetry(cfg.telemetry)
    try:
        host = AgentHost(
            cfg.base_url,
            auth=cfg.auth,
            db_url=cfg.db_url,
            partners_path=partners_path(cfg, config_dir),
            credentials=credentials,
            admin_without_auth=cfg.admin_without_auth,
            outbound_ttl_s=cfg.outbound_ttl_s,
            maintenance_interval_s=cfg.maintenance_interval_s,
            max_concurrent_tasks_per_caller=cfg.limits.max_concurrent_tasks_per_caller,
            max_consults_per_task=cfg.limits.max_consults_per_task,
            card_signer=card_signer,
            context_signer=context_signer,
            context_verifier=context_verifier,
            card_verifier=reg["verifier"],
            require_signed=reg["require_signed"],
            tls=reg["tls"],
            policy=policy,
            push=push,
            audit=cfg.audit,
        )
    except ValueError as e:  # e.g. a trusted context kid that clashes with the signing kid
        raise ConfigError(str(e)) from None
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

    Existing partners: the config entry is authoritative for ``tier``, ``credential_ref``,
    ``tls_ref`` and ``tags``. A difference is applied to the record, logged as a WARNING
    naming the fields (never their values) and audited as ``partner.update`` (actor
    "config"). Existing URL partners are then refreshed (a changed card is quarantined, never
    overwritten); existing card_file partners keep their stored card.
    An unreachable or unsafe URL partner logs a warning and startup continues; its state is
    unchanged. Every record is finally checked against ``require_signed`` (quarantined if it
    breaks it). Changes made here are audited with actor "config".
    """
    config_dir = Path(config_dir).resolve()
    reg = host.partners
    with reg.acting_as("config"):
        reg.load()
        known = {r.id for r in reg.all()}
        for p in cfg.partners:
            if p.id in known:
                _apply_drift(reg, p)
                if p.url is not None:
                    try:
                        await reg.refresh(p.id)
                    except (CardFetchError, UnsafeURL) as e:
                        logger.warning("partner %s: refresh failed (%s); state unchanged", p.id, e)
                continue
            if p.url is not None:
                try:
                    await reg.add_from_url(
                        p.id,
                        p.url,
                        p.tier,
                        credential_ref=p.credential_ref,
                        tags=p.tags,
                        tls_ref=p.tls_ref,
                    )
                except (CardFetchError, UnsafeURL) as e:
                    logger.warning("partner %s: not registered (%s); continuing", p.id, e)
            else:
                assert p.card_file is not None
                card = _read_card(config_dir / p.card_file)
                await reg.add_from_card(
                    p.id,
                    card,
                    p.tier,
                    credential_ref=p.credential_ref,
                    tags=p.tags,
                    tls_ref=p.tls_ref,
                )
        reg.enforce_signed()


def _apply_drift(reg: PartnerRegistry, p: PartnerConfig) -> None:
    """Make an existing record match its config entry (I9); WARNING with field names only."""
    clear = [f for f in ("credential_ref", "tls_ref") if getattr(p, f) is None]
    fields = reg.update_settings(
        p.id,
        tier=p.tier,
        credential_ref=p.credential_ref,
        tls_ref=p.tls_ref,
        tags=p.tags,
        clear=clear,
    )
    if fields:
        logger.warning(
            "partner %s: config differs from the registry in %s; the config entry is applied",
            p.id,
            ", ".join(fields),
        )


__all__ = [
    "ConfigError",
    "GatewayConfig",
    "build_host",
    "card_verifier",
    "config_file",
    "credentials_provider",
    "interpolate",
    "load_config",
    "partner_registry",
    "partners_path",
    "register_partners",
    "registry_options",
    "server_run_kwargs",
    "tls_configs",
]
