"""``a2agw`` command line: scaffold, serve, manage partners, validate cards, call agents."""

from __future__ import annotations

import asyncio
import functools
import json
import os
import unicodedata
from collections.abc import Callable, Coroutine
from pathlib import Path
from typing import Annotated, Any, Literal, TypeVar, cast

import httpx
import typer
import yaml
from a2a.client import ClientCallContext, ClientConfig, ClientFactory
from a2a.client.card_resolver import parse_agent_card
from a2a.helpers import new_text_message
from a2a.types import Role, SendMessageRequest, TaskState

from a2agw.config import (
    ConfigError,
    GatewayConfig,
    build_host,
    config_file,
    credentials_provider,
    load_config,
    partners_path,
    register_partners,
    registry_options,
)
from a2agw.consult.guarded_net import fixed_tier, guarded_async_client
from a2agw.consult.netguard import UnsafeURL, check_url
from a2agw.consult.registry import MAX_CARD_BYTES, CardFetchError, PartnerRegistry
from a2agw.ops.audit import ACTIONS, AuditLog, parse_since
from a2agw.serve.host import GRACEFUL_TIMEOUT_S

app = typer.Typer(help="A2A gateway: serve agents and manage partner agents.", no_args_is_help=True)
partners_app = typer.Typer(help="Manage the partner registry.", no_args_is_help=True)
card_app = typer.Typer(help="Agent Card tools.", no_args_is_help=True)
audit_app = typer.Typer(help="Export and verify the audit log (read only).", no_args_is_help=True)
app.add_typer(partners_app, name="partners")
app.add_typer(card_app, name="card")
tasks_app = typer.Typer(help="Maintenance of stored tasks.", no_args_is_help=True)
app.add_typer(audit_app, name="audit")
app.add_typer(tasks_app, name="tasks")


class DatabaseError(Exception):
    """A database could not be used; the message never contains credentials."""


KNOWN_ERRORS = (
    ConfigError,
    CardFetchError,
    UnsafeURL,
    DatabaseError,
    KeyError,
    ValueError,
    OSError,
)
OUTPUT_CAP = 64 * 1024
Tier = Literal["internal", "partner", "public"]
TIERS = ("internal", "partner", "public")

F = TypeVar("F", bound=Callable[..., Any])
_debug = False

ConfigOpt = Annotated[Path, typer.Option("-c", "--config", help="Gateway config file.")]
PartnersFileOpt = Annotated[
    Path | None, typer.Option("--partners-file", help="Partners file (overrides config).")
]


@app.callback()
def _main(debug: Annotated[bool, typer.Option("--debug", help="Show tracebacks.")] = False) -> None:
    global _debug
    _debug = debug


def guarded(fn: F) -> F:
    """Map known errors to a one-line message and exit code 1 (traceback only with --debug)."""

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except KNOWN_ERRORS as e:
            if _debug:
                raise
            msg = e.args[0] if isinstance(e, KeyError) and e.args else str(e)
            typer.echo(f"error: {msg}", err=True)
            raise typer.Exit(1) from None

    return cast(F, wrapper)


def redact_db_url(url: str) -> str:
    """``url`` without its userinfo (shown as ``***@``) and query; "<invalid>" if unparsable."""
    from sqlalchemy.engine import make_url
    from sqlalchemy.exc import ArgumentError

    try:
        parsed = make_url(url)
    except ArgumentError:
        return "<invalid>"
    userinfo = "***@" if parsed.username is not None or parsed.password is not None else ""
    host = parsed.host or ""
    port = f":{parsed.port}" if parsed.port is not None else ""
    database = f"/{parsed.database}" if parsed.database else ""
    return f"{parsed.drivername}://{userinfo}{host}{port}{database}"


_DB_DRIVERS = frozenset({"asyncpg", "aiosqlite", "psycopg", "psycopg2", "aiomysql", "asyncmy"})
# File-system errors are not database errors (a partners file, a key file, ...).
_FS_ERRORS = (FileNotFoundError, PermissionError, IsADirectoryError, NotADirectoryError)


def _is_db_error(e: BaseException) -> bool:
    """SQLAlchemy errors, driver errors, network errors reaching the server (refused,
    unresolvable host, timeout) and a missing driver module."""
    from sqlalchemy.exc import SQLAlchemyError

    if isinstance(e, SQLAlchemyError) or type(e).__module__.split(".")[0] in _DB_DRIVERS:
        return True
    if isinstance(e, ModuleNotFoundError):
        return (e.name or "").split(".")[0] in _DB_DRIVERS
    return isinstance(e, OSError) and not isinstance(e, _FS_ERRORS)


def _db_message(e: BaseException, url: str) -> str:
    from sqlalchemy.exc import ArgumentError, DBAPIError

    if isinstance(e, ArgumentError):  # unparsable URL or unknown dialect/driver
        return "invalid or unsupported database URL (db_url)"
    if isinstance(e, ModuleNotFoundError):
        return (
            f"database driver {e.name or ''} is not installed (PostgreSQL needs the "
            "postgres extra: a2a-gateway[postgres])"
        )
    cause = e.orig if isinstance(e, DBAPIError) and e.orig is not None else e
    return f"cannot use database {redact_db_url(url)}: {type(cause).__name__}"


def _db_run(db_url: str, coro: Coroutine[Any, Any, Any]) -> Any:
    """``asyncio.run(coro)`` with SQLAlchemy/driver errors (bad URL, connection refused, auth
    failed, ...) mapped to ``DatabaseError``: one line, credentials redacted."""
    try:
        return asyncio.run(coro)
    except Exception as e:
        if _is_db_error(e):
            raise DatabaseError(_db_message(e, db_url)) from None
        raise


async def _check_db(db_url: str) -> None:
    """Fail fast (before uvicorn starts) on a database the gateway could not open."""
    from sqlalchemy.engine import make_url
    from sqlalchemy.ext.asyncio import create_async_engine

    url = make_url(db_url)
    if url.get_backend_name() == "sqlite":
        db = url.database or ""
        if db not in ("", ":memory:") and not Path(db).parent.is_dir():
            raise ConfigError(f"db_url: directory of database {Path(db).name} does not exist")
        return
    engine = create_async_engine(db_url)
    try:
        async with engine.connect():
            pass
    finally:
        await engine.dispose()


def _tier(value: str) -> Tier:
    if value not in TIERS:
        raise ValueError(f"tier must be one of {', '.join(TIERS)}")
    return cast(Tier, value)


# -- init ------------------------------------------------------------------------------------
CONFIG_TEMPLATE = """\
base_url: ${A2AGW_BASE_URL:-http://localhost:8000}
db_url: sqlite+aiosqlite:///a2agw.db
admin_without_auth: true   # development only: remove and configure `auth` for real use

agents:
  - spec: agent:echo

# partners:
#   - id: acme
#     url: https://agents.acme.example
#     tier: partner
#     credential_ref: acme
# credentials:
#   acme:
#     header: Authorization
#     env: ACME_TOKEN
"""

AGENT_TEMPLATE = """\
from a2agw.adapters.callable import agent


@agent(id="echo", description="Echoes the user's message back.")
async def echo(ctx):
    return f"echo: {ctx.text}"
"""

ENV_TEMPLATE = """\
A2AGW_BASE_URL=http://localhost:8000
# ACME_TOKEN=
"""


SECURE_CONFIG_TEMPLATE = """\
base_url: ${{A2AGW_BASE_URL:-http://localhost:8000}}
db_url: ${{A2AGW_DB_URL:-sqlite+aiosqlite:///a2agw.db}}
audit: true                      # hash-chained audit log in the database
policy_file: policy.yaml         # authz, egress ceilings and routing

signing:                         # signs agent cards, push JWTs and call contexts
  key_file: keys/signing.pem     # mode 0600, git-ignored; never commit it
  kid: {kid}
  alg: EdDSA                     # publish keys/signing.pub.pem to your partners

auth:
  api_keys:
    "{key_hash}":   # sha256 of the key printed by `a2agw init --secure`
      principal_id: admin        # principal key:admin
      scopes: [a2agw:admin]

agents:
  - spec: agent:echo

# trust:                         # partner card signatures and signed call contexts
#   card_keys: {{acme-1: keys/acme.pub.pem}}
#   require_signed: [partner, public]
# partners:
#   - id: acme
#     url: https://agents.acme.example
#     tier: partner
#     credential_ref: acme
# oauth:
#   acme:
#     type: client_credentials
#     token_url: https://login.acme.example/oauth/token
#     client_id: my-gateway
#     client_secret_env: ACME_CLIENT_SECRET
"""

SECURE_POLICY_TEMPLATE = """\
version: 1
authz:
  # Only the admin key may call the agents. Add rules per principal (key:<id>, jwt:<sub>).
  - {id: admin, principal: "key:admin", agents: "*", skills: "*", effect: allow}
egress:
  tier_ceilings: {internal: restricted, partner: confidential, public: public}
"""

SECURE_ENV_TEMPLATE = """\
A2AGW_BASE_URL=http://localhost:8000
# A2AGW_DB_URL=postgresql+asyncpg://gw:${GW_DB_PASSWORD}@db.internal/gw
# ACME_CLIENT_SECRET=
"""

GITIGNORE_TEMPLATE = """\
keys/
.env
*.db
*.db-shm
*.db-wal
"""

SIGNING_KEY = "keys/signing.pem"
SIGNING_PUB = "keys/signing.pub.pem"


def _write_private(path: Path, data: bytes) -> None:
    """Create ``path`` with mode 0600 from the start (never world-readable, not even briefly)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    path.chmod(0o600)  # in case the umask stripped bits we did not ask to keep


def _secure_scaffold(directory: Path) -> tuple[dict[str, str], dict[str, bytes], str]:
    """(text files, key files, plaintext API key) for ``init --secure``."""
    import secrets

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from jwt import PyJWK
    from jwt.algorithms import OKPAlgorithm

    from a2agw.security.auth import hash_api_key
    from a2agw.security.cardsign import jwk_thumbprint

    key = ed25519.Ed25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    jwk = PyJWK(OKPAlgorithm.to_jwk(key.public_key(), as_dict=True), algorithm="EdDSA")
    kid = f"gw-{jwk_thumbprint(jwk)[:16]}"
    api_key = f"a2agw_{secrets.token_urlsafe(32)}"
    files = {
        "a2agw.yaml": SECURE_CONFIG_TEMPLATE.format(kid=kid, key_hash=hash_api_key(api_key)),
        "agent.py": AGENT_TEMPLATE,
        ".env.example": SECURE_ENV_TEMPLATE,
        ".gitignore": GITIGNORE_TEMPLATE,
        "policy.yaml": SECURE_POLICY_TEMPLATE,
    }
    return files, {SIGNING_KEY: private, SIGNING_PUB: public}, api_key


@app.command()
@guarded
def init(
    directory: Annotated[Path, typer.Argument(help="Directory to scaffold into.")],
    force: Annotated[bool, typer.Option("--force", help="Overwrite existing files.")] = False,
    secure: Annotated[
        bool,
        typer.Option(
            "--secure",
            help="Also scaffold signing keys (keys/, mode 0600), a policy, the audit log and "
            "API-key auth; prints the API key once.",
        ),
    ] = False,
) -> None:
    """Scaffold a gateway project (a2agw.yaml, agent.py, .env.example).

    With --secure: an Ed25519 signing key pair in keys/ (mode 0600, listed in the scaffolded
    .gitignore), policy.yaml, the audit log, and auth with one admin API key. Only the key's
    hash is written; the key itself is printed once. Existing key files are never
    overwritten, not even with --force."""
    keys: dict[str, bytes] = {}
    api_key = None
    if secure:
        files, keys, api_key = _secure_scaffold(directory)
    else:
        files = {
            "a2agw.yaml": CONFIG_TEMPLATE,
            "agent.py": AGENT_TEMPLATE,
            ".env.example": ENV_TEMPLATE,
        }
    existing = [n for n in files if (directory / n).exists() or (directory / n).is_symlink()]
    if existing and not force:
        raise ValueError(f"refusing to overwrite {', '.join(existing)} (use --force)")
    links = [n for n in files if (directory / n).is_symlink()]
    if links:
        raise ValueError(f"refusing to write through symlink: {', '.join(links)}")
    present = [n for n in keys if (directory / n).exists() or (directory / n).is_symlink()]
    if present:
        raise ValueError(f"refusing to overwrite key files: {', '.join(present)}")
    if keys and (directory / "keys").is_symlink():
        raise ValueError("refusing to write through symlink: keys")
    directory.mkdir(parents=True, exist_ok=True)
    if keys:
        (directory / "keys").mkdir(mode=0o700, exist_ok=True)
        (directory / "keys").chmod(0o700)
        for name, data in keys.items():
            _write_private(directory / name, data)
            typer.echo(f"wrote {directory / name} (mode 0600)")
    for name, content in files.items():
        (directory / name).write_text(content)
        typer.echo(f"wrote {directory / name}")
    if api_key is not None:
        typer.echo(f"\nAPI key: {api_key}")
        typer.echo(
            "WARNING: this API key is shown only once and is not stored anywhere (only its "
            "sha256 hash is in a2agw.yaml). Save it now in a secrets manager; send it as "
            "X-API-Key, or set A2AGW_API_KEY for `a2agw call`."
        )


# -- serve -----------------------------------------------------------------------------------
@app.command()
@guarded
def serve(
    config: ConfigOpt = Path("a2agw.yaml"),
    host: Annotated[str, typer.Option("--host")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port")] = 8000,
    ssl_certfile: Annotated[str | None, typer.Option("--ssl-certfile")] = None,
    ssl_keyfile: Annotated[str | None, typer.Option("--ssl-keyfile")] = None,
    ssl_ca_certs: Annotated[str | None, typer.Option("--ssl-ca-certs")] = None,
    require_client_cert: Annotated[
        bool, typer.Option("--require-client-cert", help="mTLS: demand a client certificate")
    ] = False,
    graceful_timeout: Annotated[
        float,
        typer.Option(
            "--graceful-timeout", min=0, help="Seconds to wait for open requests on shutdown."
        ),
    ] = GRACEFUL_TIMEOUT_S,
) -> None:
    """Run the gateway (HTTPS with --ssl-certfile or ``server_tls``; identity still comes
    from the API key or JWT).

    The ``--ssl-*`` flags override ``server_tls`` from the config. The database is checked
    before the server starts, so a bad ``db_url`` is a one-line error.

    Signals: SIGINT/SIGTERM end open event streams and stop the server gracefully. If the
    process had no Python-level handler for a signal before (a handler installed outside
    Python), the gateway's handler stays installed after the host stops, so a later SIGTERM
    in the same process is swallowed (SIGINT still raises KeyboardInterrupt)."""
    for flag, f in (
        ("--ssl-certfile", ssl_certfile),
        ("--ssl-keyfile", ssl_keyfile),
        ("--ssl-ca-certs", ssl_ca_certs),
    ):
        if f is not None and not Path(f).is_file():
            raise ConfigError(f"{flag}: file {f} not found")
    cfg = load_config(config)
    config_dir = config.resolve().parent
    tls = cfg.server_tls
    if tls is not None and ssl_certfile is None:
        ssl_certfile = str(config_file(config_dir, tls.cert_file, "server_tls.cert_file"))
        if ssl_keyfile is None:
            ssl_keyfile = str(config_file(config_dir, tls.key_file, "server_tls.key_file"))
    if tls is not None and ssl_ca_certs is None and tls.ca_file is not None:
        ssl_ca_certs = str(config_file(config_dir, tls.ca_file, "server_tls.ca_file"))
    require_client_cert = require_client_cert or (tls is not None and tls.require_client_cert)
    gw = build_host(cfg, config_dir=config_dir)
    _db_run(cfg.db_url, _check_db(cfg.db_url))
    asyncio.run(register_partners(gw, cfg, config_dir=config_dir))
    gw.run(
        host=host,
        port=port,
        ssl_certfile=ssl_certfile,
        ssl_keyfile=ssl_keyfile,
        ssl_ca_certs=ssl_ca_certs,
        require_client_cert=require_client_cert,
        graceful_timeout_s=graceful_timeout,
    )


# -- partners --------------------------------------------------------------------------------
def _registry(config: Path, partners_file: Path | None) -> PartnerRegistry:
    """The partner registry, with the config's card trust and mTLS settings (when the config
    file exists; ``--partners-file`` alone works without one)."""
    cfg = load_config(config) if config.exists() else None
    config_dir = config.resolve().parent
    if partners_file is None:
        if cfg is None:
            raise ConfigError(f"config file {config} not found (use -c or --partners-file)")
        partners_file = partners_path(cfg, config_dir)
    options = registry_options(cfg, config_dir) if cfg is not None else {}
    reg = PartnerRegistry(partners_file, **options)
    reg.load()
    return reg


@partners_app.command("add")
@guarded
def partners_add(
    id: str,
    url: str,
    tier: Annotated[str, typer.Option("--tier", help="internal | partner | public")],
    credential_ref: Annotated[str | None, typer.Option("--credential-ref")] = None,
    tag: Annotated[list[str] | None, typer.Option("--tag")] = None,
    tls_ref: Annotated[
        str | None, typer.Option("--tls-ref", help="mTLS client cert: a key of the config's tls")
    ] = None,
    config: ConfigOpt = Path("a2agw.yaml"),
    partners_file: PartnersFileOpt = None,
) -> None:
    """Fetch a partner's Agent Card and register it."""
    t = _tier(tier)
    reg = _registry(config, partners_file)
    if tls_ref is not None and tls_ref not in reg.tls:
        raise ConfigError(f"unknown tls_ref {tls_ref!r} (not in the config's tls section)")
    rec = asyncio.run(
        reg.add_from_url(id, url, t, credential_ref=credential_ref, tags=tag or (), tls_ref=tls_ref)
    )
    typer.echo(f"added {rec.id} ({rec.tier}) hash {rec.card_hash[:12]}")


@partners_app.command("list")
@guarded
def partners_list(
    config: ConfigOpt = Path("a2agw.yaml"), partners_file: PartnersFileOpt = None
) -> None:
    """List partners."""
    reg = _registry(config, partners_file)
    rows = [("ID", "TIER", "STATUS", "HASH", "PENDING", "PROTOCOL")]
    for r in reg.all():
        rows.append(
            (
                r.id,
                r.tier,
                r.status,
                r.card_hash[:12],
                "pending" if r.pending_card else "",
                "a2a-0.3" if r.v03_only else "",
            )
        )
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    for row in rows:
        typer.echo("  ".join(c.ljust(w) for c, w in zip(row, widths, strict=True)).rstrip())


@partners_app.command("verify")
@guarded
def partners_verify(
    id: Annotated[str | None, typer.Argument()] = None,
    config: ConfigOpt = Path("a2agw.yaml"),
    partners_file: PartnersFileOpt = None,
) -> None:
    """Refresh one partner (or all) and report unchanged or quarantined."""
    reg = _registry(config, partners_file)
    ids = [id] if id else [r.id for r in reg.all()]
    if id:
        reg.get(id)
    failed = False
    for pid in ids:
        try:
            typer.echo(f"{pid}: {asyncio.run(reg.refresh(pid))}")
        except (CardFetchError, UnsafeURL) as e:
            if id:
                raise
            failed = True
            typer.echo(f"{pid}: error: {e}", err=True)
    if failed:
        raise typer.Exit(1)


@partners_app.command("approve")
@guarded
def partners_approve(
    id: str,
    hash: Annotated[str | None, typer.Option("--hash", help="Expected card hash.")] = None,
    config: ConfigOpt = Path("a2agw.yaml"),
    partners_file: PartnersFileOpt = None,
) -> None:
    """Approve a quarantined card change."""
    reg = _registry(config, partners_file)
    rec = reg.approve(id, expected_hash=hash)
    typer.echo(f"approved {rec.id} hash {rec.card_hash[:12]}")


@partners_app.command("disable")
@guarded
def partners_disable(
    id: str, config: ConfigOpt = Path("a2agw.yaml"), partners_file: PartnersFileOpt = None
) -> None:
    """Disable a partner."""
    _registry(config, partners_file).disable(id)
    typer.echo(f"disabled {id}")


@partners_app.command("enable")
@guarded
def partners_enable(
    id: str, config: ConfigOpt = Path("a2agw.yaml"), partners_file: PartnersFileOpt = None
) -> None:
    """Re-enable a disabled partner."""
    _registry(config, partners_file).enable(id)
    typer.echo(f"enabled {id}")


# -- card validate / call ---------------------------------------------------------------------
def _describe(card: Any) -> str:
    skills = ", ".join(s.id for s in card.skills) or "-"
    ifaces = ", ".join(f"{i.protocol_binding} {i.url}" for i in card.supported_interfaces) or "-"
    return f"OK {card.name}\n  skills: {skills}\n  interfaces: {ifaces}"


@card_app.command("validate")
@guarded
def card_validate(
    target: Annotated[str, typer.Argument(metavar="URL|FILE")],
    tier: Annotated[str, typer.Option("--tier")] = "partner",
) -> None:
    """Validate an Agent Card from a URL or a file."""
    t = _tier(tier)
    if target.startswith(("http://", "https://")):
        rec = asyncio.run(PartnerRegistry().add_from_url("validate", target, t))
        card = rec.agent_card
    else:
        try:
            raw = Path(target).read_bytes()[: MAX_CARD_BYTES + 1]
            if len(raw) > MAX_CARD_BYTES:
                raise ValueError("agent card exceeds 1 MiB")
            data = yaml.safe_load(raw)
        except (OSError, yaml.YAMLError):
            raise ValueError(f"cannot read card file {target}") from None
        if not isinstance(data, dict):
            raise ValueError("agent card must be a JSON object")
        try:
            card = parse_agent_card(data)
        except Exception as e:  # noqa: BLE001
            raise ValueError(f"invalid agent card: {type(e).__name__}") from None
    typer.echo(_describe(card))


def _message_text(msg: Any) -> str:
    return "".join(p.text for p in msg.parts if p.WhichOneof("content") == "text")


def _result_text(task: Any) -> str:
    chunks = [_message_text(a) for a in task.artifacts]
    if task.status.HasField("message"):
        chunks.append(_message_text(task.status.message))
    return "\n".join(c for c in chunks if c)


def _origin(url: str) -> tuple[str, str, int]:
    u = httpx.URL(url)
    return u.scheme, u.host, u.port or (443 if u.scheme == "https" else 80)


async def _call(url: str, message: str, api_key: str | None, tier: Tier, timeout: float) -> str:
    await check_url(url, tier)
    rec = await PartnerRegistry().add_from_url("call", url, tier)
    params = {"A2A-Version": "1.0"}
    origin = _origin(url)
    endpoints = [i.url for i in rec.agent_card.supported_interfaces]
    cross = any(_origin(u) != origin for u in endpoints)
    if api_key and cross:
        raise ValueError("card endpoint origin differs from the URL; refusing to send the API key")
    if cross:
        typer.echo("warning: card endpoint origin differs from the URL", err=True)
    if api_key:
        params["X-API-Key"] = api_key
    state, text = "unknown", ""
    # Guarded: connects only to addresses vetted for `tier` at connect time.
    async with guarded_async_client(fixed_tier(tier), timeout=timeout) as hc:
        client = ClientFactory(ClientConfig(httpx_client=hc, streaming=False)).create(
            rec.agent_card
        )
        req = SendMessageRequest(message=new_text_message(message, role=Role.ROLE_USER))
        ctx = ClientCallContext(timeout=timeout, service_parameters=params)
        try:
            async for resp in client.send_message(req, context=ctx):
                kind = resp.WhichOneof("payload")
                if kind == "task":
                    state = TaskState.Name(resp.task.status.state)
                    text = _result_text(resp.task)
                elif kind == "message":
                    state, text = "MESSAGE", _message_text(resp.message)
        except httpx.HTTPError as e:
            raise ValueError(f"call failed: {type(e).__name__}") from None
        except Exception as e:  # noqa: BLE001 - SDK errors may carry request details
            raise ValueError(f"call failed: {type(e).__name__}") from None
    text = text.encode()[:OUTPUT_CAP].decode(errors="ignore")
    text = "".join(c for c in text if c in "\n\t" or unicodedata.category(c) != "Cc")
    return f"state: {state}\n{text}"


@app.command()
@guarded
def call(
    url: str,
    message: str,
    api_key: Annotated[
        str | None,
        typer.Option(
            "--api-key",
            envvar="A2AGW_API_KEY",
            show_envvar=True,
            help="API key to send; prefer the A2AGW_API_KEY env var (keeps it out of ps "
            "and shell history).",
        ),
    ] = None,
    tier: Annotated[str, typer.Option("--tier")] = "partner",
    timeout: Annotated[float, typer.Option("--timeout")] = 30.0,
) -> None:
    """Send one message to an A2A agent and print the final state and text."""
    typer.echo(asyncio.run(_call(url, message, api_key, _tier(tier), timeout)))


# -- audit -----------------------------------------------------------------------------------
def _with_audit(config: Path, fn: Callable[[AuditLog], Any]) -> Any:
    cfg = load_config(config)
    return _db_run(cfg.db_url, _audit_session(cfg, fn))


async def _audit_session(cfg: GatewayConfig, fn: Callable[[AuditLog], Any]) -> Any:
    """Open the configured database read only (no table creation, no pragmas) and run fn."""
    from sqlalchemy import inspect as sa_inspect
    from sqlalchemy.engine import make_url
    from sqlalchemy.ext.asyncio import create_async_engine

    url = make_url(cfg.db_url)
    if url.get_backend_name() == "sqlite":
        db = url.database or ""
        if db in ("", ":memory:") or not Path(db).is_file():
            raise ConfigError(f"database {db or ':memory:'} not found")
    engine = create_async_engine(cfg.db_url)
    try:
        async with engine.connect() as conn:
            exists = await conn.run_sync(lambda sync: sa_inspect(sync).has_table("a2agw_audit"))
        if not exists:
            raise ConfigError("no audit log in the configured database")
        return await fn(AuditLog(engine))
    finally:
        await engine.dispose()


@audit_app.command("export")
@guarded
def audit_export(
    config: ConfigOpt = Path("a2agw.yaml"),
    since: Annotated[str | None, typer.Option("--since", help="ISO 8601 timestamp.")] = None,
    action: Annotated[str | None, typer.Option("--action", help="Only this action.")] = None,
) -> None:
    """Write audit events as JSON lines (oldest first) to stdout."""
    filters: dict[str, Any] = {}
    if since is not None:
        try:
            filters["since"] = parse_since(since)
        except ValueError:
            raise ValueError("--since must be an ISO 8601 timestamp") from None
    if action is not None:
        if action not in ACTIONS:
            raise ValueError(f"--action must be one of {', '.join(sorted(ACTIONS))}")
        filters["action"] = action

    async def export(log: AuditLog) -> None:
        cursor: str | None = None
        while True:
            rows, cursor = await log.query(filters, 500, cursor, ascending=True)
            for row in rows:
                typer.echo(json.dumps(row, ensure_ascii=False, sort_keys=True))
            if cursor is None:
                return

    _with_audit(config, export)


@audit_app.command("verify")
@guarded
def audit_verify(config: ConfigOpt = Path("a2agw.yaml")) -> None:
    """Check the audit hash chain; exit 1 and name the first bad seq if it is broken."""
    bad = _with_audit(config, lambda log: log.verify_chain())
    if bad is not None:
        typer.echo(f"audit chain broken at seq {bad}", err=True)
        raise typer.Exit(1)
    typer.echo("audit chain ok")


# -- tasks -----------------------------------------------------------------------------------
@tasks_app.command("reap")
@guarded
def tasks_reap(
    agent: Annotated[str, typer.Option("--agent", help="Agent id nobody serves any more.")],
    config: ConfigOpt = Path("a2agw.yaml"),
    yes: Annotated[bool, typer.Option("--yes", help="Do it. Without it: a dry run.")] = False,
    force: Annotated[
        bool, typer.Option("--force", help="Also reap tasks changed in the last 10 minutes.")
    ] = False,
) -> None:
    """Fail the open tasks of an agent that no gateway serves, and cancel their partner tasks.

    Prints what would be reaped unless --yes is given. Refused for an agent the configured
    gateway serves and, without --force, for tasks changed within the last 10 minutes (a live
    gateway may own them). Every attempt is audited."""
    from a2agw.serve.reap import ReapRefused

    cfg = load_config(config)
    try:
        result = _db_run(cfg.db_url, _reap(cfg, config.resolve().parent, agent, yes, force))
    except ReapRefused as exc:
        raise ValueError(
            "refused: agent is served by this gateway"
            if exc.reason == "served"
            else f"refused: {exc.count} task(s) changed in the last 10 minutes; use --force"
        ) from None
    if result.dry_run:
        typer.echo(
            f"dry run: {result.tasks} open task(s), {result.handles} partner task(s) would be "
            f"cancelled, {result.recent} changed recently; re-run with --yes"
        )
        return
    report = result.report
    assert report is not None
    typer.echo(
        f"reaped {len(report.failed)} task(s); cancelled {report.outbound_cancelled} "
        f"partner task(s); {len(report.cancel_errors)} cancel error(s)"
    )


async def _reap(
    cfg: GatewayConfig, config_dir: Path, agent: str, confirm: bool, force: bool
) -> Any:
    """Open the database, index, handles and registry directly: no host, no agent adapters
    are started, and no recovery runs. Partner cancels use the configured credentials
    (static and OAuth) and mTLS settings."""
    from a2agw.config import _load_agent, partner_registry
    from a2agw.consult.client import PartnerClient
    from a2agw.consult.handles import OutboundHandleStore
    from a2agw.ops.bus import EventBus
    from a2agw.serve.reap import make_cancel_outbound, reap_agent
    from a2agw.serve.store import TaskIndex, create_engine

    # Only the specs are imported (their ids tell which agents this config serves).
    served = {_load_agent(ref.spec, config_dir).id for ref in cfg.agents}
    registry = partner_registry(cfg, config_dir)
    registry.load()
    engine = await create_engine(cfg.db_url)
    client = None
    try:
        index, handles = TaskIndex(engine), OutboundHandleStore(engine)
        await index.initialize()
        await handles.initialize()
        audit = AuditLog(engine)
        await audit.initialize()
        client = PartnerClient(
            registry,
            credentials=credentials_provider(cfg),
            handles=handles,
            bus=EventBus(),
            agent_id="host",
            tls=registry.tls,
        )
        return await reap_agent(
            index,
            handles,
            make_cancel_outbound(client),
            audit,
            agent,
            served=served,
            confirm=confirm,
            force=force,
            actor="system",
        )
    finally:
        if client is not None:
            await client.aclose()
        await engine.dispose()
