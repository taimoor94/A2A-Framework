"""``a2agw control``: scaffold, serve and bootstrap the control plane.

Importing this module does not import FastAPI (only ``serve`` does, when it runs), so the
gateway CLI can mount it cheaply. API keys and gateway tokens are printed once, by the command
that creates them; only their digests are stored.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any, TypeVar, cast

import typer

from a2agw.control.settings import ROLES, ControlSettings, load_control_settings

F = TypeVar("F", bound=Callable[..., Any])

control_app = typer.Typer(
    help="The control plane: a service gateways connect to (needs a2a-gateway[control]).",
    no_args_is_help=True,
)
ControlConfigOpt = Annotated[
    Path, typer.Option("-c", "--config", help="Control-plane config file.")
]

CONTROL_TEMPLATE = """\
# a2agw control plane configuration. ${VAR} and ${VAR:-default} read the environment.
# Secrets never go in this file: name an environment variable in a *_env key instead.

# The public URL of the control plane (what browsers and gateways use to reach it).
base_url: ${A2AGW_CONTROL_BASE_URL:-http://localhost:8100}

# SQLite for a single replica; PostgreSQL (a2a-gateway[postgres]) for several:
#   db_url: postgresql+asyncpg://cp@db/cp   (put a password in ${VAR}, never inline)
db_url: sqlite+aiosqlite:///a2agw-control.db

# Sign-in for people, through your OpenID Connect provider (authorization code + PKCE).
# Automation uses API keys instead: a2agw control create-api-key --name N --role R
# oidc:
#   issuer: https://idp.example.com
#   client_id: a2agw-console
#   client_secret_env: A2AGW_CONTROL_OIDC_SECRET
#   scopes: [openid, profile, email]
#   roles_claim: groups          # the ID-token claim holding the user's groups
#   role_map:                    # IdP group -> viewer | operator | security | admin
#     platform-admins: admin
#     sec-team: security
#     sre: operator

# Console sessions (seconds). cookie_secure: false only for plain-http development.
session:
  absolute_s: 28800
  idle_s: 3600
  cookie_secure: true

# How long gateway events and finished commands are kept (days).
retention:
  events_days: 7
  commands_days: 7

# Limits on what gateways send.
limits:
  report_max_bytes: 1048576
  report_max_items: 1000
  stream_keepalive_s: 15

# Keys trusted for partner card signatures (the gateway's `trust` section).
# trust:
#   card_keys: {partner-kid: keys/partner.pub}
#   require_signed: [public]
"""


def _guarded(fn: F) -> F:
    """The gateway CLI's error mapping (one line, exit code 1), looked up at call time:
    ``a2agw.cli`` imports this module."""

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        from a2agw.cli import guarded

        return guarded(fn)(*args, **kwargs)

    return cast(F, wrapper)


def _cli_actor() -> str:
    from a2agw.cli import _cli_actor as actor

    return actor()


async def _with_store(settings: ControlSettings, work: Callable[[Any], Any]) -> Any:
    from a2agw.control.store import AUDIT_TABLE, ControlStore
    from a2agw.ops.audit import AuditLog
    from a2agw.serve.store import create_engine

    engine = await create_engine(settings.db_url)
    try:
        audit = AuditLog(engine, table_name=AUDIT_TABLE)
        store = ControlStore(engine, audit=audit)
        await store.initialize()
        await audit.initialize()
        result = await work(store)
        await audit.drain()
        return result
    finally:
        await engine.dispose()


def _run(settings: ControlSettings, work: Callable[[Any], Any]) -> Any:
    from a2agw.cli import _check_db, _db_run

    _db_run(settings.db_url, _check_db(settings.db_url))
    return _db_run(settings.db_url, _with_store(settings, work))


@control_app.command("init")
@_guarded
def init(
    directory: Annotated[Path, typer.Argument(help="Directory to write control.yaml into.")] = Path(
        "."
    ),
    force: Annotated[bool, typer.Option("--force", help="Overwrite control.yaml.")] = False,
) -> None:
    """Write a commented control.yaml."""
    path = directory / "control.yaml"
    if path.is_symlink():
        raise ValueError("refusing to write through symlink: control.yaml")
    if path.exists() and not force:
        raise ValueError("refusing to overwrite control.yaml (use --force)")
    directory.mkdir(parents=True, exist_ok=True)
    path.write_text(CONTROL_TEMPLATE)
    typer.echo(f"wrote {path}")


@control_app.command("serve")
@_guarded
def serve(
    config: ControlConfigOpt = Path("control.yaml"),
    host: Annotated[str, typer.Option("--host")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port")] = 8100,
) -> None:
    """Run the control plane. The database is checked before the server starts."""
    import uvicorn

    from a2agw.cli import _check_db, _db_run
    from a2agw.control.app import create_app

    settings = load_control_settings(config)
    _db_run(settings.db_url, _check_db(settings.db_url))
    uvicorn.run(create_app(settings), host=host, port=port)


@control_app.command("create-api-key")
@_guarded
def create_api_key(
    name: Annotated[str, typer.Option("--name", help="What the key is for.")],
    role: Annotated[str, typer.Option("--role", help=f"One of {', '.join(ROLES)}.")],
    config: ControlConfigOpt = Path("control.yaml"),
) -> None:
    """Create an API key; it is printed once (only its digest is stored)."""
    settings = load_control_settings(config)
    actor = _cli_actor()
    key_id, key = _run(settings, lambda s: s.create_api_key(name, role, actor=actor))
    typer.echo(f"API key id: {key_id} (role {role})")
    typer.echo(f"API key: {key}")
    typer.echo(
        "WARNING: this key is shown only once and is not stored (only its sha256 digest is). "
        "Send it as `Authorization: Bearer <key>`."
    )


@control_app.command("create-gateway")
@_guarded
def create_gateway(
    name: Annotated[str, typer.Option("--name", help="A unique name for the gateway.")],
    config: ControlConfigOpt = Path("control.yaml"),
) -> None:
    """Register a gateway; its id and token are printed once (only the digest is stored)."""
    settings = load_control_settings(config)
    actor = _cli_actor()
    gateway_id, token = _run(settings, lambda s: s.create_gateway(name, actor=actor))
    typer.echo(f"gateway id: {gateway_id}")
    typer.echo(f"gateway token: {token}")
    typer.echo(
        "WARNING: this token is shown only once and is not stored (only its sha256 digest "
        "is). Give it to the gateway through an environment variable."
    )
