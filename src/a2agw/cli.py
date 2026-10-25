"""``a2agw`` command line: scaffold, serve, manage partners, validate cards, call agents."""

from __future__ import annotations

import asyncio
import functools
import json
import unicodedata
from collections.abc import Callable
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
    build_host,
    load_config,
    partners_path,
    register_partners,
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

KNOWN_ERRORS = (ConfigError, CardFetchError, UnsafeURL, KeyError, ValueError, OSError)
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


@app.command()
@guarded
def init(
    directory: Annotated[Path, typer.Argument(help="Directory to scaffold into.")],
    force: Annotated[bool, typer.Option("--force", help="Overwrite existing files.")] = False,
) -> None:
    """Scaffold a gateway project (a2agw.yaml, agent.py, .env.example)."""
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
    directory.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (directory / name).write_text(content)
        typer.echo(f"wrote {directory / name}")


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
    """Run the gateway (HTTPS with --ssl-certfile; identity still comes from API key or JWT)."""
    for flag, f in (
        ("--ssl-certfile", ssl_certfile),
        ("--ssl-keyfile", ssl_keyfile),
        ("--ssl-ca-certs", ssl_ca_certs),
    ):
        if f is not None and not Path(f).is_file():
            raise ConfigError(f"{flag}: file {f} not found")
    cfg = load_config(config)
    config_dir = config.resolve().parent
    gw = build_host(cfg, config_dir=config_dir)
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
    if partners_file is None:
        if not config.exists():
            raise ConfigError(f"config file {config} not found (use -c or --partners-file)")
        cfg = load_config(config)
        partners_file = partners_path(cfg, config.resolve().parent)
    reg = PartnerRegistry(partners_file)
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
    config: ConfigOpt = Path("a2agw.yaml"),
    partners_file: PartnersFileOpt = None,
) -> None:
    """Fetch a partner's Agent Card and register it."""
    t = _tier(tier)
    reg = _registry(config, partners_file)
    rec = asyncio.run(reg.add_from_url(id, url, t, credential_ref=credential_ref, tags=tag or ()))
    typer.echo(f"added {rec.id} ({rec.tier}) hash {rec.card_hash[:12]}")


@partners_app.command("list")
@guarded
def partners_list(
    config: ConfigOpt = Path("a2agw.yaml"), partners_file: PartnersFileOpt = None
) -> None:
    """List partners."""
    reg = _registry(config, partners_file)
    rows = [("ID", "TIER", "STATUS", "HASH", "PENDING")]
    for r in reg.all():
        rows.append((r.id, r.tier, r.status, r.card_hash[:12], "pending" if r.pending_card else ""))
    widths = [max(len(row[i]) for row in rows) for i in range(5)]
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
async def _with_audit(config: Path, fn: Callable[[AuditLog], Any]) -> Any:
    """Open the configured database read only (no table creation, no pragmas) and run fn."""
    from sqlalchemy import inspect as sa_inspect
    from sqlalchemy.engine import make_url
    from sqlalchemy.ext.asyncio import create_async_engine

    cfg = load_config(config)
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

    asyncio.run(_with_audit(config, export))


@audit_app.command("verify")
@guarded
def audit_verify(config: ConfigOpt = Path("a2agw.yaml")) -> None:
    """Check the audit hash chain; exit 1 and name the first bad seq if it is broken."""
    bad = asyncio.run(_with_audit(config, lambda log: log.verify_chain()))
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

    try:
        result = asyncio.run(_reap(config, agent, yes, force))
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


async def _reap(config: Path, agent: str, confirm: bool, force: bool) -> Any:
    """Open the database, index, handles and registry directly: no host, no agent adapters
    are started, and no recovery runs."""
    from a2agw.config import _load_agent
    from a2agw.consult.client import PartnerClient
    from a2agw.consult.credentials import EnvCredentials
    from a2agw.consult.handles import OutboundHandleStore
    from a2agw.consult.registry import PartnerRegistry
    from a2agw.ops.bus import EventBus
    from a2agw.serve.reap import make_cancel_outbound, reap_agent
    from a2agw.serve.store import TaskIndex, create_engine

    cfg = load_config(config)
    config_dir = config.resolve().parent
    # Only the specs are imported (their ids tell which agents this config serves).
    served = {_load_agent(ref.spec, config_dir).id for ref in cfg.agents}
    registry = PartnerRegistry(partners_path(cfg, config_dir))
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
            credentials=EnvCredentials({k: (v.header, v.env) for k, v in cfg.credentials.items()}),
            handles=handles,
            bus=EventBus(),
            agent_id="host",
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
