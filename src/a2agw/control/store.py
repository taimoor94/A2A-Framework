"""Control-plane storage: every ``cp_*`` table (SQLAlchemy Core) and the operations on them.

All ids are ``String(64)`` and all timestamps ``Float`` epoch seconds. Secrets are never
stored: gateway tokens, API keys, session ids and CSRF tokens are kept as their SHA-256
digest (``token_digest``), and the token itself is returned once, by the call that creates it.

Schema: ``initialize`` runs ``create_all(checkfirst=True)`` through ``retry_ddl``, so several
replicas (or a replica and the CLI) can start against one empty database. Columns added in
later releases will need an ``_ADDED_COLUMNS`` step like ``OutboundHandleStore``'s.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from collections.abc import Callable
from typing import Any

from sqlalchemy import (
    Boolean,
    Column,
    Float,
    Integer,
    MetaData,
    PrimaryKeyConstraint,
    String,
    Table,
    Text,
    delete,
    select,
    update,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine

from a2agw._ddl import retry_ddl
from a2agw.control.settings import ROLES
from a2agw.ops.audit import AuditEvent, AuditLog

ID = 64  # every id column
AUDIT_TABLE = "cp_audit"  # the control plane's own audit chain
NAME = 256
DAY_S = 86400.0

_metadata = MetaData()


def _id(name: str, **kw: Any) -> Column[Any]:
    return Column(name, String(ID), **kw)


GATEWAYS = Table(
    "cp_gateways",
    _metadata,
    _id("id", primary_key=True),
    Column("name", String(NAME), nullable=False, unique=True),
    Column("created_at", Float, nullable=False),
    Column("created_by", String(NAME), nullable=False),
    Column("last_seen_at", Float, nullable=True),
    Column("last_version_applied", Integer, nullable=False, default=0, server_default="0"),
    Column("status", String(16), nullable=False, default="active"),  # active | revoked
    Column("info_json", Text, nullable=False, default="{}"),
)
GATEWAY_TOKENS = Table(
    "cp_gateway_tokens",
    _metadata,
    _id("digest", primary_key=True),
    _id("gateway_id", nullable=False, index=True),
    Column("created_at", Float, nullable=False),
    Column("revoked_at", Float, nullable=True),
)
USERS = Table(
    "cp_users",
    _metadata,
    _id("id", primary_key=True),  # "oidc:<sub>"
    Column("email", String(NAME), nullable=True),
    Column("name", String(NAME), nullable=True),
    Column("roles_json", Text, nullable=False, default="[]"),
    Column("created_at", Float, nullable=False),
    Column("last_login_at", Float, nullable=True),
    Column("disabled", Boolean, nullable=False, default=False),
)
SESSIONS = Table(
    "cp_sessions",
    _metadata,
    _id("digest", primary_key=True),
    _id("user_id", nullable=False, index=True),
    _id("csrf_digest", nullable=False),
    Column("created_at", Float, nullable=False),
    Column("last_used_at", Float, nullable=False),
    Column("expires_at", Float, nullable=False),
)
# A sign-in in progress (10 minutes); deleted at the callback.
LOGIN_STATES = Table(
    "cp_login_states",
    _metadata,
    _id("state_digest", primary_key=True),
    Column("nonce", String(NAME), nullable=False),
    Column("code_verifier", String(NAME), nullable=False),
    Column("next_path", Text, nullable=False, default="/"),
    Column("expires_at", Float, nullable=False),
)
API_KEYS = Table(
    "cp_api_keys",
    _metadata,
    _id("digest", primary_key=True),
    _id("id", nullable=False, unique=True),
    Column("name", String(NAME), nullable=False),
    Column("role", String(16), nullable=False),
    Column("created_by", String(NAME), nullable=False),
    Column("created_at", Float, nullable=False),
    Column("revoked_at", Float, nullable=True),
    Column("last_used_at", Float, nullable=True),
)
PARTNERS = Table(
    "cp_partners",
    _metadata,
    _id("id", primary_key=True),
    Column("card_url", Text, nullable=True),
    Column("tier", String(16), nullable=False),
    _id("credential_ref", nullable=True),
    _id("tls_ref", nullable=True),
    Column("tags_json", Text, nullable=False, default="[]"),
    # pending | approved | quarantined | rejected
    Column("status", String(16), nullable=False, default="pending"),
    Column("current_version", Integer, nullable=False, default=0),
    Column("created_at", Float, nullable=False),
    Column("updated_at", Float, nullable=False),
)
PARTNER_VERSIONS = Table(
    "cp_partner_versions",
    _metadata,
    _id("partner_id", nullable=False),
    Column("version", Integer, nullable=False),
    Column("card_json", Text, nullable=False),
    _id("card_hash", nullable=False),
    _id("signed_key_id", nullable=True),
    Column("fetched_at", Float, nullable=False),
    Column("approved_by", String(NAME), nullable=True),
    Column("approved_at", Float, nullable=True),
    PrimaryKeyConstraint("partner_id", "version"),
)
POLICIES = Table(
    "cp_policies",
    _metadata,
    _id("id", primary_key=True),
    Column("name", String(NAME), nullable=False, unique=True),
    Column("created_at", Float, nullable=False),
)
POLICY_VERSIONS = Table(
    "cp_policy_versions",
    _metadata,
    _id("policy_id", nullable=False),
    Column("version", Integer, nullable=False),
    Column("doc_json", Text, nullable=False),
    _id("doc_hash", nullable=False),
    Column("created_by", String(NAME), nullable=False),
    Column("created_at", Float, nullable=False),
    Column("comment", Text, nullable=False, default=""),
    PrimaryKeyConstraint("policy_id", "version"),
)
ASSIGNMENTS = Table(
    "cp_assignments",
    _metadata,
    _id("gateway_id", nullable=False),
    Column("kind", String(16), nullable=False),  # partner | policy
    _id("ref_id", nullable=False),
    Column("ref_version", Integer, nullable=True),  # null: follow the current version
    PrimaryKeyConstraint("gateway_id", "kind", "ref_id"),
)
DESIRED = Table(
    "cp_desired",
    _metadata,
    _id("gateway_id", primary_key=True),
    Column("version", Integer, nullable=False),
    Column("doc_json", Text, nullable=False),
    _id("doc_hash", nullable=False),
    Column("computed_at", Float, nullable=False),
)
COMMAND_STATUSES = ("pending", "delivered", "done", "failed", "expired")
COMMANDS = Table(
    "cp_commands",
    _metadata,
    _id("id", primary_key=True),
    _id("gateway_id", nullable=False, index=True),
    Column("kind", String(64), nullable=False),
    Column("args_json", Text, nullable=False, default="{}"),
    Column("status", String(16), nullable=False, default="pending"),
    Column("result_json", Text, nullable=True),
    Column("actor", String(NAME), nullable=False),
    Column("created_at", Float, nullable=False),
    Column("delivered_at", Float, nullable=True),
    Column("finished_at", Float, nullable=True),
    Column("expires_at", Float, nullable=False),
)
EVENTS = Table(
    "cp_events",
    _metadata,
    Column("seq", Integer, primary_key=True, autoincrement=True),
    _id("gateway_id", nullable=False, index=True),
    Column("ts", Float, nullable=False, index=True),
    Column("kind", String(64), nullable=False, index=True),
    Column("agent_id", String(NAME), nullable=True, index=True),
    Column("partner_id", String(NAME), nullable=True),
    Column("task_id", String(NAME), nullable=True, index=True),
    _id("trace_id", nullable=True, index=True),
    Column("data_json", Text, nullable=False, default="{}"),
    sqlite_autoincrement=True,
)
# Copies of each gateway's own audit rows (its seq, the row as JSON).
GATEWAY_AUDIT = Table(
    "cp_gateway_audit",
    _metadata,
    _id("gateway_id", nullable=False),
    Column("seq", Integer, nullable=False),
    Column("row_json", Text, nullable=False),
    Column("ts", Float, nullable=False, index=True),
    PrimaryKeyConstraint("gateway_id", "seq"),
)
HEALTH = Table(
    "cp_health",
    _metadata,
    _id("gateway_id", primary_key=True),
    Column("ts", Float, nullable=False),
    Column("health_json", Text, nullable=False, default="{}"),
    Column("metrics_json", Text, nullable=False, default="{}"),
)
TABLES = tuple(_metadata.sorted_tables)


def token_digest(token: str) -> str:
    """The stored form of a token, key or session id: its SHA-256 as hex."""
    return hashlib.sha256(token.encode()).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


class ControlStore:
    """The control plane's tables. ``audit`` (the ``cp_audit`` chain) records the writes made
    here; ``clock`` gives epoch seconds (tests pass a fake one)."""

    def __init__(
        self,
        engine: AsyncEngine,
        *,
        audit: AuditLog | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.engine = engine
        self.audit = audit
        self._clock = clock

    async def initialize(self) -> None:
        async def create() -> None:
            async with self.engine.begin() as conn:
                await conn.run_sync(_metadata.create_all, checkfirst=True)

        await retry_ddl(create)

    async def _audit(self, ev: AuditEvent) -> None:
        if self.audit is not None:
            await self.audit.emit(ev)

    # -- gateways ------------------------------------------------------------------------

    async def create_gateway(self, name: str, *, actor: str) -> tuple[str, str]:
        """Register a gateway; returns ``(gateway id, token)``. The token is shown only here
        (its digest is stored). ``ValueError`` if the name is taken."""
        name = name.strip()
        if not name or len(name) > NAME:
            raise ValueError(f"gateway name must be 1 to {NAME} characters")
        gateway_id = f"gw-{secrets.token_hex(8)}"
        token = new_token()
        now = self._clock()
        try:
            async with self.engine.begin() as conn:
                taken = await conn.execute(select(GATEWAYS.c.id).where(GATEWAYS.c.name == name))
                if taken.first() is not None:
                    raise ValueError("a gateway with this name already exists")
                await conn.execute(
                    GATEWAYS.insert().values(
                        id=gateway_id,
                        name=name,
                        created_at=now,
                        created_by=actor,
                        last_version_applied=0,
                        status="active",
                        info_json="{}",
                    )
                )
                await conn.execute(
                    GATEWAY_TOKENS.insert().values(
                        digest=token_digest(token), gateway_id=gateway_id, created_at=now
                    )
                )
        except IntegrityError:  # a concurrent create with the same name won
            raise ValueError("a gateway with this name already exists") from None
        await self._audit(
            AuditEvent(
                actor=actor,
                action="cp.gateway.create",
                outcome="active",
                detail={"gateway": gateway_id},
                ts=now,
            )
        )
        return gateway_id, token

    async def rotate_gateway_token(self, gateway_id: str, *, actor: str) -> str:
        """A new token for ``gateway_id``; every earlier token is revoked. ``KeyError`` for
        an unknown gateway, ``ValueError`` for a revoked one."""
        token = new_token()
        now = self._clock()
        async with self.engine.begin() as conn:
            status = (
                await conn.execute(select(GATEWAYS.c.status).where(GATEWAYS.c.id == gateway_id))
            ).scalar_one_or_none()
            if status is None:
                raise KeyError(f"unknown gateway {gateway_id}")
            if status != "active":
                raise ValueError("gateway is revoked")
            await conn.execute(
                update(GATEWAY_TOKENS)
                .where(GATEWAY_TOKENS.c.gateway_id == gateway_id)
                .where(GATEWAY_TOKENS.c.revoked_at.is_(None))
                .values(revoked_at=now)
            )
            await conn.execute(
                GATEWAY_TOKENS.insert().values(
                    digest=token_digest(token), gateway_id=gateway_id, created_at=now
                )
            )
        await self._audit(
            AuditEvent(
                actor=actor,
                action="cp.gateway.create",
                outcome="active",
                detail={"gateway": gateway_id, "reason": "rotate"},
                ts=now,
            )
        )
        return token

    # -- API keys ------------------------------------------------------------------------

    async def create_api_key(self, name: str, role: str, *, actor: str) -> tuple[str, str]:
        """A new API key with ``role``; returns ``(key id, key)``. The key is shown only here
        (its digest is stored)."""
        if role not in ROLES:
            raise ValueError(f"role must be one of {', '.join(ROLES)}")
        name = name.strip()
        if not name or len(name) > NAME:
            raise ValueError(f"API key name must be 1 to {NAME} characters")
        key_id = f"ak-{secrets.token_hex(8)}"
        key = new_token()
        now = self._clock()
        async with self.engine.begin() as conn:
            await conn.execute(
                API_KEYS.insert().values(
                    digest=token_digest(key),
                    id=key_id,
                    name=name,
                    role=role,
                    created_by=actor,
                    created_at=now,
                )
            )
        await self._audit(
            AuditEvent(
                actor=actor,
                action="cp.apikey.create",
                outcome="created",
                detail={"key_id": key_id, "role": role},
                ts=now,
            )
        )
        return key_id, key

    # -- maintenance ---------------------------------------------------------------------

    async def expire_commands(self, *, now: float) -> int:
        """Pending or delivered commands past ``expires_at`` become ``expired`` (never
        delivered later). Returns how many."""
        async with self.engine.begin() as conn:
            result = await conn.execute(
                update(COMMANDS)
                .where(COMMANDS.c.status.in_(("pending", "delivered")))
                .where(COMMANDS.c.expires_at <= now)
                .values(status="expired", finished_at=now)
            )
        return int(result.rowcount or 0)

    async def purge(
        self, *, now: float, events_days: float, commands_days: float
    ) -> dict[str, int]:
        """Delete events older than ``events_days`` and finished commands (done, failed,
        expired) created more than ``commands_days`` ago."""
        async with self.engine.begin() as conn:
            events = await conn.execute(
                delete(EVENTS).where(EVENTS.c.ts < now - events_days * DAY_S)
            )
            commands = await conn.execute(
                delete(COMMANDS)
                .where(COMMANDS.c.status.in_(("done", "failed", "expired")))
                .where(COMMANDS.c.created_at < now - commands_days * DAY_S)
            )
        return {"events": int(events.rowcount or 0), "commands": int(commands.rowcount or 0)}
