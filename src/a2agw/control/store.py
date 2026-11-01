"""Control-plane storage: every ``cp_*`` table (SQLAlchemy Core) and the operations on them.

All ids are ``String(64)`` and all timestamps ``Float`` epoch seconds. Secrets are never
stored: gateway tokens, API keys, session ids and CSRF tokens are kept as their SHA-256
digest (``token_digest``), and the token itself is returned once, by the call that creates it.

Schema: ``initialize`` runs ``create_all(checkfirst=True)`` through ``retry_ddl``, so several
replicas (or a replica and the CLI) can start against one empty database. Columns added in
later releases will need an ``_ADDED_COLUMNS`` step like ``OutboundHandleStore``'s.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    Float,
    Index,
    Integer,
    MetaData,
    PrimaryKeyConstraint,
    String,
    Table,
    Text,
    delete,
    func,
    select,
    update,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects import sqlite as sqlite_dialect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine

from a2agw._ddl import retry_ddl
from a2agw.control.settings import ROLES
from a2agw.ops.audit import AuditEvent, AuditLog

ID = 64  # every id column
AUDIT_TABLE = "cp_audit"  # the control plane's own audit chain
NAME = 256
DAY_S = 86400.0
BATCH = 1000  # rows per maintenance statement
LOGIN_STATE_TTL_S = 600.0  # a sign-in must finish within 10 minutes
TOUCH_EVERY_S = 60.0  # last_used_at of sessions and API keys moves at most this often

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
    # bumped by ``channel.mark_dirty``: the desired state is recomputed while it is ahead
    # of ``cp_desired.source_gen``
    Column("desired_gen", Integer, nullable=False, default=0, server_default="0"),
    # the store epoch of ``last_version_applied`` (see ``ControlStore.epoch``)
    _id("epoch_applied", nullable=True),
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
    Column("expires_at", Float, nullable=False, index=True),
)
# A sign-in in progress (10 minutes), bound to the browser that started it; deleted at the
# callback.
LOGIN_STATES = Table(
    "cp_login_states",
    _metadata,
    _id("state_digest", primary_key=True),
    Column("nonce", String(NAME), nullable=False),
    Column("code_verifier", String(NAME), nullable=False),
    Column("next_path", Text, nullable=False, default="/"),
    Column("expires_at", Float, nullable=False, index=True),
    # digest of the a2agw_login cookie set with it: the state is bound to that browser
    _id("browser_digest", nullable=False),
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
# What each gateway last reported about a partner (``partner.state`` events): its local
# status (active | quarantined | disabled) and, when it holds a pending card, that card's
# hash. Only the hash: the control plane never takes a card from a gateway.
PARTNER_STATES = Table(
    "cp_partner_states",
    _metadata,
    _id("gateway_id", nullable=False),
    _id("partner_id", nullable=False, index=True),
    Column("status", String(16), nullable=False),
    _id("pending_hash", nullable=True),
    Column("event", String(32), nullable=False),
    Column("ts", Float, nullable=False),
    PrimaryKeyConstraint("gateway_id", "partner_id"),
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
    # the cp_gateways.desired_gen this document was computed from
    Column("source_gen", Integer, nullable=False, default=0, server_default="0"),
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
    Index("ix_cp_commands_status_expires_at", "status", "expires_at"),
    # a stream's poll for its gateway's pending commands
    Index("ix_cp_commands_gateway_status_expires_at", "gateway_id", "status", "expires_at"),
)
EVENTS = Table(
    "cp_events",
    _metadata,
    # 64-bit on Postgres; INTEGER on sqlite, where only "INTEGER PRIMARY KEY" is AUTOINCREMENT
    Column(
        "seq", BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True
    ),
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
# Settings of the store itself; ``epoch`` is chosen once, when the schema is first created.
META = Table(
    "cp_meta",
    _metadata,
    Column("key", String(ID), primary_key=True),
    Column("value", Text, nullable=False),
)
EPOCH_KEY = "epoch"
TABLES = tuple(_metadata.sorted_tables)


def token_digest(token: str) -> str:
    """The stored form of a token, key or session id: its SHA-256 as hex."""
    return hashlib.sha256(token.encode()).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


def csrf_token_for(session_id: str) -> str:
    """The CSRF token of a session: an HMAC of a fixed label keyed with the session id.

    Only its digest is stored; it is derived again from the session cookie when ``/me``
    hands it to the page, so no plaintext copy is kept. Without the session id (an
    HttpOnly cookie) it cannot be computed."""
    mac = hmac.new(session_id.encode(), b"a2agw-csrf-v1", hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode()


@dataclass(frozen=True)
class LoginState:
    nonce_digest: str
    code_verifier: str
    next_path: str


@dataclass(frozen=True)
class User:
    id: str
    email: str | None
    name: str | None
    roles: tuple[str, ...]
    disabled: bool


@dataclass(frozen=True)
class Session:
    user_id: str
    csrf_digest: str
    email: str | None
    name: str | None
    roles: tuple[str, ...]


@dataclass(frozen=True)
class ApiKey:
    id: str
    name: str
    role: str


def _roles(raw: str | None) -> tuple[str, ...]:
    try:
        value = json.loads(raw or "[]")
    except ValueError:
        return ()
    return tuple(sorted({r for r in value if r in ROLES})) if isinstance(value, list) else ()


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
        self._epoch: str | None = None

    @property
    def epoch(self) -> str:
        """This database's epoch: 32 random hex characters chosen by the first
        ``initialize`` and never changed. Desired-state versions count within an epoch, so
        a gateway that applied a version of another epoch (the database was reset or
        replaced) is behind whatever its version number. ``RuntimeError`` before
        ``initialize``."""
        if self._epoch is None:
            raise RuntimeError("ControlStore.initialize() has not run")
        return self._epoch

    def now(self) -> float:
        """The store's clock (epoch seconds)."""
        return self._clock()

    async def initialize(self) -> None:
        async def create() -> None:
            async with self.engine.begin() as conn:
                await conn.run_sync(_metadata.create_all, checkfirst=True)

        await retry_ddl(create)
        self._epoch = await self._ensure_epoch()

    async def _ensure_epoch(self) -> str:
        """The stored epoch, created first if there is none (a concurrent initialize may
        win the insert: then its epoch is the one read back)."""
        insert = (
            sqlite_dialect.insert if self.engine.dialect.name == "sqlite" else postgresql.insert
        )
        async with self.engine.begin() as conn:
            await conn.execute(
                insert(META)
                .values(key=EPOCH_KEY, value=secrets.token_hex(16))
                .on_conflict_do_nothing()
            )
            value = (
                await conn.execute(select(META.c.value).where(META.c.key == EPOCH_KEY))
            ).scalar_one()
        return str(value)

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

    async def revoke_gateway(self, gateway_id: str, *, actor: str) -> bool:
        """Revoke a gateway: its status becomes ``revoked`` and every token stops working
        (an open stream closes at its next poll). Returns False when it was already
        revoked (nothing changes, nothing is audited); ``KeyError`` for an unknown
        gateway."""
        now = self._clock()
        async with self.engine.begin() as conn:
            changed = await conn.execute(
                update(GATEWAYS)
                .where(GATEWAYS.c.id == gateway_id)
                .where(GATEWAYS.c.status != "revoked")
                .values(status="revoked")
            )
            if not changed.rowcount:
                known = await conn.execute(select(GATEWAYS.c.id).where(GATEWAYS.c.id == gateway_id))
                if known.first() is None:
                    raise KeyError(f"unknown gateway {gateway_id}")
                return False
            await conn.execute(
                update(GATEWAY_TOKENS)
                .where(GATEWAY_TOKENS.c.gateway_id == gateway_id)
                .where(GATEWAY_TOKENS.c.revoked_at.is_(None))
                .values(revoked_at=now)
            )
        await self._audit(
            AuditEvent(
                actor=actor,
                action="cp.gateway.revoke",
                outcome="revoked",
                detail={"gateway": gateway_id},
                ts=now,
            )
        )
        return True

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

    async def revoke_api_key(self, key_id: str, *, actor: str) -> None:
        """Revoke an API key: it stops working at its next use. ``KeyError`` for an unknown
        key; revoking a revoked key changes nothing."""
        now = self._clock()
        async with self.engine.begin() as conn:
            result = await conn.execute(
                update(API_KEYS)
                .where(API_KEYS.c.id == key_id)
                .where(API_KEYS.c.revoked_at.is_(None))
                .values(revoked_at=now)
            )
            if not result.rowcount:
                known = await conn.execute(select(API_KEYS.c.id).where(API_KEYS.c.id == key_id))
                if known.first() is None:
                    raise KeyError(f"unknown API key {key_id}")
                return
        await self._audit(
            AuditEvent(
                actor=actor,
                action="cp.apikey.revoke",
                outcome="revoked",
                detail={"key_id": key_id},
                ts=now,
            )
        )

    async def get_api_key(self, key: str, *, now: float) -> ApiKey | None:
        """The live (not revoked) API key ``key``, or None. ``last_used_at`` is updated at
        most once per ``TOUCH_EVERY_S``."""
        digest = token_digest(key)
        async with self.engine.connect() as conn:
            row = (
                await conn.execute(
                    select(API_KEYS)
                    .where(API_KEYS.c.digest == digest)
                    .where(API_KEYS.c.revoked_at.is_(None))
                )
            ).first()
        if row is None:
            return None
        if row.last_used_at is None or now - row.last_used_at >= TOUCH_EVERY_S:
            async with self.engine.begin() as conn:
                await conn.execute(
                    update(API_KEYS).where(API_KEYS.c.digest == digest).values(last_used_at=now)
                )
        return ApiKey(id=row.id, name=row.name, role=row.role)

    # -- sign-in: login states, users, sessions -------------------------------------------

    async def create_login_state(
        self,
        *,
        state: str,
        nonce: str,
        code_verifier: str,
        next_path: str,
        now: float,
        browser: str,
        ttl_s: float = LOGIN_STATE_TTL_S,
    ) -> None:
        """A sign-in in progress, bound to ``browser`` (the value of the browser-binding
        cookie set with it). The state, nonce and binding are kept as digests; the PKCE
        verifier is kept as is (it is sent to the token endpoint), for ``ttl_s`` at most."""
        async with self.engine.begin() as conn:
            await conn.execute(
                LOGIN_STATES.insert().values(
                    state_digest=token_digest(state),
                    nonce=token_digest(nonce),
                    code_verifier=code_verifier,
                    next_path=next_path,
                    expires_at=now + ttl_s,
                    browser_digest=token_digest(browser),
                )
            )

    async def take_login_state(self, state: str, *, now: float, browser: str) -> LoginState | None:
        """The sign-in started with ``state``, deleted as it is read (single use); None when
        unknown, already taken (also by a concurrent callback) or expired.

        ``browser`` is the binding cookie the callback came with. It must match the one the
        sign-in was started with (compared as digests) before anything is consumed: from
        another browser (or without the cookie) this returns None and the state stays
        usable by the browser that started it, so a leaked state or callback link cannot be
        used to cancel someone else's sign-in."""
        digest = token_digest(state)
        async with self.engine.begin() as conn:
            row = (
                await conn.execute(
                    select(LOGIN_STATES).where(LOGIN_STATES.c.state_digest == digest)
                )
            ).first()
            if row is None:
                return None
            if not hmac.compare_digest(token_digest(browser), row.browser_digest):
                return None
            gone = await conn.execute(
                delete(LOGIN_STATES).where(LOGIN_STATES.c.state_digest == digest)
            )
            if gone.rowcount != 1:
                return None
        if row.expires_at <= now:
            return None
        return LoginState(
            nonce_digest=row.nonce, code_verifier=row.code_verifier, next_path=row.next_path
        )

    async def upsert_user(
        self,
        user_id: str,
        *,
        email: str | None,
        name: str | None,
        roles: Iterable[str],
        now: float,
    ) -> User:
        """Record a sign-in: the user's name, email and roles (re-derived at every login)
        replace the stored ones. A disabled user stays disabled."""
        role_list = sorted({r for r in roles if r in ROLES})
        email = email[:NAME] if email else None
        name = name[:NAME] if name else None
        values: dict[str, Any] = {
            "email": email,
            "name": name,
            "roles_json": json.dumps(role_list),
            "last_login_at": now,
        }
        for attempt in range(2):
            try:
                async with self.engine.begin() as conn:
                    row = (
                        await conn.execute(select(USERS.c.disabled).where(USERS.c.id == user_id))
                    ).first()
                    if row is None:
                        await conn.execute(
                            USERS.insert().values(
                                id=user_id, created_at=now, disabled=False, **values
                            )
                        )
                        disabled = False
                    else:
                        await conn.execute(
                            update(USERS).where(USERS.c.id == user_id).values(**values)
                        )
                        disabled = bool(row.disabled)
                break
            except IntegrityError:  # a concurrent first sign-in inserted the row
                if attempt:
                    raise
        return User(
            id=user_id,
            email=email,
            name=name,
            roles=tuple(role_list),
            disabled=disabled,
        )

    async def set_user_disabled(self, user_id: str, disabled: bool, *, actor: str) -> None:
        """Disable (or enable) a user. Disabling ends every session of the user at once.
        ``KeyError`` for an unknown user."""
        now = self._clock()
        async with self.engine.begin() as conn:
            result = await conn.execute(
                update(USERS).where(USERS.c.id == user_id).values(disabled=disabled)
            )
            if not result.rowcount:
                raise KeyError(f"unknown user {user_id}")
            if disabled:
                await conn.execute(delete(SESSIONS).where(SESSIONS.c.user_id == user_id))
        await self._audit(
            AuditEvent(
                actor=actor,
                action="cp.user.update",
                outcome="disabled" if disabled else "enabled",
                detail={"user": user_id},
                ts=now,
            )
        )

    async def create_session(
        self,
        user_id: str,
        *,
        now: float,
        absolute_s: float,
        idle_s: float,
        replace: str | None = None,
    ) -> tuple[str, str]:
        """A new session for ``user_id``; returns ``(session id, CSRF token)``, both shown
        only here (digests are stored). ``replace`` is the session id the browser still
        had, deleted in the same transaction (a fresh id at every login)."""
        session_id = new_token()
        csrf = csrf_token_for(session_id)
        async with self.engine.begin() as conn:
            if replace:
                await conn.execute(
                    delete(SESSIONS).where(SESSIONS.c.digest == token_digest(replace))
                )
            await conn.execute(
                SESSIONS.insert().values(
                    digest=token_digest(session_id),
                    user_id=user_id,
                    csrf_digest=token_digest(csrf),
                    created_at=now,
                    last_used_at=now,
                    expires_at=now + min(absolute_s, idle_s),
                )
            )
        return session_id, csrf

    async def get_session(
        self, session_id: str, *, now: float, absolute_s: float, idle_s: float
    ) -> Session | None:
        """The live session ``session_id`` with its user, or None.

        ``expires_at`` is the earlier of the absolute limit (``created_at + absolute_s``)
        and the idle limit (``last_used_at + idle_s``). A use moves ``last_used_at`` (and so
        the idle limit) at most once per ``TOUCH_EVERY_S``, so the idle limit can come up to
        that much early. An expired session, or one of a disabled or deleted user, is
        deleted when seen."""
        digest = token_digest(session_id)
        query = (
            select(SESSIONS, USERS.c.email, USERS.c.name, USERS.c.roles_json, USERS.c.disabled)
            .select_from(SESSIONS.outerjoin(USERS, SESSIONS.c.user_id == USERS.c.id))
            .where(SESSIONS.c.digest == digest)
        )
        async with self.engine.connect() as conn:
            row = (await conn.execute(query)).first()
        if row is None:
            return None
        if row.expires_at <= now or row.disabled is None or row.disabled:
            await self.delete_session(session_id)
            return None
        if now - row.last_used_at >= TOUCH_EVERY_S:
            async with self.engine.begin() as conn:
                await conn.execute(
                    update(SESSIONS)
                    .where(SESSIONS.c.digest == digest)
                    .values(
                        last_used_at=now,
                        expires_at=min(row.created_at + absolute_s, now + idle_s),
                    )
                )
        return Session(
            user_id=row.user_id,
            csrf_digest=row.csrf_digest,
            email=row.email,
            name=row.name,
            roles=_roles(row.roles_json),
        )

    async def delete_session(self, session_id: str) -> str | None:
        """Delete a session; returns its user id, or None if there was no such session."""
        digest = token_digest(session_id)
        async with self.engine.begin() as conn:
            user_id = (
                await conn.execute(select(SESSIONS.c.user_id).where(SESSIONS.c.digest == digest))
            ).scalar_one_or_none()
            if user_id is None:
                return None
            gone = await conn.execute(delete(SESSIONS).where(SESSIONS.c.digest == digest))
        return str(user_id) if gone.rowcount else None

    # -- maintenance ---------------------------------------------------------------------

    async def expire_commands(self, *, now: float, batch: int = BATCH) -> int:
        """Pending or delivered commands past ``expires_at`` become ``expired`` (never
        delivered later), ``batch`` rows per transaction. Returns how many."""
        due = COMMANDS.c.status.in_(("pending", "delivered"))
        total = 0
        while True:
            async with self.engine.begin() as conn:
                ids = list(
                    (
                        await conn.execute(
                            select(COMMANDS.c.id)
                            .where(due)
                            .where(COMMANDS.c.expires_at <= now)
                            .limit(batch)
                        )
                    ).scalars()
                )
                if not ids:
                    return total
                result = await conn.execute(
                    update(COMMANDS)
                    .where(COMMANDS.c.id.in_(ids))
                    .where(due)
                    .values(status="expired", finished_at=now)
                )
            total += int(result.rowcount or 0)
            if len(ids) < batch:
                return total

    async def _delete_batched(self, table: Table, key: Column[Any], where: Any, batch: int) -> int:
        """Delete the rows of ``table`` matching ``where``, ``batch`` per transaction, so a
        pass after a long downtime is many small transactions, not one huge one."""
        total = 0
        while True:
            async with self.engine.begin() as conn:
                keys = list((await conn.execute(select(key).where(where).limit(batch))).scalars())
                if not keys:
                    return total
                result = await conn.execute(delete(table).where(key.in_(keys)))
            total += int(result.rowcount or 0)
            if len(keys) < batch:
                return total

    async def purge(
        self, *, now: float, events_days: float, commands_days: float, batch: int = BATCH
    ) -> dict[str, int]:
        """Delete events older than ``events_days``; finished commands (done, failed,
        expired) that finished more than ``commands_days`` ago (by ``finished_at``, or
        ``created_at`` when it is not set); and expired login states and sessions."""
        events = await self._delete_batched(
            EVENTS, EVENTS.c.seq, EVENTS.c.ts < now - events_days * DAY_S, batch
        )
        finished = func.coalesce(COMMANDS.c.finished_at, COMMANDS.c.created_at)
        commands = await self._delete_batched(
            COMMANDS,
            COMMANDS.c.id,
            COMMANDS.c.status.in_(("done", "failed", "expired"))
            & (finished < now - commands_days * DAY_S),
            batch,
        )
        login_states = await self._delete_batched(
            LOGIN_STATES, LOGIN_STATES.c.state_digest, LOGIN_STATES.c.expires_at <= now, batch
        )
        sessions = await self._delete_batched(
            SESSIONS, SESSIONS.c.digest, SESSIONS.c.expires_at <= now, batch
        )
        return {
            "events": events,
            "commands": commands,
            "login_states": login_states,
            "sessions": sessions,
        }
