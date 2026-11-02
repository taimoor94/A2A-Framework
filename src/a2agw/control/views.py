"""Console API: the read views (spec §7.10 screens), computed on query from what gateways
report (``cp_events``, ``cp_gateway_audit``, ``cp_health``, ``cp_gateways.info_json``,
``cp_partner_states``) and the catalogue. No materialized tables: the event retention
(7 days by default) bounds every scan, and each one is a time range of one event kind
(``ix_cp_events_kind_ts``) or the events of one task (``ix_cp_events_kind_gateway_task``).

Every list answers ``{items, next_cursor}``: ``limit`` 1..200 (50 by default) and an opaque
``cursor``. A cursor is a keyset position (never an offset) bound to the view and its
filters: the filters of the request are always applied, and a cursor made for another view
or other filters is a 400 ``bad_request``, so a cursor cannot widen what a caller sees.

- ``GET /api/v1/overview`` (``read``): gateways (total active, connected, stale), new tasks
  per minute over the last 60 minutes (distinct tasks submitted, from ``task.state``), the
  task error rate over 15 minutes (failed or rejected among the tasks that ended), the top
  partners of the last hour (calls, errors, p95) and alerts: a gateway not seen for more
  than 60 s, a partner whose breaker a gateway reports open, a partner quarantined on a
  gateway, a desired state a gateway rejected (until it applies a later one).
- ``GET /api/v1/agents`` (``read``) ``kind=hosted|partner``: the hosted agents each gateway
  reports (id, name, version, skill ids, card URL; a gateway that sends bare ids leaves
  name, version and skills null) and the
  catalogue's partners with their card's name, version and skills, tier, status, and the
  worst breaker state gateways report for them (``health``).
- ``GET /api/v1/tasks`` (``read``): the latest ``task.state`` of each task; filters
  ``gateway_id``, ``agent_id``, ``state``, ``since``, ``trace_id`` (any event of the task),
  ``q`` (a task id prefix).
- ``GET /api/v1/tasks/{gateway_id}/{agent_id}/{task_id}`` (``read``): a ``task.get``
  command for the gateway (shared by concurrent requests and reused for
  ``DETAIL_REUSE_S`` once answered; at most ``DETAIL_WAITERS_MAX`` requests wait, the others
  answer 202 at once), waited for ``DETAIL_WAIT_S``: its compact task detail (the last
  messages, clipped, with totals and ``clipped``) plus ``timeline``, or 202
  ``{command_id, timeline}`` when it does not answer in time.
- ``GET /api/v1/topology`` (``read``) ``window_m`` 5..1440: who called whom, from
  ``partner.call`` events, with each edge's routing decision under the gateway's desired
  policy (``allowed``, ``forbidden``, ``forced``, ``preferred``).
- ``GET /api/v1/audit``, ``/audit/export`` and ``/audit/verify`` (``audit.read``): the
  control plane's own chain and the rows gateways copied to it.
- ``GET /api/v1/credentials`` (``read``): credential and TLS reference names catalogue
  partners use. Names only: the control plane holds no secret.

Principal ids: the read views show none (a task's owner is shown as its kind, like the
policy dry-run's ``actor_kind``); the audit views, behind ``audit.read``, show actors.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import csv
import hashlib
import io
import json
import math
import re
from collections.abc import AsyncIterator, Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Annotated, Any, Literal

from a2agw.control import require_fastapi

require_fastapi()

from fastapi import Depends, HTTPException, Query, Request
from fastapi import Path as PathParam
from fastapi.exceptions import RequestValidationError
from fastapi.responses import StreamingResponse
from pydantic import ValidationError
from sqlalchemy import Integer, Table, and_, case, cast, exists, func, literal, or_, select
from sqlalchemy import tuple_ as row
from sqlalchemy.ext.asyncio import AsyncConnection

from a2agw.consult.registry import PartnerRecord
from a2agw.control import channel
from a2agw.control.rbac import Actor, Permission, require, route
from a2agw.control.responses import JSONResponse
from a2agw.control.store import (
    ASSIGNMENTS,
    EVENTS,
    GATEWAY_AUDIT,
    GATEWAYS,
    HEALTH,
    ID,
    NAME,
    PARTNER_STATES,
    PARTNER_VERSIONS,
    PARTNERS,
    ControlStore,
)
from a2agw.ops.audit import AuditEvent, AuditLog, canonical_json, parse_since
from a2agw.ops.metrics import ERROR_STATES
from a2agw.security.policy import PolicyEngine, PolicyError, parse_policy
from a2agw.security.principal import Principal

READ = Permission.READ
AUDIT_READ = Permission.AUDIT_READ
Reader = Annotated[Actor, Depends(require(READ))]
Auditor = Annotated[Actor, Depends(require(AUDIT_READ))]

DEFAULT_LIMIT = 50
MAX_LIMIT = 200
CURSOR_MAX = 1024
INT_EXACT = 2**53  # cursor numbers: exact as a float
INT_MAX = 2**63  # cursor integers: a BIGINT

BUCKETS = 60  # tasks per minute: the last 60 one-minute buckets
ERROR_WINDOW_S = 900.0
TOP_WINDOW_S = 3600.0
TOP_PARTNERS = 10
DISCONNECTED_S = 60.0
NEW_TASK = "TASK_STATE_SUBMITTED"
TASK_ENDS = frozenset(
    {"TASK_STATE_COMPLETED", "TASK_STATE_FAILED", "TASK_STATE_REJECTED", "TASK_STATE_CANCELED"}
)
TASK_ERRORS = frozenset({"TASK_STATE_FAILED", "TASK_STATE_REJECTED"})
BREAKER_ORDER = {"closed": 0, "half_open": 1, "open": 2}

DETAIL_WAIT_S = 5.0  # how long a task detail waits for the gateway's answer
DETAIL_REUSE_S = 5.0  # a task.get answered this recently is shared, not asked again
DETAIL_WAITERS_MAX = 16  # requests waiting for task.get answers at once (per process)
TIMELINE_MAX = 500
TRACES_MAX = 50
HANDLES_MAX = 100
HANDLE_FIELDS = ("partner_id", "task_id", "context_id", "state", "created_at", "end_reason")
EDGES_MAX = 500  # topology: the busiest edges

EXPORT_MAX = 100_000
EXPORT_BATCH = 1000
CSV_COLUMNS = (
    "source",
    "gateway_id",
    "generation",
    "seq",
    "ts",
    "actor",
    "action",
    "agent_id",
    "partner_id",
    "task_id",
    "classification",
    "outcome",
    "detail",
    "prev_hash",
    "hash",
)
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")  # OWASP CSV injection

CARD_PATH = "/.well-known/agent-card.json"  # a hosted agent's card: /agents/{id}<CARD_PATH>


def _loads(raw: str | None, default: Any) -> Any:
    try:
        return json.loads(raw) if raw else default
    except ValueError:
        return default


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _not_found(what: str) -> HTTPException:
    return HTTPException(404, {"error": "not_found", "detail": f"unknown {what}"})


def _invalid(loc: tuple[str, ...], msg: str) -> RequestValidationError:
    return RequestValidationError([{"loc": loc, "msg": msg, "type": "value_error"}])


def _time(value: str | None, name: str) -> float | None:
    """A ``since``/``until`` query value (ISO 8601 or epoch seconds) as epoch seconds."""
    if value is None:
        return None
    try:
        return parse_since(value)
    except ValueError:
        raise _invalid(("query", name), "must be an ISO 8601 timestamp or epoch seconds") from None


# -- pagination ----------------------------------------------------------------------------


def _bad_cursor(detail: str = "invalid cursor") -> HTTPException:
    return HTTPException(400, {"error": "bad_request", "detail": detail})


@dataclass(frozen=True)
class PageArgs:
    limit: int
    cursor: str | None


def page_args(
    limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    cursor: str | None = Query(None, max_length=CURSOR_MAX),
) -> PageArgs:
    return PageArgs(limit, cursor)


PageQuery = Annotated[PageArgs, Depends(page_args)]
Shape = tuple[type, ...]  # the types of a cursor's position, in order


@dataclass(frozen=True)
class Keyset:
    """The pagination of one list: the view, the filters a cursor is bound to, the shape of
    its position and the page size."""

    view: str
    filters: dict[str, Any]
    shape: Shape
    args: PageArgs

    @property
    def limit(self) -> int:
        return self.args.limit

    def _bound(self) -> str:
        return hashlib.sha256(canonical_json([self.view, self.filters]).encode()).hexdigest()[:16]

    def after(self) -> list[Any] | None:
        """The position the page starts after (None: the first page). 400 for a malformed
        cursor or one made for another view or other filters."""
        if self.args.cursor is None:
            return None
        try:
            padded = self.args.cursor + "=" * (-len(self.args.cursor) % 4)
            data = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
        except (ValueError, UnicodeError, binascii.Error):
            raise _bad_cursor() from None
        if not isinstance(data, dict) or set(data) != {"q", "k"}:
            raise _bad_cursor()
        if data["q"] != self._bound():
            raise _bad_cursor("cursor does not match the query")
        position = data["k"]
        if not isinstance(position, list) or len(position) != len(self.shape):
            raise _bad_cursor()
        for value, kind in zip(position, self.shape, strict=True):
            if isinstance(value, bool) or not _fits(value, kind):
                raise _bad_cursor()
        return [
            float(v) if kind is float else v for v, kind in zip(position, self.shape, strict=True)
        ]

    def cursor(self, position: Sequence[Any]) -> str:
        raw = json.dumps({"q": self._bound(), "k": list(position)}, separators=(",", ":"))
        return base64.urlsafe_b64encode(raw.encode()).rstrip(b"=").decode()

    def page(self, items: list[Any], last: Sequence[Any] | None, more: bool) -> dict[str, Any]:
        return {"items": items, "next_cursor": self.cursor(last) if more and last else None}


def _fits(value: Any, kind: type) -> bool:
    """Whether a cursor value has its position's type (and a size a column can hold)."""
    if isinstance(value, int):
        return abs(value) < (INT_EXACT if kind is float else INT_MAX) and kind in (int, float)
    if kind is float:
        return isinstance(value, float) and math.isfinite(value)
    return isinstance(value, kind)


def paginate_sorted(
    keyset: Keyset, items: Iterable[tuple[tuple[Any, ...], dict[str, Any]]]
) -> dict[str, Any]:
    """A page of an in-memory list of ``(sort key, item)``, ascending by key."""
    after = keyset.after()
    ordered = sorted(items, key=lambda kv: kv[0])
    if after is not None:
        start = tuple(after)
        ordered = [kv for kv in ordered if kv[0] > start]
    chosen = ordered[: keyset.limit]
    more = len(ordered) > keyset.limit
    return keyset.page([v for _k, v in chosen], chosen[-1][0] if chosen else None, more)


# -- shared reads --------------------------------------------------------------------------


@dataclass(frozen=True)
class GatewayRow:
    id: str
    name: str
    created_at: float
    last_seen_at: float | None
    info: dict[str, Any]
    version_applied: int
    epoch_applied: str | None
    connected: bool


async def _active_gateways(request: Request) -> list[GatewayRow]:
    state = request.app.state
    store: ControlStore = state.store
    window = 2 * state.settings.limits.stream_keepalive_s  # as the gateway list counts it
    now = state.clock()
    query = select(GATEWAYS).where(GATEWAYS.c.status == "active").order_by(GATEWAYS.c.id)
    async with store.engine.connect() as conn:
        rows = (await conn.execute(query)).all()
    return [
        GatewayRow(
            id=r.id,
            name=r.name,
            created_at=r.created_at,
            last_seen_at=r.last_seen_at,
            info=_dict(_loads(r.info_json, {})),
            version_applied=r.last_version_applied,
            epoch_applied=r.epoch_applied,
            connected=r.last_seen_at is not None and now - r.last_seen_at <= window,
        )
        for r in rows
    ]


async def _health(store: ControlStore, gateway_ids: list[str]) -> dict[str, Any]:
    """``{gateway_id: row}`` of ``cp_health`` (ts, health and metrics as dicts)."""
    if not gateway_ids:
        return {}
    async with store.engine.connect() as conn:
        rows = (
            await conn.execute(select(HEALTH).where(HEALTH.c.gateway_id.in_(gateway_ids)))
        ).all()
    return {
        r.gateway_id: (r.ts, _dict(_loads(r.health_json, {})), _dict(_loads(r.metrics_json, {})))
        for r in rows
    }


def _breakers(metrics: dict[str, Any]) -> dict[str, str]:
    """``{partner_id: breaker state}`` of a metrics snapshot."""
    out: dict[str, str] = {}
    for pid, stats in _dict(metrics.get("partners")).items():
        breaker = _dict(stats).get("breaker")
        if isinstance(pid, str) and breaker in BREAKER_ORDER:
            out[pid] = breaker
    return out


async def percentiles(
    conn: AsyncConnection, where: list[Any], group: list[Any], pcts: tuple[int, ...]
) -> dict[tuple[Any, ...], dict[int, float]]:
    """Nearest-rank percentiles of ``duration_ms`` per ``group`` over the events matching
    ``where``, in one statement: each group's durations are numbered in order
    (``row_number``, ``count`` over the group) and only the rank rows are kept, the rank of
    ``p`` being ``ceil(p * n / 100)`` in integer arithmetic. A group without durations is
    absent (0.0 for it, as the gateway's own metrics)."""
    e = EVENTS.c
    ordered = func.row_number().over(partition_by=group, order_by=(e.duration_ms, e.seq))
    total = func.count().over(partition_by=group)
    ranked = (
        select(*group, e.duration_ms, ordered.label("rn"), total.label("n"))
        .where(*where, e.duration_ms.is_not(None))
        .subquery()
    )
    keys = [ranked.c[c.name] for c in group]

    def rank(p: int) -> Any:
        return (ranked.c.n * p + 99) // 100

    query = (
        select(
            *keys,
            *(
                func.max(case((ranked.c.rn == rank(p), ranked.c.duration_ms))).label(f"p{p}")
                for p in pcts
            ),
        )
        .where(or_(*(ranked.c.rn == rank(p) for p in pcts)))
        .group_by(*keys)
    )
    out: dict[tuple[Any, ...], dict[int, float]] = {}
    for r in (await conn.execute(query)).all():
        values = tuple(r)
        out[values[: len(keys)]] = {
            p: float(v) if v is not None else 0.0
            for p, v in zip(pcts, values[len(keys) :], strict=True)
        }
    return out


def _errors() -> Any:
    return func.sum(case((EVENTS.c.state.in_(sorted(ERROR_STATES)), 1), else_=0))


# -- overview ------------------------------------------------------------------------------


def _minute_of(conn: AsyncConnection, start: float) -> Any:
    """The bucket index of an event: whole minutes since ``start`` (never negative here,
    so sqlite's truncating cast is a floor)."""
    offset = (EVENTS.c.ts - start) / 60
    if conn.dialect.name == "postgresql":
        return cast(func.floor(offset), Integer)
    return cast(offset, Integer)


async def _tasks_per_min(conn: AsyncConnection, now: float) -> list[dict[str, Any]]:
    start = (now // 60) * 60 - (BUCKETS - 1) * 60
    bucket = _minute_of(conn, start).label("bucket")
    task = EVENTS.c.gateway_id + literal("/") + EVENTS.c.task_id
    query = (
        select(bucket, func.count(func.distinct(task)))
        .where(EVENTS.c.kind == "task.state")
        .where(EVENTS.c.ts >= start, EVENTS.c.ts < start + BUCKETS * 60)
        .where(EVENTS.c.state == NEW_TASK)
        .group_by(bucket)
    )
    counts = {int(b): int(n) for b, n in (await conn.execute(query)).all()}
    return [{"ts": start + 60 * i, "count": counts.get(i, 0)} for i in range(BUCKETS)]


async def _error_rate(conn: AsyncConnection, now: float) -> float:
    query = (
        select(EVENTS.c.state, func.count())
        .where(EVENTS.c.kind == "task.state")
        .where(EVENTS.c.ts >= now - ERROR_WINDOW_S)
        .where(EVENTS.c.state.in_(sorted(TASK_ENDS)))
        .group_by(EVENTS.c.state)
    )
    ended = {str(s): int(n) for s, n in (await conn.execute(query)).all()}
    total = sum(ended.values())
    return sum(n for s, n in ended.items() if s in TASK_ERRORS) / total if total else 0.0


async def _top_partners(conn: AsyncConnection, now: float) -> list[dict[str, Any]]:
    window = [
        EVENTS.c.kind == "partner.call",
        EVENTS.c.ts >= now - TOP_WINDOW_S,
        EVENTS.c.partner_id.is_not(None),
    ]
    calls = func.count().label("calls")
    query = (
        select(EVENTS.c.partner_id, calls, _errors())
        .where(*window)
        .group_by(EVENTS.c.partner_id)
        .order_by(calls.desc(), EVENTS.c.partner_id)
        .limit(TOP_PARTNERS)
    )
    top = (await conn.execute(query)).all()
    if not top:
        return []
    ids = [r[0] for r in top]
    ranks = await percentiles(
        conn, [*window, EVENTS.c.partner_id.in_(ids)], [EVENTS.c.partner_id], (95,)
    )
    return [
        {
            "partner_id": pid,
            "calls": int(n),
            "errors": int(errors or 0),
            "p95_ms": ranks.get((pid,), {}).get(95, 0.0),
        }
        for pid, n, errors in top
    ]


def _rejection_alert(gw: GatewayRow) -> dict[str, Any] | None:
    """The gateway's last rejected desired state, unless it applied that version (or a
    later one) of the same epoch since."""
    rejection = _dict(gw.info.get("last_rejection"))
    version, at = rejection.get("version"), rejection.get("at")
    if not isinstance(version, int) or not isinstance(at, int | float):
        return None
    if gw.epoch_applied == rejection.get("epoch") and gw.version_applied >= version:
        return None
    return {"kind": "desired_rejected", "gateway_id": gw.id, "since": float(at)}


async def _alerts(
    store: ControlStore, gateways: list[GatewayRow], now: float
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    ids = [g.id for g in gateways]
    for gw in gateways:
        seen = gw.last_seen_at if gw.last_seen_at is not None else gw.created_at
        if now - seen > DISCONNECTED_S:
            out.append({"kind": "gateway_disconnected", "gateway_id": gw.id, "since": seen})
        rejected = _rejection_alert(gw)
        if rejected is not None:
            out.append(rejected)
    for gid, (ts, _health_doc, metrics) in (await _health(store, ids)).items():
        for pid, breaker in sorted(_breakers(metrics).items()):
            if breaker == "open":
                out.append(
                    {"kind": "breaker_open", "gateway_id": gid, "partner_id": pid, "since": ts}
                )
    if ids:
        query = (
            select(PARTNER_STATES)
            .where(PARTNER_STATES.c.status == "quarantined")
            .where(PARTNER_STATES.c.gateway_id.in_(ids))
        )
        async with store.engine.connect() as conn:
            for r in (await conn.execute(query)).all():
                out.append(
                    {
                        "kind": "partner_quarantined",
                        "gateway_id": r.gateway_id,
                        "partner_id": r.partner_id,
                        "since": r.ts,
                    }
                )
    out.sort(key=lambda a: (-a["since"], a["kind"], a["gateway_id"], a.get("partner_id") or ""))
    return out


@route("GET", "/api/v1/overview", READ)
async def overview(request: Request) -> dict[str, Any]:
    store: ControlStore = request.app.state.store
    now = request.app.state.clock()
    gateways = await _active_gateways(request)
    connected = sum(1 for g in gateways if g.connected)
    async with store.engine.connect() as conn:
        tasks = await _tasks_per_min(conn, now)
        error_rate = await _error_rate(conn, now)
        top = await _top_partners(conn, now)
    return {
        "gateways": {
            "total": len(gateways),
            "connected": connected,
            "stale": len(gateways) - connected,
        },
        "tasks_per_min": tasks,
        "error_rate": error_rate,
        "top_partners": top,
        "alerts": await _alerts(store, gateways, now),
    }


# -- agents --------------------------------------------------------------------------------


def _hosted(gw: GatewayRow, health: dict[str, Any] | None) -> list[dict[str, Any]]:
    """The gateway's hosted agents as it reported them: objects ``{id, name, version,
    skills, card_url}`` (bare ids from older gateways and rows: the rest null, the card URL
    derived from the gateway's layout)."""
    base = _str(gw.info.get("base_url"))
    status = _str(_dict(health).get("status")) if health is not None else None
    state = (status or "unknown") if gw.connected else "disconnected"
    agents = gw.info.get("agents")
    reported: dict[str, dict[str, Any]] = {}
    for a in agents if isinstance(agents, list) else []:
        entry = {"id": a} if isinstance(a, str) else _dict(a)
        if isinstance(entry.get("id"), str):
            reported.setdefault(entry["id"], entry)
    out = []
    for agent_id, entry in sorted(reported.items()):
        skills = entry.get("skills")
        card_url = _str(entry.get("card_url"))
        if card_url is not None and not channel.http_url(card_url):
            card_url = None  # stored before reports were checked: never served
        if card_url is None and base:
            card_url = f"{base.rstrip('/')}/agents/{agent_id}{CARD_PATH}"
        out.append(
            {
                "kind": "hosted",
                "id": agent_id,
                "name": _str(entry.get("name")),
                "version": _str(entry.get("version")),
                "skills": [x for x in skills if isinstance(x, str)]
                if isinstance(skills, list)
                else None,
                "card_url": card_url,
                "gateway_id": gw.id,
                "health": state,
                "tier": None,
                "status": None,
            }
        )
    return out


async def _catalogue_partners(store: ControlStore) -> list[Any]:
    """Every catalogue partner with the card shown for it: the approved version, else the
    latest one."""
    latest = (
        select(PARTNER_VERSIONS.c.partner_id, func.max(PARTNER_VERSIONS.c.version).label("v"))
        .group_by(PARTNER_VERSIONS.c.partner_id)
        .subquery()
    )
    shown = case((PARTNERS.c.current_version > 0, PARTNERS.c.current_version), else_=latest.c.v)
    query = (
        select(PARTNERS, PARTNER_VERSIONS.c.card_json)
        .outerjoin(latest, latest.c.partner_id == PARTNERS.c.id)
        .outerjoin(
            PARTNER_VERSIONS,
            (PARTNER_VERSIONS.c.partner_id == PARTNERS.c.id)
            & (PARTNER_VERSIONS.c.version == shown),
        )
        .order_by(PARTNERS.c.id)
    )
    async with store.engine.connect() as conn:
        return list((await conn.execute(query)).all())


def _partner_item(p: Any, breaker: str | None) -> dict[str, Any]:
    card = _dict(_loads(p.card_json, {}))
    skills = card.get("skills")
    return {
        "kind": "partner",
        "id": p.id,
        "name": _str(card.get("name")),
        "version": _str(card.get("version")),
        "skills": [s["id"] for s in skills if isinstance(s, dict) and isinstance(s.get("id"), str)]
        if isinstance(skills, list)
        else [],
        "card_url": p.card_url,
        "gateway_id": None,
        "health": breaker,
        "tier": p.tier,
        "status": p.status,
    }


@route("GET", "/api/v1/agents", READ)
async def list_agents(
    request: Request, page: PageQuery, kind: Literal["hosted", "partner"] | None = None
) -> dict[str, Any]:
    keyset = Keyset("agents", {"kind": kind}, (str, str, str), page)
    store: ControlStore = request.app.state.store
    gateways = await _active_gateways(request)
    health = await _health(store, [g.id for g in gateways])
    items: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    if kind in (None, "hosted"):
        for gw in gateways:
            reported = health.get(gw.id)
            for agent in _hosted(gw, reported[1] if reported is not None else None):
                items.append((("hosted", gw.id, agent["id"]), agent))
    if kind in (None, "partner"):
        worst: dict[str, str] = {}
        for _ts, _doc, metrics in health.values():
            for pid, breaker in _breakers(metrics).items():
                if BREAKER_ORDER[breaker] >= BREAKER_ORDER.get(worst.get(pid, ""), -1):
                    worst[pid] = breaker
        for p in await _catalogue_partners(store):
            items.append((("partner", "", p.id), _partner_item(p, worst.get(p.id))))
    return paginate_sorted(keyset, items)


# -- tasks ---------------------------------------------------------------------------------


def _like_prefix(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


@route("GET", "/api/v1/tasks", READ)
async def list_tasks(
    request: Request,
    page: PageQuery,
    gateway_id: str | None = Query(None, max_length=ID),
    agent_id: str | None = Query(None, max_length=NAME),
    state: str | None = Query(None, max_length=64),
    since: str | None = Query(None, max_length=64),
    trace_id: str | None = Query(None, max_length=ID),
    q: str | None = Query(None, min_length=1, max_length=NAME),
) -> dict[str, Any]:
    after_ts = _time(since, "since")
    filters = {
        "gateway_id": gateway_id,
        "agent_id": agent_id,
        "state": state,
        "since": after_ts,
        "trace_id": trace_id,
        "q": q,
    }
    keyset = Keyset("tasks", filters, (float, int), page)
    after = keyset.after()
    store: ControlStore = request.app.state.store
    e = EVENTS.c
    scope = [e.kind == "task.state", e.task_id.is_not(None)]
    if gateway_id is not None:
        scope.append(e.gateway_id == gateway_id)
    if agent_id is not None:
        scope.append(e.agent_id == agent_id)
    if q is not None:
        scope.append(e.task_id.like(_like_prefix(q), escape="\\"))
    latest = (
        select(e.gateway_id, e.task_id, func.max(e.seq).label("seq"))
        .where(*scope)
        .group_by(e.gateway_id, e.task_id)
        .subquery()
    )
    traced = (
        select(e.gateway_id, e.task_id, func.max(e.seq).label("seq"))
        .where(*scope, e.trace_id.is_not(None))
        .group_by(e.gateway_id, e.task_id)
        .subquery()
    )
    tr = EVENTS.alias("tr")
    query = select(
        e.seq, e.gateway_id, e.agent_id, e.task_id, e.ts, e.state, e.data_json, tr.c.trace_id
    ).select_from(
        EVENTS.join(latest, latest.c.seq == e.seq)
        .outerjoin(traced, (traced.c.gateway_id == e.gateway_id) & (traced.c.task_id == e.task_id))
        .outerjoin(tr, tr.c.seq == traced.c.seq)
    )
    if state is not None:
        query = query.where(e.state == state)
    if after_ts is not None:
        query = query.where(e.ts >= after_ts)
    if trace_id is not None:
        other = EVENTS.alias("other")
        query = query.where(
            exists()
            .where(other.c.kind == "task.state")
            .where(other.c.gateway_id == e.gateway_id)
            .where(other.c.task_id == e.task_id)
            .where(other.c.trace_id == trace_id)
        )
    if after is not None:
        query = query.where(row(e.ts, e.seq) < row(*after))
    query = query.order_by(e.ts.desc(), e.seq.desc()).limit(keyset.limit + 1)
    async with store.engine.connect() as conn:
        rows = (await conn.execute(query)).all()
    more = len(rows) > keyset.limit
    rows = rows[: keyset.limit]
    items = []
    for r in rows:
        data = _dict(_loads(r.data_json, {}))
        items.append(
            {
                "gateway_id": r.gateway_id,
                "agent_id": r.agent_id,
                "task_id": r.task_id,
                "context_id": _str(data.get("context_id")),
                "state": r.state if r.state is not None else _str(data.get("state")),
                "updated_at": r.ts,
                "trace_id": r.trace_id,
            }
        )
    last = (rows[-1].ts, rows[-1].seq) if rows else None
    return keyset.page(items, last, more)


def _owner_kind(owner: Any) -> str | None:
    return Principal.from_id(owner).kind if isinstance(owner, str) else None


def _answerer_kind(actor: Any) -> str | None:
    """The kind of whoever answered a prompt for the owner: ``console`` for an operator of
    the control plane (actor ``cp:<id>``), else the gateway principal's kind."""
    if not isinstance(actor, str):
        return None
    return "console" if actor.startswith("cp:") else Principal.from_id(actor).kind


def _public_message(message: Any) -> Any:
    """A history message without the answering operator's id (``answered_by_kind``)."""
    if not isinstance(message, dict) or "answered_by" not in message:
        return message
    shown = {k: v for k, v in message.items() if k != "answered_by"}
    shown["answered_by_kind"] = _answerer_kind(message["answered_by"])
    return shown


def public_detail(result: dict[str, Any]) -> dict[str, Any]:
    """A gateway's task detail without principal ids: the owner becomes ``owner_kind``, a
    message's ``answered_by`` becomes ``answered_by_kind``, and a partner task keeps only
    ``HANDLE_FIELDS`` (no caller id). A detail the gateway
    cut for size (``{"truncated": true}``) is ``task: null`` with ``truncated: true``."""
    task = result.get("task")
    if not isinstance(task, dict):
        return {
            "task": None,
            "partner_tasks": [],
            "pending_prompt": None,
            "truncated": bool(result.get("truncated")),
        }
    shown = {k: v for k, v in task.items() if k != "owner"}
    shown["owner_kind"] = _owner_kind(task.get("owner"))
    history = task.get("history")
    if isinstance(history, list):
        shown["history"] = [_public_message(m) for m in history]
    handles = result.get("partner_tasks")
    out = {
        "task": shown,
        "partner_tasks": [
            {k: h.get(k) for k in HANDLE_FIELDS}
            for h in (handles if isinstance(handles, list) else [])[:HANDLES_MAX]
            if isinstance(h, dict)
        ],
        "pending_prompt": result.get("pending_prompt"),
    }
    # the compact detail's totals and whether anything was cut (gateways since it)
    for key in ("history_total", "artifacts_total", "partner_tasks_total"):
        if isinstance(result.get(key), int):
            out[key] = result[key]
    if isinstance(result.get("clipped"), bool):
        out["clipped"] = result["clipped"]
    return out


def _timeline_entry(r: Any) -> dict[str, Any]:
    data = _dict(_loads(r.data_json, {}))
    return {
        "ts": r.ts,
        "gateway_id": r.gateway_id,
        "agent_id": r.agent_id,
        "kind": r.kind,
        "task_id": r.task_id,
        "context_id": _str(data.get("context_id")),
        "state": r.state if r.state is not None else _str(data.get("state")),
        "trace_id": r.trace_id,
        "partner_id": r.partner_id,
        "duration_ms": r.duration_ms,
    }


async def timeline(
    store: ControlStore,
    gateway_id: str,
    task_id: str,
    traces: Iterable[str] = (),
    handles: Iterable[tuple[str, str]] = (),
) -> list[dict[str, Any]]:
    """The events of a task across gateways, oldest first (``TIMELINE_MAX`` at most): its
    own ``task.state`` events, every task state change and partner call sharing one of its
    traces (``traces`` plus those its events carry), and the partner calls of its partner
    tasks (``handles``: (partner id, task id); for events from gateways whose
    ``partner.call`` carries no trace yet)."""
    e = EVENTS.c
    own = (e.kind == "task.state") & (e.gateway_id == gateway_id) & (e.task_id == task_id)
    async with store.engine.connect() as conn:
        carried = await conn.execute(
            select(e.trace_id).where(own, e.trace_id.is_not(None)).distinct().limit(TRACES_MAX)
        )
        trace_ids = sorted({*traces, *(str(t) for t in carried.scalars())})[:TRACES_MAX]
        matches = [own]
        if trace_ids:
            matches.append(e.trace_id.in_(trace_ids) & e.kind.in_(("task.state", "partner.call")))
        for partner_id, partner_task in list(handles)[:HANDLES_MAX]:
            matches.append(
                (e.kind == "partner.call")
                & (e.gateway_id == gateway_id)
                & (e.partner_id == partner_id)
                & (e.task_id == partner_task)
            )
        query = select(EVENTS).where(or_(*matches)).order_by(e.ts, e.seq).limit(TIMELINE_MAX)
        rows = (await conn.execute(query)).all()
    return [_timeline_entry(r) for r in rows]


# An id in a path that is sent on to a gateway (agent, task, partner, gateway ids): at most
# ``PATH_ID_MAX`` characters, no control characters (422 otherwise).
PATH_ID_MAX = 256
PATH_ID_PATTERN = r"^[^\x00-\x1f\x7f]+$"
PathId = Annotated[str, PathParam(max_length=PATH_ID_MAX, pattern=PATH_ID_PATTERN)]


class DetailGate:
    """Bounds what task details cost (``app.state.task_details``): concurrent requests for
    one task share one ``task.get`` (found or queued under ``lock``, so two requests of
    this process never both queue it), and at most ``DETAIL_WAITERS_MAX`` requests wait for
    answers at once; the others answer 202 at once."""

    def __init__(self) -> None:
        self.lock = asyncio.Lock()
        self.waiting = 0


async def _detail_command(
    store: ControlStore, gate: DetailGate, gateway_id: str, args: dict[str, Any], actor: str
) -> str:
    async with gate.lock:
        found = await channel.find_command(
            store, gateway_id, "task.get", args, now=store.now(), done_within_s=DETAIL_REUSE_S
        )
        if found is not None:
            if store.audit is not None:  # who read it, though the gateway ran it once
                await store.audit.emit(
                    AuditEvent(
                        actor=actor,
                        action="cp.command",
                        outcome="shared",
                        detail={"gateway": gateway_id, "command": "task.get"},
                        ts=store.now(),
                    )
                )
            return found
        try:
            return await channel.enqueue_command(store, gateway_id, "task.get", args, actor)
        except KeyError:
            raise _not_found("gateway") from None
        except ValueError:
            raise HTTPException(
                409, {"error": "conflict", "detail": "gateway is revoked"}
            ) from None
        except channel.TooManyCommands:
            raise channel.queue_full() from None


@route("GET", "/api/v1/tasks/{gateway_id}/{agent_id}/{task_id}", READ)
async def task_detail(
    gateway_id: PathId, agent_id: PathId, task_id: PathId, request: Request, actor: Reader
) -> Any:
    state = request.app.state
    store: ControlStore = state.store
    gate: DetailGate = state.task_details
    args = {"agent_id": agent_id, "task_id": task_id}
    command_id = await _detail_command(store, gate, gateway_id, args, actor.id)
    if gate.waiting >= DETAIL_WAITERS_MAX:
        command = await channel.get_command(store, command_id)
    else:
        gate.waiting += 1
        try:  # polls the command row: one short query per poll, no connection held between
            command = await channel.wait_command(
                store, command_id, DETAIL_WAIT_S, sleep=state.sleep
            )
        finally:
            gate.waiting -= 1
    result = _dict(command.result)
    if command.status == "failed":
        if result.get("error") == "not_found":
            raise _not_found("task")
        code = _str(result.get("error")) or "error"
        raise HTTPException(502, {"error": "gateway", "detail": code[:64]})
    if command.status != "done":  # not answered in time: the command stays queued
        events = await timeline(store, gateway_id, task_id)
        return JSONResponse({"command_id": command_id, "timeline": events}, status_code=202)
    detail = public_detail(result)
    task = detail["task"] or {}
    traces = [t] if isinstance(t := task.get("trace_id"), str) else []
    handles = [
        (h["partner_id"], h["task_id"])
        for h in detail["partner_tasks"]
        if isinstance(h["partner_id"], str) and isinstance(h["task_id"], str)
    ]
    return {**detail, "timeline": await timeline(store, gateway_id, task_id, traces, handles)}


# -- topology ------------------------------------------------------------------------------


@dataclass
class _Overlay:
    """A gateway's desired policy and the partner records it routes over."""

    engine: PolicyEngine | None
    records: dict[str, PartnerRecord] = field(default_factory=dict)


def _record(p: dict[str, Any]) -> PartnerRecord | None:
    try:
        return PartnerRecord(
            id=p["id"],
            card=_dict(p.get("card")),
            card_hash=_str(p.get("card_hash")) or "",
            tier=p.get("tier") or "public",
            tags=[t for t in p.get("tags") or [] if isinstance(t, str)],
        )
    except (KeyError, TypeError, ValidationError):
        return None


async def _overlay(store: ControlStore, gateway_id: str) -> _Overlay:
    desired = await channel.load_desired(store, gateway_id)
    if desired is None:
        return _Overlay(None)
    engine = None
    if desired.policy is not None:
        try:
            engine = PolicyEngine(parse_policy(desired.policy))
        except PolicyError:
            engine = None
    records = {}
    for p in desired.partners:
        rec = _record(_dict(p))
        if rec is not None:
            records[rec.id] = rec
    return _Overlay(engine, records)


async def _catalogue_records(store: ControlStore, ids: set[str]) -> dict[str, PartnerRecord]:
    """Records of partners a gateway called that are not in its desired state (tier, tags
    and approved card from the catalogue; an unknown partner gets an empty public one)."""
    out: dict[str, PartnerRecord] = {}
    if ids:
        query = (
            select(PARTNERS, PARTNER_VERSIONS.c.card_json)
            .outerjoin(
                PARTNER_VERSIONS,
                and_(
                    PARTNER_VERSIONS.c.partner_id == PARTNERS.c.id,
                    PARTNER_VERSIONS.c.version == PARTNERS.c.current_version,
                ),
            )
            .where(PARTNERS.c.id.in_(sorted(ids)))
        )
        async with store.engine.connect() as conn:
            for p in (await conn.execute(query)).all():
                rec = _record(
                    {
                        "id": p.id,
                        "card": _loads(p.card_json, {}),
                        "tier": p.tier,
                        "tags": _loads(p.tags_json, []),
                    }
                )
                if rec is not None:
                    out[p.id] = rec
    for pid in ids - out.keys():
        rec = _record({"id": pid})
        if rec is not None:
            out[pid] = rec
    return out


def _decision(plan: Any, partner_id: str) -> str:
    if partner_id in plan.forced:
        return "forced"
    if partner_id not in plan.visible:
        return "forbidden"  # a forbid rule (a force that conflicts with one included)
    return "preferred" if partner_id in plan.preferred else "allowed"


async def _policy_overlay(
    store: ControlStore, edges: list[tuple[str, str, str]]
) -> dict[tuple[str, str, str], str]:
    """The routing decision of each (gateway, agent, partner) edge under the gateway's
    desired policy (``PolicyEngine.route``, the gateway's own evaluation). No policy (or
    none that parses) has no routing rule: every edge is allowed."""
    by_gateway: dict[str, dict[str, set[str]]] = {}
    for gid, agent, pid in edges:
        by_gateway.setdefault(gid, {}).setdefault(agent, set()).add(pid)
    out: dict[tuple[str, str, str], str] = {}
    for gid, agents in by_gateway.items():
        overlay = await _overlay(store, gid)
        wanted = set().union(*agents.values())
        if overlay.engine is None:
            for agent, pids in agents.items():
                out.update({(gid, agent, pid): "allowed" for pid in pids})
            continue
        records = {
            **await _catalogue_records(store, wanted - overlay.records.keys()),
            **overlay.records,
        }
        for agent, pids in agents.items():
            plan = overlay.engine.route(agent, [records[p] for p in sorted(pids) if p in records])
            out.update({(gid, agent, pid): _decision(plan, pid) for pid in pids})
    return out


@route("GET", "/api/v1/topology", READ)
async def topology(request: Request, window_m: int = Query(60, ge=5, le=1440)) -> dict[str, Any]:
    store: ControlStore = request.app.state.store
    since = request.app.state.clock() - window_m * 60.0
    e = EVENTS.c
    window = [
        e.kind == "partner.call",
        e.ts >= since,
        e.partner_id.is_not(None),
        e.agent_id.is_not(None),
    ]
    calls = func.count().label("calls")
    query = (
        select(e.gateway_id, e.agent_id, e.partner_id, calls, _errors())
        .where(*window)
        .group_by(e.gateway_id, e.agent_id, e.partner_id)
        .order_by(calls.desc(), e.gateway_id, e.agent_id, e.partner_id)
        .limit(EDGES_MAX)
    )
    async with store.engine.connect() as conn:
        rows = (await conn.execute(query)).all()
        ranks = (
            await percentiles(conn, window, [e.gateway_id, e.agent_id, e.partner_id], (50, 95))
            if rows
            else {}
        )
    found = []
    for gid, agent, pid, n, errors in rows:
        p = ranks.get((gid, agent, pid), {})
        found.append(((gid, agent, pid), int(n), int(errors or 0), p.get(50, 0.0), p.get(95, 0.0)))
    decisions = await _policy_overlay(store, [key for key, *_ in found])
    nodes: dict[str, dict[str, Any]] = {}
    edges = []
    for (gid, agent, pid), n, errors, p50, p95 in found:
        hosted = f"{gid}/{agent}"
        nodes[hosted] = {"id": hosted, "kind": "hosted", "gateway_id": gid, "agent_id": agent}
        nodes.setdefault(pid, {"id": pid, "kind": "partner"})
        edges.append(
            {
                "from": hosted,
                "to": pid,
                "calls": n,
                "errors": errors,
                "p50_ms": p50,
                "p95_ms": p95,
                "policy": decisions[(gid, agent, pid)],
            }
        )
    return {"nodes": [nodes[k] for k in sorted(nodes)], "edges": edges}


# -- audit ---------------------------------------------------------------------------------

Source = Literal["control", "gateway"]
_RANK: dict[str, int] = {"control": 0, "gateway": 1}  # the order of the sources at one ts


@dataclass(frozen=True)
class AuditFilters:
    source: Source | None
    gateway_id: str | None
    action: str | None
    actor: str | None
    agent: str | None
    partner: str | None
    since: float | None
    until: float | None

    def bound(self) -> dict[str, Any]:
        return dict(self.__dict__)

    def used(self) -> list[str]:
        return sorted(k for k, v in self.__dict__.items() if v is not None)


def audit_filters(
    source: Source | None = None,
    gateway_id: str | None = Query(None, max_length=ID),
    action: str | None = Query(None, max_length=64),
    actor: str | None = Query(None, max_length=NAME),
    agent: str | None = Query(None, max_length=NAME),
    partner: str | None = Query(None, max_length=NAME),
    since: str | None = Query(None, max_length=64),
    until: str | None = Query(None, max_length=64),
) -> AuditFilters:
    return AuditFilters(
        source,
        gateway_id,
        action,
        actor,
        agent,
        partner,
        _time(since, "since"),
        _time(until, "until"),
    )


AuditQuery = Annotated[AuditFilters, Depends(audit_filters)]
# (ts, source rank, gateway id, generation, seq): sorted descending
Position = tuple[float, int, str, int, int]


def _contains(conn: AsyncConnection, column: Any, needle: str) -> Any:
    """An exact, case-sensitive substring test (sqlite's LIKE ignores ASCII case)."""
    if conn.dialect.name == "postgresql":
        return func.strpos(column, needle) > 0
    return func.instr(column, needle) > 0


def _pair(key: str, value: str, *, ascii_only: bool) -> str:
    """``"key":"value"`` as the stored JSON spells it (sorted, compact)."""
    return f"{json.dumps(key)}:{json.dumps(value, ensure_ascii=ascii_only)}"


def _control_query(conn: AsyncConnection, t: Table, f: AuditFilters, after: Position | None) -> Any:
    query = select(t)
    for column, value in (
        (t.c.action, f.action),
        (t.c.actor, f.actor),
        (t.c.agent_id, f.agent),
        (t.c.partner_id, f.partner),
    ):
        if value is not None:
            query = query.where(column == value)
    if f.gateway_id is not None:  # rows about the gateway
        needle = _pair("gateway", f.gateway_id, ascii_only=False)
        query = query.where(_contains(conn, t.c.detail_json, needle))
    if f.since is not None:
        query = query.where(t.c.ts >= f.since)
    if f.until is not None:
        query = query.where(t.c.ts <= f.until)
    if after is not None:
        ts, rank, _gid, _generation, seq = after
        if rank > _RANK["control"]:
            query = query.where(t.c.ts <= ts)
        else:
            query = query.where(row(t.c.ts, t.c.seq) < row(ts, seq))
    return query.order_by(t.c.ts.desc(), t.c.seq.desc())


def _gateway_query(conn: AsyncConnection, f: AuditFilters, after: Position | None) -> Any:
    g = GATEWAY_AUDIT.c
    query = select(GATEWAY_AUDIT)
    if f.gateway_id is not None:
        query = query.where(g.gateway_id == f.gateway_id)
    for key, value in (
        ("action", f.action),
        ("actor", f.actor),
        ("agent_id", f.agent),
        ("partner_id", f.partner),
    ):
        if value is not None:  # rows are stored as sorted, compact, ASCII-escaped JSON
            query = query.where(_contains(conn, g.row_json, _pair(key, value, ascii_only=True)))
    if f.since is not None:
        query = query.where(g.ts >= f.since)
    if f.until is not None:
        query = query.where(g.ts <= f.until)
    if after is not None:
        ts, rank, gid, generation, seq = after
        if rank < _RANK["gateway"]:
            query = query.where(g.ts < ts)
        else:
            position = row(g.ts, g.gateway_id, g.generation, g.seq)
            query = query.where(position < row(ts, gid, generation, seq))
    return query.order_by(g.ts.desc(), g.gateway_id.desc(), g.generation.desc(), g.seq.desc())


def _control_item(r: Any) -> dict[str, Any]:
    return {
        "source": "control",
        "gateway_id": None,
        "generation": None,
        "seq": r.seq,
        "ts": r.ts,
        "actor": r.actor,
        "action": r.action,
        "agent_id": r.agent_id,
        "partner_id": r.partner_id,
        "task_id": r.task_id,
        "classification": r.classification,
        "outcome": r.outcome,
        "detail": _dict(_loads(r.detail_json, {})),
        "prev_hash": r.prev_hash,
        "hash": r.hash,
    }


def _gateway_item(r: Any) -> dict[str, Any]:
    """A copied gateway row (the row as the gateway wrote it, with the stored ``ts``)."""
    data = _dict(_loads(r.row_json, {}))
    return {
        "source": "gateway",
        "gateway_id": r.gateway_id,
        "generation": r.generation,  # the gateway's sequence resets (see channel)
        "seq": r.seq,
        "ts": r.ts,
        **{
            k: _str(data.get(k))
            for k in (
                "actor",
                "action",
                "agent_id",
                "partner_id",
                "task_id",
                "classification",
                "outcome",
            )
        },
        "detail": _dict(data.get("detail")),
        "prev_hash": _str(data.get("prev_hash")),
        "hash": _str(data.get("hash")),
    }


def _matches(item: dict[str, Any], f: AuditFilters) -> bool:
    return all(
        value is None or item[key] == value
        for key, value in (
            ("action", f.action),
            ("actor", f.actor),
            ("agent_id", f.agent),
            ("partner_id", f.partner),
        )
    )


async def audit_page(
    store: ControlStore, log: AuditLog, f: AuditFilters, after: Position | None, limit: int
) -> tuple[list[dict[str, Any]], Position | None, bool]:
    """Up to ``limit`` rows of both sources after ``after``, newest first: ``(items, the
    position of the last row read, whether there are more)``. Each source is read with its
    own keyset (``limit + 1`` rows, one short query each) and the two are merged."""
    read: list[tuple[Position, dict[str, Any] | None]] = []
    async with store.engine.connect() as conn:
        if f.source in (None, "control"):
            query = _control_query(conn, log.table, f, after).limit(limit + 1)
            for r in (await conn.execute(query)).all():
                read.append(((r.ts, _RANK["control"], "", 0, r.seq), _control_item(r)))
        if f.source in (None, "gateway"):
            query = _gateway_query(conn, f, after).limit(limit + 1)
            for r in (await conn.execute(query)).all():
                # the SQL substring tests are exact for rows a gateway wrote; a row whose
                # fields still differ is read (its position counts) but not shown
                item = _gateway_item(r)
                keep = item if _matches(item, f) else None
                read.append(((r.ts, _RANK["gateway"], r.gateway_id, r.generation, r.seq), keep))
    read.sort(key=lambda pi: pi[0], reverse=True)
    chosen = read[:limit]
    items = [item for _pos, item in chosen if item is not None]
    return items, chosen[-1][0] if chosen else None, len(read) > limit


AUDIT_SHAPE: Shape = (float, int, str, int, int)


def _position(value: list[Any] | None) -> Position | None:
    return (value[0], value[1], value[2], value[3], value[4]) if value is not None else None


@route("GET", "/api/v1/audit", AUDIT_READ)
async def list_audit(request: Request, page: PageQuery, f: AuditQuery) -> dict[str, Any]:
    keyset = Keyset("audit", f.bound(), AUDIT_SHAPE, page)
    state = request.app.state
    items, last, more = await audit_page(
        state.store, state.audit, f, _position(keyset.after()), keyset.limit
    )
    return keyset.page(items, last, more)


def csv_cell(value: Any) -> str:
    """One CSV cell: objects as JSON, and a text that a spreadsheet would run as a formula
    (``= + - @``, tab, carriage return) prefixed with ``'``."""
    if value is None:
        text = ""
    elif isinstance(value, dict | list):
        text = json.dumps(value, sort_keys=True, separators=(",", ":"))
    else:
        text = str(value)
    return "'" + text if text.startswith(FORMULA_PREFIXES) else text


_SURROGATES = re.compile("[\ud800-\udfff]")


def utf8(text: str) -> bytes:
    """``text`` as UTF-8, a lone surrogate (which a gateway can send, and which UTF-8 cannot
    encode) replaced by U+FFFD."""
    return _SURROGATES.sub("\ufffd", text).encode("utf-8")


def _csv_lines(rows: Iterable[Sequence[Any]]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    for r in rows:
        writer.writerow([csv_cell(v) for v in r])
    return out.getvalue()


async def _export(
    request: Request, f: AuditFilters, render: Callable[[list[dict[str, Any]]], str]
) -> AsyncIterator[bytes]:
    """The rows of an export, ``EXPORT_BATCH`` per database read (each its own short
    connection, shielded from the client's disconnect like a stream poll), ``EXPORT_MAX``
    in all. At most one batch is in memory."""
    state = request.app.state
    background: channel.Background = state.background
    after: Position | None = None
    sent = 0
    while sent < EXPORT_MAX:
        limit = min(EXPORT_BATCH, EXPORT_MAX - sent)
        items, after, more = await background.run(
            audit_page(state.store, state.audit, f, after, limit)
        )
        if items:
            sent += len(items)
            yield utf8(render(items))
        if not more or after is None:
            return


@route("GET", "/api/v1/audit/export", AUDIT_READ)
async def export_audit(
    request: Request,
    f: AuditQuery,
    actor: Auditor,
    fmt: Literal["jsonl", "csv"] = Query("jsonl", alias="format"),
) -> StreamingResponse:
    store: ControlStore = request.app.state.store
    if store.audit is not None:
        detail = {"format": fmt, "source": f.source or "all", "fields": ",".join(f.used())}
        await store.audit.emit(
            AuditEvent(
                actor=actor.id,
                action="cp.audit.export",
                outcome="started",
                detail=detail,
                ts=request.app.state.clock(),
            )
        )

    def as_jsonl(items: list[dict[str, Any]]) -> str:
        return "".join(json.dumps(i, sort_keys=True, separators=(",", ":")) + "\n" for i in items)

    def as_csv(items: list[dict[str, Any]]) -> str:
        return _csv_lines([i[c] for c in CSV_COLUMNS] for i in items)

    async def body() -> AsyncIterator[bytes]:
        if fmt == "csv":
            yield utf8(_csv_lines([CSV_COLUMNS]))
        async for chunk in _export(request, f, as_csv if fmt == "csv" else as_jsonl):
            yield chunk

    media = "text/csv; charset=utf-8" if fmt == "csv" else "application/x-ndjson"
    return StreamingResponse(
        body(),
        media_type=media,
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": f'attachment; filename="a2agw-audit.{fmt}"',
        },
    )


@route("GET", "/api/v1/audit/verify", AUDIT_READ)
async def verify_audit(request: Request) -> dict[str, Any]:
    """Recompute the control plane's own chain (``cp_audit``); the first bad seq, if any.
    Gateways' chains are verified on each gateway (``a2agw audit verify``)."""
    log: AuditLog = request.app.state.audit
    bad = await log.verify_chain()
    return {"ok": bad is None, "first_bad_seq": bad}


# -- credentials ---------------------------------------------------------------------------


@route("GET", "/api/v1/credentials", READ)
async def list_credentials(request: Request, page: PageQuery) -> dict[str, Any]:
    """The credential and TLS reference names catalogue partners use, with the partners
    and the gateways they are assigned to. Gateways report no reference names (their info
    is version, agents, base URL and limits), so the catalogue is the only source."""
    keyset = Keyset("credentials", {}, (str, str), page)
    store: ControlStore = request.app.state.store
    query = select(PARTNERS.c.id, PARTNERS.c.credential_ref, PARTNERS.c.tls_ref).where(
        or_(PARTNERS.c.credential_ref.is_not(None), PARTNERS.c.tls_ref.is_not(None))
    )
    assigned_q = select(ASSIGNMENTS.c.ref_id, ASSIGNMENTS.c.gateway_id).where(
        ASSIGNMENTS.c.kind == "partner"
    )
    async with store.engine.connect() as conn:
        partners = (await conn.execute(query)).all()
        assigned: dict[str, set[str]] = {}
        for ref_id, gid in (await conn.execute(assigned_q)).all():
            assigned.setdefault(ref_id, set()).add(gid)
    refs: dict[tuple[str, str], tuple[set[str], set[str]]] = {}
    for pid, credential_ref, tls_ref in partners:
        for kind, name in (("credential", credential_ref), ("tls", tls_ref)):
            if name:
                users, gateways = refs.setdefault((kind, name), (set(), set()))
                users.add(pid)
                gateways.update(assigned.get(pid, ()))
    items = [
        (
            (kind, name),
            {"kind": kind, "name": name, "partners": sorted(users), "gateways": sorted(gws)},
        )
        for (kind, name), (users, gws) in refs.items()
    ]
    return paginate_sorted(keyset, items)
