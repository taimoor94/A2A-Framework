"""Console API: operator actions, each queued as a command for one gateway.

- ``POST /api/v1/tasks/{gateway_id}/{agent_id}/{task_id}/cancel`` (``tasks.operate``):
  ``task.cancel``.
- ``POST /api/v1/tasks/{gateway_id}/{agent_id}/{task_id}/answer`` ``{text}``
  (``tasks.operate``): ``task.answer``. ``text`` is at most ``ANSWER_MAX_BYTES`` bytes of
  UTF-8 (413 ``too_large`` beyond; 422 for an empty or malformed one). The text is not
  audited (the command row, which the gateway reads, holds it).
- ``POST /api/v1/gateways/{gateway_id}/reap`` ``{agent_id, confirm, force}``
  (``tasks.operate``): ``tasks.reap``.
- ``POST /api/v1/partners/{id}/gateways/{gateway_id}/refresh`` (``tasks.operate``):
  ``partner.refresh`` on one gateway.

Ids in these paths (and the reap body's ``agent_id``) are at most 256 characters with no
control characters (422 otherwise). A gateway with ``channel.OPEN_COMMANDS_MAX`` open
commands answers 429 ``too_many_requests``.
- ``GET /api/v1/commands/{id}`` (``read``): ``{id, gateway_id, kind, status, result, actor,
  created_at, finished_at}``. ``actor`` is its kind (``console`` for a signed-in user,
  ``key`` for an API key), like the other read views show no principal ids; a ``task.get``
  result goes through ``views.public_detail``.

Every action is its own command (never shared or reused, unlike ``task.get``), expires
``COMMAND_TTL_S`` (60 s) after it is queued and is audited ``cp.command`` (by
``enqueue_command``: the operator, the gateway and the command kind). A request waits up to
``OPERATE_WAIT_S`` for the gateway: 200 ``{command_id, status: "done", result}``; 409
``{command_id, status: "failed" | "expired", result}`` when the gateway reports a failure
(or the command expired); 202 ``{command_id, status: "pending" | "delivered"}`` otherwise
(follow it with ``GET /commands/{id}``). At most ``OPERATE_WAITERS_MAX`` requests wait at
once (per process); the others answer 202 at once. No database connection is held while
waiting.
"""

from __future__ import annotations

import re
from typing import Annotated, Any

from a2agw.control import require_fastapi

require_fastapi()

from fastapi import Depends, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, ConfigDict, Field, StrictBool
from sqlalchemy import select

from a2agw.control import channel
from a2agw.control.rbac import Actor, Permission, require, route
from a2agw.control.responses import JSONResponse
from a2agw.control.store import PARTNERS, ControlStore
from a2agw.control.views import PATH_ID_MAX, PATH_ID_PATTERN, PathId, public_detail

OPERATE = Permission.TASKS_OPERATE
READ = Permission.READ
Operator = Annotated[Actor, Depends(require(OPERATE))]
Reader = Annotated[Actor, Depends(require(READ))]

OPERATE_WAIT_S = 10.0  # how long an action waits for the gateway's answer
OPERATE_WAITERS_MAX = 16  # requests waiting for command results at once (per process)
ANSWER_MAX_BYTES = 32 * 1024  # an operator's answer, UTF-8 (like the gateway's limit)
OPEN = ("pending", "delivered")
_SURROGATE = re.compile("[\ud800-\udfff]")

_FORBID = ConfigDict(extra="forbid")


class OperateGate:
    """Bounds waiting (``app.state.operations``): at most ``OPERATE_WAITERS_MAX`` requests
    wait for command results at once; the others answer 202 at once."""

    def __init__(self) -> None:
        self.waiting = 0


class AnswerBody(BaseModel):
    model_config = _FORBID
    text: str


class ReapBody(BaseModel):
    model_config = _FORBID
    agent_id: str = Field(max_length=PATH_ID_MAX, pattern=PATH_ID_PATTERN)
    confirm: StrictBool = False
    force: StrictBool = False


def _not_found(what: str) -> HTTPException:
    return HTTPException(404, {"error": "not_found", "detail": f"unknown {what}"})


def _invalid(loc: tuple[str, ...], msg: str) -> RequestValidationError:
    return RequestValidationError([{"loc": loc, "msg": msg, "type": "value_error"}])


async def _operate(request: Request, actor: Actor, gateway_id: str, kind: str, args: Any) -> Any:
    state = request.app.state
    store: ControlStore = state.store
    gate: OperateGate = state.operations
    try:
        command_id = await channel.enqueue_command(store, gateway_id, kind, args, actor.id)
    except KeyError:
        raise _not_found("gateway") from None
    except ValueError:
        raise HTTPException(409, {"error": "conflict", "detail": "gateway is revoked"}) from None
    except channel.TooManyCommands:
        raise channel.queue_full() from None
    if gate.waiting >= OPERATE_WAITERS_MAX:
        command = await channel.get_command(store, command_id)
    else:
        gate.waiting += 1
        try:  # polls the command row: one short query per poll, no connection held between
            command = await channel.wait_command(
                store, command_id, OPERATE_WAIT_S, sleep=state.sleep
            )
        finally:
            gate.waiting -= 1
    status = _status(command, store.now())
    if status in OPEN:
        return JSONResponse({"command_id": command_id, "status": status}, status_code=202)
    body = {"command_id": command_id, "status": status, "result": command.result}
    return JSONResponse(body, status_code=200 if status == "done" else 409)


def _status(command: channel.CommandRow, now: float) -> str:
    """The command's status; one still ``pending`` past its expiry is ``expired`` already
    (final: the stream never delivers it, the maintenance pass only records it later). A
    ``delivered`` one stays so until the gateway's result or the sweep: the gateway may
    still report it done."""
    if command.status == "pending" and command.expires_at <= now:
        return "expired"
    return command.status


@route("POST", "/api/v1/tasks/{gateway_id}/{agent_id}/{task_id}/cancel", OPERATE)
async def cancel_task(
    gateway_id: PathId, agent_id: PathId, task_id: PathId, request: Request, actor: Operator
) -> Any:
    args = {"agent_id": agent_id, "task_id": task_id}
    return await _operate(request, actor, gateway_id, "task.cancel", args)


@route("POST", "/api/v1/tasks/{gateway_id}/{agent_id}/{task_id}/answer", OPERATE)
async def answer_task(
    gateway_id: PathId,
    agent_id: PathId,
    task_id: PathId,
    body: AnswerBody,
    request: Request,
    actor: Operator,
) -> Any:
    size = len(body.text.encode("utf-8", "surrogatepass"))
    if size > ANSWER_MAX_BYTES:
        raise HTTPException(
            413, {"error": "too_large", "detail": f"text is longer than {ANSWER_MAX_BYTES} bytes"}
        )
    if not body.text.strip():
        raise _invalid(("body", "text"), "text must not be empty")
    if "\x00" in body.text:
        raise _invalid(("body", "text"), "text contains NUL")
    if _SURROGATE.search(body.text):  # not UTF-8: the gateway refuses it too
        raise _invalid(("body", "text"), "text contains a lone surrogate")
    args = {"agent_id": agent_id, "task_id": task_id, "text": body.text}
    return await _operate(request, actor, gateway_id, "task.answer", args)


@route("POST", "/api/v1/gateways/{gateway_id}/reap", OPERATE)
async def reap_tasks(gateway_id: PathId, body: ReapBody, request: Request, actor: Operator) -> Any:
    args = {"agent_id": body.agent_id, "confirm": body.confirm, "force": body.force}
    return await _operate(request, actor, gateway_id, "tasks.reap", args)


@route("POST", "/api/v1/partners/{partner_id}/gateways/{gateway_id}/refresh", OPERATE)
async def refresh_partner(
    partner_id: PathId, gateway_id: PathId, request: Request, actor: Operator
) -> Any:
    store: ControlStore = request.app.state.store
    async with store.engine.connect() as conn:
        known = (
            await conn.execute(select(PARTNERS.c.id).where(PARTNERS.c.id == partner_id))
        ).scalar_one_or_none()
    if known is None:
        raise _not_found("partner")
    return await _operate(request, actor, gateway_id, "partner.refresh", {"id": partner_id})


def _actor_kind(actor: str) -> str:
    """Who queued a command, as a kind: ``key`` for an API key (``ak-...``), else
    ``console`` (a signed-in user)."""
    return "key" if actor.startswith("ak-") else "console"


@route("GET", "/api/v1/commands/{command_id}", READ)
async def get_command(command_id: str, request: Request, actor: Reader) -> dict[str, Any]:
    store: ControlStore = request.app.state.store
    try:
        command = await channel.get_command(store, command_id)
    except KeyError:
        raise _not_found("command") from None
    result = command.result
    if command.kind == "task.get" and isinstance(result, dict):
        result = public_detail(result)  # no principal ids for READ roles
    return {
        "id": command.id,
        "gateway_id": command.gateway_id,
        "kind": command.kind,
        "status": _status(command, store.now()),
        "result": result,
        "actor": _actor_kind(command.actor),
        "created_at": command.created_at,
        "finished_at": command.finished_at,
    }
