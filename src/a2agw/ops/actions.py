"""Gateway write operations: one implementation, one audit trail.

The admin API (``a2agw.ops.admin``), the CLI (``a2agw partners ...``) and the control-plane
connector all change a gateway through these functions. Each takes the host first and the
acting principal as the keyword ``actor`` (``key:<id>``, ``jwt:<sub>``, ``cli:<user>``,
``cp:<command id>`` ...), and returns a JSON-able dict.

Auditing: partner changes are audited by the registry's listener (``registry_audit_event``,
installed by ``AgentHost`` and by the CLI), tagged with ``actor`` through
``PartnerRegistry.acting_as``; refusals and the reload, reap and policy operations are
audited here or by the host method they call. Errors are the underlying ones
(``KeyError`` unknown partner, ``ValueError`` invalid request, ``CardFetchError``,
``PartnersInUse``, ``ReloadConflict``, ``PolicyError``, ``AgentServedError``,
``RecentActivityError``); messages carry ids and field paths, never secrets.

Tasks: ``task_detail``, ``cancel_task`` and ``answer_task`` go through the agent's own A2A
request handler (``host.handlers[agent_id]``) with a server call context whose user is the
task's owner (``Principal.from_id(owner)``), so the SDK's owner-scoped store finds the task,
the cancel cascade runs and an answered task stays the owner's. An unknown agent and an
unknown task are the same ``TaskNotFound`` (one index lookup either way: nothing tells them
apart). ``TaskConflict`` carries the refusal ("task is final", "task is not waiting for
input"). All three are audited with ``actor``: ``admin.read`` (``detail.reason``
"tasks.detail"), ``task.cancel`` and ``task.answer`` (outcome ok / refused / not_found).

The CLI has no running gateway: it passes ``RegistryHost(registry)``, which supports the
partner operations. Without a handle store the open outbound tasks of a removed partner
are not counted there; a running gateway checks them again on its next partners reload
(``POST partners/reload`` refuses unless forced, and a forced reload cancels them).
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from a2a.server.context import ServerCallContext
from a2a.types import (
    CancelTaskRequest,
    GetTaskRequest,
    Message,
    Part,
    Role,
    SendMessageConfiguration,
    SendMessageRequest,
    Task,
    TaskNotCancelableError,
    TaskNotFoundError,
    TaskState,
    UnsupportedOperationError,
)
from google.protobuf.json_format import MessageToDict

from a2agw.consult.carddiff import card_diff
from a2agw.consult.registry import PartnerRecord, PartnerRegistry, ReloadConflict, card_hash
from a2agw.ops.audit import AuditEvent, AuditLog
from a2agw.security.policy import PolicyError, parse_policy, policy_hash
from a2agw.security.principal import Principal, PrincipalUser

if TYPE_CHECKING:
    from a2agw.consult.handles import OutboundHandleStore
    from a2agw.consult.netguard import Tier
    from a2agw.serve.host import AgentHost

logger = logging.getLogger(__name__)
PolicySource = Literal["file", "control_plane", "admin"]

HISTORY_MAX = 50  # task detail: the last messages shown
ARTIFACTS_MAX = 50  # task detail: the last artifacts shown
MAX_ANSWER_BYTES = 32 * 1024  # an operator's answer, UTF-8
ANSWERED_BY_KEY = "a2agw.answered_by"  # message metadata: who answered for the owner
TASK_FINAL = "task is final"
NOT_WAITING = "task is not waiting for input"


class TaskNotFound(LookupError):
    """No such task for that agent, or no such agent here: deliberately the same."""


class TaskConflict(Exception):
    """The task is in a state that refuses the operation; ``error`` says which."""

    def __init__(self, error: str) -> None:
        super().__init__(error)
        self.error = error


class PolicyManaged(Exception):
    """The control plane owns this gateway's policy: a local (admin) change is refused."""


@dataclass
class RegistryHost:
    """A partners file without a running gateway (the CLI): enough for the partner
    operations. No handle store, no audit log of its own (the CLI collects the registry's
    events and appends them to the configured database's log)."""

    partners: PartnerRegistry
    handles: OutboundHandleStore | None = None
    audit: AuditLog | None = None

    async def cancel_partner_tasks(
        self,
        partner_ids: list[str],
        *,
        actor: str = "system",
        disabled_for_removal: Iterable[str] = (),
    ) -> tuple[int, int]:
        """No partner client here: nothing to cancel with (a running gateway cancels them
        when its reload is forced)."""
        return 0, 0


def _summary(rec: PartnerRecord) -> dict[str, Any]:
    return {
        "id": rec.id,
        "tier": rec.tier,
        "status": rec.status,
        "card_hash": rec.card_hash,
        "card_url": rec.card_url,
        "pending_hash": card_hash(rec.pending_card) if rec.pending_card is not None else None,
    }


async def _emit(host: AgentHost | RegistryHost, ev: AuditEvent) -> None:
    audit = getattr(host, "audit", None)
    if audit is not None:
        await audit.emit(ev)


async def _refused(
    host: AgentHost | RegistryHost, actor: str, action: Any, partner_id: str, reason: str
) -> None:
    """A refused partner change (the registry's own messages: ids and reasons only)."""
    await _emit(
        host,
        AuditEvent(
            actor=actor,
            action=action,
            partner_id=partner_id,
            outcome="refused",
            detail={"reason": reason},
        ),
    )


# -- partners -------------------------------------------------------------------------------


async def add_partner(
    host: AgentHost | RegistryHost,
    *,
    actor: str,
    id: str,
    tier: Tier,
    card_url: str | None = None,
    card: dict[str, Any] | None = None,
    credential_ref: str | None = None,
    tls_ref: str | None = None,
    tags: Iterable[str] = (),
) -> dict[str, Any]:
    """Register a partner from its card URL (fetched, SSRF-checked, signature-verified) or
    from a card document (exactly one of ``card_url`` / ``card``)."""
    if (card_url is None) == (card is None):
        raise ValueError("add_partner needs exactly one of card_url or card")
    reg = host.partners
    with reg.acting_as(actor):
        if card_url is not None:
            rec = await reg.add_from_url(
                id, card_url, tier, credential_ref=credential_ref, tags=tags, tls_ref=tls_ref
            )
        else:
            assert card is not None
            rec = await reg.add_from_card(
                id, card, tier, credential_ref=credential_ref, tags=tags, tls_ref=tls_ref
            )
    return _summary(rec)


async def approve_partner(
    host: AgentHost | RegistryHost, id: str, *, actor: str, expected_hash: str | None
) -> dict[str, Any]:
    """Approve a quarantined card change (``expected_hash``: the hash the operator reviewed;
    a pending card that changed since is refused)."""
    reg = host.partners
    try:
        with reg.acting_as(actor):
            rec = reg.approve(id, expected_hash=expected_hash)
    except ValueError as exc:
        await _refused(host, actor, "partner.approve", id, str(exc))
        raise
    return _summary(rec)


async def reject_partner(host: AgentHost | RegistryHost, id: str, *, actor: str) -> dict[str, Any]:
    """Refuse a quarantined card change: keep the approved card, disable the partner."""
    reg = host.partners
    try:
        with reg.acting_as(actor):
            rec = reg.reject(id)
    except ValueError as exc:
        await _refused(host, actor, "partner.reject", id, str(exc))
        raise
    return _summary(rec)


async def disable_partner(host: AgentHost | RegistryHost, id: str, *, actor: str) -> dict[str, Any]:
    reg = host.partners
    with reg.acting_as(actor):
        rec = reg.disable(id)
    return _summary(rec)


async def enable_partner(host: AgentHost | RegistryHost, id: str, *, actor: str) -> dict[str, Any]:
    """Re-enable a disabled partner (straight into quarantine if it breaks require_signed:
    see ``status`` in the result)."""
    reg = host.partners
    with reg.acting_as(actor):
        rec = reg.enable(id)
    return _summary(rec)


async def remove_partner(
    host: AgentHost | RegistryHost, id: str, *, actor: str, force: bool = False
) -> dict[str, Any]:
    """Remove a partner. If it still has open outbound tasks the removal is refused with
    ``PartnersInUse`` (audited ``partner.remove`` / ``refused``) unless ``force``; forced,
    the partner is first disabled (no new consult starts), then those tasks are cancelled,
    best effort (``AgentHost.cancel_partner_tasks``, as ``reload_partners(force=True)``
    does), then the partner goes."""
    from a2agw.serve.host import PartnersInUse

    reg = host.partners
    reg.get(id)  # KeyError before anything else
    open_handles = cancelled = cancel_errors = 0
    if host.handles is not None:
        open_handles = (await host.handles.count_open([id])).get(id, 0)
    if open_handles and not force:
        await _emit(
            host,
            AuditEvent(
                actor=actor,
                action="partner.remove",
                partner_id=id,
                outcome="refused",
                detail={"reason": "open outbound tasks", "count": open_handles},
            ),
        )
        raise PartnersInUse(open_handles)
    if open_handles:
        # Disabled first: no new consult starts while its tasks are cancelled. Only a
        # partner that was active is still contacted for the cancels.
        was_active = reg.get(id).status == "active"
        with reg.acting_as(actor):
            if reg.get(id).status != "disabled":
                reg.disable(id)
        cancelled, cancel_errors = await host.cancel_partner_tasks(
            [id], actor=actor, disabled_for_removal=[id] if was_active else []
        )
    with reg.acting_as(actor):
        reg.remove(id)
    if open_handles:
        logger.warning(
            "partner %s removed with %d open outbound task(s) (%d cancelled, %d cancel errors)",
            id,
            open_handles,
            cancelled,
            cancel_errors,
        )
    return {
        "id": id,
        "removed": True,
        "open_handles": open_handles,
        "cancelled": cancelled,
        "cancel_errors": cancel_errors,
    }


async def refresh_partner(host: AgentHost | RegistryHost, id: str, *, actor: str) -> dict[str, Any]:
    """Re-fetch the partner's card now: ``result`` is "unchanged" or "quarantined" (a
    significant change is staged for approval)."""
    reg = host.partners
    with reg.acting_as(actor):
        result = await reg.refresh(id)
    return {**_summary(reg.get(id)), "result": result}


async def update_partner(
    host: AgentHost | RegistryHost, id: str, *, actor: str, **settings: Any
) -> dict[str, Any]:
    """Change operator-owned settings (``tier``, ``credential_ref``, ``tls_ref``, ``tags``,
    ``clear``): see ``PartnerRegistry.update_settings``. ``fields`` lists what changed."""
    reg = host.partners
    with reg.acting_as(actor):
        fields = reg.update_settings(id, **settings)
    return {"id": id, "fields": fields}


async def partner_detail(host: AgentHost | RegistryHost, id: str, *, actor: str) -> dict[str, Any]:
    """The full record (the approved card, any pending card and its ``card_diff``) for a
    review screen. Records hold credential and TLS ref names only, never secrets. A read:
    not audited here (the read route audits ``admin.read``)."""
    rec = host.partners.get(id)
    out = rec.model_dump(mode="json")
    pending = rec.pending_card
    out["pending_hash"] = card_hash(pending) if pending is not None else None
    out["diff"] = [c.as_dict() for c in card_diff(rec.card, pending)] if pending else []
    return out


async def reload_partners(host: AgentHost, *, actor: str, force: bool = False) -> dict[str, Any]:
    """Re-read the partners file into the running registry (``AgentHost.reload_partners``),
    audited as ``partner.reload`` with outcome ok / refused / conflict / error."""
    from a2agw.serve.host import PartnersInUse

    async def record(outcome: str, reason: str) -> None:
        await _emit(
            host,
            AuditEvent(
                actor=actor, action="partner.reload", outcome=outcome, detail={"reason": reason}
            ),
        )

    try:
        changes = await host.reload_partners(force=force, actor=actor)
    except PartnersInUse as exc:
        await record("refused", f"open handles {exc.open_handles}")
        raise
    except ReloadConflict:
        await record("conflict", "registry changed")
        raise
    except Exception as exc:
        # The message may quote the file: only its class goes to the audit.
        await record("error", type(exc).__name__)
        raise
    counts = ", ".join(f"{k} {len(v)}" for k, v in changes.items() if isinstance(v, list))
    await record("ok", counts)
    return changes


# -- tasks ----------------------------------------------------------------------------------


async def reap(
    host: AgentHost, agent_id: str, *, actor: str, confirm: bool, force: bool
) -> dict[str, Any]:
    """Fail the open tasks of an agent nobody serves (``AgentHost.reap``, audited
    ``task.reap``). Without ``confirm`` a dry run that only counts."""
    result = await host.reap(agent_id, confirm=confirm, force=force, actor=actor)
    if result.dry_run:
        return {
            "dry_run": True,
            "tasks": result.tasks,
            "handles": result.handles,
            "recent": result.recent,
        }
    report = result.report
    assert report is not None
    return {
        "dry_run": False,
        "reaped": len(report.failed),
        "outbound_cancelled": report.outbound_cancelled,
        "cancel_errors": len(report.cancel_errors),
        "errors": len(report.errors),
    }


# -- policy ---------------------------------------------------------------------------------


async def set_policy(
    host: AgentHost,
    policy_doc: dict[str, Any] | None,
    *,
    actor: str,
    source: PolicySource = "admin",
    allow_clear: bool = True,
) -> dict[str, Any]:
    """Validate ``policy_doc`` and put it in force at once (``AgentHost.set_policy``);
    ``None`` restores no-policy. An invalid document raises ``PolicyError`` (field paths
    only), changes nothing and is audited ``policy.update`` / ``rejected``. While the
    control plane manages the policy (``host.policy_managed``) an ``admin`` change raises
    ``PolicyManaged`` (audited ``refused``). ``allow_clear=False`` treats ``None`` as an
    invalid document (the admin API's PUT never clears the policy by accident)."""
    if source == "admin" and getattr(host, "policy_managed", False):
        await _emit(
            host,
            AuditEvent(
                actor=actor, action="policy.update", outcome="refused", detail={"reason": source}
            ),
        )
        raise PolicyManaged
    policy = None
    if policy_doc is not None or not allow_clear:
        try:
            policy = parse_policy(policy_doc)
        except PolicyError:
            await _emit(
                host,
                AuditEvent(
                    actor=actor,
                    action="policy.update",
                    outcome="rejected",
                    detail={"reason": source},
                ),
            )
            raise
    host.set_policy(policy, actor=actor, source=source)
    return {"applied": True, "hash": policy_hash(policy) if policy is not None else None}


def policy_state(host: AgentHost) -> dict[str, Any]:
    """The policy in force: ``managed`` (the control plane owns it), ``source`` (who set
    it: file, admin, control_plane; None if never set) and the document (None: no policy).
    A read: not audited here."""
    engine = host.policy
    return {
        "managed": bool(getattr(host, "policy_managed", False)),
        "source": getattr(host, "policy_source", None),
        "policy": engine.policy.model_dump(mode="json") if engine is not None else None,
    }


# -- task detail, cancel, answer ------------------------------------------------------------


def _owner_context(owner: str) -> ServerCallContext:
    """The call context of the task's owner, as the auth middleware builds it (no scopes):
    the SDK's owner-scoped task store resolves the owner from it."""
    return ServerCallContext(user=PrincipalUser(Principal.from_id(owner)))


async def _locate(host: AgentHost, agent_id: str, task_id: str) -> tuple[dict[str, Any], Any]:
    """The index row and request handler of an agent's task. Exactly one index lookup,
    whether the agent or the task is unknown or not, so the two are indistinguishable."""
    if host.index is None:
        raise RuntimeError("host not started")
    row = await host.index.get(agent_id, task_id)
    handler = host.handlers.get(agent_id)
    if row is None or handler is None:
        raise TaskNotFound
    return row, handler


async def _get_task(handler: Any, task_id: str, ctx: ServerCallContext) -> Task:
    try:
        task = await handler.on_get_task(GetTaskRequest(id=task_id), ctx)
    except TaskNotFoundError:
        raise TaskNotFound from None
    if task is None:
        raise TaskNotFound
    return task


async def _task_audit(
    host: AgentHost,
    action: Any,
    actor: str,
    agent_id: str,
    task_id: str,
    outcome: str,
    **detail: Any,
) -> None:
    await _emit(
        host,
        AuditEvent(
            actor=actor,
            action=action,
            agent_id=agent_id,
            task_id=task_id,
            outcome=outcome,
            detail={k: v for k, v in detail.items() if v is not None},
        ),
    )


def _part(part: Part) -> dict[str, Any]:
    """A part for display: text and data as they are; a file by name, MIME type and size
    only (never its bytes or URL)."""
    kind = part.WhichOneof("content")
    if kind == "text":
        return {"kind": "text", "text": part.text}
    if kind == "data":
        return {"kind": "data", "data": MessageToDict(part.data)}
    return {
        "kind": "file",
        "name": part.filename or None,
        "media_type": part.media_type or None,
        "size": len(part.raw) if kind == "raw" else None,
    }


def _text(message: Message) -> str | None:
    texts = [p.text for p in message.parts if p.WhichOneof("content") == "text"]
    return "\n".join(texts) if texts else None


def _message(message: Message) -> dict[str, Any]:
    """A history message. Metadata is left out (it carries call contexts and their
    signatures) except who answered for the owner."""
    out: dict[str, Any] = {
        "message_id": message.message_id,
        "role": Role.Name(message.role).removeprefix("ROLE_").lower(),
        "parts": [_part(p) for p in message.parts],
    }
    answered_by = MessageToDict(message.metadata).get(ANSWERED_BY_KEY)
    if isinstance(answered_by, str):
        out["answered_by"] = answered_by
    return out


async def task_detail(
    host: AgentHost, agent_id: str, task_id: str, *, actor: str
) -> dict[str, Any]:
    """One task for an operator: its index row, the last ``HISTORY_MAX`` messages and
    ``ARTIFACTS_MAX`` artifacts, the partner tasks it started (outbound handles) and the
    question it is waiting on (``pending_prompt``, input-required only). ``TaskNotFound``
    for an unknown agent or task. Audited ``admin.read`` (task contents are sensitive)."""
    try:
        row, handler = await _locate(host, agent_id, task_id)
        task = await _get_task(handler, task_id, _owner_context(row["owner"]))
    except TaskNotFound:
        await _task_audit(
            host, "admin.read", actor, agent_id, task_id, "not_found", reason="tasks.detail"
        )
        raise
    state = TaskState.Name(task.status.state)
    status_message = _text(task.status.message) if task.status.HasField("message") else None
    handles = await host.handles.by_inbound(task_id) if host.handles is not None else []
    out = {
        "task": {
            "id": task.id,
            "context_id": task.context_id,
            "state": state,
            "owner": row["owner"],
            "updated_at": row["updated_at"],
            "trace_id": row.get("trace_id"),
            "status_message": status_message,
            "history": [_message(m) for m in list(task.history)[-HISTORY_MAX:]],
            "artifacts": [
                {
                    "artifact_id": a.artifact_id,
                    "name": a.name or None,
                    "parts": [_part(p) for p in a.parts],
                }
                for a in list(task.artifacts)[-ARTIFACTS_MAX:]
            ],
        },
        "partner_tasks": [dict(h) for h in handles],
        "pending_prompt": (
            status_message if task.status.state == TaskState.TASK_STATE_INPUT_REQUIRED else None
        ),
    }
    await _task_audit(host, "admin.read", actor, agent_id, task_id, "ok", reason="tasks.detail")
    return out


async def cancel_task(
    host: AgentHost, agent_id: str, task_id: str, *, actor: str
) -> dict[str, Any]:
    """Cancel a task through its agent's handler (as its owner), so the cascade cancels the
    partner tasks it started. ``TaskConflict(TASK_FINAL)`` for a task already ended.
    Audited ``task.cancel``."""
    try:
        row, handler = await _locate(host, agent_id, task_id)
        result = await handler.on_cancel_task(
            CancelTaskRequest(id=task_id), _owner_context(row["owner"])
        )
    except (TaskNotFound, TaskNotFoundError):
        await _task_audit(host, "task.cancel", actor, agent_id, task_id, "not_found")
        raise TaskNotFound from None
    except TaskNotCancelableError:
        await _task_audit(
            host, "task.cancel", actor, agent_id, task_id, "refused", reason=TASK_FINAL
        )
        raise TaskConflict(TASK_FINAL) from None
    state = TaskState.Name(result.status.state)
    await _task_audit(host, "task.cancel", actor, agent_id, task_id, "ok", state=state)
    return {"state": state}


def check_answer(text: Any) -> str:
    """An answer's text: a non-empty string of at most ``MAX_ANSWER_BYTES`` (UTF-8), with no
    NUL. ValueError otherwise (the message never quotes it)."""
    if not isinstance(text, str) or not text:
        raise ValueError("text must be a non-empty string")
    if len(text.encode("utf-8", "surrogatepass")) > MAX_ANSWER_BYTES:
        raise ValueError(f"text is longer than {MAX_ANSWER_BYTES} bytes")
    if "\x00" in text:
        raise ValueError("text contains NUL")
    return text


async def answer_task(
    host: AgentHost, agent_id: str, task_id: str, text: str, *, actor: str
) -> dict[str, Any]:
    """Answer an input-required task for its owner: ``text`` goes in as a new user message
    (metadata ``a2agw.answered_by`` = ``actor``) through the agent's handler, with the
    owner's call context, so the task resumes and stays the owner's. The call returns once
    the turn has started (``state`` then). Auth-required and every other state raise
    ``TaskConflict(NOT_WAITING)``: an operator never supplies someone else's credentials.
    ValueError for bad ``text`` (``check_answer``). Audited ``task.answer``.

    One answer per task at a time (per process): the task is held in
    ``host.answers_in_flight`` from the state check until the send returns, so a second
    answer meanwhile (a double click) is refused ``NOT_WAITING`` instead of resuming the
    task twice (neither the SDK nor the executor serializes a second message to an open
    task)."""
    check_answer(text)
    try:
        row, handler = await _locate(host, agent_id, task_id)
    except TaskNotFound:
        await _task_audit(host, "task.answer", actor, agent_id, task_id, "not_found")
        raise
    key = (agent_id, task_id)
    in_flight: set[tuple[str, str]] = host.answers_in_flight
    if key in in_flight:
        await _task_audit(
            host,
            "task.answer",
            actor,
            agent_id,
            task_id,
            "refused",
            reason=NOT_WAITING,
            context="answer in progress",
        )
        raise TaskConflict(NOT_WAITING)
    in_flight.add(key)  # no await between the check and this
    try:
        return await _answer(host, handler, row, task_id, agent_id, text, actor=actor)
    finally:
        in_flight.discard(key)


async def _answer(
    host: AgentHost,
    handler: Any,
    row: dict[str, Any],
    task_id: str,
    agent_id: str,
    text: str,
    *,
    actor: str,
) -> dict[str, Any]:
    ctx = _owner_context(row["owner"])
    try:
        task = await _get_task(handler, task_id, ctx)
    except TaskNotFound:
        await _task_audit(host, "task.answer", actor, agent_id, task_id, "not_found")
        raise
    if task.status.state != TaskState.TASK_STATE_INPUT_REQUIRED:
        await _task_audit(
            host,
            "task.answer",
            actor,
            agent_id,
            task_id,
            "refused",
            reason=NOT_WAITING,
            state=TaskState.Name(task.status.state),
        )
        raise TaskConflict(NOT_WAITING)
    message = Message(
        message_id=uuid.uuid4().hex,
        role=Role.ROLE_USER,
        task_id=task.id,
        context_id=task.context_id,
        parts=[Part(text=text)],
    )
    message.metadata.update({ANSWERED_BY_KEY: actor})
    request = SendMessageRequest(
        message=message, configuration=SendMessageConfiguration(return_immediately=True)
    )
    try:
        result = await handler.on_message_send(request, ctx)
    except (UnsupportedOperationError, TaskNotFoundError):  # it ended meanwhile
        await _task_audit(
            host, "task.answer", actor, agent_id, task_id, "refused", reason=NOT_WAITING
        )
        raise TaskConflict(NOT_WAITING) from None
    state = TaskState.Name(result.status.state) if isinstance(result, Task) else "DIRECT_REPLY"
    await _task_audit(host, "task.answer", actor, agent_id, task_id, "ok", state=state)
    return {"state": state}
