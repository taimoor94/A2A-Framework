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

The CLI has no running gateway: it passes ``RegistryHost(registry)``, which supports the
partner operations. Without a handle store the open outbound tasks of a removed partner
are not counted there; a running gateway checks them again on its next partners reload
(``POST partners/reload`` refuses unless forced, and a forced reload cancels them).
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from a2agw.consult.carddiff import card_diff
from a2agw.consult.registry import PartnerRecord, PartnerRegistry, ReloadConflict, card_hash
from a2agw.ops.audit import AuditEvent, AuditLog
from a2agw.security.policy import PolicyError, parse_policy, policy_hash

if TYPE_CHECKING:
    from a2agw.consult.handles import OutboundHandleStore
    from a2agw.consult.netguard import Tier
    from a2agw.serve.host import AgentHost

logger = logging.getLogger(__name__)
PolicySource = Literal["file", "control_plane", "admin"]


@dataclass
class RegistryHost:
    """A partners file without a running gateway (the CLI): enough for the partner
    operations. No handle store, no audit log of its own (the CLI collects the registry's
    events and appends them to the configured database's log)."""

    partners: PartnerRegistry
    handles: OutboundHandleStore | None = None
    audit: AuditLog | None = None

    async def cancel_partner_tasks(
        self, partner_ids: list[str], *, actor: str = "system"
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
    with reg.acting_as(actor):
        rec = reg.approve(id, expected_hash=expected_hash)
    return _summary(rec)


async def reject_partner(host: AgentHost | RegistryHost, id: str, *, actor: str) -> dict[str, Any]:
    """Refuse a quarantined card change: keep the approved card, disable the partner."""
    reg = host.partners
    with reg.acting_as(actor):
        rec = reg.reject(id)
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
    those tasks are cancelled first, best effort (``AgentHost.cancel_partner_tasks``, as
    ``reload_partners(force=True)`` does), then the partner goes."""
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
        cancelled, cancel_errors = await host.cancel_partner_tasks([id], actor=actor)
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
) -> dict[str, Any]:
    """Validate ``policy_doc`` and put it in force at once (``AgentHost.set_policy``);
    ``None`` restores no-policy. An invalid document raises ``PolicyError`` (field paths
    only), changes nothing and is audited ``policy.update`` / ``rejected``."""
    policy = None
    if policy_doc is not None:
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
