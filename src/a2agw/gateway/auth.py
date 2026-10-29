"""Who is calling the gateway's sidecar APIs (the outbound REST API and the MCP server).

A sidecar call acts as one agent id, established in one of two ways:

1. **Linked:** ``Authorization: Bearer <consult token>``, a token the host issued for one
   turn of an external agent (``a2agw.gateway.tokens``). The token decides the agent id; an
   ``X-A2AGW-Agent`` header is ignored.
2. **Standalone:** the gateway's normal auth (API key or JWT) for a principal with the
   ``a2agw:sidecar`` scope, plus ``X-A2AGW-Agent: <agent id>``, an agent id that
   ``sidecar.clients`` maps that principal to.

Anything else is refused: 401, or 403 for an agent id the principal is not mapped to. Each
refusal is audited as ``sidecar.denied`` with the reason and the agent id only (never a
token or a key). An agent id that is not a valid one (``AGENT_ID_PATTERN``) counts as none.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from a2agw.ops.admin import SIDECAR_SCOPE
from a2agw.ops.audit import AuditEvent
from a2agw.security.principal import Principal, PrincipalUser
from a2agw.serve.agent import AGENT_ID_PATTERN

if TYPE_CHECKING:
    from starlette.requests import Request

    from a2agw.gateway.tokens import Binding
    from a2agw.serve.host import AgentHost

__all__ = [
    "AGENT_HEADER",
    "MCP_EXTRA_HINT",
    "MCP_PREFIX",
    "SidecarAuthError",
    "SidecarIdentity",
    "audit_denied",
    "from_headers",
    "resolve_sidecar",
    "valid_agent_id",
]

AGENT_HEADER = "x-a2agw-agent"
MCP_PREFIX = "/a2agw/mcp"  # the MCP server's mount (``a2agw.gateway.mcp_server``)
MCP_EXTRA_HINT = "the MCP server needs the mcp extra: pip install 'a2a-gateway[mcp]'"

# Refusal reasons (audited; fixed text, never a value from the request).
NOT_AUTHENTICATED = "not authenticated"
MISSING_SCOPE = "missing a2agw:sidecar scope"
NO_AGENT = "no agent id"
AGENT_NOT_ALLOWED = "agent not allowed for principal"
OTHER_AGENT = "consult token for another agent"  # MCP: the path names the agent

_AGENT_ID = re.compile(AGENT_ID_PATTERN)


def valid_agent_id(value: str) -> bool:
    """Whether ``value`` is a valid agent id (``AGENT_ID_PATTERN``). A sidecar agent id from
    a request (the ``X-A2AGW-Agent`` header, the MCP path) that is not counts as none
    (``NO_AGENT``): it is never used, nor audited."""
    return _AGENT_ID.fullmatch(value) is not None


@dataclass(frozen=True)
class SidecarIdentity:
    """The agent a sidecar call acts as; ``binding`` for a linked call (a consult token),
    else ``principal`` (the standalone caller)."""

    agent_id: str
    binding: Binding | None
    principal: Principal | None


class SidecarAuthError(Exception):
    """A refused sidecar call: ``status`` is 401 or 403, ``reason`` fixed text."""

    def __init__(
        self,
        status: Literal[401, 403],
        reason: str,
        *,
        agent_id: str | None = None,
        principal: Principal | None = None,
    ) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.agent_id = agent_id
        self.principal = principal


def _bearer(headers: Mapping[str, str]) -> str | None:
    scheme, _, value = (headers.get("authorization") or "").partition(" ")
    if scheme.lower() != "bearer":
        return None
    return value.strip() or None


def from_headers(
    headers: Mapping[str, str], principal: Principal | None, host: AgentHost
) -> SidecarIdentity:
    """The identity of a sidecar call from its headers (a Starlette ``Headers``, or a mapping
    with lower-case names) and the principal the gateway's auth established (None when it
    established none). Raises ``SidecarAuthError``; audits nothing (see ``audit_denied``)."""
    token = _bearer(headers)
    if token is not None:
        binding = host.consult_tokens.resolve(token)
        if binding is not None:
            return SidecarIdentity(binding.agent_id, binding, binding.caller)
    agent_id = headers.get(AGENT_HEADER) or None
    if agent_id is not None and not valid_agent_id(agent_id):
        agent_id = None  # counts as no agent id: never used, nor audited
    if principal is None or principal.kind == "anonymous":
        raise SidecarAuthError(401, NOT_AUTHENTICATED, agent_id=agent_id, principal=principal)
    if SIDECAR_SCOPE not in principal.scopes:
        raise SidecarAuthError(401, MISSING_SCOPE, agent_id=agent_id, principal=principal)
    if agent_id is None:
        raise SidecarAuthError(401, NO_AGENT, principal=principal)
    if agent_id not in host.sidecar_clients.get(principal.id, ()):
        raise SidecarAuthError(403, AGENT_NOT_ALLOWED, agent_id=agent_id, principal=principal)
    return SidecarIdentity(agent_id, None, principal)


async def audit_denied(host: AgentHost, err: SidecarAuthError) -> None:
    """One ``sidecar.denied`` row: the reason and the agent id. Refusals of callers the
    gateway could not authenticate are coalesced (one row per reason per window)."""
    log = host.audit
    if log is None:
        return
    p = err.principal
    authenticated = p is not None and p.kind != "anonymous"
    ev = AuditEvent(
        actor=p.id if p is not None and authenticated else "anonymous",
        action="sidecar.denied",
        agent_id=err.agent_id,
        outcome="forbidden" if err.status == 403 else "unauthenticated",
        detail={"reason": err.reason},
    )
    if authenticated:
        await log.emit(ev)
    else:
        await log.emit_coalesced(ev, f"sidecar:{err.reason}")


async def resolve_sidecar(request: Request, host: AgentHost) -> SidecarIdentity:
    """``from_headers`` for a Starlette request (its principal is the one the host's auth
    middleware stored); a refusal is audited, then raised."""
    user = request.scope.get("user")
    principal = user.principal if isinstance(user, PrincipalUser) else None
    try:
        return from_headers(request.headers, principal, host)
    except SidecarAuthError as err:
        await audit_denied(host, err)
        raise
