"""Wire the three agents into one AgentHost and register the partners."""

from __future__ import annotations

import httpx
from google.protobuf.json_format import MessageToDict

from a2agw.serve.agent import build_card
from a2agw.serve.host import AgentHost

from .architect import architect_agent
from .pm import pm_agent
from .security import security_agent


async def build_team(
    base_url: str, *, db_url: str, partner_http: httpx.AsyncClient | None = None
) -> AgentHost:
    """A host serving pm, architect and security at ``{base_url}/agents/{id}``.

    architect and security are registered as ``internal`` partners from their card JSON (the
    same card the host will serve), so pm sees them as ``ask_architect`` / ``ask_security``.
    Call ``host.startup()`` (or run ``host.app()`` with its lifespan) before use.
    """
    host = AgentHost(base_url, db_url=db_url, partner_http=partner_http)
    partners = [architect_agent(), security_agent()]
    host.add(pm_agent(host))
    for spec in partners:
        host.add(spec)
    for spec in partners:
        card = MessageToDict(build_card(spec, base_url, security=None))
        await host.partners.add_from_card(spec.id, card, "internal")
    return host
