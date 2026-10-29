"""Wire the agents into one AgentHost and register the partners.

Phase 1: pm, architect and security, all in Python. Phase 3 adds a Node ``coder`` (a webhook
agent, ``examples/node_coder``) and an MCP-only agent, ``pm-desk`` (``examples/mcp_client``),
which reaches the network through the gateway's MCP server.
"""

from __future__ import annotations

from pathlib import Path

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from google.protobuf.json_format import MessageToDict

from a2agw.adapters.webhook import WebhookAdapter
from a2agw.consult.credentials import StaticCredentials
from a2agw.consult.netguard import Tier
from a2agw.context.signing import CallContextSigner, CallContextVerifier
from a2agw.ops.admin import SIDECAR_SCOPE
from a2agw.security.auth import ApiKeyEntry, AuthConfig, hash_api_key
from a2agw.security.cardsign import CardSigner, CardVerifier, load_public_key
from a2agw.serve.agent import AgentSpec, SkillSpec, build_card
from a2agw.serve.host import AgentHost

from .architect import architect_agent
from .pm import pm_agent
from .security import security_agent

KID = "software-team-1"
MCP_AGENT = "pm-desk"  # the MCP-only agent's id (spec 7.7 sidecar identity)
MCP_PRINCIPAL = "pm-desk-client"  # its API key's principal: key:pm-desk-client
TEAM_PRINCIPAL = "team"  # the key the agents' partner calls carry (credential_ref "team")


def generate_signing_key(directory: Path) -> tuple[Path, Path]:
    """A fresh Ed25519 key pair in ``directory`` (private key mode 0600): (private, public)."""
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    from a2agw import cli

    key = ed25519.Ed25519PrivateKey.generate()
    private, public = directory / "signing.pem", directory / "signing.pub.pem"
    private.unlink(missing_ok=True)
    # The CLI's writer: created 0600 from the start, never through a symlink.
    cli._write_private(
        private,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    public.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return private, public


def coder_agent(url: str, secret: str) -> AgentSpec:
    """The Node coder, served through the webhook transport (HMAC-signed invokes)."""
    return AgentSpec(
        id="coder",
        name="Coder",
        description="Writes code from a design (a Node webhook agent); asks security to review it.",
        skills=[
            SkillSpec(
                id="code",
                name="Write code",
                description="Implements a design as code.",
                examples=["Implement the design: ..."],
            )
        ],
        adapter=WebhookAdapter(url, secret=secret),
    )


async def build_team(
    base_url: str,
    *,
    db_url: str,
    partner_http: httpx.AsyncClient | None = None,
    signing_dir: Path | None = None,
    coder_url: str | None = None,
    coder_secret: str | None = None,
    mcp_key: str | None = None,
    team_key: str | None = None,
) -> AgentHost:
    """A host serving pm, architect and security at ``{base_url}/agents/{id}``.

    architect and security are registered as ``internal`` partners from their card JSON (the
    same card the host will serve), so pm sees them as ``ask_architect`` / ``ask_security``.
    The audit log is on (the ``AgentHost`` default).

    With ``signing_dir``, a fresh Ed25519 key is generated there and the team runs signed:
    every card the host serves is signed, the partner cards are registered signed and
    verified against that key (the ``internal`` tier requires signatures), and pm's partner
    calls carry signed call contexts, which the agents verify.

    With ``coder_url`` (and its ``coder_secret``), the Node coder at that webhook URL is served
    as ``coder`` and registered as a partner; pm then asks it for the code between the design
    and the review.

    With ``mcp_key`` (and ``team_key``), auth is on: ``mcp_key`` is the MCP-only agent's API
    key (principal ``key:pm-desk-client``, scope ``a2agw:sidecar``, mapped to agent id
    ``pm-desk`` in ``sidecar_clients``), ``pm-desk`` is served over MCP at
    ``/a2agw/mcp/pm-desk``, pm is registered as a partner too, and every partner call
    carries ``team_key`` (``StaticCredentials``, credential_ref ``team``).
    Call ``host.startup()`` (or run ``host.app()`` with its lifespan) before use.
    """
    card_signer = card_verifier = context_signer = context_verifier = None
    require_signed: frozenset[Tier] = frozenset()
    if signing_dir is not None:
        private, public = generate_signing_key(signing_dir)
        card_signer = CardSigner(private, KID, "EdDSA")
        card_verifier = CardVerifier(trusted={KID: load_public_key(public)})
        require_signed = frozenset({"internal"})
        context_signer = CallContextSigner(private, KID, "EdDSA", base_url)
        context_verifier = CallContextVerifier({})  # the host adds its own key
    if coder_url is not None and not coder_secret:
        raise ValueError("coder_url needs coder_secret")
    auth = credentials = credential_ref = None
    sidecar: dict = {}
    if mcp_key is not None:
        if not team_key:
            raise ValueError("mcp_key needs team_key")
        auth = AuthConfig(
            api_keys={
                hash_api_key(team_key): ApiKeyEntry(principal_id=TEAM_PRINCIPAL),
                hash_api_key(mcp_key): ApiKeyEntry(
                    principal_id=MCP_PRINCIPAL, scopes=[SIDECAR_SCOPE]
                ),
            }
        )
        credentials = StaticCredentials({TEAM_PRINCIPAL: {"X-API-Key": team_key}})
        credential_ref = TEAM_PRINCIPAL
        sidecar = {
            "sidecar_clients": {f"key:{MCP_PRINCIPAL}": [MCP_AGENT]},
            "mcp_agents": [MCP_AGENT],
        }
    host = AgentHost(
        base_url,
        db_url=db_url,
        partner_http=partner_http,
        auth=auth,
        credentials=credentials,
        audit=True,
        card_signer=card_signer,
        card_verifier=card_verifier,
        require_signed=require_signed,
        context_signer=context_signer,
        context_verifier=context_verifier,
        **sidecar,
    )
    partners = [architect_agent(), security_agent()]
    if coder_url is not None:
        assert coder_secret is not None
        partners.append(coder_agent(coder_url, coder_secret))
    pm = pm_agent(host, coder=coder_url is not None)
    host.add(pm)
    for spec in partners:
        host.add(spec)
    if mcp_key is not None:
        partners.insert(0, pm)  # pm-desk consults pm
    for spec in partners:
        card = build_card(spec, base_url, security=None)
        if card_signer is not None:
            card = card_signer.sign(card)
        await host.partners.add_from_card(
            spec.id, MessageToDict(card), "internal", credential_ref=credential_ref
        )
    return host
