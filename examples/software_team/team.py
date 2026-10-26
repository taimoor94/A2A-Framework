"""Wire the three agents into one AgentHost and register the partners."""

from __future__ import annotations

from pathlib import Path

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from google.protobuf.json_format import MessageToDict

from a2agw.consult.netguard import Tier
from a2agw.context.signing import CallContextSigner, CallContextVerifier
from a2agw.security.cardsign import CardSigner, CardVerifier, load_public_key
from a2agw.serve.agent import build_card
from a2agw.serve.host import AgentHost

from .architect import architect_agent
from .pm import pm_agent
from .security import security_agent

KID = "software-team-1"


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


async def build_team(
    base_url: str,
    *,
    db_url: str,
    partner_http: httpx.AsyncClient | None = None,
    signing_dir: Path | None = None,
) -> AgentHost:
    """A host serving pm, architect and security at ``{base_url}/agents/{id}``.

    architect and security are registered as ``internal`` partners from their card JSON (the
    same card the host will serve), so pm sees them as ``ask_architect`` / ``ask_security``.
    The audit log is on (the ``AgentHost`` default).

    With ``signing_dir``, a fresh Ed25519 key is generated there and the team runs signed:
    every card the host serves is signed, the partner cards are registered signed and
    verified against that key (the ``internal`` tier requires signatures), and pm's partner
    calls carry signed call contexts, which the agents verify.
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
    host = AgentHost(
        base_url,
        db_url=db_url,
        partner_http=partner_http,
        audit=True,
        card_signer=card_signer,
        card_verifier=card_verifier,
        require_signed=require_signed,
        context_signer=context_signer,
        context_verifier=context_verifier,
    )
    partners = [architect_agent(), security_agent()]
    host.add(pm_agent(host))
    for spec in partners:
        host.add(spec)
    for spec in partners:
        card = build_card(spec, base_url, security=None)
        if card_signer is not None:
            card = card_signer.sign(card)
        await host.partners.add_from_card(spec.id, MessageToDict(card), "internal")
    return host
