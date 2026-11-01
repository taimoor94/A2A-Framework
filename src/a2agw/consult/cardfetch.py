"""Fetching and checking an Agent Card: the path ``PartnerRegistry`` uses, shared with the
control plane's partner catalogue.

- ``fetch_card(url, tier)``: the card document (a JSON object) behind a card URL, fetched
  with the SSRF guard of ``tier`` (``netguard.safe_get``: no redirects, a size cap, one
  deadline; a guarded client for the tier unless ``http`` is injected, the test seam).
- ``normalize_card(raw)``: parsed by the A2A SDK and dumped back, so every stored card has
  one canonical shape; ``card_hash`` is the SHA-256 of its sorted, compact JSON.
- ``verify_signature``: the verified key id for a tier that requires signed cards.
- ``check_endpoints``: every interface URL passes ``check_url`` for the tier.

Every failure is a ``CardFetchError``; its subclass names what failed (the class name is
what the control plane answers with, never the message).
"""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any
from urllib.parse import urlsplit

import httpx
from a2a.client.card_resolver import parse_agent_card
from a2a.types import AgentCard
from a2a.utils.constants import AGENT_CARD_WELL_KNOWN_PATH
from google.protobuf.json_format import MessageToDict

from a2agw.consult.guarded_net import fixed_tier
from a2agw.consult.netguard import FetchError, Tier, UnsafeURL, check_url, safe_get
from a2agw.consult.tls import TlsClientConfig, build_async_client
from a2agw.security.cardsign import CardSignatureError, CardVerifier

MAX_CARD_BYTES = 1024 * 1024
FETCH_TIMEOUT_S = 10.0


class CardFetchError(Exception):
    """The Agent Card could not be fetched or validated."""


class UnsafeCardURL(CardFetchError):
    """The card URL was refused by the SSRF guard of the tier."""


class CardUnavailable(CardFetchError):
    """The card could not be fetched (network, status, size or time limit)."""


class InvalidCard(CardFetchError):
    """The document is not a valid Agent Card."""


class CardSignatureInvalid(CardFetchError):
    """A tier that requires signed cards got a card whose signature does not verify."""


class UnsafeInterfaceURL(CardFetchError):
    """An interface URL of the card was refused by the SSRF guard of the tier."""


class TlsConfigMissing(CardFetchError):
    """The partner's ``tls_ref`` names no client-certificate config here."""


def card_hash(card: dict[str, Any]) -> str:
    blob = json.dumps(card, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


def normalize_card(card: dict[str, Any]) -> tuple[dict[str, Any], AgentCard]:
    try:
        proto = parse_agent_card(copy.deepcopy(card))
    except Exception as e:  # noqa: BLE001 - any parse failure is a bad card
        raise InvalidCard(f"invalid agent card: {type(e).__name__}") from None
    return MessageToDict(proto), proto


def card_document_url(base: str) -> str:
    """The URL the card is fetched from: ``base`` itself when it names a ``.json`` file,
    else the well-known card path under it."""
    parts = urlsplit(base)
    if parts.path.endswith(".json"):
        return base
    return base.rstrip("/") + AGENT_CARD_WELL_KNOWN_PATH


async def fetch_card(
    card_url: str,
    tier: Tier,
    *,
    http: httpx.AsyncClient | None = None,
    tls: TlsClientConfig | None = None,
    deadline_s: float = FETCH_TIMEOUT_S,
    max_bytes: int = MAX_CARD_BYTES,
) -> dict[str, Any]:
    """The card document behind ``card_url`` (not yet normalized). With ``tls`` (an mTLS
    partner) a guarded client presenting that certificate is used, never ``http``."""
    url = card_document_url(card_url)
    own: httpx.AsyncClient | None = None
    if tls is not None:
        own = http = build_async_client(
            tls, httpx.Timeout(deadline_s), tier_for_host=fixed_tier(tier)
        )
    try:
        body = await safe_get(url, tier, max_bytes=max_bytes, deadline_s=deadline_s, http=http)
    except UnsafeURL as e:
        raise UnsafeCardURL(f"unsafe card URL: {e}") from None
    except FetchError as e:
        raise CardUnavailable(f"card fetch failed: {e}") from None
    finally:
        if own is not None:
            await own.aclose()
    try:
        data = json.loads(body)
    except ValueError:
        raise InvalidCard("agent card is not valid JSON") from None
    if not isinstance(data, dict):
        raise InvalidCard("agent card must be a JSON object")
    return data


async def verify_signature(
    proto: AgentCard,
    tier: Tier,
    *,
    verifier: CardVerifier | None,
    require_signed: frozenset[Tier],
) -> str | None:
    """The verified key id when ``tier`` requires signed cards, else None (not checked).

    Raises ``CardSignatureError`` when a required signature does not verify. Any other
    error inside the verifier is reported the same way: verification fails closed."""
    if tier not in require_signed:
        return None
    if verifier is None:  # never treat as verified
        raise CardSignatureError("no card verifier configured")
    try:
        return (await verifier.verify(proto)).id
    except CardSignatureError:
        raise
    except Exception as e:  # noqa: BLE001
        raise CardSignatureError(f"verification error: {type(e).__name__}") from None


async def check_endpoints(proto: AgentCard, tier: Tier) -> None:
    """``UnsafeInterfaceURL`` unless every interface URL passes ``check_url`` for ``tier``."""
    for iface in proto.supported_interfaces:
        try:
            await check_url(iface.url, tier)
        except UnsafeURL as e:
            raise UnsafeInterfaceURL(f"unsafe interface URL: {e}") from None
