"""Partner registry: card fetch with SSRF guard, quarantine on significant card change."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import time
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx
import yaml
from a2a.client.card_resolver import parse_agent_card
from a2a.types import AgentCard
from a2a.utils.constants import AGENT_CARD_WELL_KNOWN_PATH
from google.protobuf.json_format import MessageToDict
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from a2agw.consult.netguard import (
    FetchError,
    Tier,
    UnsafeURL,
    check_url,
    check_url_syntax,
    safe_get,
)
from a2agw.security.cardsign import CardSignatureError, CardVerifier

MAX_CARD_BYTES = 1024 * 1024
FETCH_TIMEOUT_S = 10.0
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
# Everything except these top-level fields is significant (name/description reach LLM tool text).
COSMETIC_FIELDS = frozenset({"version", "documentationUrl", "iconUrl", "provider"})
# Signature bytes are not content (ECDSA re-signs differ every time); a change of signing key
# is judged separately, by the verified key id.
_NOT_COMPARED = COSMETIC_FIELDS | {"signatures"}

Status = Literal["active", "quarantined", "disabled"]


class CardFetchError(Exception):
    """The Agent Card could not be fetched or validated."""


def card_hash(card: dict[str, Any]) -> str:
    blob = json.dumps(card, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


class PartnerRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    card_url: str | None = None
    card: dict[str, Any]
    card_hash: str
    tier: Tier
    status: Status = "active"
    credential_ref: str | None = None
    tags: list[str] = Field(default_factory=list)
    fetched_at: float = 0.0
    ttl_s: int = 3600
    pending_card: dict[str, Any] | None = None
    # VerifiedKey.id ("source#kid#thumbprint") of the key that verified `card` /
    # `pending_card`; None when the tier is not signature-checked. Both default to None so
    # Phase 1 partner files still load.
    signed_key_id: str | None = None
    pending_key_id: str | None = None
    # Name of the client-certificate config (PartnerClient ``tls``) used to call this partner.
    tls_ref: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _drop_legacy_kid_fields(cls, data: Any) -> Any:
        # Early Phase 2 files pinned a bare kid, which is not a key identity. Drop it: the
        # partner re-pins (via quarantine + approve) on its first verified refresh.
        if isinstance(data, dict) and ("signed_kid" in data or "pending_kid" in data):
            data = {k: v for k, v in data.items() if k not in ("signed_kid", "pending_kid")}
        return data

    @field_validator("id")
    @classmethod
    def _valid_id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError(f"invalid partner id: {v!r}")
        return v

    @property
    def agent_card(self) -> AgentCard:
        return parse_agent_card(copy.deepcopy(self.card))


def _normalize(card: dict[str, Any]) -> tuple[dict[str, Any], AgentCard]:
    try:
        proto = parse_agent_card(copy.deepcopy(card))
    except Exception as e:  # noqa: BLE001 - any parse failure is a bad card
        raise CardFetchError(f"invalid agent card: {type(e).__name__}") from None
    return MessageToDict(proto), proto


def _card_urls(base: str) -> str:
    parts = urlsplit(base)
    if parts.path.endswith(".json"):
        return base
    return base.rstrip("/") + AGENT_CARD_WELL_KNOWN_PATH


def _significant_differs(old: dict[str, Any], new: dict[str, Any]) -> bool:
    keys = (set(old) | set(new)) - _NOT_COMPARED
    return any(old.get(k) != new.get(k) for k in keys)


class PartnerRegistry:
    def __init__(
        self,
        path: Path | None = None,
        *,
        http: httpx.AsyncClient | None = None,
        verifier: CardVerifier | None = None,
        require_signed: frozenset[Tier] = frozenset(),
    ):
        if require_signed and verifier is None:
            raise ValueError("require_signed needs a verifier")
        self.path = path
        self._http = http
        self.verifier = verifier
        self.require_signed = frozenset(require_signed)
        self._records: dict[str, PartnerRecord] = {}
        self.on_change: Callable[[PartnerRecord, str], None] | None = None

    # -- fetching -------------------------------------------------------
    async def _fetch(self, card_url: str, tier: Tier) -> dict[str, Any]:
        url = _card_urls(card_url)
        try:
            body = await safe_get(
                url, tier, max_bytes=MAX_CARD_BYTES, deadline_s=FETCH_TIMEOUT_S, http=self._http
            )
        except UnsafeURL as e:
            raise CardFetchError(f"unsafe card URL: {e}") from None
        except FetchError as e:
            raise CardFetchError(f"card fetch failed: {e}") from None
        try:
            data = json.loads(body)
        except ValueError:
            raise CardFetchError("agent card is not valid JSON") from None
        if not isinstance(data, dict):
            raise CardFetchError("agent card must be a JSON object")
        return data

    async def _verify_signature(self, proto: AgentCard, tier: Tier) -> str | None:
        """The verified key id when `tier` requires signed cards, else None (not checked).

        Raises CardSignatureError when a required signature does not verify. Any other
        error inside the verifier is reported the same way: verification fails closed."""
        if tier not in self.require_signed:
            return None
        if self.verifier is None:  # unreachable via __init__; never treat as verified
            raise CardSignatureError("no card verifier configured")
        try:
            return (await self.verifier.verify(proto)).id
        except CardSignatureError:
            raise
        except Exception as e:  # noqa: BLE001
            raise CardSignatureError(f"verification error: {type(e).__name__}") from None

    async def _check_endpoints(self, proto: AgentCard, tier: Tier) -> None:
        for iface in proto.supported_interfaces:
            try:
                await check_url(iface.url, tier)
            except UnsafeURL as e:
                raise CardFetchError(f"unsafe interface URL: {e}") from None

    # -- mutations ------------------------------------------------------
    async def add_from_url(
        self,
        id: str,
        url: str,
        tier: Tier,
        *,
        credential_ref: str | None = None,
        tags: Iterable[str] = (),
    ) -> PartnerRecord:
        self._check_new_id(id)
        raw = await self._fetch(url, tier)
        return await self._add(id, raw, tier, url, credential_ref, tags)

    async def add_from_card(
        self,
        id: str,
        card: dict[str, Any],
        tier: Tier,
        *,
        credential_ref: str | None = None,
        tags: Iterable[str] = (),
    ) -> PartnerRecord:
        self._check_new_id(id)
        return await self._add(id, card, tier, None, credential_ref, tags)

    def _check_new_id(self, id: str) -> None:
        if not _ID_RE.match(id):
            raise ValueError(f"invalid partner id: {id!r}")
        if id in self._records:
            raise ValueError(f"duplicate partner id: {id!r}")

    async def _add(self, id, raw, tier, url, credential_ref, tags) -> PartnerRecord:
        card, proto = _normalize(raw)
        try:
            key_id = await self._verify_signature(proto, tier)
        except CardSignatureError:
            raise CardFetchError("card signature invalid") from None
        await self._check_endpoints(proto, tier)
        if id in self._records:  # re-check after awaits
            raise ValueError(f"duplicate partner id: {id!r}")
        rec = PartnerRecord(
            id=id,
            card_url=url,
            card=card,
            card_hash=card_hash(card),
            tier=tier,
            credential_ref=credential_ref,
            tags=list(tags),
            fetched_at=time.time(),
            signed_key_id=key_id,
        )
        self._records[id] = rec
        self._changed(rec, "added")
        return rec

    async def verify_endpoints(self, id: str) -> None:
        """Run the full SSRF check on a stored card's interface URLs (call before use)."""
        rec = self.get(id)
        await self._check_endpoints(rec.agent_card, rec.tier)

    async def refresh(self, id: str) -> Literal["unchanged", "quarantined"]:
        rec = self.get(id)
        if rec.status == "disabled" or not rec.card_url:
            return "unchanged"
        raw = await self._fetch(rec.card_url, rec.tier)
        card, proto = _normalize(raw)
        signature_ok = True
        try:
            key_id = await self._verify_signature(proto, rec.tier)
        except CardSignatureError:
            signature_ok, key_id = False, None
        if signature_ok:
            await self._check_endpoints(proto, rec.tier)
        if self._records.get(id) is not rec or rec.status == "disabled":
            return "unchanged"  # changed while we awaited
        rec.fetched_at = time.time()
        if not signature_ok:
            # Fail closed, and never stage an unverified card for approval.
            rec.pending_card = rec.pending_key_id = None
            rec.status = "quarantined"
            self._changed(rec, "quarantined")
            return "quarantined"
        new_hash = card_hash(card)
        # Any change of key identity (source, kid or key material) is significant.
        key_changed = rec.tier in self.require_signed and key_id != rec.signed_key_id
        if key_changed or _significant_differs(rec.card, card):
            rec.pending_card, rec.pending_key_id = card, key_id
            rec.status = "quarantined"
            self._changed(rec, "quarantined")
            return "quarantined"
        # Same significant content (and key) as the approved card: apply cosmetics, lift quarantine.
        changed = new_hash != rec.card_hash or rec.status == "quarantined"
        if rec.tier not in self.require_signed and rec.signed_key_id is not None:
            # Not verified this time: drop the stale pin so it cannot silently match later.
            rec.signed_key_id = None
            changed = True
        rec.card, rec.card_hash = card, new_hash
        rec.pending_card = rec.pending_key_id = None
        rec.status = "active"
        if changed:
            self._changed(rec, "updated")
        elif self.path is not None:
            self.save()
        return "unchanged"

    def approve(self, id: str, expected_hash: str | None = None) -> PartnerRecord:
        rec = self.get(id)
        if rec.status == "disabled":
            raise ValueError("partner is disabled; re-enable explicitly before approving")
        if rec.pending_card is not None:
            if expected_hash is not None and expected_hash != card_hash(rec.pending_card):
                raise ValueError("pending card changed since it was reviewed")
            rec.card = rec.pending_card
            rec.card_hash = card_hash(rec.card)
            rec.signed_key_id = rec.pending_key_id
            rec.pending_card = rec.pending_key_id = None
        elif expected_hash is not None and expected_hash != rec.card_hash:
            raise ValueError("card changed since it was reviewed")
        rec.status = "active"
        self._changed(rec, "approved")
        return rec

    def disable(self, id: str) -> PartnerRecord:
        rec = self.get(id)
        rec.status = "disabled"
        self._changed(rec, "disabled")
        return rec

    def enable(self, id: str) -> PartnerRecord:
        rec = self.get(id)
        if rec.status != "disabled":
            raise ValueError(f"partner {id!r} is not disabled (status: {rec.status})")
        rec.status = "active"
        self._changed(rec, "enabled")
        return rec

    # -- queries --------------------------------------------------------
    def get(self, id: str) -> PartnerRecord:
        try:
            return self._records[id]
        except KeyError:
            raise KeyError(f"unknown partner: {id!r}") from None

    def active(self) -> list[PartnerRecord]:
        return [r for r in self._records.values() if r.status == "active"]

    def all(self) -> list[PartnerRecord]:
        return list(self._records.values())

    # -- persistence ----------------------------------------------------
    def _changed(self, rec: PartnerRecord, event: str) -> None:
        if self.path is not None:
            self.save()
        if self.on_change is not None:
            self.on_change(rec, event)

    def save(self) -> None:
        if self.path is None:
            return
        data = {"partners": [r.model_dump(mode="json") for r in self._records.values()]}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(yaml.safe_dump(data, sort_keys=False))
        os.replace(tmp, self.path)

    def load(self) -> None:
        if self.path is None or not self.path.exists():
            return
        data = yaml.safe_load(self.path.read_text())
        if not isinstance(data, dict) or not isinstance(data.get("partners"), list):
            raise ValueError("partner file must be a mapping with a 'partners' list")  # noqa: TRY004
        records: dict[str, PartnerRecord] = {}
        for item in data["partners"]:
            rec = self._validate_loaded(item)
            if rec.id in records:
                raise ValueError(f"duplicate partner id in file: {rec.id!r}")
            records[rec.id] = rec
        self._records = records

    @staticmethod
    def _validate_loaded(item: Any) -> PartnerRecord:
        if not isinstance(item, dict):
            raise ValueError("partner entry must be a mapping")  # noqa: TRY004
        rec = PartnerRecord.model_validate(item)
        if card_hash(rec.card) != rec.card_hash:
            raise ValueError(f"card hash mismatch for partner {rec.id!r}")
        try:
            rec.card, proto = _normalize(rec.card)
            if rec.pending_card is not None:
                rec.pending_card, _ = _normalize(rec.pending_card)
            if rec.card_url is not None:
                check_url_syntax(rec.card_url)
            for iface in proto.supported_interfaces:
                check_url_syntax(iface.url)
        except (CardFetchError, UnsafeURL) as e:
            raise ValueError(f"invalid partner {rec.id!r}: {e}") from None
        rec.card_hash = card_hash(rec.card)
        return rec
