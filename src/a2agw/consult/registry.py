"""Partner registry: card fetch with SSRF guard, quarantine on significant card change."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import logging
import os
import re
import stat
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
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

from a2agw.consult.guarded_net import fixed_tier
from a2agw.consult.netguard import (
    FetchError,
    Tier,
    UnsafeURL,
    check_url,
    check_url_syntax,
    safe_get,
)
from a2agw.consult.tls import TlsClientConfig, build_async_client
from a2agw.security.cardsign import CardSignatureError, CardVerifier

logger = logging.getLogger(__name__)
MAX_CARD_BYTES = 1024 * 1024
FETCH_TIMEOUT_S = 10.0
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
# Everything except these top-level fields is significant (name/description reach LLM tool text).
COSMETIC_FIELDS = frozenset({"version", "documentationUrl", "iconUrl", "provider"})
# Signature bytes are not content (ECDSA re-signs differ every time); a change of signing key
# is judged separately, by the verified key id.
_NOT_COMPARED = COSMETIC_FIELDS | {"signatures"}

Status = Literal["active", "quarantined", "disabled"]
# Record fields owned by the operator (the config file is authoritative for them).
_SETTINGS = ("tier", "credential_ref", "tls_ref", "tags")
# Quarantine reasons of the require_signed invariant (see ``PartnerRegistry.signed_violation``).
UNSIGNED = "unsigned card"
KEY_UNTRUSTED = "signing key no longer trusted"


LOCK_RETRY_S = 0.02


class PartnersFileBusy(TimeoutError):
    """Another process held the partners file lock for longer than the registry waits."""


@contextmanager
def _file_lock(path: Path, timeout_s: float = 10.0) -> Iterator[None]:
    """Exclusive lock on ``<path>.lock`` (POSIX ``fcntl.flock``; elsewhere no lock), held
    while a registry re-reads and rewrites the partners file. Never waits longer than
    ``timeout_s`` (non-blocking attempts, retried): ``PartnersFileBusy`` after that."""
    lock_path = path.with_name(path.name + ".lock")
    try:
        import fcntl
    except ImportError:  # pragma: no cover - not POSIX
        yield
        return
    with open(lock_path, "a") as f:
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise PartnersFileBusy(f"{path.name} is locked by another process") from None
                time.sleep(LOCK_RETRY_S)
        try:
            yield
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def _write_durably(path: Path, text: str) -> None:
    """Replace ``path`` with ``text`` atomically and durably: a temporary file (never
    following a symlink, with the current file's mode, or 0644 under the umask for a new
    file) is fsynced before ``os.replace``, then the directory is fsynced, so a crash
    leaves either the old file or the new one, never an empty or truncated one."""
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except FileNotFoundError:
        mode = None
    tmp = path.with_name(path.name + ".tmp")
    try:
        tmp.unlink()  # a leftover temporary file, or a planted symlink: never written through
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        if mode is not None:
            os.fchmod(fd, mode)
        with os.fdopen(fd, "w") as f:
            fd = -1
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        if fd != -1:
            os.close(fd)
        tmp.unlink(missing_ok=True)
        raise
    try:
        dir_fd = os.open(path.parent, os.O_RDONLY)
    except OSError:  # pragma: no cover - platform without directory fds
        return
    try:
        os.fsync(dir_fd)
    except OSError:  # pragma: no cover - some filesystems refuse a directory fsync
        pass
    finally:
        os.close(dir_fd)


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
    def v03_only(self) -> bool:
        """True when every interface of the card is at A2A protocol 0.3: the partner is
        consulted through the SDK's 0.3 compatibility mode (spec 8.13). Derived from the
        card, so it is never stored."""
        versions = [
            i.get("protocolVersion") for i in self.card.get("supportedInterfaces", []) or []
        ]
        return bool(versions) and all(_major_minor(v) == (0, 3) for v in versions)

    @property
    def agent_card(self) -> AgentCard:
        return parse_agent_card(copy.deepcopy(self.card))


def _major_minor(version: Any) -> tuple[int, int] | None:
    if not isinstance(version, str):
        return None
    parts = version.strip().split(".")
    try:
        return int(parts[0]), int(parts[1]) if len(parts) > 1 else 0
    except ValueError:
        return None


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


class ReloadConflict(RuntimeError):
    """The registry changed between ``prepare_reload`` and ``apply_reload``."""


@dataclass
class ReloadPlan:
    """A validated partners file and its diff against the registry (``prepare_reload``)."""

    fresh: dict[str, PartnerRecord]
    added: list[str]
    updated: list[str]
    removed: list[str]
    version: int
    # Records of the file that break the require_signed invariant, quarantined in the plan.
    quarantined: dict[str, str] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)  # each entry as read from the file

    def changes(self) -> dict[str, list[str]]:
        return {"added": self.added, "updated": self.updated, "removed": self.removed}


class PartnerRegistry:
    """Registered partners. Card fetches go through a guarded client for the partner's tier
    (``a2agw.consult.guarded_net``: connects only to vetted addresses). An injected ``http``
    client is used as given and bypasses that guard: it is the test seam. mTLS card fetches
    (``tls_ref``) always use a guarded client, even when ``http`` is injected."""

    def __init__(
        self,
        path: Path | None = None,
        *,
        http: httpx.AsyncClient | None = None,
        verifier: CardVerifier | None = None,
        require_signed: frozenset[Tier] = frozenset(),
        tls: Mapping[str, TlsClientConfig] | None = None,
        lock_timeout_s: float = 10.0,
        defer_busy_saves: bool = False,
    ):
        if require_signed and verifier is None:
            raise ValueError("require_signed needs a verifier")
        self.path = path
        self._http = http
        self.tls: dict[str, TlsClientConfig] = dict(tls or {})
        for cfg in self.tls.values():  # load certificates now, not on the event loop later
            cfg.ssl_context()
        self.verifier = verifier
        self.require_signed = frozenset(require_signed)
        self._records: dict[str, PartnerRecord] = {}
        # Persistence (see ``save``): each record as this registry last read it from, or
        # wrote it to, the partners file, and the records changed since the last save.
        self._disk: dict[str, Any] = {}
        self._dirty: set[str] = set()
        self._version = 0  # bumped by every change (reload plans are checked against it)
        # How long a save waits for the partners file lock, and what a save does when it
        # cannot get it: raise ``PartnersFileBusy`` (the CLI: the operator must know), or
        # keep the changes unsaved with a WARNING until ``flush`` (the host: never stall
        # the event loop behind another process).
        self.lock_timeout_s = lock_timeout_s
        self.defer_busy_saves = defer_busy_saves
        self.on_change: Callable[[PartnerRecord, str], None] | None = None
        # Extra detail of the change being reported, readable from inside ``on_change``
        # (e.g. {"reason": ..., "actor": ..., "fields": ...}); None outside of it.
        self.change_info: dict[str, Any] | None = None
        self._listeners: list[Callable[[PartnerRecord, str], None]] = []
        self._actor: str | None = None  # see ``acting_as``

    # -- fetching -------------------------------------------------------
    async def _fetch(self, card_url: str, tier: Tier, tls_ref: str | None = None) -> dict[str, Any]:
        url = _card_urls(card_url)
        own: httpx.AsyncClient | None = None
        http = self._http
        if tls_ref is not None:  # mTLS partner: never fall back to a plain client
            cfg = self.tls.get(tls_ref)
            if cfg is None:
                raise CardFetchError("tls config missing")
            own = http = build_async_client(
                cfg, httpx.Timeout(FETCH_TIMEOUT_S), tier_for_host=fixed_tier(tier)
            )
        try:
            body = await safe_get(
                url, tier, max_bytes=MAX_CARD_BYTES, deadline_s=FETCH_TIMEOUT_S, http=http
            )
        except UnsafeURL as e:
            raise CardFetchError(f"unsafe card URL: {e}") from None
        except FetchError as e:
            raise CardFetchError(f"card fetch failed: {e}") from None
        finally:
            if own is not None:
                await own.aclose()
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
        tls_ref: str | None = None,
    ) -> PartnerRecord:
        self._check_new_id(id)
        raw = await self._fetch(url, tier, tls_ref)
        return await self._add(id, raw, tier, url, credential_ref, tags, tls_ref)

    async def add_from_card(
        self,
        id: str,
        card: dict[str, Any],
        tier: Tier,
        *,
        credential_ref: str | None = None,
        tags: Iterable[str] = (),
        tls_ref: str | None = None,
    ) -> PartnerRecord:
        self._check_new_id(id)
        return await self._add(id, card, tier, None, credential_ref, tags, tls_ref)

    def _check_new_id(self, id: str) -> None:
        if not _ID_RE.match(id):
            raise ValueError(f"invalid partner id: {id!r}")
        if id in self._records:
            raise ValueError(f"duplicate partner id: {id!r}")

    async def _add(self, id, raw, tier, url, credential_ref, tags, tls_ref=None) -> PartnerRecord:
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
            tls_ref=tls_ref,
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
        raw = await self._fetch(rec.card_url, rec.tier, rec.tls_ref)
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
        # Unchanged: nothing is written (fetched_at is kept in memory only), so a refresh
        # never touches the file another process may be editing.
        return "unchanged"

    def approve(self, id: str, expected_hash: str | None = None) -> PartnerRecord:
        rec = self.get(id)
        if rec.status == "disabled":
            raise ValueError("partner is disabled; re-enable explicitly before approving")
        if rec.pending_card is not None:
            if expected_hash is not None and expected_hash != card_hash(rec.pending_card):
                raise ValueError("pending card changed since it was reviewed")
            staged = rec.model_copy(
                update={"card": rec.pending_card, "signed_key_id": rec.pending_key_id}
            )
            violation = self.signed_violation(staged)
        else:
            violation = self.signed_violation(rec)
        if violation is not None:
            # Approval never activates a card the require_signed tiers would refuse: refresh
            # the partner to fetch (and verify) a signed card first.
            raise ValueError(f"cannot approve {id!r}: {violation}; refresh to verify a signed card")
        if rec.pending_card is not None:
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

    def suspend(self, ids: Iterable[str]) -> None:
        """Disable partners a prepared reload is about to remove, so no new consult starts
        while their open tasks are cancelled. In memory only: the file already lacks them,
        nothing is saved, and the registry version is kept, so the prepared plan stays
        applicable. Listeners see "disabled" (audited ``partner.disable``)."""
        for id in ids:
            rec = self._records.get(id)
            if rec is None or rec.status == "disabled":
                continue
            rec.status = "disabled"
            self._notify(rec, "disabled")

    def reject(self, id: str) -> PartnerRecord:
        """Refuse a quarantined card change: the pending card (and its key id) is dropped,
        the approved card is kept, and the partner is disabled (event "rejected"), so it is
        not called until an operator re-enables it. ValueError when nothing is pending."""
        rec = self.get(id)
        if rec.pending_card is None:
            raise ValueError(f"partner {id!r} has no pending card to reject")
        rec.pending_card = rec.pending_key_id = None
        rec.status = "disabled"
        self._changed(rec, "rejected")
        return rec

    def remove(self, id: str) -> None:
        """Remove a partner from the registry and the partners file (event "removed").
        KeyError for an unknown id. Open outbound tasks are the caller's concern
        (``AgentHost`` refuses removals that would orphan them unless forced)."""
        rec = self.get(id)
        del self._records[id]
        self._changed(rec, "removed")

    def enable(self, id: str) -> PartnerRecord:
        rec = self.get(id)
        if rec.status != "disabled":
            raise ValueError(f"partner {id!r} is not disabled (status: {rec.status})")
        violation = self.signed_violation(rec)
        if violation is not None:  # re-enabled, but straight into quarantine
            rec.status = "quarantined"
            self._changed(rec, "quarantined", reason=violation)
            return rec
        rec.status = "active"
        self._changed(rec, "enabled")
        return rec

    # -- the require_signed invariant -------------------------------------------------
    def signed_violation(self, rec: PartnerRecord) -> str | None:
        """Why ``rec`` breaks the require_signed invariant, or None if it holds.

        A record whose tier is in ``require_signed`` needs a ``signed_key_id`` (else
        ``UNSIGNED``) that the current verifier still trusts (else ``KEY_UNTRUSTED``): a
        pinned key must still be pinned with the same key material, and the stored card must
        still verify against it locally; a JWKS key needs its URL still allowlisted. Fails
        closed: any error is a violation."""
        if rec.tier not in self.require_signed:
            return None
        if not rec.signed_key_id:
            return UNSIGNED
        if self.verifier is None:
            return KEY_UNTRUSTED
        try:
            card = parse_agent_card(copy.deepcopy(rec.card))
            ok = self.verifier.still_trusts(rec.signed_key_id, card)
        except Exception:  # noqa: BLE001 - fail closed
            ok = False
        return None if ok else KEY_UNTRUSTED

    def enforce_signed(self, ids: Iterable[str] | None = None) -> dict[str, str]:
        """Quarantine every (or every listed) active record that breaks the require_signed
        invariant; ``on_change`` reports each as "quarantined" with ``change_info["reason"]``.
        Returns {id: reason}."""
        out: dict[str, str] = {}
        for pid in list(self._records) if ids is None else list(ids):
            rec = self._records.get(pid)
            if rec is None or rec.status != "active":
                continue
            reason = self.signed_violation(rec)
            if reason is not None:
                rec.status = "quarantined"
                out[pid] = reason
                self._changed(rec, "quarantined", reason=reason)
        return out

    def _quarantine_fresh(self, records: dict[str, PartnerRecord]) -> dict[str, str]:
        """``enforce_signed`` on records read from the file but not yet installed: their
        status is changed in place, nothing is reported. Returns {id: reason}."""
        out: dict[str, str] = {}
        for pid, rec in records.items():
            if rec.status != "active":
                continue
            reason = self.signed_violation(rec)
            if reason is not None:
                rec.status = "quarantined"
                out[pid] = reason
        return out

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
    @contextmanager
    def acting_as(self, actor: str) -> Iterator[None]:
        """Changes made inside report ``change_info["actor"] = actor`` (e.g. "config" while
        ``register_partners`` applies the config file, ``cli:<user>`` for the CLI)."""
        previous, self._actor = self._actor, actor
        try:
            yield
        finally:
            self._actor = previous

    def update_settings(
        self,
        id: str,
        *,
        tier: Tier | None = None,
        credential_ref: str | None = None,
        tls_ref: str | None = None,
        tags: Iterable[str] | None = None,
        clear: Iterable[str] = (),
    ) -> list[str]:
        """Set operator-owned fields of a record (``tier``, ``credential_ref``, ``tls_ref``,
        ``tags``); ``clear`` names ref fields to set to None. Returns the names of the fields
        that changed (reported as one "updated" event with ``change_info["fields"]``). A new
        tier is then checked against require_signed (quarantined if it now breaks it)."""
        rec = self.get(id)
        wanted: dict[str, Any] = {}
        if tier is not None:
            wanted["tier"] = tier
        if credential_ref is not None:
            wanted["credential_ref"] = credential_ref
        if tls_ref is not None:
            wanted["tls_ref"] = tls_ref
        if tags is not None:
            wanted["tags"] = list(tags)
        for name in clear:
            if name not in ("credential_ref", "tls_ref"):
                raise ValueError(f"cannot clear {name}")
            wanted[name] = None
        fields = [f for f in _SETTINGS if f in wanted and getattr(rec, f) != wanted[f]]
        if not fields:
            return []
        for f in fields:
            setattr(rec, f, wanted[f])
        self._changed(rec, "updated", fields=fields)
        self.enforce_signed([id])
        return fields

    def _changed(self, rec: PartnerRecord, event: str, **info: Any) -> None:
        self._version += 1
        self._dirty.add(rec.id)
        if self.path is not None:
            self._save_dirty()
        self._notify(rec, event, info)

    def add_listener(self, fn: Callable[[PartnerRecord, str], None]) -> None:
        """Call ``fn(rec, event)`` on every change, after ``on_change`` (which stays the
        single user-settable callback); ``change_info`` is readable from inside it."""
        self._listeners.append(fn)

    def remove_listener(self, fn: Callable[[PartnerRecord, str], None]) -> None:
        """Stop calling ``fn`` (added with ``add_listener``); unknown ones are ignored."""
        with contextlib.suppress(ValueError):
            self._listeners.remove(fn)

    def _notify(self, rec: PartnerRecord, event: str, info: dict[str, Any] | None = None) -> None:
        callbacks = [cb for cb in (self.on_change, *self._listeners) if cb is not None]
        if not callbacks:
            return
        info = dict(info or {})
        if self._actor is not None:
            info.setdefault("actor", self._actor)
        self.change_info = info or None
        try:
            for cb in callbacks:
                cb(rec, event)
        finally:
            self.change_info = None

    def save(self) -> None:
        """Write every in-memory record to the partners file, merge-safe (see
        ``_save_dirty``): records only on disk stay, and a record changed on disk since this
        registry read or wrote it keeps its disk version (WARNING)."""
        self._dirty.update(self._records)
        self._dirty.update(set(self._disk) - set(self._records))  # removed here: removed there
        self._save_dirty()

    @property
    def unsaved(self) -> bool:
        """Whether changes are waiting to be written to the partners file."""
        return self.path is not None and bool(self._dirty)

    def flush(self) -> None:
        """Write the changes a busy lock kept unsaved (see ``defer_busy_saves``)."""
        self._save_dirty()

    def _save_dirty(self) -> None:
        try:
            self._save_dirty_locked()
        except PartnersFileBusy:
            if not self.defer_busy_saves:
                raise
            logger.warning(
                "partners file %s busy (locked by another process); %d change(s) kept "
                "unsaved, retried on the next save or maintenance pass",
                self.path.name if self.path else "",
                len(self._dirty),
            )

    def _save_dirty_locked(self) -> None:
        """Write the records changed since the last save, and nothing else.

        Under an exclusive lock on the sidecar ``<file>.lock`` (taken by every registry
        that saves, the host's and the CLI's), the current file is re-read; each changed
        record replaces its entry (new ones are appended) unless that entry was changed on
        disk since this registry last read or wrote it. Then the entry on disk wins, this
        registry's change to it is not written, and a WARNING asks for a reload. Every
        other entry is written back exactly as it was read. The file is replaced
        atomically (temporary file, then ``os.replace``). An unreadable file is never
        overwritten: the save is skipped with a WARNING."""
        if self.path is None or not self._dirty:
            return
        path = self.path
        path.parent.mkdir(parents=True, exist_ok=True)
        with _file_lock(path, self.lock_timeout_s):
            try:
                entries = self._read_raw(path) if path.exists() else []
            except ValueError as e:
                logger.warning("partners file not saved: %s; fix the file, then reload", e)
                return
            index = {e["id"]: i for i, e in enumerate(entries) if isinstance(e, dict)}
            written: list[str] = []
            order = list(self._records)
            removed: set[str] = set()
            for pid in sorted(self._dirty, key=lambda i: order.index(i) if i in order else -1):
                rec = self._records.get(pid)
                on_disk = entries[index[pid]] if pid in index else None
                if rec is None and pid not in self._disk:
                    continue
                if on_disk != self._disk.get(pid):
                    logger.warning(
                        "partner %s was changed in %s by another process; its change here "
                        "was not written (reload the partners file to see the current one)",
                        pid,
                        path.name,
                    )
                    continue
                if rec is None:  # gone from this registry: drop the unchanged disk entry
                    if pid in index:
                        removed.add(pid)
                    self._disk.pop(pid, None)
                    written.append(pid)
                    continue
                dump = rec.model_dump(mode="json")
                if pid in index:
                    entries[index[pid]] = dump
                else:
                    index[pid] = len(entries)
                    entries.append(dump)
                written.append(pid)
            self._dirty.clear()
            if not written:
                return
            entries = [e for e in entries if not (isinstance(e, dict) and e.get("id") in removed)]
            text = yaml.safe_dump({"partners": entries}, sort_keys=False)
            _write_durably(path, text)
            reread = {e["id"]: e for e in yaml.safe_load(text)["partners"]}
            for pid in written:
                if pid in reread:
                    self._disk[pid] = reread[pid]

    def load(self) -> None:
        if self.path is None or not self.path.exists():
            return
        self._records, self._disk = self._read_file_and_raw(self.path)
        self._dirty.clear()
        self._version += 1
        # The invariant holds however a record got into the file (written before
        # require_signed was turned on, a key since removed from the trust config, an edit).
        self.enforce_signed()

    def prepare_reload(self) -> ReloadPlan:
        """Read and validate the partners file and diff it against the registry, without
        changing anything (ValueError if there is no file path or the file is invalid; a
        missing file counts as empty). Apply the plan with ``apply_reload``."""
        if self.path is None:
            raise ValueError("registry has no partners file")
        fresh, raw = self._read_file_and_raw(self.path) if self.path.exists() else ({}, {})
        quarantined = self._quarantine_fresh(fresh)
        old = self._records
        updated = [
            i
            for i in fresh
            if i in old and fresh[i].model_dump(mode="json") != old[i].model_dump(mode="json")
        ]
        return ReloadPlan(
            fresh=fresh,
            added=[i for i in fresh if i not in old],
            updated=updated,
            removed=[i for i in old if i not in fresh],
            version=self._version,
            quarantined=quarantined,
            raw=raw,
        )

    def apply_reload(self, plan: ReloadPlan) -> dict[str, list[str]]:
        """Apply a plan in one step (no await): new partners are added, changed records
        replace the old ones, removed ones go, unchanged records keep their identity.
        ``on_change`` fires per partner ("added", "updated", "removed"); the file is not
        rewritten. ReloadConflict if the registry changed since the plan was made."""
        if plan.version != self._version:
            raise ReloadConflict("partner registry changed during reload")
        old = self._records
        keep = set(old) - set(plan.updated)
        self._records = {i: old[i] if i in keep else r for i, r in plan.fresh.items()}
        # The file now is what was read: the base for later merge-safe saves.
        self._disk = dict(plan.raw)
        self._dirty &= set(self._records)
        self._version += 1
        if self.on_change is not None or self._listeners:
            for event, ids, source in (
                ("added", plan.added, self._records),
                ("updated", plan.updated, self._records),
                ("removed", plan.removed, old),
            ):
                for i in ids:
                    self._notify(source[i], event, self._event_info(old, source[i], event))
            for i, reason in plan.quarantined.items():
                if i in plan.added or i in plan.updated:
                    self._notify(self._records[i], "quarantined", {"reason": reason})
        return plan.changes()

    @staticmethod
    def _event_info(
        old: dict[str, PartnerRecord], rec: PartnerRecord, event: str
    ) -> dict[str, Any] | None:
        """Reload: an updated record whose status changed reports that transition."""
        prev = old.get(rec.id)
        if event != "updated" or prev is None or prev.status == rec.status:
            return None
        return {"from_status": prev.status}

    def reload(self) -> dict[str, list[str]]:
        """Re-read the partners file (e.g. after ``a2agw partners add`` on a running host):
        ``prepare_reload`` then ``apply_reload``. A ``PartnerClient`` on this registry sees
        the result on its next call. Returns the ids per change."""
        return self.apply_reload(self.prepare_reload())

    def _read_file(self, path: Path) -> dict[str, PartnerRecord]:
        return self._read_file_and_raw(path)[0]

    @staticmethod
    def _read_raw(path: Path) -> list[Any]:
        """The file's ``partners`` entries as parsed (ValueError if it is not valid)."""
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (yaml.YAMLError, UnicodeDecodeError) as e:
            # The parser's message quotes the offending lines: never pass it on.
            raise ValueError(f"partner file is not valid YAML ({type(e).__name__})") from None
        if not isinstance(data, dict) or not isinstance(data.get("partners"), list):
            raise ValueError("partner file must be a mapping with a 'partners' list")  # noqa: TRY004
        return data["partners"]

    def _read_file_and_raw(self, path: Path) -> tuple[dict[str, PartnerRecord], dict[str, Any]]:
        records: dict[str, PartnerRecord] = {}
        raw: dict[str, Any] = {}
        for item in self._read_raw(path):
            snapshot = copy.deepcopy(item)
            rec = self._validate_loaded(item)
            if rec.id in records:
                raise ValueError(f"duplicate partner id in file: {rec.id!r}")
            records[rec.id] = rec
            raw[rec.id] = snapshot
        return records, raw

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
