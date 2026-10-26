"""OAuth2 outbound credentials: client credentials (RFC 6749 4.4) and token exchange (RFC 8693).

Both providers fetch tokens from a ``token_url`` that must be https (plain http only with
``A2AGW_DEV=1``) and pass ``check_url(..., tier)`` (``tier`` defaults to ``public``; use
``internal`` for an identity provider on a private network), with no redirects, a 64 KiB response cap and a 10 s deadline. They authenticate as the client
with HTTP Basic (the secret is read from an environment variable at fetch time, never kept),
cache tokens until 30 s before they expire, fetch at most once at a time per cache key
(a failed fetch is remembered for 5 s, so callers queued behind it fail fast during an
identity provider outage), and expose ``invalidate(partner, token)`` so the partner client
can refresh once after an HTTP 401.

Tokens are only ever sent to partners whose ``credential_ref`` is set and, when ``refs`` is
given, listed in it. Tokens live in memory only; nothing is persisted.

Secrets (the client secret, issued tokens and the inbound token being exchanged) never
appear in a repr, a log line or an error message; token endpoint failures never include the
response body.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import inspect
import json
import math
import os
import time
from collections import OrderedDict
from collections.abc import Callable, Hashable
from dataclasses import dataclass, field
from urllib.parse import quote_plus

import httpx
import jwt

from a2agw.consult.credentials import CredentialError, CredentialProvider, MissingCredential
from a2agw.consult.netguard import FetchError, Tier, UnsafeURL, require_https, safe_post
from a2agw.consult.registry import PartnerRecord
from a2agw.context.call_context import current_inbound_token, maintenance_call
from a2agw.security.principal import Principal

__all__ = ["OAuthClientCredentials", "OAuthTokenExchange", "TokenError"]

TOKEN_MAX_BYTES = 64 * 1024
TOKEN_DEADLINE_S = 10.0
EXPIRY_MARGIN_S = 30.0
MAX_LIFETIME_S = 24 * 3600.0  # an absurd expires_in is capped
EXCHANGE_CACHE_SIZE = 1024
NEGATIVE_CACHE_S = 5.0  # a failed fetch is reported to callers for this long

TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"


def _now() -> float:  # module level so tests can move the clock
    return time.monotonic()


class TokenError(CredentialError):
    """The token endpoint was refused or failed. Never includes secrets or the response body."""

    def __init__(self, ref: str | None, reason: str) -> None:
        super().__init__(f"credential {ref!r}: token endpoint {reason}")
        self.ref = ref
        self.reason = reason


@dataclass
class _Lock:
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    users: int = 0


class _OAuthProvider:
    """Shared token fetch, cache and single-flight logic."""

    def __init__(
        self,
        token_url: str,
        client_id: str,
        client_secret_env: str,
        refs: set[str] | None,
        http: httpx.AsyncClient | None,
        cache_size: int,
        tier: Tier = "public",
    ) -> None:
        if tier not in ("internal", "partner", "public"):
            raise ValueError(f"invalid token endpoint tier: {tier!r}")
        # Fail early (https on every tier); the full tier check runs per fetch.
        require_https(token_url)
        self.tier: Tier = tier
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret_env = client_secret_env
        self.refs = frozenset(refs) if refs is not None else None
        self._http = http
        self._cache_size = cache_size
        self._cache: OrderedDict[Hashable, tuple[str, float]] = OrderedDict()
        self._failed: dict[Hashable, tuple[str, float]] = {}  # key -> (safe message, until)
        self._locks: dict[Hashable, _Lock] = {}

    def __repr__(self) -> str:
        refs = sorted(self.refs) if self.refs is not None else None
        return (
            f"{type(self).__name__}(token_url={self.token_url!r}, client_id={self.client_id!r}, "
            f"client_secret_env={self.client_secret_env!r}, refs={refs!r})"
        )

    def _applies(self, partner: PartnerRecord) -> bool:
        ref = partner.credential_ref
        return ref is not None and (self.refs is None or ref in self.refs)

    def _cached(self, key: Hashable) -> str | None:
        hit = self._cache.get(key)
        if hit is None:
            return None
        token, refresh_at = hit
        if _now() >= refresh_at:
            del self._cache[key]
            return None
        self._cache.move_to_end(key)
        return token

    def _drop(self, key: Hashable, token: str | None) -> None:
        """Drop the cached token for ``key``; with ``token``, only if it is that token (a
        newer one fetched meanwhile by another call is kept)."""
        hit = self._cache.get(key)
        if hit is not None and (token is None or hit[0] == token):
            del self._cache[key]

    def _recent_failure(self, key: Hashable, ref: str | None) -> None:
        failed = self._failed.get(key)
        if failed is None:
            return
        message, until = failed
        if _now() >= until:
            del self._failed[key]
            return
        raise TokenError(ref, f"{message} (recent failure, not retried yet)")

    async def _token(
        self, key: Hashable, ref: str | None, form: Callable[[], dict[str, str]]
    ) -> str:
        """The cached token for ``key``, else one fresh fetch shared by concurrent callers."""
        token = self._cached(key)
        if token is not None:
            return token
        slot = self._locks.setdefault(key, _Lock())
        slot.users += 1
        try:
            async with slot.lock:
                token = self._cached(key)  # fetched by whoever held the lock before us
                if token is not None:
                    return token
                self._recent_failure(key, ref)
                try:
                    token, lifetime = await self._fetch(ref, form())
                except TokenError as e:
                    self._failed[key] = (e.reason, _now() + NEGATIVE_CACHE_S)
                    while len(self._failed) > self._cache_size:
                        self._failed.pop(next(iter(self._failed)))
                    raise
                self._failed.pop(key, None)
                if lifetime > EXPIRY_MARGIN_S:
                    self._cache[key] = (token, _now() + lifetime - EXPIRY_MARGIN_S)
                    self._cache.move_to_end(key)
                    while len(self._cache) > self._cache_size:
                        self._cache.popitem(last=False)
                return token
        finally:
            slot.users -= 1
            if slot.users == 0:
                del self._locks[key]

    async def _fetch(self, ref: str | None, form: dict[str, str]) -> tuple[str, float]:
        secret = os.environ.get(self.client_secret_env)
        if not secret:
            raise MissingCredential(ref, self.client_secret_env)
        # RFC 6749 2.3.1: both parts are form-encoded before Basic encoding.
        pair = f"{quote_plus(self.client_id)}:{quote_plus(secret)}".encode()
        headers = {
            "Authorization": f"Basic {base64.b64encode(pair).decode('ascii')}",
            "Accept": "application/json",
        }
        try:
            require_https(self.token_url)
            body = await safe_post(
                self.token_url,
                self.tier,
                data=form,
                headers=headers,
                max_bytes=TOKEN_MAX_BYTES,
                deadline_s=TOKEN_DEADLINE_S,
                http=self._http,
            )
        except UnsafeURL as e:
            raise TokenError(ref, f"URL is unsafe: {e}") from None
        except FetchError as e:
            raise TokenError(ref, f"request failed: {e}") from None
        return _parse(ref, body)


def _parse(ref: str | None, body: bytes) -> tuple[str, float]:
    """(access token, lifetime in seconds) from a token response; lifetime 0 means unknown."""
    try:
        doc = json.loads(body)
    except ValueError:
        raise TokenError(ref, "response is not JSON") from None
    if not isinstance(doc, dict):
        raise TokenError(ref, "response is not a JSON object")
    token = doc.get("access_token")
    if not isinstance(token, str) or not token:
        raise TokenError(ref, "response has no access_token")
    token_type = doc.get("token_type")
    if token_type is not None and (
        not isinstance(token_type, str) or token_type.lower() != "bearer"
    ):
        raise TokenError(ref, "response token_type is not Bearer")
    lifetime = 0.0
    expires_in = doc.get("expires_in")
    if isinstance(expires_in, str):  # some servers send a numeric string
        try:
            expires_in = float(expires_in.strip())
        except ValueError:
            expires_in = None
    if isinstance(expires_in, (int, float)) and not isinstance(expires_in, bool):
        lifetime = float(expires_in)
    elif token.count(".") == 2:
        try:  # unverified: only used to decide when to refresh our own copy
            exp = jwt.decode(token, options={"verify_signature": False}).get("exp")
        except jwt.PyJWTError:
            exp = None
        if isinstance(exp, (int, float)) and not isinstance(exp, bool):
            lifetime = float(exp) - time.time()
    if not math.isfinite(lifetime) or lifetime < 0:
        lifetime = 0.0
    return token, min(lifetime, MAX_LIFETIME_S)


class OAuthClientCredentials(_OAuthProvider):
    """OAuth2 client credentials grant: one gateway token for every partner it applies to:
    those whose ``credential_ref`` is in ``refs`` or, when ``refs`` is None, every partner
    whose ``credential_ref`` is set. Partners without a ``credential_ref`` get nothing."""

    def __init__(
        self,
        token_url: str,
        client_id: str,
        client_secret_env: str,
        scope: str | None = None,
        audience: str | None = None,
        refs: set[str] | None = None,
        http: httpx.AsyncClient | None = None,
        *,
        tier: Tier = "public",
    ) -> None:
        super().__init__(
            token_url, client_id, client_secret_env, refs, http, cache_size=1, tier=tier
        )
        self.scope = scope
        self.audience = audience

    def _form(self) -> dict[str, str]:
        form = {"grant_type": "client_credentials"}
        if self.scope:
            form["scope"] = self.scope
        if self.audience:
            form["audience"] = self.audience
        return form

    async def headers(self, partner: PartnerRecord, caller: Principal | None) -> dict[str, str]:
        if not self._applies(partner):
            return {}
        token = await self._token("client", partner.credential_ref, self._form)
        return {"Authorization": f"Bearer {token}"}

    def invalidate(self, partner: PartnerRecord, token: str | None = None) -> bool:
        """Drop the cached token (only if it is ``token``, when given). Returns whether this
        provider applies to ``partner``, i.e. whether a resend would carry a fresh token."""
        if not self._applies(partner):
            return False
        self._drop("client", token)
        return True


class OAuthTokenExchange(_OAuthProvider):
    """RFC 8693 token exchange: the inbound caller's JWT (``current_inbound_token``) is
    exchanged for a token for ``audience``, so the partner sees a token issued for the
    original caller. Tokens are cached in memory per (caller token, audience), at most 1024.

    ``refs`` is required and must be non-empty: an exchanged token lets its holder act as the
    user, so it is only sent to partners whose ``credential_ref`` is listed.

    With no inbound JWT (an API-key caller, or a call outside an inbound request) this
    raises MissingCredential, except during gateway maintenance calls (``maintenance_call``:
    cascade cancels, cleanup of cancelled calls, restart recovery), where ``fallback`` (e.g.
    an ``OAuthClientCredentials`` for the gateway's own service principal) is used instead
    if given. Partners must grant that service principal the right to cancel tasks started
    on behalf of their users, or such cancels fail and the partner work is left running."""

    def __init__(
        self,
        token_url: str,
        client_id: str,
        client_secret_env: str,
        audience: str,
        refs: set[str] | None = None,
        *,
        http: httpx.AsyncClient | None = None,
        fallback: CredentialProvider | None = None,
        tier: Tier = "public",
    ) -> None:
        if not refs:
            raise ValueError("OAuthTokenExchange requires a non-empty refs set")
        self.fallback = fallback
        super().__init__(
            token_url,
            client_id,
            client_secret_env,
            refs,
            http,
            cache_size=EXCHANGE_CACHE_SIZE,
            tier=tier,
        )
        self.audience = audience

    def __repr__(self) -> str:
        return f"{super().__repr__()[:-1]}, audience={self.audience!r}, fallback={self.fallback!r})"

    def _key(self, subject: str) -> tuple[str, str]:
        return hashlib.sha256(subject.encode()).hexdigest(), self.audience

    async def headers(self, partner: PartnerRecord, caller: Principal | None) -> dict[str, str]:
        if not self._applies(partner):
            return {}
        subject = current_inbound_token.get()
        if not subject:
            if self.fallback is not None and maintenance_call.get():
                return await self.fallback.headers(partner, caller)
            raise MissingCredential(
                partner.credential_ref, reason="no inbound caller token to exchange"
            )

        def form() -> dict[str, str]:
            return {
                "grant_type": TOKEN_EXCHANGE,
                "subject_token": subject,
                "subject_token_type": JWT_TOKEN_TYPE,
                "audience": self.audience,
                "requested_token_type": ACCESS_TOKEN_TYPE,
            }

        token = await self._token(self._key(subject), partner.credential_ref, form)
        return {"Authorization": f"Bearer {token}"}

    def invalidate(self, partner: PartnerRecord, token: str | None = None) -> bool:
        """Drop the token cached for the current caller (only if it is ``token``, when
        given). Returns whether a resend would carry a fresh token."""
        if not self._applies(partner):
            return False
        subject = current_inbound_token.get()
        if subject:
            self._drop(self._key(subject), token)
            return True
        inv = getattr(self.fallback, "invalidate", None)
        if maintenance_call.get() and callable(inv) and not inspect.iscoroutinefunction(inv):
            return bool(inv(partner, token))  # a fallback's invalidate must be synchronous
        return False
