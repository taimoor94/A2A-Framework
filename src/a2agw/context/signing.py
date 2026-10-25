"""Signed call contexts: a JWS over the call-context metadata, between gateways that trust
each other.

The sending gateway (``PartnerClient(context_signer=...)``) attaches a compact JWS under
``JWS_METADATA_KEY``, next to the unsigned call context, over the context exactly as sent
(R6: ``current_call`` unchanged). A receiving gateway that trusts the signer's key
(``AgentHost(context_verifier=...)``) admits the call under the *signed* context: its
``path``, ``hop`` and ``origin`` cannot be rewritten by a partner that forwards the token,
so loop detection keeps working across partners that strip the unsigned path. Local limits
are still applied (``CallContext.clamp``) and the Phase 1 field validation runs on the signed
values (``CallContext.from_metadata``).

Inbound rule:

- No JWS: Phase 1 behaviour, unchanged.
- JWS present, no verifier configured: the JWS is ignored entirely and the unsigned context
  is used. A gateway that has not opted into signing must not break when a partner signs.
- JWS present, verifier configured: the call is admitted under the verified context, or
  rejected with "invalid call context" when verification fails for any reason (bad
  signature, unknown ``kid``, wrong issuer for the ``kid``, expired, not yet valid, wrong
  ``typ``, disallowed algorithm, oversized token, invalid ``cc`` claim). A present but
  unverifiable token is never silently downgraded to the unsigned context.

Token: header ``{"alg", "kid", "typ": "a2agw-cc+jwt"}``; claims ``cc`` (the call-context
object), ``iss``, ``iat``, ``nbf`` = ``iat``, ``exp`` = the context deadline (truncated) but
at most ``iat`` + 600 s, and a random ``jti``. Allowed algorithms: ES256, RS256, EdDSA.

A verified token is a bearer assertion until it expires: a partner may replay it, unchanged,
for up to ten minutes. Signing never weakens Phase 1: a partner that drops the token falls
back to the unsigned context, which it could forge anyway.

Errors and audit records carry the reason category only, never token contents.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import jwt
from jwt import PyJWK

from a2agw.context.call_context import (
    EXTENSION_URI,
    METADATA_KEY,
    CallContext,
    CallContextViolation,
)
from a2agw.security.cardsign import ALGORITHMS, Alg, _check_bound_alg, load_private_key

JWS_METADATA_KEY = f"{EXTENSION_URI}#jws"
TYP = "a2agw-cc+jwt"
MAX_TOKEN_BYTES = 8 * 1024
MAX_LIFETIME_S = 600
LEEWAY_S = 30
_BAD = "bad signature"


class CallContextSigner:
    """Signs call contexts with one private key (EC P-256, RSA >= 2048 or Ed25519)."""

    def __init__(self, key_path: Path, kid: str, alg: Alg, issuer: str) -> None:
        if alg not in ALGORITHMS:
            raise ValueError(f"alg must be one of {', '.join(ALGORITHMS)}")
        if not kid:
            raise ValueError("kid must be non-empty")
        if not issuer:
            raise ValueError("issuer must be non-empty")
        key = load_private_key(key_path)
        if key.algorithm_name != alg:
            raise ValueError(f"key type does not match alg {alg}")
        self.kid = kid
        self.alg = alg
        self.issuer = issuer
        self._key = key

    def sign(self, cc: CallContext) -> str:
        """A compact JWS over ``cc``; ``exp`` never exceeds ``cc.deadline``."""
        iat = int(time.time())
        cap = iat + MAX_LIFETIME_S
        exp = min(int(cc.deadline), cap) if cc.deadline is not None else cap
        claims: dict[str, Any] = {
            "cc": cc.to_metadata()[METADATA_KEY],
            "iss": self.issuer,
            "iat": iat,
            "nbf": iat,
            "exp": exp,
            "jti": uuid.uuid4().hex,
        }
        return jwt.encode(
            claims, self._key.key, algorithm=self.alg, headers={"kid": self.kid, "typ": TYP}
        )


class CallContextVerifier:
    """Verifies call-context tokens against pinned keys: ``kid`` -> (issuer, public key)."""

    def __init__(self, trusted: Mapping[str, tuple[str, PyJWK]]) -> None:
        self.trusted: dict[str, tuple[str, PyJWK]] = {}
        for kid, (issuer, key) in trusted.items():
            if not kid or not isinstance(issuer, str) or not issuer:
                raise ValueError("every trusted key needs a non-empty kid and issuer")
            try:
                _check_bound_alg(key)
            except ValueError:
                raise ValueError(f"trusted key {kid!r} is not an allowed key/algorithm") from None
            self.trusted[kid] = (issuer, key)

    def verify(self, token: Any) -> CallContext:
        """The signed CallContext, or ``CallContextViolation("bad signature")``."""
        try:
            return self._verify(token)
        except Exception:  # noqa: BLE001 - fail closed; the reason is never more specific
            raise CallContextViolation(_BAD) from None

    def _verify(self, token: Any) -> CallContext:
        if not isinstance(token, str):
            raise TypeError
        if len(token.encode("utf-8")) > MAX_TOKEN_BYTES:
            raise ValueError
        header = jwt.get_unverified_header(token)
        kid, alg = header.get("kid"), header.get("alg")
        if header.get("typ") != TYP or alg not in ALGORITHMS or not isinstance(kid, str):
            raise ValueError
        issuer, key = self.trusted[kid]  # KeyError for an unknown kid
        if key.algorithm_name != alg:
            raise ValueError
        claims = jwt.decode(
            token,
            key.key,
            algorithms=[alg],
            issuer=issuer,
            leeway=LEEWAY_S,
            options={"require": ["exp", "iat", "iss"], "verify_aud": False},
        )
        raw = claims.get("cc")
        if not isinstance(raw, Mapping):
            raise TypeError
        cc = CallContext.from_metadata({METADATA_KEY: raw})
        if cc is None:  # pragma: no cover - raw is a mapping, so never None
            raise ValueError
        return cc
