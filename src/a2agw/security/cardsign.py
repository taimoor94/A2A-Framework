"""Signed Agent Cards: sign the cards we serve, verify the cards partners serve.

Canonicalization (RFC 8785) and the JWS mechanics are the SDK's (`a2a.utils.signing`). This
module adds key loading, a fixed algorithm allowlist, key selection by `kid` (pinned keys) or
`jku` (allowlisted, SSRF-guarded JWKS URLs), and reporting which key verified.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, get_args

import httpx
import jwt
from a2a.types import AgentCard, AgentCardSignature
from a2a.utils.signing import (
    ProtectedHeader,
    create_agent_card_signer,
    create_signature_verifier,
)
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from jwt import PyJWK
from jwt.algorithms import ECAlgorithm, OKPAlgorithm, RSAAlgorithm
from jwt.exceptions import PyJWKError
from jwt.utils import base64url_decode, base64url_encode

from a2agw.consult.netguard import FetchError, UnsafeURL, check_url_syntax, safe_get

Alg = Literal["ES256", "RS256", "EdDSA"]
ALGORITHMS: tuple[str, ...] = get_args(Alg)
JWKS_MAX_BYTES = 1024 * 1024
JWKS_DEADLINE_S = 10.0
JWKS_TTL_S = 300.0
JWKS_REFETCH_MIN_S = 60.0  # unknown-kid cache bypass, at most once per URL per this
JWKS_REFETCH_FAIL_BACKOFF_S = 60.0  # after a failed bypass, no new one for this long
MAX_SIGNATURES = 8  # signatures examined per card; more is a DoS lever, not a use case
MIN_RSA_BITS = 2048


class CardSignatureError(Exception):
    """The card carries no signature that verifies against a trusted key.

    The reason names the failure only; it never contains key material or card contents."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _alg_for(key: Any) -> Alg:
    """The algorithm a key may sign with, or ValueError for anything outside the allowlist."""
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        if isinstance(key.curve, ec.SECP256R1):
            return "ES256"
        raise ValueError("only the P-256 curve is allowed for EC keys")
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        if key.key_size < MIN_RSA_BITS:
            raise ValueError(f"RSA keys must be at least {MIN_RSA_BITS} bits")
        return "RS256"
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
        return "EdDSA"
    raise ValueError("unsupported key type (allowed: EC P-256, RSA, Ed25519)")


def _to_pyjwk(key: Any) -> PyJWK:
    alg = _alg_for(key)
    if alg == "ES256":
        data = ECAlgorithm.to_jwk(key, as_dict=True)
    elif alg == "RS256":
        data = RSAAlgorithm.to_jwk(key, as_dict=True)
    else:
        data = OKPAlgorithm.to_jwk(key, as_dict=True)
    return PyJWK(data, algorithm=alg)


def load_private_key(pem_path: Path) -> PyJWK:
    """Load an unencrypted PEM private key (EC P-256, RSA >= 2048 or Ed25519) as a PyJWK."""
    try:
        key = serialization.load_pem_private_key(Path(pem_path).read_bytes(), password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise ValueError(f"cannot load private key from {Path(pem_path).name}") from None
    return _to_pyjwk(key)


def load_public_key(pem_path: Path) -> PyJWK:
    """Load a PEM public key (EC P-256, RSA >= 2048 or Ed25519) as a PyJWK for verification."""
    try:
        key = serialization.load_pem_public_key(Path(pem_path).read_bytes())
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise ValueError(f"cannot load public key from {Path(pem_path).name}") from None
    return _to_pyjwk(key)


class CardSigner:
    """Signs an AgentCard with one private key (adds one JWS signature per `sign`)."""

    def __init__(self, key_path: Path, kid: str, alg: Alg, jku: str | None = None) -> None:
        if alg not in ALGORITHMS:
            raise ValueError(f"alg must be one of {', '.join(ALGORITHMS)}")
        if not kid:
            raise ValueError("kid must be non-empty")
        key = load_private_key(key_path)
        if key.algorithm_name != alg:
            raise ValueError(f"key type does not match alg {alg}")
        header: dict[str, Any] = {"kid": kid, "alg": alg, "typ": "JOSE"}
        if jku is not None:
            check_url_syntax(jku)
            header["jku"] = jku
        self.kid = kid
        self.alg = alg
        self._key = key
        self._sign = create_agent_card_signer(key, ProtectedHeader(**header))  # type: ignore[typeddict-item]

    def sign(self, card: AgentCard) -> AgentCard:
        """Return a copy of `card` with one more signature; `card` itself is unchanged."""
        out = AgentCard()
        out.CopyFrom(card)
        return self._sign(out)

    def sign_jwt(self, claims: dict[str, Any]) -> str:
        """A compact JWT over `claims`, signed with this signer's key (header `kid`, `alg`).

        The claims are signed as given; the caller sets `iss`, `aud`, `exp` and the rest."""
        return jwt.encode(claims, self._key.key, algorithm=self.alg, headers={"kid": self.kid})


def _protected_header(sig: AgentCardSignature) -> dict[str, Any] | None:
    try:
        header = json.loads(base64url_decode(sig.protected.encode("ascii")))
    except (ValueError, UnicodeError):
        return None
    return header if isinstance(header, dict) else None


def _parse_jwks(body: bytes, reserved_kids: frozenset[str]) -> dict[str, PyJWK]:
    """kid -> key for every usable asymmetric key in an allowed algorithm; the rest is dropped.

    A key whose kid shadows a pinned (trusted) kid is dropped too: pinned kids always resolve
    to the pinned key, so a JWKS can never stand in for one."""
    try:
        data = json.loads(body)
    except ValueError:
        raise CardSignatureError("jwks is not valid JSON") from None
    if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
        raise CardSignatureError("jwks must be an object with a 'keys' list")
    out: dict[str, PyJWK] = {}
    for item in data["keys"]:
        if not isinstance(item, dict) or not isinstance(item.get("kid"), str):
            continue
        if item["kid"] in reserved_kids:
            continue
        if item.get("kty") not in ("EC", "RSA", "OKP") or "d" in item:
            continue  # symmetric or private material is never a verification key
        try:
            jwk = PyJWK(item)
            check_bound_alg(jwk)
        except (PyJWKError, ValueError, TypeError):
            continue
        out[item["kid"]] = jwk
    return out


def check_bound_alg(jwk: PyJWK) -> None:
    """ValueError unless the key's type passes the key rules and matches its bound algorithm."""
    if jwk.algorithm_name not in ALGORITHMS or _alg_for(jwk.key) != jwk.algorithm_name:
        raise ValueError("key type does not match its algorithm")


_THUMBPRINT_MEMBERS = {
    "EC": ("crv", "kty", "x", "y"),
    "RSA": ("e", "kty", "n"),
    "OKP": ("crv", "kty", "x"),
}


def jwk_thumbprint(jwk: PyJWK) -> str:
    """RFC 7638 SHA-256 thumbprint (base64url) of the public key behind `jwk`."""
    key = jwk.key
    if hasattr(key, "public_key"):
        key = key.public_key()
    data = _to_pyjwk(key)._jwk_data
    members = {m: data[m] for m in _THUMBPRINT_MEMBERS[data["kty"]]}
    canonical = json.dumps(members, sort_keys=True, separators=(",", ":"))
    return base64url_encode(hashlib.sha256(canonical.encode("utf-8")).digest()).decode("ascii")


@dataclass(frozen=True)
class VerifiedKey:
    """The key that verified a card. `source` is "trusted" (pinned) or the exact jku URL."""

    kid: str
    source: str
    thumbprint: str

    @property
    def id(self) -> str:
        return f"{self.source}#{self.kid}#{self.thumbprint}"


def _fixed_key(key: PyJWK) -> Callable[[str | None, str | None], PyJWK]:
    """A key provider for the SDK verifier that always answers with the pre-selected key."""

    def provide(_kid: str | None, _jku: str | None) -> PyJWK:
        return key

    return provide


class CardVerifier:
    """Verifies AgentCard signatures against pinned keys and allowlisted JWKS URLs."""

    def __init__(
        self,
        trusted: dict[str, PyJWK] | None = None,
        jwks_urls: list[str] | tuple[str, ...] = (),
        http: httpx.AsyncClient | None = None,
    ) -> None:
        self.trusted = dict(trusted or {})
        for kid, key in self.trusted.items():
            try:
                check_bound_alg(key)
            except ValueError:
                raise ValueError(f"trusted key {kid!r} is not an allowed key/algorithm") from None
        for url in jwks_urls:
            check_url_syntax(url)
        self.jwks_urls = frozenset(jwks_urls)
        self._http = http
        self._jwks: dict[str, tuple[float, dict[str, PyJWK]]] = {}
        self._refetch_failed: dict[str, float] = {}  # url -> when a forced refetch failed

    async def _fetch_jwks(self, url: str) -> dict[str, PyJWK]:
        try:
            body = await safe_get(
                url,
                "public",
                max_bytes=JWKS_MAX_BYTES,
                deadline_s=JWKS_DEADLINE_S,
                http=self._http,
            )
        except UnsafeURL as e:
            raise CardSignatureError(f"jwks fetch refused: {e}") from None
        except FetchError as e:
            raise CardSignatureError(f"jwks fetch failed: {e}") from None
        keys = _parse_jwks(body, frozenset(self.trusted))
        self._jwks[url] = (time.monotonic(), keys)
        return keys

    async def _jwks_key(self, url: str, kid: str) -> PyJWK | None:
        cached = self._jwks.get(url)
        if cached is None or time.monotonic() - cached[0] >= JWKS_TTL_S:
            return (await self._fetch_jwks(url)).get(kid)
        fetched_at, keys = cached
        if kid in keys:
            return keys[kid]
        # Unknown kid: the partner may have rotated. Bypass the cache, at most once per
        # JWKS_REFETCH_MIN_S per URL, so unknown kids cannot turn into a fetch flood. A failed
        # bypass is not retried for JWKS_REFETCH_FAIL_BACKOFF_S (the cached keys stay in use).
        now = time.monotonic()
        failed_at = self._refetch_failed.get(url)
        if failed_at is not None and now - failed_at < JWKS_REFETCH_FAIL_BACKOFF_S:
            return None
        if now - fetched_at >= JWKS_REFETCH_MIN_S:
            try:
                keys = await self._fetch_jwks(url)
            except CardSignatureError:
                self._refetch_failed[url] = time.monotonic()
                raise
            self._refetch_failed.pop(url, None)
            return keys.get(kid)
        return None

    async def _key_for(
        self, kid: str, jku: Any, failed: dict[str, CardSignatureError]
    ) -> tuple[PyJWK, str] | None:
        if kid in self.trusted:
            return self.trusted[kid], "trusted"
        if not (isinstance(jku, str) and jku in self.jwks_urls):
            return None  # a jku outside the allowlist is ignored
        if jku in failed:  # one failed fetch per URL per verify call
            raise failed[jku]
        try:
            key = await self._jwks_key(jku, kid)
        except CardSignatureError as e:
            failed[jku] = e
            raise
        return (key, jku) if key is not None else None

    def still_trusts(self, key_id: str, card: AgentCard | None = None) -> bool:
        """Whether a stored ``VerifiedKey.id`` is still trusted by this verifier, offline.

        A pinned key ("trusted" source) must still be pinned under that kid with the same key
        material (thumbprint), and, given ``card``, one of its signatures with that kid must
        still verify against it locally. A JWKS key needs its URL still allowlisted (the key
        itself is checked at the next refresh). Any parse or verification error is False."""
        try:
            source, kid, thumbprint = key_id.rsplit("#", 2)
        except (AttributeError, ValueError):
            return False
        if source != "trusted":
            return source in self.jwks_urls
        key = self.trusted.get(kid)
        try:
            if key is None or jwk_thumbprint(key) != thumbprint:
                return False
        except Exception:  # noqa: BLE001 - an unusable key is not trusted
            return False
        if card is None:
            return True
        for sig in list(card.signatures)[:MAX_SIGNATURES]:
            header = _protected_header(sig)
            if (
                header is None
                or header.get("kid") != kid
                or header.get("alg") != key.algorithm_name
            ):
                continue
            if self._verifies(card, sig, key):
                return True
        return False

    @staticmethod
    def _verifies(card: AgentCard, sig: AgentCardSignature, key: PyJWK) -> bool:
        single = AgentCard()
        single.CopyFrom(card)
        del single.signatures[:]
        single.signatures.append(sig)
        verifier = create_signature_verifier(_fixed_key(key), list(ALGORITHMS))
        try:
            verifier(single)
        except Exception:  # noqa: BLE001 - any failure means this signature is bad
            return False
        return True

    async def verify(self, card: AgentCard) -> VerifiedKey:
        """Return the key of the first signature that verifies, else raise CardSignatureError."""
        if not card.signatures:
            raise CardSignatureError("card is not signed")
        failed: dict[str, CardSignatureError] = {}
        fetch_error: CardSignatureError | None = None
        for sig in list(card.signatures)[:MAX_SIGNATURES]:
            header = _protected_header(sig)
            if header is None:
                continue
            kid, alg = header.get("kid"), header.get("alg")
            if not isinstance(kid, str) or not kid or alg not in ALGORITHMS:
                continue
            try:
                found = await self._key_for(kid, header.get("jku"), failed)
            except CardSignatureError as e:
                fetch_error = fetch_error or e
                continue
            if found is None:
                continue
            key, source = found
            if key.algorithm_name != alg or not self._verifies(card, sig, key):
                continue
            return VerifiedKey(kid=kid, source=source, thumbprint=jwk_thumbprint(key))
        if fetch_error is not None:
            raise fetch_error
        raise CardSignatureError("no signature verifies against a trusted key")
