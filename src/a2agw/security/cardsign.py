"""Signed Agent Cards: sign the cards we serve, verify the cards partners serve.

Canonicalization (RFC 8785) and the JWS mechanics are the SDK's (`a2a.utils.signing`). This
module adds key loading, a fixed algorithm allowlist, key selection by `kid` (pinned keys) or
`jku` (allowlisted, SSRF-guarded JWKS URLs), and reporting which key verified.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal, get_args

import httpx
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
from jwt.utils import base64url_decode

from a2agw.consult.netguard import FetchError, UnsafeURL, _safe_get, check_url_syntax

Alg = Literal["ES256", "RS256", "EdDSA"]
ALGORITHMS: tuple[str, ...] = get_args(Alg)
JWKS_MAX_BYTES = 1024 * 1024
JWKS_DEADLINE_S = 10.0
JWKS_TTL_S = 300.0
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
        self._sign = create_agent_card_signer(key, ProtectedHeader(**header))  # type: ignore[typeddict-item]

    def sign(self, card: AgentCard) -> AgentCard:
        """Return a copy of `card` with one more signature; `card` itself is unchanged."""
        out = AgentCard()
        out.CopyFrom(card)
        return self._sign(out)


def _protected_header(sig: AgentCardSignature) -> dict[str, Any] | None:
    try:
        header = json.loads(base64url_decode(sig.protected.encode("ascii")))
    except (ValueError, UnicodeError):
        return None
    return header if isinstance(header, dict) else None


def _parse_jwks(body: bytes) -> dict[str, PyJWK]:
    """kid -> key for every usable asymmetric key in an allowed algorithm; the rest is dropped."""
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
        if item.get("kty") not in ("EC", "RSA", "OKP") or "d" in item:
            continue  # symmetric or private material is never a verification key
        try:
            jwk = PyJWK(item)
            _alg_for(jwk.key)
        except (PyJWKError, ValueError, TypeError):
            continue
        if jwk.algorithm_name in ALGORITHMS:
            out[item["kid"]] = jwk
    return out


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
            if key.algorithm_name not in ALGORITHMS:
                raise ValueError(f"trusted key {kid!r} uses a disallowed algorithm")
        for url in jwks_urls:
            check_url_syntax(url)
        self.jwks_urls = frozenset(jwks_urls)
        self._http = http
        self._jwks: dict[str, tuple[float, dict[str, PyJWK]]] = {}

    async def _jwks_keys(self, url: str) -> dict[str, PyJWK]:
        cached = self._jwks.get(url)
        if cached is not None and time.monotonic() - cached[0] < JWKS_TTL_S:
            return cached[1]
        try:
            body = await _safe_get(
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
        keys = _parse_jwks(body)
        self._jwks[url] = (time.monotonic(), keys)
        return keys

    async def _key_for(self, kid: str, jku: Any) -> PyJWK | None:
        if kid in self.trusted:
            return self.trusted[kid]
        if isinstance(jku, str) and jku in self.jwks_urls:
            return (await self._jwks_keys(jku)).get(kid)
        return None  # a jku outside the allowlist is ignored

    async def verify(self, card: AgentCard) -> str:
        """Return the kid of the first signature that verifies, else raise CardSignatureError."""
        if not card.signatures:
            raise CardSignatureError("card is not signed")
        fetch_error: CardSignatureError | None = None
        for sig in list(card.signatures)[:MAX_SIGNATURES]:
            header = _protected_header(sig)
            if header is None:
                continue
            kid, alg = header.get("kid"), header.get("alg")
            if not isinstance(kid, str) or not kid or alg not in ALGORITHMS:
                continue
            try:
                key = await self._key_for(kid, header.get("jku"))
            except CardSignatureError as e:
                fetch_error = fetch_error or e
                continue
            if key is None or key.algorithm_name != alg:
                continue
            single = AgentCard()
            single.CopyFrom(card)
            del single.signatures[:]
            single.signatures.append(sig)
            verifier = create_signature_verifier(_fixed_key(key), list(ALGORITHMS))
            try:
                verifier(single)
            except Exception:  # noqa: BLE001, S112 - any failure means this signature is bad
                continue
            return kid
        if fetch_error is not None:
            raise fetch_error
        raise CardSignatureError("no signature verifies against a trusted key")
