"""Client-side TLS material for mutual-TLS partners.

A ``TlsClientConfig`` names the client certificate, its private key and (optionally) the CA
bundle that must have signed the partner's server certificate. Only paths are held; the
files are read when the SSL context is built. Errors name paths, never file contents.
"""

from __future__ import annotations

import logging
import os
import ssl
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import httpx
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from a2agw.consult.guarded_net import fixed_tier, guarded_async_client
from a2agw.consult.netguard import Tier

logger = logging.getLogger(__name__)
_WARNED: set[Path] = set()


@dataclass(frozen=True)
class TlsClientConfig:
    cert_file: Path
    key_file: Path
    ca_file: Path | None = None
    _ctx: list[ssl.SSLContext] = field(default_factory=list, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "cert_file", Path(self.cert_file))
        object.__setattr__(self, "key_file", Path(self.key_file))
        if self.ca_file is not None:
            object.__setattr__(self, "ca_file", Path(self.ca_file))
        for label, p in (
            ("cert_file", self.cert_file),
            ("key_file", self.key_file),
            ("ca_file", self.ca_file),
        ):
            if p is None:
                continue
            if not p.is_file() or not os.access(p, os.R_OK):
                raise ValueError(f"TLS {label} {p} is not a readable file")
        self._check_key()

    def _check_key(self) -> None:
        """Refuse passphrase-protected keys (OpenSSL would prompt on the tty) and warn once
        when the key file is group/world accessible. Never includes file contents."""
        try:
            data = self.key_file.read_bytes()
            encrypted = b"ENCRYPTED" in data
            if not encrypted and b"-----BEGIN" in data:
                try:
                    load_pem_private_key(data, password=None)
                except TypeError:
                    encrypted = True
                except ValueError:
                    pass  # unparsable: reported when the context is built
        except OSError:
            raise ValueError(f"TLS key_file {self.key_file} is not a readable file") from None
        if encrypted:
            raise ValueError(
                f"private key {self.key_file} is encrypted; "
                "passphrase-protected keys are not supported"
            )
        try:
            mode = self.key_file.stat().st_mode
        except OSError:
            return
        if mode & 0o077 and self.key_file not in _WARNED:
            _WARNED.add(self.key_file)
            logger.warning("TLS private key %s is accessible by group/others", self.key_file)

    def ssl_context(self) -> ssl.SSLContext:
        """TLS >= 1.2, hostname checking on, trusting ``ca_file`` (or the system roots) and
        presenting the client certificate. Built once per instance."""
        if self._ctx:
            return self._ctx[0]
        ctx = ssl.create_default_context(
            cafile=str(self.ca_file) if self.ca_file is not None else None
        )
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname = True
        try:
            ctx.load_cert_chain(str(self.cert_file), str(self.key_file), password=lambda: b"")
        except (ssl.SSLError, OSError) as exc:
            raise ValueError(
                f"cannot load TLS client certificate {self.cert_file} / key {self.key_file}"
            ) from exc
        self._ctx.append(ctx)
        return ctx


def build_async_client(
    cfg: TlsClientConfig,
    timeout: httpx.Timeout,
    *,
    tier_for_host: Callable[[str], Tier] | None = None,
) -> httpx.AsyncClient:
    """A guarded httpx client (``a2agw.consult.guarded_net``) presenting ``cfg``'s
    certificate: it connects only to addresses vetted for ``tier_for_host(host)`` (default:
    every host is ``public``, the strictest) and never follows redirects."""
    tiers = tier_for_host if tier_for_host is not None else fixed_tier("public")
    return guarded_async_client(tiers, verify=cfg.ssl_context(), timeout=timeout)
