"""SSRF guard for outbound URLs (partner cards and endpoints)."""

from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
from typing import Literal
from urllib.parse import urlsplit

Tier = Literal["internal", "partner", "public"]

_METADATA_IPS = frozenset(
    ipaddress.ip_address(a) for a in ("169.254.169.254", "fd00:ec2::254", "100.100.100.200")
)


class UnsafeURL(ValueError):
    """The URL is not allowed for the given tier. The reason never contains resolved IPs."""


async def _resolve(host: str) -> list[str]:
    """Resolve host to address strings. Raises OSError when unresolvable."""
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return [str(info[4][0]) for info in infos]


def _is_public(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(addr, ipaddress.IPv6Address):
        mapped = addr.ipv4_mapped
        if mapped is not None:
            addr = mapped
        elif addr.sixtofour is not None and not _is_public(addr.sixtofour):
            return False
    if addr in _METADATA_IPS:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
        or not addr.is_global
    )


async def check_url(url: str, tier: Tier) -> None:
    """Raise UnsafeURL if `url` must not be fetched/called for `tier`."""
    try:
        parts = urlsplit(url)
        host = parts.hostname
        parts.port  # noqa: B018 - validates the port
    except ValueError:
        raise UnsafeURL("malformed URL") from None
    if parts.scheme not in ("http", "https"):
        raise UnsafeURL("scheme must be http or https")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise UnsafeURL("userinfo in URL is not allowed")
    if not host:
        raise UnsafeURL("URL has no host")
    if tier == "internal":
        return  # R2: no IP checks, unresolvable hosts allowed
    if parts.scheme != "https" and os.environ.get("A2AGW_DEV") != "1":
        raise UnsafeURL("https is required")

    try:
        addrs = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            resolved = await _resolve(host)
            addrs = [ipaddress.ip_address(a.split("%", 1)[0]) for a in resolved]
        except (OSError, ValueError):
            raise UnsafeURL("host could not be resolved") from None
        if not addrs:
            raise UnsafeURL("host could not be resolved")
    if not all(_is_public(a) for a in addrs):
        raise UnsafeURL("host resolves to a non-public address")
