"""SSRF guard for outbound URLs (partner cards and endpoints)."""

from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
from collections.abc import Awaitable, Callable
from typing import Any, Literal

import httpx

Tier = Literal["internal", "partner", "public"]

_METADATA_IPS = frozenset(
    ipaddress.ip_address(a) for a in ("169.254.169.254", "fd00:ec2::254", "100.100.100.200")
)


class UnsafeURL(ValueError):
    """The URL is not allowed for the given tier. The reason never contains resolved IPs."""


class FetchError(Exception):
    """A guarded GET failed. The reason never contains the response body."""


async def _resolve(host: str) -> list[str]:
    """Resolve host to address strings. Raises OSError when unresolvable."""
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return [str(info[4][0]) for info in infos]


def _is_metadata(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """A cloud metadata endpoint (also as an IPv4-mapped IPv6 address). Refused on every
    tier, ``internal`` included: no partner, card, key or webhook legitimately lives there."""
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return addr in _METADATA_IPS


def _parse_ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return None


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


def check_url_syntax(url: str) -> tuple[str, str]:
    """Synchronous checks (scheme, userinfo, host). Returns (scheme, host-as-httpx-connects)."""
    try:
        parsed = httpx.URL(url)
        host = parsed.raw_host.decode("ascii")  # IDNA2008, exactly what httpx connects to
        userinfo = parsed.userinfo
    except (httpx.InvalidURL, UnicodeError, ValueError):
        raise UnsafeURL("malformed URL") from None
    if parsed.scheme not in ("http", "https"):
        raise UnsafeURL("scheme must be http or https")
    if userinfo or "@" in parsed.netloc.decode("ascii", "replace"):
        raise UnsafeURL("userinfo in URL is not allowed")
    if not host:
        raise UnsafeURL("URL has no host")
    return parsed.scheme, host


Resolver = Callable[[str], Awaitable[list[str]]]


class Unresolvable(UnsafeURL):
    """The host has no usable address. The reason never names the host."""


async def resolve_and_vet(host: str, tier: Tier, *, resolver: Resolver | None = None) -> list[str]:
    """The addresses `host` may be connected to for `tier`, in resolver order, de-duplicated.

    An IP literal is vetted as is (no lookup). For the ``internal`` tier the addresses are
    not checked (R2) except that cloud metadata addresses are refused on every tier; for any
    other tier every address must be public, otherwise the whole answer is refused
    (UnsafeURL). Raises Unresolvable when there is no address. This is the
    one implementation shared by ``check_url`` and the guarded network backend
    (``a2agw.consult.guarded_net``), which connects only to the addresses returned here."""
    try:
        ipaddress.ip_address(host.split("%", 1)[0])
        resolved = [host]
    except ValueError:
        lookup = resolver if resolver is not None else _resolve  # module global, patchable
        try:
            resolved = list(dict.fromkeys(await lookup(host)))
        except (OSError, ValueError):
            raise Unresolvable("host could not be resolved") from None
        if not resolved:
            raise Unresolvable("host could not be resolved")
    if tier == "internal":
        if any((a := _parse_ip(r)) is not None and _is_metadata(a) for r in resolved):
            raise UnsafeURL("host resolves to a metadata address")
        return resolved
    try:
        addrs = [ipaddress.ip_address(a.split("%", 1)[0]) for a in resolved]
    except ValueError:
        raise Unresolvable("host could not be resolved") from None
    if not all(_is_public(a) for a in addrs):
        raise UnsafeURL("host resolves to a non-public address")
    return resolved


async def check_url(url: str, tier: Tier) -> None:
    """Raise UnsafeURL if `url` must not be fetched/called for `tier`.

    This gives an early, clear error. Enforcement happens again at connect time: the
    guarded clients (``a2agw.consult.guarded_net``) re-resolve and connect only to a vetted
    address, so a DNS answer that changes after this check cannot redirect the connection."""
    scheme, host = check_url_syntax(url)
    if tier == "internal":
        # R2: no lookup, unresolvable hosts allowed. A metadata IP literal is still refused
        # here; a name resolving to one is refused at connect time (resolve_and_vet).
        addr = _parse_ip(host.strip("[]"))
        if addr is not None and _is_metadata(addr):
            raise UnsafeURL("metadata address is not allowed")
        return
    if scheme != "https" and os.environ.get("A2AGW_DEV") != "1":
        raise UnsafeURL("https is required")
    await resolve_and_vet(host, tier)


def _size_label(n: int) -> str:
    mib = 1024 * 1024
    return f"{n // mib} MiB" if n % mib == 0 else f"{n} bytes"


async def safe_get(
    url: str,
    tier: Tier,
    *,
    max_bytes: int,
    deadline_s: float,
    http: httpx.AsyncClient | None = None,
) -> bytes:
    """GET `url` after the SSRF check for `tier`: no redirects, a body cap and one total deadline.

    The deadline covers the DNS check, the connection and the whole body. Raises UnsafeURL
    when the URL is refused and FetchError for every other failure. Without ``http`` the
    request goes through a guarded client for `tier` (connects only to vetted addresses);
    an injected ``http`` client is used as given (the test seam)."""
    return await _guarded("GET", url, tier, max_bytes, deadline_s, http, {})


async def safe_post(
    url: str,
    tier: Tier,
    *,
    data: dict[str, str],
    headers: dict[str, str] | None = None,
    max_bytes: int,
    deadline_s: float,
    http: httpx.AsyncClient | None = None,
) -> bytes:
    """POST a form to `url` with the same protections as ``safe_get``.

    Only a 200 response body is returned; any other status is a FetchError that names the
    status but never includes the body."""
    return await _guarded(
        "POST", url, tier, max_bytes, deadline_s, http, {"data": data, "headers": headers or {}}
    )


async def _guarded(
    method: str,
    url: str,
    tier: Tier,
    max_bytes: int,
    deadline_s: float,
    http: httpx.AsyncClient | None,
    kwargs: dict[str, Any],
) -> bytes:
    try:
        async with asyncio.timeout(deadline_s):
            await check_url(url, tier)
            if http is not None:
                return await _capped(http, method, url, max_bytes, deadline_s, kwargs)
            from a2agw.consult.guarded_net import fixed_tier, guarded_async_client

            async with guarded_async_client(fixed_tier(tier), timeout=deadline_s) as c:
                return await _capped(c, method, url, max_bytes, deadline_s, kwargs)
    except TimeoutError:
        raise FetchError("timed out") from None


async def _capped(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    max_bytes: int,
    timeout: float,
    kwargs: dict[str, Any],
) -> bytes:
    try:
        async with client.stream(
            method, url, follow_redirects=False, timeout=timeout, **kwargs
        ) as resp:
            if 300 <= resp.status_code < 400:
                raise FetchError("redirects are not followed")
            if resp.status_code != 200:
                raise FetchError(f"unexpected status {resp.status_code}")
            buf = bytearray()
            async for chunk in resp.aiter_bytes():
                buf.extend(chunk)
                if len(buf) > max_bytes:
                    raise FetchError(f"response exceeds {_size_label(max_bytes)}")
    except httpx.HTTPError as e:
        raise FetchError(f"request failed: {type(e).__name__}") from None
    return bytes(buf)
