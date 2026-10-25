"""DNS-rebinding-proof outbound connections.

``check_url`` vets a URL's host before a request, but httpx would then resolve the name again
on its own when it connects: a DNS answer that changes in between (rebinding to, say,
169.254.169.254) would send the request somewhere that was never checked. ``GuardedBackend``
closes that window. It is the httpcore network backend of every outbound client: it resolves
the host itself (with netguard's resolver), vets every address with netguard's rules for the
host's tier, and opens the TCP connection to a vetted IP address only. TLS still verifies, and
sends SNI for, the hostname from the URL (httpcore passes it to ``start_tls`` separately), and
the ``Host`` header is unchanged.

``guarded_async_client`` builds an ``httpx.AsyncClient`` around it; redirects are never
followed. httpx 0.28 does not let a transport take a network backend, so the client's
transport gets an ``httpcore.AsyncConnectionPool`` built with the backend (``_swap_pool``, the
one place touching httpx internals). Proxies are not supported: a proxy would resolve the
name itself. Environment proxy settings are ignored, because the client has an explicit
transport.

Clients injected for tests (``http=`` / ``partner_http``) are used as given and bypass the
guard; that is the documented test seam.
"""

from __future__ import annotations

import logging
import time
import typing
from collections.abc import Callable, Iterable

import anyio
import httpcore
import httpx

from a2agw.consult.netguard import Resolver, Tier, Unresolvable, UnsafeURL, resolve_and_vet

__all__ = ["GuardedBackend", "fixed_tier", "guarded_async_client"]

logger = logging.getLogger(__name__)

TierForHost = Callable[[str], Tier]

DEFAULT_TIMEOUT = httpx.Timeout(5.0)  # httpx's own default
_REFUSED_KWARGS = ("follow_redirects", "transport", "mounts", "proxy", "app")


def fixed_tier(tier: Tier) -> TierForHost:
    """A ``tier_for_host`` giving `tier` for every host."""
    return lambda _host: tier


class GuardedBackend(httpcore.AsyncNetworkBackend):
    """An httpcore network backend that connects only to addresses vetted for the host's
    tier (``tier_for_host(host)``). Everything but ``connect_tcp`` is delegated to ``inner``
    (default ``httpcore.AnyIOBackend()``).

    Errors never name the host or an address: a refused host gives
    ``httpcore.ConnectError("unsafe address")``."""

    def __init__(
        self,
        tier_for_host: TierForHost,
        *,
        resolver: Resolver | None = None,
        inner: httpcore.AsyncNetworkBackend | None = None,
    ) -> None:
        self._tier_for_host = tier_for_host
        self._resolver = resolver  # None: netguard's resolver, as used by check_url
        self._inner = inner if inner is not None else httpcore.AnyIOBackend()

    async def _vetted(self, host: str, timeout: float | None) -> list[str]:
        try:
            tier = self._tier_for_host(host)
            with anyio.fail_after(timeout):
                return await resolve_and_vet(host, tier, resolver=self._resolver)
        except TimeoutError:
            raise httpcore.ConnectTimeout("timed out resolving host") from None
        except Unresolvable:
            raise httpcore.ConnectError("host could not be resolved") from None
        except UnsafeURL:
            raise httpcore.ConnectError("unsafe address") from None
        except Exception as exc:  # noqa: BLE001 - fail closed: never connect unvetted
            logger.warning("outbound address check failed: %s", type(exc).__name__)
            raise httpcore.ConnectError("unsafe address") from None

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        """Resolve and vet `host`, then connect to the first vetted address that accepts,
        within one `timeout` for the lookup and all connection attempts together."""
        deadline = None if timeout is None else time.monotonic() + timeout
        addrs = await self._vetted(host, timeout)
        last: Exception | None = None
        for ip in addrs:
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                raise httpcore.ConnectTimeout("timed out connecting")
            try:
                return await self._inner.connect_tcp(
                    ip,
                    port,
                    timeout=remaining,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last = exc
        assert last is not None  # resolve_and_vet never returns an empty list
        raise last

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        return await self._inner.connect_unix_socket(
            path, timeout=timeout, socket_options=socket_options
        )

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


def _swap_pool(transport: httpx.AsyncHTTPTransport, pool: httpcore.AsyncConnectionPool) -> None:
    """Replace the transport's connection pool (httpx 0.28 keeps it in ``_pool``).

    Fails loudly if httpx changes that, rather than leaving an unguarded pool in place."""
    current = getattr(transport, "_pool", None)
    if type(current) is not httpcore.AsyncConnectionPool:
        raise RuntimeError(
            "unsupported httpx version: AsyncHTTPTransport._pool is not an AsyncConnectionPool"
        )
    transport._pool = pool  # type: ignore[attr-defined]


def guarded_async_client(
    tier_for_host: TierForHost,
    *,
    verify: typing.Any = True,
    cert: typing.Any = None,
    timeout: typing.Any = DEFAULT_TIMEOUT,
    limits: httpx.Limits | None = None,
    resolver: Resolver | None = None,
    inner: httpcore.AsyncNetworkBackend | None = None,
    **kw: typing.Any,
) -> httpx.AsyncClient:
    """An ``httpx.AsyncClient`` whose connections go through ``GuardedBackend``.

    ``verify``/``cert`` are httpx's (pass an ``ssl.SSLContext`` as ``verify`` for mTLS);
    ``resolver`` and ``inner`` are test seams. Redirects are never followed; transports,
    mounts and proxies cannot be set (they would bypass the guard)."""
    refused = [k for k in _REFUSED_KWARGS if k in kw]
    if refused:
        raise TypeError(f"guarded_async_client does not accept {', '.join(refused)}")
    limits = (
        limits
        if limits is not None
        else httpx.Limits(max_connections=100, max_keepalive_connections=20)
    )
    ssl_context = httpx.create_ssl_context(verify=verify, cert=cert)
    transport = httpx.AsyncHTTPTransport(verify=ssl_context, limits=limits)
    pool = httpcore.AsyncConnectionPool(
        ssl_context=ssl_context,
        max_connections=limits.max_connections,
        max_keepalive_connections=limits.max_keepalive_connections,
        keepalive_expiry=limits.keepalive_expiry,
        network_backend=GuardedBackend(tier_for_host, resolver=resolver, inner=inner),
    )
    _swap_pool(transport, pool)
    return httpx.AsyncClient(transport=transport, timeout=timeout, follow_redirects=False, **kw)
