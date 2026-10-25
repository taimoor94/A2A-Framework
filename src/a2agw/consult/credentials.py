"""Per-partner outbound credentials. Secret values never appear in repr or messages."""

from __future__ import annotations

import os
from typing import Protocol

from a2a.client.client import ClientCallContext
from a2a.client.interceptors import AfterArgs, BeforeArgs, ClientCallInterceptor

from a2agw.consult.registry import PartnerRecord
from a2agw.security.principal import Principal


class CredentialError(Exception):
    """Base of every outbound credential failure. Messages never contain secret values."""


class MissingCredential(CredentialError):
    def __init__(self, ref: str | None, env_var: str | None = None, *, reason: str | None = None):
        detail = reason or f"environment variable {env_var} is unset or empty"
        super().__init__(f"credential {ref!r}: {detail}")
        self.ref = ref
        self.env_var = env_var


class InvalidCredential(CredentialError):
    """A header name or value contains CR, LF or NUL. Never includes the value."""

    def __init__(self, ref: str | None, header: str):
        super().__init__(f"credential {ref!r}: header {header!r} has illegal control characters")
        self.ref = ref
        self.header = header


_BAD = ("\r", "\n", "\0")


def _check_header(ref: str | None, name: str, value: str) -> None:
    if any(c in name or c in value for c in _BAD):
        safe = name if not any(c in name for c in _BAD) else "<invalid name>"
        raise InvalidCredential(ref, safe)


class CredentialProvider(Protocol):
    async def headers(self, partner: PartnerRecord, caller: Principal | None) -> dict[str, str]: ...


class EnvCredentials:
    """mapping: credential_ref -> (header name, env var name)."""

    def __init__(self, mapping: dict[str, tuple[str, str]]):
        self._mapping = dict(mapping)

    def __repr__(self) -> str:
        return f"EnvCredentials(refs={sorted(self._mapping)})"

    async def headers(self, partner: PartnerRecord, caller: Principal | None) -> dict[str, str]:
        ref = partner.credential_ref
        if ref is None or ref not in self._mapping:
            return {}
        header, env_var = self._mapping[ref]
        value = os.environ.get(env_var)
        if not value:
            raise MissingCredential(ref, env_var)
        _check_header(ref, header, value)
        return {header: value}


class StaticCredentials:
    """mapping: credential_ref -> headers. For tests and local development."""

    def __init__(self, mapping: dict[str, dict[str, str]]):
        self._mapping = {k: dict(v) for k, v in mapping.items()}

    def __repr__(self) -> str:
        return f"StaticCredentials(refs={sorted(self._mapping)})"

    async def headers(self, partner: PartnerRecord, caller: Principal | None) -> dict[str, str]:
        ref = partner.credential_ref
        if ref is None:
            return {}
        return dict(self._mapping.get(ref, {}))


class ChainCredentials:
    """The first provider returning a non-empty dict wins."""

    def __init__(self, *providers: CredentialProvider):
        self._providers = providers

    def __repr__(self) -> str:
        return f"ChainCredentials({', '.join(repr(p) for p in self._providers)})"

    @property
    def providers(self) -> tuple[CredentialProvider, ...]:
        return self._providers

    async def headers(self, partner: PartnerRecord, caller: Principal | None) -> dict[str, str]:
        for p in self._providers:
            found = await p.headers(partner, caller)
            if found:
                return found
        return {}


class CredentialInterceptor(ClientCallInterceptor):
    """Adds a partner's credential headers to every outbound call.

    Bound to one partner (a2a interceptors do not know which partner they serve).
    The SDK sends ClientCallContext.service_parameters as HTTP headers.
    """

    def __init__(
        self,
        provider: CredentialProvider,
        partner: PartnerRecord,
        caller: Principal | None = None,
    ):
        self._provider = provider
        self._partner = partner
        self._caller = caller

    def __repr__(self) -> str:
        return f"CredentialInterceptor(partner={self._partner.id!r})"

    async def before(self, args: BeforeArgs) -> None:
        headers = await self._provider.headers(self._partner, self._caller)
        if not headers:
            return
        if args.context is None:
            args.context = ClientCallContext()
        for name, value in headers.items():
            _check_header(self._partner.credential_ref, name, value)
        args.context.service_parameters = {**(args.context.service_parameters or {}), **headers}

    async def after(self, args: AfterArgs) -> None:
        return None
