"""The authenticated caller identity."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from a2a.auth.user import User
from starlette.authentication import BaseUser


@dataclass(frozen=True)
class Principal:
    id: str
    kind: Literal["api_key", "jwt", "anonymous"]
    scopes: frozenset[str]
    tenant: str = ""

    @classmethod
    def from_id(cls, principal_id: str) -> Principal:
        """Rebuild a stored caller from its prefixed id, without scopes (``key:`` is an API
        key, ``jwt:`` a JWT subject, anything else anonymous)."""
        if principal_id.startswith("key:"):
            kind: Literal["api_key", "jwt", "anonymous"] = "api_key"
        elif principal_id.startswith("jwt:"):
            kind = "jwt"
        else:
            kind = "anonymous"
        return cls(id=principal_id, kind=kind, scopes=frozenset())


class PrincipalUser(User, BaseUser):
    """Adapts a Principal to the A2A SDK User (used for task ownership scoping). It is also
    the Starlette user the authentication middleware puts on the request."""

    def __init__(self, principal: Principal) -> None:
        self._principal = principal

    @property
    def principal(self) -> Principal:
        return self._principal

    @property
    def is_authenticated(self) -> bool:
        return self._principal.kind != "anonymous"

    @property
    def user_name(self) -> str:
        return self._principal.id

    @property
    def display_name(self) -> str:
        return self._principal.id

    @property
    def identity(self) -> str:
        return self._principal.id
