"""Agent declaration and A2A Agent Card construction."""

from __future__ import annotations

import re
from typing import Annotated

from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentExtension,
    AgentInterface,
    AgentProvider,
    AgentSkill,
    APIKeySecurityScheme,
    HTTPAuthSecurityScheme,
    SecurityRequirement,
    SecurityScheme,
    StringList,
)
from pydantic import BaseModel, ConfigDict, Field, field_validator

from a2agw.context.call_context import EXTENSION_URI
from a2agw.core.spi import InboundAdapter
from a2agw.security.auth import AgentAccess, AuthConfig

# The rule for agent ids (``AgentSpec.id``, and external agents in the config).
AGENT_ID_PATTERN = r"^[a-z0-9][a-z0-9-]{0,62}$"
_AGENT_ID = re.compile(AGENT_ID_PATTERN)

# Fields the A2A card marks REQUIRED: an empty value would make every built card invalid.
_NonEmpty = Annotated[str, Field(min_length=1)]


def _default_modes() -> list[str]:
    return ["text/plain", "application/json"]


class SkillSpec(BaseModel):
    id: _NonEmpty
    name: _NonEmpty
    description: _NonEmpty
    tags: list[str] = Field(default_factory=list)
    examples: list[str] = Field(default_factory=list)
    # None = inherit the agent's default modes.
    input_modes: list[str] | None = None
    output_modes: list[str] | None = None


class AgentSpec(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    id: str
    name: str = Field(min_length=1)
    description: str = Field(min_length=1)
    version: _NonEmpty = "0.1.0"
    skills: list[SkillSpec] = Field(min_length=1)
    adapter: InboundAdapter
    provider: tuple[_NonEmpty, _NonEmpty] | None = None  # (organization, url)
    access: AgentAccess = Field(default_factory=AgentAccess)
    input_modes: list[str] = Field(default_factory=_default_modes, min_length=1)
    output_modes: list[str] = Field(default_factory=_default_modes, min_length=1)
    streaming: bool = True
    tenant: str = ""
    allow_reentry: bool = False
    # Lets the adapter answer a new turn with a bare A2A Message (a ``Reply`` first event).
    # The task is then created lazily, on the adapter's first other event: until then it is
    # not visible to GetTask/CancelTask and no WORKING status is sent. The turn is still
    # indexed (SUBMITTED) from admission, so re-entry detection and the cancellation cascade
    # cover it; a direct Reply deletes that row and cancels any partner tasks the turn started.
    direct_replies: bool = False

    @field_validator("id")
    @classmethod
    def _valid_id(cls, v: str) -> str:
        if not _AGENT_ID.fullmatch(v):
            raise ValueError(f"agent id must match {_AGENT_ID.pattern}")
        return v


def build_card(
    spec: AgentSpec, base_url: str, *, security: AuthConfig | None, push: bool = False
) -> AgentCard:
    """The agent's card. ``push`` declares push-notification support (set by ``AgentHost``
    only when it is configured with ``PushSettings``)."""
    base = base_url.rstrip("/")
    root = f"{base}/agents/{spec.id}"

    schemes: dict[str, SecurityScheme] = {}
    if security is not None:
        if security.api_keys:
            schemes["apiKey"] = SecurityScheme(
                api_key_security_scheme=APIKeySecurityScheme(location="header", name="X-API-Key")
            )
        if security.jwt is not None:
            schemes["bearer"] = SecurityScheme(
                http_auth_security_scheme=HTTPAuthSecurityScheme(
                    scheme="Bearer", bearer_format="JWT"
                )
            )

    card = AgentCard(
        name=spec.name,
        description=spec.description,
        version=spec.version,
        supported_interfaces=[
            AgentInterface(
                url=f"{root}/",
                protocol_binding="JSONRPC",
                protocol_version="1.0",
                tenant=spec.tenant,
            ),
            AgentInterface(
                url=f"{root}/rest",
                protocol_binding="HTTP+JSON",
                protocol_version="1.0",
                tenant=spec.tenant,
            ),
        ],
        capabilities=AgentCapabilities(
            streaming=spec.streaming,
            push_notifications=push,
            extensions=[AgentExtension(uri=EXTENSION_URI, required=False)],
        ),
        default_input_modes=spec.input_modes,
        default_output_modes=spec.output_modes,
        skills=[
            AgentSkill(
                id=s.id,
                name=s.name,
                description=s.description,
                tags=s.tags or [s.id],
                examples=s.examples,
                input_modes=s.input_modes or [],
                output_modes=s.output_modes or [],
            )
            for s in spec.skills
        ],
        security_schemes=schemes,
        security_requirements=[
            SecurityRequirement(schemes={name: StringList()}) for name in schemes
        ],
    )
    if spec.provider is not None:
        org, url = spec.provider
        card.provider.CopyFrom(AgentProvider(organization=org, url=url))
    return card
