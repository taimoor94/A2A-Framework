import hashlib

import pytest
from a2a.client.card_resolver import parse_agent_card
from google.protobuf.json_format import MessageToDict
from pydantic import ValidationError

from a2agw.context.call_context import EXTENSION_URI
from a2agw.security.auth import ApiKeyEntry, AuthConfig, JwtConfig
from a2agw.serve.agent import AgentSpec, SkillSpec, build_card


class _Adapter:
    durable_sessions = False

    async def run(self, ctx):
        if False:
            yield


def _spec(**kw) -> AgentSpec:
    base = {
        "id": "billing-bot",
        "name": "Billing",
        "description": "Handles billing",
        "skills": [
            SkillSpec(id="refund", name="Refund", description="Refunds", tags=["pay"]),
            SkillSpec(id="csv", name="CSV", description="Exports", input_modes=["text/csv"]),
        ],
        "adapter": _Adapter(),
        "provider": ("Acme", "https://acme.example"),
    }
    base.update(kw)
    return AgentSpec(**base)


def test_card_has_two_interfaces_with_agent_paths():
    card = build_card(_spec(), "https://gw.example/", security=None)
    ifs = {i.protocol_binding: i for i in card.supported_interfaces}
    assert set(ifs) == {"JSONRPC", "HTTP+JSON"}
    assert ifs["JSONRPC"].url == "https://gw.example/agents/billing-bot/"
    assert ifs["HTTP+JSON"].url == "https://gw.example/agents/billing-bot/rest"
    assert all(i.protocol_version == "1.0" for i in ifs.values())
    assert card.capabilities.streaming is True
    assert card.capabilities.push_notifications is False
    assert card.provider.organization == "Acme"
    assert card.provider.url == "https://acme.example"
    assert list(card.default_input_modes) == ["text/plain", "application/json"]
    refund, csv = card.skills
    assert refund.id == "refund" and list(refund.tags) == ["pay"]
    assert list(refund.input_modes) == []
    assert list(csv.input_modes) == ["text/csv"]
    assert len(card.security_schemes) == 0
    assert len(card.security_requirements) == 0


def test_card_declares_call_context_extension():
    card = build_card(_spec(), "https://gw.example", security=None)
    (ext,) = card.capabilities.extensions
    assert ext.uri == EXTENSION_URI
    assert ext.required is False


def test_card_security_from_auth_config():
    auth = AuthConfig(
        api_keys={hashlib.sha256(b"k").hexdigest(): ApiKeyEntry(principal_id="p")},
        jwt=JwtConfig(issuer="i", audience="a", public_key_pem="pem"),
    )
    card = build_card(_spec(), "https://gw.example", security=auth)
    assert set(card.security_schemes) == {"apiKey", "bearer"}
    key = card.security_schemes["apiKey"].api_key_security_scheme
    assert (key.location, key.name) == ("header", "X-API-Key")
    bearer = card.security_schemes["bearer"].http_auth_security_scheme
    assert (bearer.scheme, bearer.bearer_format) == ("Bearer", "JWT")
    assert sorted(next(iter(r.schemes)) for r in card.security_requirements) == [
        "apiKey",
        "bearer",
    ]
    assert all(len(r.schemes) == 1 for r in card.security_requirements)

    only_jwt = build_card(_spec(), "https://gw.example", security=AuthConfig(jwt=auth.jwt))
    assert set(only_jwt.security_schemes) == {"bearer"}


@pytest.mark.parametrize("bad", ["", "Bad", "-x", "a_b", "a" * 64, "a b"])
def test_invalid_agent_id_rejected(bad):
    with pytest.raises(ValidationError):
        _spec(id=bad)


def test_card_json_roundtrip():
    auth = AuthConfig(jwt=JwtConfig(issuer="i", audience="a", public_key_pem="pem"))
    card = build_card(_spec(), "https://gw.example", security=auth)
    assert parse_agent_card(MessageToDict(card)) == card


def test_card_passes_sdk_required_field_validation():
    from a2a.utils.proto_utils import validate_proto_required_fields

    card = build_card(_spec(), "https://gw.example", security=None)
    validate_proto_required_fields(card)
    csv = card.skills[1]
    assert list(csv.tags) == ["csv"]


def test_empty_skills_rejected():
    with pytest.raises(ValidationError):
        _spec(skills=[])


def test_empty_name_rejected():
    with pytest.raises(ValidationError):
        _spec(name="")


@pytest.mark.parametrize(
    "bad",
    [
        {"skills": [SkillSpec(id="s", name="S", description="d")], "input_modes": []},
        {"output_modes": []},
        {"version": ""},
        {"provider": ("", "https://acme.example")},
        {"provider": ("Acme", "")},
    ],
)
def test_spec_fields_required_by_card_rejected_when_empty(bad):
    """Finding 5: an empty value for a field the card marks REQUIRED is refused up front."""
    with pytest.raises(ValidationError):
        _spec(**bad)


@pytest.mark.parametrize("field", ["id", "name", "description"])
def test_empty_skill_field_rejected(field):
    kw = {"id": "s", "name": "S", "description": "d", field: ""}
    with pytest.raises(ValidationError):
        SkillSpec(**kw)


@pytest.mark.parametrize(
    "variant",
    [
        {},
        {"provider": None},
        {"skills": [SkillSpec(id="x", name="X", description="d")]},
        {"input_modes": ["text/plain"], "output_modes": ["application/json"]},
        {"tenant": "t1", "streaming": False},
    ],
)
@pytest.mark.parametrize(
    "security",
    [
        None,
        AuthConfig(api_keys={"a" * 64: ApiKeyEntry(principal_id="ci")}),
    ],
)
def test_built_card_always_passes_sdk_validation(variant, security):
    from a2a.utils.proto_utils import validate_proto_required_fields

    card = build_card(_spec(**variant), "https://gw.example", security=security)
    validate_proto_required_fields(card)
    validate_proto_required_fields(parse_agent_card(MessageToDict(card)))
