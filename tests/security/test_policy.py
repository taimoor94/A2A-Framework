"""Policy model, loading and evaluation (authz, egress, routing)."""

import logging

import pytest
from pydantic import ValidationError

from a2agw.consult.registry import PartnerRecord
from a2agw.security.classify import Classification, RegexPiiClassifier
from a2agw.security.policy import (
    Decision,
    Policy,
    PolicyEngine,
    PolicyError,
    RoutePlan,
    load_policy,
)
from a2agw.security.principal import Principal

C = Classification


def _p(pid: str) -> Principal:
    return Principal.from_id(pid)


ALICE = _p("key:alice")
BOB = _p("jwt:bob")
ANON = _p("anonymous")


def _partner(pid: str, tier: str = "partner", tags=(), skills=()) -> PartnerRecord:
    card = {"name": pid, "skills": [{"id": s, "name": s, "tags": []} for s in skills]}
    return PartnerRecord(id=pid, card=card, card_hash="h", tier=tier, tags=list(tags))


def _policy(**kw) -> Policy:
    return Policy.model_validate({"version": 1, **kw})


# -- authz -------------------------------------------------------------------------------

AUTHZ_RULES = [
    {
        "id": "alice-all",
        "principal": "key:alice",
        "agents": ["billing"],
        "skills": "*",
        "effect": "allow",
    },
    {"principal": "*", "agents": ["billing"], "skills": ["read"], "effect": "allow"},
    {
        "id": "no-bob-refund",
        "principal": "jwt:bob",
        "agents": "*",
        "skills": ["refund"],
        "effect": "deny",
    },
    {
        "id": "anon-status",
        "principal": "anonymous",
        "agents": ["status"],
        "skills": "*",
        "effect": "allow",
    },
    {"principal": "*", "agents": ["ops"], "skills": "*", "effect": "deny"},
]


@pytest.mark.parametrize(
    ("principal", "agent", "skill", "allowed", "reason", "rule"),
    [
        # explicit allow
        (ALICE, "billing", "refund", True, None, "alice-all"),
        (ALICE, "billing", None, True, None, "alice-all"),
        # wildcard principal allows any authenticated caller for skill "read"
        (BOB, "billing", "read", True, None, "authz[1]"),
        # skill_id None: allow rules need skills="*", deny rules match whatever their skills
        (BOB, "billing", None, False, "denied by rule", "no-bob-refund"),
        # deny overrides allow
        (BOB, "billing", "refund", False, None, "no-bob-refund"),
        # rules exist for the agent, none match: default deny
        (BOB, "billing", "export", False, "no matching allow rule", None),
        # anonymous is never matched by "*"
        (ANON, "billing", "read", False, "no matching allow rule", None),
        (None, "billing", "read", False, "no matching allow rule", None),
        # ... only by an exact "anonymous" id
        (ANON, "status", None, True, None, "anon-status"),
        (None, "status", "x", True, None, "anon-status"),
        # "agents: *" deny rule mentions every agent: bob is default-denied on "status"
        (BOB, "status", "x", False, "no matching allow rule", None),
        # wildcard deny
        (ALICE, "ops", None, False, None, "authz[4]"),
        # a "*" deny matches anonymous and None principals too
        (ANON, "ops", None, False, "denied by rule", "authz[4]"),
        (None, "ops", "x", False, "denied by rule", "authz[4]"),
    ],
)
def test_authorize_table(principal, agent, skill, allowed, reason, rule):
    engine = PolicyEngine(_policy(authz=AUTHZ_RULES))
    d = engine.authorize(principal, agent, skill)
    assert d.allowed is allowed
    assert d.rule == rule
    assert d.classification is None
    if reason is not None:
        assert d.reason == reason


def test_authorize_without_rules_for_agent_allows():
    rules = [{"principal": "key:alice", "agents": ["billing"], "effect": "allow"}]
    engine = PolicyEngine(_policy(authz=rules))
    d = engine.authorize(BOB, "search", "q")
    assert d == Decision(True, "no authz rules for agent", None, None)


def test_authorize_empty_policy_allows():
    assert PolicyEngine(_policy()).authorize(None, "a", None).allowed


def test_skill_scoped_deny_applies_when_skill_unknown():
    rules = [
        {"principal": "*", "agents": ["billing"], "effect": "allow"},
        {"principal": "key:alice", "agents": ["billing"], "skills": ["transfer"], "effect": "deny"},
    ]
    engine = PolicyEngine(_policy(authz=rules))
    assert not engine.authorize(ALICE, "billing", None).allowed
    assert not engine.authorize(ALICE, "billing", "transfer").allowed
    assert engine.authorize(ALICE, "billing", "read").allowed
    assert engine.authorize(BOB, "billing", None).allowed


def test_wildcard_deny_locks_out_anonymous():
    rules = [
        {"principal": "anonymous", "agents": ["pub"], "effect": "allow"},
        {"id": "lockdown", "principal": "*", "agents": ["pub"], "effect": "deny"},
    ]
    engine = PolicyEngine(_policy(authz=rules))
    for who in (ANON, None, ALICE):
        d = engine.authorize(who, "pub", None)
        assert not d.allowed and d.rule == "lockdown"


def test_lone_deny_rule_denies_everyone_on_that_agent():
    engine = PolicyEngine(
        _policy(authz=[{"principal": "key:mallory", "agents": ["billing"], "effect": "deny"}])
    )
    assert engine.authorize(BOB, "billing", None).reason == "no matching allow rule"
    assert not engine.authorize(BOB, "billing", None).allowed
    assert engine.authorize(BOB, "hr", None).allowed


def test_authz_skills_default_to_wildcard():
    engine = PolicyEngine(
        _policy(authz=[{"principal": "key:alice", "agents": ["a"], "effect": "allow"}])
    )
    assert engine.authorize(ALICE, "a", None).allowed
    assert engine.authorize(ALICE, "a", "s").allowed


# -- egress ------------------------------------------------------------------------------


def test_pii_to_public_partner_denied():
    engine = PolicyEngine(_policy(), classifier=RegexPiiClassifier())
    pub = _partner("pub", tier="public")
    d = engine.egress("a", pub, None, "mail jane@example.com", None)
    assert not d.allowed
    assert d.classification is C.CONFIDENTIAL
    assert d.reason == "classification confidential exceeds public ceiling for partner pub"
    assert engine.egress("a", pub, None, "hello", None).allowed


def test_restricted_to_partner_tier_denied():
    engine = PolicyEngine(_policy())
    d = engine.egress("a", _partner("p1"), C.RESTRICTED, "hi", None)
    assert not d.allowed
    assert d.classification is C.RESTRICTED
    assert "restricted exceeds confidential ceiling for partner p1" in d.reason
    assert engine.egress("a", _partner("p1"), C.CONFIDENTIAL, "hi", None).allowed
    assert engine.egress("a", _partner("i1", tier="internal"), C.RESTRICTED, "hi", None).allowed


def test_partner_override_raises_single_ceiling():
    engine = PolicyEngine(_policy(egress={"partner_ceilings": {"p1": "restricted"}}))
    assert engine.egress("a", _partner("p1"), C.RESTRICTED, "", None).allowed
    assert not engine.egress("a", _partner("p2"), C.RESTRICTED, "", None).allowed


def test_partner_override_can_lower_ceiling():
    engine = PolicyEngine(_policy(egress={"partner_ceilings": {"i1": "public"}}))
    d = engine.egress("a", _partner("i1", tier="internal"), C.INTERNAL, "", None)
    assert not d.allowed


def test_tier_ceiling_partial_override_keeps_defaults():
    pol = _policy(egress={"tier_ceilings": {"public": "internal"}})
    assert pol.egress.tier_ceilings == {
        "internal": C.RESTRICTED,
        "partner": C.CONFIDENTIAL,
        "public": C.INTERNAL,
    }
    engine = PolicyEngine(pol)
    assert engine.egress("a", _partner("x", tier="public"), C.INTERNAL, "", None).allowed


def test_effective_is_max_of_explicit_default_classifier():
    pol = _policy(defaults={"agent_classification": {"hr": "internal"}})
    engine = PolicyEngine(pol, classifier=RegexPiiClassifier())
    pub = _partner("pub", tier="public")
    # agent default beats a lower explicit value
    d = engine.egress("hr", pub, C.PUBLIC, "hello", None)
    assert d.classification is C.INTERNAL and not d.allowed
    # classifier beats agent default
    d = engine.egress("hr", _partner("p"), None, "", {"e": "x@example.com"})
    assert d.classification is C.CONFIDENTIAL and d.allowed
    # explicit beats both
    d = engine.egress("hr", _partner("p"), C.RESTRICTED, "x@example.com", None)
    assert d.classification is C.RESTRICTED and not d.allowed


def test_unknown_classification_used_when_nothing_classifies():
    pol = _policy(defaults={"unknown_classification": "confidential"})
    engine = PolicyEngine(pol)
    d = engine.egress("a", _partner("pub", tier="public"), None, "", None)
    assert d.classification is C.CONFIDENTIAL and not d.allowed
    # an explicit value counts as classifying the data
    d = engine.egress("a", _partner("pub", tier="public"), C.PUBLIC, "", None)
    assert d.classification is C.PUBLIC and d.allowed


def test_classifier_cannot_lower_unknown_classification():
    pol = _policy(defaults={"unknown_classification": "internal"})
    pub = _partner("pub", tier="public")
    for clf in (None, RegexPiiClassifier()):
        d = PolicyEngine(pol, classifier=clf).egress("a", pub, None, "hello", None)
        assert not d.allowed and d.classification is C.INTERNAL
    # the classifier still raises it
    d = PolicyEngine(pol, classifier=RegexPiiClassifier()).egress(
        "a", _partner("p"), None, "x@example.com", None
    )
    assert d.classification is C.CONFIDENTIAL


def test_classifier_raises_explicit_label():
    engine = PolicyEngine(_policy(), classifier=RegexPiiClassifier())
    d = engine.egress("a", _partner("pub", tier="public"), C.PUBLIC, "x@example.com", None)
    assert d.classification is C.CONFIDENTIAL and not d.allowed


def test_egress_defaults_public_with_no_classifier():
    engine = PolicyEngine(_policy())
    d = engine.egress("a", _partner("pub", tier="public"), None, "x@example.com", None)
    assert d.allowed and d.classification is C.PUBLIC


class _Boom:
    def classify(self, text, data):
        raise RuntimeError("secret text in message")


def test_classifier_error_fails_closed(caplog):
    engine = PolicyEngine(_policy(), classifier=_Boom())
    with caplog.at_level(logging.WARNING):
        d = engine.egress("a", _partner("i", tier="internal"), None, "secret text", None)
    assert d == Decision(False, "policy evaluation error", None, None)
    assert "RuntimeError" in caplog.text
    assert "secret text" not in caplog.text


def test_authorize_error_fails_closed(caplog):
    engine = PolicyEngine(_policy())
    with caplog.at_level(logging.WARNING):
        d = engine.authorize(object(), "a", None)  # type: ignore[arg-type]
    assert d == Decision(False, "policy evaluation error", None, None)
    assert "AttributeError" in caplog.text


# -- routing -----------------------------------------------------------------------------


def _ids(*pids):
    return [_partner(p) for p in pids]


def test_forbid_hides_partner():
    pol = _policy(routing=[{"agent": "a", "partners": ["p2"], "mode": "forbid"}])
    plan = PolicyEngine(pol).route("a", _ids("p1", "p2", "p3"))
    assert plan == RoutePlan(visible=["p1", "p3"], forced=[], preferred=[], conflicts=[])


def test_rules_apply_only_to_their_agent():
    pol = _policy(routing=[{"agent": "a", "partners": ["p2"], "mode": "forbid"}])
    plan = PolicyEngine(pol).route("b", _ids("p1", "p2"))
    assert plan.visible == ["p1", "p2"]


def test_force_reports_forced_partner():
    pol = _policy(routing=[{"agent": "a", "partners": ["p3", "ghost"], "mode": "force"}])
    plan = PolicyEngine(pol).route("a", _ids("p1", "p2", "p3"))
    assert plan.forced == ["p3"]
    assert plan.visible == ["p1", "p2", "p3"]


def test_prefer_orders_partners():
    pol = _policy(
        routing=[
            {"agent": "a", "partners": ["p3"], "mode": "prefer"},
            {"agent": "a", "partners": ["p2", "p3"], "mode": "prefer"},
        ]
    )
    plan = PolicyEngine(pol).route("a", _ids("p1", "p2", "p3", "p4"))
    assert plan.preferred == ["p3", "p2"]
    assert plan.visible == ["p3", "p2", "p1", "p4"]


def test_forbid_wins_over_force_and_prefer():
    pol = _policy(
        routing=[
            {"agent": "a", "partners": ["p1", "p2"], "mode": "force"},
            {"agent": "a", "partners": ["p1"], "mode": "prefer"},
            {"id": "no-p1", "agent": "a", "partners": ["p1"], "mode": "forbid"},
        ]
    )
    plan = PolicyEngine(pol).route("a", _ids("p1", "p2"))
    assert plan == RoutePlan(visible=["p2"], forced=["p2"], preferred=[], conflicts=["p1"])


def test_match_by_tags_and_skills():
    partners = [
        _partner("eu", tags=["eu"], skills=["translate"]),
        _partner("us", tags=["us"], skills=["translate"]),
        _partner("calc", skills=["math"]),
    ]
    pol = _policy(
        routing=[
            {
                "agent": "a",
                "match": {"tags_any": ["us"]},
                "partners": ["eu", "us"],
                "mode": "forbid",
            },
            {
                "agent": "a",
                "match": {"skills_any": ["math"]},
                "partners": ["eu", "calc"],
                "mode": "force",
            },
        ]
    )
    plan = PolicyEngine(pol).route("a", partners)
    assert plan.visible == ["eu", "calc"]
    assert plan.forced == ["calc"]


def test_match_uses_card_skill_tags():
    rec = PartnerRecord(
        id="t", card={"skills": [{"id": "s", "tags": ["pii"]}]}, card_hash="h", tier="public"
    )
    pol = _policy(
        routing=[
            {"agent": "a", "match": {"tags_any": ["pii"]}, "partners": ["t"], "mode": "forbid"},
        ]
    )
    assert PolicyEngine(pol).route("a", [rec]).visible == []


def test_route_error_fails_closed(caplog):
    pol = _policy(routing=[{"agent": "a", "partners": ["p"], "mode": "forbid"}])
    with caplog.at_level(logging.WARNING):
        plan = PolicyEngine(pol).route("a", [object()])  # type: ignore[list-item]
    assert plan == RoutePlan(visible=[], forced=[], preferred=[], conflicts=[])
    assert "AttributeError" in caplog.text


# -- model and loading -------------------------------------------------------------------


def test_unknown_field_rejected_with_path(tmp_path):
    f = tmp_path / "policy.yaml"
    f.write_text(
        "version: 1\nauthz:\n  - principal: key:alice\n    agents: [billing]\n    efect: allow\n"
    )
    with pytest.raises(PolicyError) as ei:
        load_policy(f)
    msg = str(ei.value)
    assert "authz.0.efect" in msg
    assert "extra_forbidden" in msg
    assert "authz.0.effect" in msg  # the missing required field too


@pytest.mark.parametrize(
    ("yaml_text", "path"),
    [
        ("version: 1\nbogus: 1\n", "bogus"),
        (
            "version: 1\negress:\n  tier_ceilings:\n    public: topsecret\n",
            "egress.tier_ceilings.public",
        ),
        ("version: 1\negress:\n  ceiling: public\n", "egress.ceiling"),
        (
            "version: 1\nrouting:\n  - agent: a\n    partners: [p]\n    mode: maybe\n",
            "routing.0.mode",
        ),
        (
            (
                "version: 1\nrouting:\n  - agent: a\n    partners: [p]\n    mode: force\n"
                "    match: {tag_any: [x]}\n"
            ),
            "routing.0.match.tag_any",
        ),
        (
            "version: 1\ndefaults:\n  agent_classification: {a: hush}\n",
            "defaults.agent_classification.a",
        ),
        ("version: 2\n", "version"),
        ("authz: []\n", "version"),
    ],
)
def test_validation_errors_name_path(tmp_path, yaml_text, path):
    f = tmp_path / "p.yaml"
    f.write_text(yaml_text)
    with pytest.raises(PolicyError) as ei:
        load_policy(f)
    assert path in str(ei.value)


@pytest.mark.parametrize(
    "principal", ["alice", " key:alice", "key:alice ", "key:", "jwt:", "user:bob", "Anonymous", ""]
)
def test_bad_principal_rejected(tmp_path, principal):
    f = tmp_path / "p.yaml"
    f.write_text(
        f"version: 1\nauthz:\n  - {{principal: '{principal}', agents: [a], effect: deny}}\n"
    )
    with pytest.raises(PolicyError) as ei:
        load_policy(f)
    assert "authz.0.principal" in str(ei.value)


@pytest.mark.parametrize("principal", ["*", "anonymous", "key:alice", "jwt:auth0|abc def"])
def test_good_principal_accepted(principal):
    _policy(authz=[{"principal": principal, "agents": ["a"], "effect": "allow"}])


@pytest.mark.parametrize("section", ["authz", "routing"])
def test_duplicate_rule_ids_rejected(tmp_path, section):
    rule = (
        "{id: r, principal: '*', agents: [a], effect: allow}"
        if section == "authz"
        else "{id: r, agent: a, partners: [p], mode: forbid}"
    )
    f = tmp_path / "p.yaml"
    f.write_text(f"version: 1\n{section}:\n  - {rule}\n  - {rule}\n")
    with pytest.raises(PolicyError) as ei:
        load_policy(f)
    assert f"duplicate rule id at {section}[1]" in str(ei.value)


def test_error_message_omits_values(tmp_path):
    f = tmp_path / "p.yaml"
    f.write_text("version: 1\negress:\n  partner_ceilings: {p: s3cr3t-value}\n")
    with pytest.raises(PolicyError) as ei:
        load_policy(f)
    assert "s3cr3t-value" not in str(ei.value)
    assert "egress.partner_ceilings.p" in str(ei.value)


@pytest.mark.parametrize("text", ["", "   \n# only a comment\n", "- a\n- b\n", "just a string\n"])
def test_empty_or_non_mapping_rejected(tmp_path, text):
    f = tmp_path / "p.yaml"
    f.write_text(text)
    with pytest.raises(PolicyError):
        load_policy(f)


def test_missing_file_rejected(tmp_path):
    with pytest.raises(PolicyError, match="not found"):
        load_policy(tmp_path / "nope.yaml")


def test_invalid_yaml_rejected_without_content(tmp_path):
    f = tmp_path / "p.yaml"
    f.write_text("version: 1\nauthz: [s3cr3t: {\n")
    with pytest.raises(PolicyError) as ei:
        load_policy(f)
    assert "s3cr3t" not in str(ei.value)


def test_load_full_policy(tmp_path):
    f = tmp_path / "p.yaml"
    f.write_text(
        "version: 1\n"
        "authz:\n"
        "  - {id: r1, principal: '*', agents: '*', skills: [read], effect: allow}\n"
        "egress:\n"
        "  tier_ceilings: {partner: internal}\n"
        "  partner_ceilings: {acme: Confidential}\n"
        "routing:\n"
        "  - {id: f, agent: a, partners: [x], mode: forbid, match: {tags_any: [eu]}}\n"
        "defaults:\n"
        "  agent_classification: {hr: restricted}\n"
        "  unknown_classification: internal\n"
    )
    pol = load_policy(f)
    assert pol.authz[0].id == "r1" and pol.authz[0].agents == "*"
    assert pol.egress.tier_ceilings["partner"] is C.INTERNAL
    assert pol.egress.partner_ceilings == {"acme": C.CONFIDENTIAL}
    assert pol.routing[0].match is not None and pol.routing[0].match.tags_any == ["eu"]
    assert pol.defaults.agent_classification == {"hr": C.RESTRICTED}
    assert pol.defaults.unknown_classification is C.INTERNAL
    dumped = pol.model_dump(mode="json")
    assert dumped["defaults"]["agent_classification"] == {"hr": "restricted"}
    assert dumped["egress"]["partner_ceilings"] == {"acme": "confidential"}
    assert Policy.model_validate(dumped) == pol


def test_classification_rejects_integers():
    with pytest.raises(ValidationError):
        _policy(defaults={"unknown_classification": 3})
