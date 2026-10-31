"""Structured Agent Card diff (``a2agw.consult.carddiff``)."""

from __future__ import annotations

import copy
import dataclasses

import pytest

from a2agw.consult.carddiff import CardChange, card_diff

CARD = {
    "name": "Partner",
    "description": "does things",
    "version": "1.0",
    "supportedInterfaces": [
        {"url": "https://p.example.com/rpc", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
    ],
    "skills": [
        {"id": "code-review", "name": "Review", "description": "reviews code", "tags": ["a"]},
        {"id": "lint", "name": "Lint", "description": "lints", "tags": []},
    ],
}


def variant(**kw):
    c = copy.deepcopy(CARD)
    c.update(kw)
    return c


def test_skill_description_change_is_significant_and_keyed_by_id():
    new = copy.deepcopy(CARD)
    new["skills"][0]["description"] = "reviews code and sends it elsewhere"
    assert card_diff(CARD, new) == [
        CardChange(
            path="skills[code-review].description",
            kind="changed",
            old="reviews code",
            new="reviews code and sends it elsewhere",
            significant=True,
        )
    ]


def test_version_change_is_cosmetic():
    (change,) = card_diff(CARD, variant(version="1.1"))
    assert (change.path, change.kind, change.old, change.new) == (
        "version",
        "changed",
        "1.0",
        "1.1",
    )
    assert change.significant is False
    # Signatures are not content either.
    (sig,) = card_diff(CARD, variant(signatures=[{"protected": "x", "signature": "y"}]))
    assert sig.path == "signatures" and sig.kind == "added" and sig.significant is False


def test_identical_cards_no_changes():
    assert card_diff(CARD, copy.deepcopy(CARD)) == []
    assert card_diff({}, {}) == []


def test_added_and_removed_skills():
    new = copy.deepcopy(CARD)
    new["skills"] = [new["skills"][1], {"id": "deploy", "name": "Deploy", "description": "d"}]
    changes = card_diff(CARD, new)
    assert [(c.path, c.kind) for c in changes] == [
        ("skills[code-review]", "removed"),
        ("skills[deploy]", "added"),
    ]
    removed, added = changes
    assert removed.old == CARD["skills"][0] and removed.new is None
    assert added.old is None and added.new == new["skills"][1]
    assert all(c.significant for c in changes)


def test_lists_without_ids_are_keyed_by_index_and_top_level_keys_added_removed():
    new = variant(supportedInterfaces=[{**CARD["supportedInterfaces"][0], "url": "https://x/rpc"}])
    del new["description"]
    new["iconUrl"] = "https://p.example.com/i.png"
    changes = {c.path: c for c in card_diff(CARD, new)}
    assert changes["supportedInterfaces[0].url"].kind == "changed"
    assert changes["supportedInterfaces[0].url"].significant is True
    assert changes["description"].kind == "removed" and changes["description"].new is None
    assert changes["iconUrl"].kind == "added" and changes["iconUrl"].significant is False


def test_card_change_is_frozen_and_jsonable():
    (change,) = card_diff(CARD, variant(version="2"))
    with pytest.raises(dataclasses.FrozenInstanceError):
        change.path = "x"  # type: ignore[misc]
    assert change.as_dict() == {
        "path": "version",
        "kind": "changed",
        "old": "1.0",
        "new": "2",
        "significant": False,
    }
