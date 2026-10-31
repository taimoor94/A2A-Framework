"""Structured diff of two Agent Cards (e.g. the approved card and a quarantined pending one).

``card_diff(old, new)`` lists every leaf that was added, removed or changed, as
``CardChange`` records with a dotted ``path``. List items are keyed by their ``id`` when
every item of both lists has a distinct string ``id`` (``skills[code-review].description``),
otherwise by index (``supportedInterfaces[0].url``). ``significant`` follows the registry's
quarantine rule (``a2agw.consult.registry._significant_differs``): a change under any
top-level key other than ``COSMETIC_FIELDS`` and ``signatures`` is significant.

Pure and deterministic (dict keys are walked in sorted order); cards hold no secrets.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Literal

from a2agw.consult.registry import COSMETIC_FIELDS

ChangeKind = Literal["added", "removed", "changed"]
_NOT_SIGNIFICANT = COSMETIC_FIELDS | {"signatures"}
_MISSING = object()


@dataclass(frozen=True)
class CardChange:
    path: str
    kind: ChangeKind
    old: Any
    new: Any
    significant: bool

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def card_diff(old: dict[str, Any], new: dict[str, Any]) -> list[CardChange]:
    out: list[CardChange] = []
    for key in _keys(old, new):
        significant = key not in _NOT_SIGNIFICANT
        _walk(key, old.get(key, _MISSING), new.get(key, _MISSING), significant, out)
    return out


def _keys(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    return sorted(set(old) | set(new), key=str)


def _walk(path: str, old: Any, new: Any, significant: bool, out: list[CardChange]) -> None:
    if old is _MISSING:
        out.append(CardChange(path, "added", None, new, significant))
    elif new is _MISSING:
        out.append(CardChange(path, "removed", old, None, significant))
    elif isinstance(old, dict) and isinstance(new, dict):
        for key in _keys(old, new):
            _walk(f"{path}.{key}", old.get(key, _MISSING), new.get(key, _MISSING), significant, out)
    elif isinstance(old, list) and isinstance(new, list):
        old_items, new_items = _keyed(old, new)
        for label in _labels(old_items, new_items):
            _walk(
                f"{path}[{label}]",
                old_items.get(label, _MISSING),
                new_items.get(label, _MISSING),
                significant,
                out,
            )
    elif old != new or type(old) is not type(new):
        out.append(CardChange(path, "changed", old, new, significant))


def _ids(items: list[Any]) -> list[str] | None:
    ids = [i.get("id") for i in items if isinstance(i, dict)]
    if len(ids) != len(items) or not all(isinstance(i, str) for i in ids):
        return None
    return ids if len(set(ids)) == len(ids) else None  # type: ignore[return-value]


def _keyed(old: list[Any], new: list[Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    old_ids, new_ids = _ids(old), _ids(new)
    if old_ids is not None and new_ids is not None and (old or new):
        return dict(zip(old_ids, old, strict=True)), dict(zip(new_ids, new, strict=True))
    return {str(i): v for i, v in enumerate(old)}, {str(i): v for i, v in enumerate(new)}


def _labels(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    """Old order first (removed and changed items where they were), then new items."""
    return list(old) + [k for k in new if k not in old]
