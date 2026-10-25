"""Data classification levels and classifiers.

``Classification`` is an ordered level: ``public < internal < confidential < restricted``.
Policy files use the lowercase names.

``RegexPiiClassifier`` is a cheap, opt-in detector (off unless configured): an e-mail
address, a phone number, a mod-97-valid IBAN or a Luhn-valid card number anywhere in the
text or in the JSON form of ``data`` makes the payload ``confidential``; otherwise it is
``public``. Input is bounded (the first 256 KiB of the text and of the serialized data) and
every pattern is free of nested quantifiers, so scanning time is linear in the input.
"""

from __future__ import annotations

import enum
import json
import re
from typing import Any, Protocol, runtime_checkable

MAX_SCAN_CHARS = 256 * 1024


class Classification(enum.IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    RESTRICTED = 3

    @classmethod
    def parse(cls, value: str) -> Classification:
        """Case-insensitive name lookup; ``ValueError`` on anything else."""
        try:
            return cls[value.strip().upper()]
        except KeyError:
            raise ValueError("unknown classification") from None


@runtime_checkable
class Classifier(Protocol):
    def classify(self, text: str, data: dict[str, Any] | None) -> Classification: ...


# E-mail: anchored on "@" (one local-part char behind it) so the scan only does work at
# "@" signs; the domain needs at least one dot.
_EMAIL = re.compile(r"(?<=[A-Za-z0-9._%+-])@[A-Za-z0-9-]{1,63}\.[A-Za-z]{2,63}\b")
# Phone: E.164, or 2-4/3-4/3-4 digit groups with separators and an optional +CC prefix.
# The lookarounds stop it matching a slice of a longer digit-group run (e.g. a card).
_PHONE_E164 = re.compile(r"(?<![\w+])\+[1-9]\d{8,14}(?!\d)")
_PHONE_GROUPED = re.compile(
    r"(?<![\d+])(?<!\d[ .-])(?:\+\d{1,3}[ .-])?\(?\d{2,4}\)?[ .-]\d{3,4}[ .-]\d{3,4}(?![ .-]?\d)"
)
_IBAN = re.compile(r"(?<![A-Za-z0-9])[A-Z]{2}\d{2}[A-Z0-9]{11,30}(?![A-Za-z0-9])")
# Cards: 13-19 contiguous digits, 4-4-4-(1..4) groups, or Amex 4-6-5, spaces or dashes.
_CARD_PLAIN = re.compile(r"(?<!\d)\d{13,19}(?!\d)")
_CARD_GROUPED = re.compile(r"(?<![\d-])\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{1,4}(?!\d)")
_CARD_AMEX = re.compile(r"(?<![\d-])\d{4}[ -]\d{6}[ -]\d{5}(?!\d)")
_SEPARATORS = re.compile(r"[^0-9]")


def _luhn(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _iban_ok(candidate: str) -> bool:
    rearranged = candidate[4:] + candidate[:4]
    number = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(number) % 97 == 1


def _digits(match: str) -> str:
    return _SEPARATORS.sub("", match)


def _has_pii(text: str) -> bool:
    if _EMAIL.search(text) or _PHONE_E164.search(text):
        return True
    if any(len(_digits(m.group())) >= 9 for m in _PHONE_GROUPED.finditer(text)):
        return True
    if any(_iban_ok(m.group()) for m in _IBAN.finditer(text)):
        return True
    for pattern in (_CARD_PLAIN, _CARD_GROUPED, _CARD_AMEX):
        for m in pattern.finditer(text):
            d = _digits(m.group())
            if 13 <= len(d) <= 19 and _luhn(d):
                return True
    return False


class RegexPiiClassifier:
    """Flags common PII patterns as ``confidential``; everything else is ``public``."""

    def classify(self, text: str, data: dict[str, Any] | None) -> Classification:
        if _has_pii(text[:MAX_SCAN_CHARS]):
            return Classification.CONFIDENTIAL
        if data:
            blob = json.dumps(data, ensure_ascii=False, default=lambda _o: "")
            if _has_pii(blob[:MAX_SCAN_CHARS]):
                return Classification.CONFIDENTIAL
        return Classification.PUBLIC
