"""Data classification levels and classifiers.

``Classification`` is an ordered level: ``public < internal < confidential < restricted``.
Policy files use the lowercase names.

``RegexPiiClassifier`` is a cheap, opt-in detector (off unless configured): an e-mail
address, a phone number, a mod-97-valid IBAN or a Luhn-valid card number anywhere in the
text or in the JSON form of ``data`` makes the payload ``confidential``; otherwise it is
``public``. Card numbers must also carry a real issuer prefix and length. Input is NFKC
normalised (Unicode digits become ASCII) and bounded: text or serialized data longer than
256 KiB (characters) is not scanned but classified ``confidential`` (fail closed). Every
pattern is free of nested quantifiers, so scanning time is linear in the input.
"""

from __future__ import annotations

import enum
import json
import re
import unicodedata
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


# Every pattern is compiled with re.ASCII (``\d`` is [0-9], ``\b`` is ASCII); input is
# NFKC-normalised and any remaining Unicode decimal digits are mapped to ASCII first.
_A = re.ASCII
# E-mail: anchored on "@" (one local-part char behind it) so the scan only does work at
# "@" signs; the domain needs at least one dot.
_EMAIL = re.compile(r"(?<=[A-Za-z0-9._%+-])@[A-Za-z0-9-]{1,63}\.[A-Za-z]{2,63}\b", _A)
# Phone: E.164, or 2-4/3-4/3-4 digit groups with separators and an optional +CC prefix.
# The lookarounds stop it matching a slice of a longer digit-group run (e.g. a card).
_PHONE_E164 = re.compile(r"(?<![\w+])\+[1-9]\d{8,14}(?!\d)", _A)
_PHONE_GROUPED = re.compile(
    r"(?<![\d+])(?<!\d[ .-])(?:\+\d{1,3}[ .-])?\(?\d{2,4}\)?[ .-]\d{3,4}[ .-]\d{3,4}(?![ .-]?\d)",
    _A,
)
# IBAN, either case: compact, or in groups of 4 separated by single spaces.
_IBAN_COMPACT = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]{2}\d{2}[A-Za-z0-9]{11,30}(?![A-Za-z0-9])", _A)
_IBAN_SPACED = re.compile(
    r"(?<![A-Za-z0-9])[A-Za-z]{2}\d{2}(?: [A-Za-z0-9]{4}){2,7}(?: [A-Za-z0-9]{1,4})?"
    r"(?![A-Za-z0-9])",
    _A,
)
# Cards: 13-19 contiguous digits, 4-4-4-(1..4) groups, or Amex 4-6-5, spaces or dashes.
_CARD_PLAIN = re.compile(r"(?<!\d)\d{13,19}(?!\d)", _A)
_CARD_GROUPED = re.compile(r"(?<![\d-])\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{1,4}(?!\d)", _A)
_CARD_AMEX = re.compile(r"(?<![\d-])\d{4}[ -]\d{6}[ -]\d{5}(?!\d)", _A)
_SEPARATORS = re.compile(r"[^0-9]", _A)
# Unicode-mode: a decimal digit that is not ASCII (Arabic-Indic, Devanagari, ...).
_NON_ASCII_DIGIT = re.compile(r"(?![0-9])\d")

# Issuer prefixes (IIN ranges) with the card lengths each network issues.
_IIN: tuple[tuple[int, int, int, frozenset[int]], ...] = (
    # (prefix length, low, high, valid lengths)
    (1, 4, 4, frozenset({13, 16, 19})),  # Visa
    (2, 51, 55, frozenset({16})),  # Mastercard
    (4, 2221, 2720, frozenset({16})),  # Mastercard 2-series
    (2, 34, 34, frozenset({15})),  # Amex
    (2, 37, 37, frozenset({15})),  # Amex
    (4, 6011, 6011, frozenset(range(16, 20))),  # Discover
    (2, 65, 65, frozenset(range(16, 20))),  # Discover
    (2, 35, 35, frozenset(range(16, 20))),  # JCB
    (2, 30, 30, frozenset(range(14, 20))),  # Diners
    (2, 36, 36, frozenset(range(14, 20))),  # Diners
    (2, 38, 38, frozenset(range(14, 20))),  # Diners
)


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


def _iin_ok(digits: str) -> bool:
    n = len(digits)
    return any(
        n in lengths and low <= int(digits[:size]) <= high for size, low, high, lengths in _IIN
    )


def _iban_ok(candidate: str) -> bool:
    if not 15 <= len(candidate) <= 34:
        return False
    rearranged = candidate[4:] + candidate[:4]
    number = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(number) % 97 == 1


def _spaced_iban_ok(match: str) -> bool:
    # The trailing group may be a following 4-character word: also try shorter prefixes.
    groups = match.split(" ")
    return any(_iban_ok("".join(groups[:k]).upper()) for k in range(len(groups), 2, -1))


def _digits(match: str) -> str:
    return _SEPARATORS.sub("", match)


def _normalise(text: str) -> str:
    if text.isascii():
        return text
    text = unicodedata.normalize("NFKC", text)
    return _NON_ASCII_DIGIT.sub(lambda m: str(unicodedata.decimal(m.group())), text)


def _has_pii(text: str) -> bool:
    if _EMAIL.search(text) or _PHONE_E164.search(text):
        return True
    if any(len(_digits(m.group())) >= 9 for m in _PHONE_GROUPED.finditer(text)):
        return True
    if any(_iban_ok(m.group().upper()) for m in _IBAN_COMPACT.finditer(text)):
        return True
    if any(_spaced_iban_ok(m.group()) for m in _IBAN_SPACED.finditer(text)):
        return True
    for pattern in (_CARD_PLAIN, _CARD_GROUPED, _CARD_AMEX):
        for m in pattern.finditer(text):
            d = _digits(m.group())
            if 13 <= len(d) <= 19 and _iin_ok(d) and _luhn(d):
                return True
    return False


def _bounded_json(data: dict[str, Any]) -> str | None:
    """JSON form of ``data``, or None as soon as it passes ``MAX_SCAN_CHARS``."""
    encoder = json.JSONEncoder(ensure_ascii=False, default=lambda _o: "")
    parts: list[str] = []
    size = 0
    for chunk in encoder.iterencode(data):
        size += len(chunk)
        if size > MAX_SCAN_CHARS:
            return None
        parts.append(chunk)
    return "".join(parts)


def _scan(text: str) -> bool:
    """True when ``text`` holds PII or cannot be scanned within the bound (fail closed)."""
    if len(text) > MAX_SCAN_CHARS:
        return True
    text = _normalise(text)
    return len(text) > MAX_SCAN_CHARS or _has_pii(text)


class RegexPiiClassifier:
    """Flags common PII patterns as ``confidential``; everything else is ``public``.

    Input beyond the scan bound is not skipped: an over-long text or data blob is
    ``confidential``. Data that cannot be serialised (circular, too deep) raises, which the
    policy engine turns into a denial.
    """

    def classify(self, text: str, data: dict[str, Any] | None) -> Classification:
        if _scan(text):
            return Classification.CONFIDENTIAL
        if data:
            blob = _bounded_json(data)
            if blob is None or _scan(blob):
                return Classification.CONFIDENTIAL
        return Classification.PUBLIC
