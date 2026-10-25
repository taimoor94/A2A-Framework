"""Classification levels and the regex PII classifier."""

import time

import pytest

from a2agw.security.classify import Classification, Classifier, RegexPiiClassifier

C = Classification


def test_levels_are_ordered():
    assert C.PUBLIC < C.INTERNAL < C.CONFIDENTIAL < C.RESTRICTED
    assert max(C.INTERNAL, C.RESTRICTED, C.PUBLIC) is C.RESTRICTED


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("public", C.PUBLIC),
        ("Internal", C.INTERNAL),
        ("CONFIDENTIAL", C.CONFIDENTIAL),
        (" restricted ", C.RESTRICTED),
    ],
)
def test_parse_case_insensitive(raw, expected):
    assert Classification.parse(raw) is expected


@pytest.mark.parametrize("raw", ["secret", "", "0", "publicx"])
def test_parse_unknown_raises(raw):
    with pytest.raises(ValueError):
        Classification.parse(raw)


def test_regex_classifier_satisfies_protocol():
    assert isinstance(RegexPiiClassifier(), Classifier)


@pytest.mark.parametrize(
    "text",
    [
        "reach me at jane.doe@example.com please",
        "mail: x@mail.example.co.uk",
        "call +447911123456 tomorrow",
        "call (555) 123-4567 tomorrow",
        "office: +44 20 7946 0958",
        "dial 555-123-4567",
        "IBAN GB82WEST12345698765432 for payment",
        "iban DE89370400440532013000.",
        "card 4111111111111111 exp 12/29",
        "card 4111 1111 1111 1111",
        "card 4111-1111-1111-1111 now 12",
        "amex 3782 822463 10005",
        "card 5500005555555559",
    ],
)
def test_pii_detected(text):
    assert RegexPiiClassifier().classify(text, None) is C.CONFIDENTIAL


@pytest.mark.parametrize(
    "text",
    [
        "the weather is nice",
        "version 2026-10-25 released",
        "ip 192.168.100.200 is private",
        "order number 12345678",
        "user@localhost",
        "GB00WEST12345698765432",  # bad IBAN check digits
        "call 12-34",
    ],
)
def test_clean_text_public(text):
    assert RegexPiiClassifier().classify(text, None) is C.PUBLIC


def test_luhn_false_positive_not_flagged():
    clf = RegexPiiClassifier()
    # 16 digits in card shape, but the Luhn check fails.
    assert clf.classify("ref 4111111111111112", None) is C.PUBLIC
    assert clf.classify("ref 4111 1111 1111 1112", None) is C.PUBLIC
    assert clf.classify("ref 4111-1111-1111-1112", None) is C.PUBLIC
    # Same number with a valid check digit is flagged.
    assert clf.classify("ref 4111 1111 1111 1111", None) is C.CONFIDENTIAL


def test_data_is_scanned():
    clf = RegexPiiClassifier()
    assert clf.classify("", {"contact": {"email": "a.b@example.org"}}) is C.CONFIDENTIAL
    assert clf.classify("", {"amount": 12, "items": ["x"]}) is C.PUBLIC


def test_unserialisable_data_does_not_raise():
    clf = RegexPiiClassifier()
    assert clf.classify("hi", {"obj": object()}) is C.PUBLIC


def test_input_is_bounded():
    clf = RegexPiiClassifier()
    pad = "x" * (256 * 1024)
    assert clf.classify(pad + " jane@example.com", None) is C.PUBLIC
    assert clf.classify("", {"pad": pad, "email": "jane@example.com"}) is C.PUBLIC


@pytest.mark.parametrize(
    "unit",
    [
        "a",
        "a@",
        "a@b",
        "a@b.",
        "1",
        "1 ",
        "1-",
        "+1",
        "+1 ",
        "(1) ",
        "GB82",
        "GB8",
        "A1",
        "1111 ",
        "a.b@",
        "@a.",
    ],
)
def test_adversarial_input_is_fast(unit):
    text = (unit * (256 * 1024 // len(unit) + 1))[: 256 * 1024]
    clf = RegexPiiClassifier()
    start = time.perf_counter()
    clf.classify(text, {"t": text})
    assert time.perf_counter() - start < 0.5
