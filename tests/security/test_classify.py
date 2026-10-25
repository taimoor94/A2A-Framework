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


def test_over_bound_input_fails_closed():
    clf = RegexPiiClassifier()
    pad = "x" * (256 * 1024)
    assert clf.classify(pad, None) is C.PUBLIC  # exactly at the bound is scanned
    assert clf.classify(pad + " jane@example.com", None) is C.CONFIDENTIAL
    assert clf.classify(pad + "x", None) is C.CONFIDENTIAL
    assert clf.classify("", {"pad": pad, "email": "jane@example.com"}) is C.CONFIDENTIAL
    assert clf.classify("", {"pad": pad}) is C.CONFIDENTIAL


def test_huge_data_stops_serialising_early():
    clf = RegexPiiClassifier()
    big = {"items": ["x" * 1024] * 50_000}  # ~50 MB if fully serialised
    start = time.process_time()  # CPU time: unaffected by other processes on the machine
    assert clf.classify("", big) is C.CONFIDENTIAL
    assert time.process_time() - start < 0.5


def test_circular_data_raises():
    loop: dict = {}
    loop["self"] = loop
    with pytest.raises(ValueError):
        RegexPiiClassifier().classify("", loop)


@pytest.mark.parametrize(
    "text",
    [
        "pay DE89 3704 0044 0532 0130 00 now",
        "pay de89370400440532013000 now",
        "pay gb82 west 1234 5698 7654 32",
        "acct BE68 5390 0754 7034 then done",  # 16-char IBAN followed by a 4-letter word
    ],
)
def test_iban_spaced_and_lowercase(text):
    assert RegexPiiClassifier().classify(text, None) is C.CONFIDENTIAL


@pytest.mark.parametrize(
    "text",
    [
        "\uff14" + "\uff11" * 15,  # fullwidth 4111111111111111
        "\u0664" + "\u0661" * 15,  # Arabic-Indic 4111111111111111
        "jane\uff20example.com",  # fullwidth at sign
        "\u0968\u0968 \u0967\u0968\u0969 \u0967\u0968\u0969",  # Devanagari digits, too short
    ],
)
def test_unicode_digits_normalised(text):
    expected = C.PUBLIC if "\u0968" in text else C.CONFIDENTIAL
    assert RegexPiiClassifier().classify(text, None) is expected


def test_card_requires_issuer_prefix():
    clf = RegexPiiClassifier()
    # Luhn-valid but no real IIN prefix (starts with 1 / 9) or wrong length for the brand.
    assert clf.classify("id 1234567812345670", None) is C.PUBLIC
    assert clf.classify("id 9111111111111111", None) is C.PUBLIC
    assert clf.classify("id 411111111111111113", None) is C.PUBLIC  # 18-digit "Visa"


def test_timestamps_and_snowflakes_not_flagged():
    import random

    rng = random.Random(1234)
    clf = RegexPiiClassifier()
    for _ in range(2000):
        epoch_ms = str(1_600_000_000_000 + rng.randrange(10**12))
        # Snowflake-style ids: 18-19 digits with a leading 1.
        snow18 = str(rng.randrange(10**17, 2 * 10**17))
        snow19 = str(rng.randrange(10**18, 2 * 10**18))
        assert clf.classify(f"ts {epoch_ms}", None) is C.PUBLIC
        assert clf.classify(f"id {snow18} {snow19}", None) is C.PUBLIC


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
        "AB12 CCCC ",
        "ab12cccc",
        "\u0664",
        "a.b@",
        "@a.",
    ],
)
def test_adversarial_input_is_fast(unit):
    text = (unit * (256 * 1024 // len(unit) + 1))[: 256 * 1024]
    clf = RegexPiiClassifier()
    start = time.process_time()  # CPU time: unaffected by other processes on the machine
    clf.classify(text, {"t": text[: 200 * 1024]})
    assert time.process_time() - start < 0.5
