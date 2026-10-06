"""
Unit tests for modules/base64_util.py
"""

import pytest

from modules.base64_util import (
    decode_base64,
    encode_base64,
)


def test_encode_known_value():
    assert (
        encode_base64("Hello, World!")
        == "SGVsbG8sIFdvcmxkIQ=="
    )


def test_decode_known_value():
    assert (
        decode_base64("SGVsbG8sIFdvcmxkIQ==")
        == "Hello, World!"
    )


def test_round_trip():

    original = (
        "CyberSec 101 — let's secure it! 🛡"
    )

    encoded = encode_base64(original)

    decoded = decode_base64(encoded)

    assert decoded == original


def test_empty_string_round_trip():

    assert encode_base64("") == ""

    assert decode_base64("") == ""


def test_encode_rejects_non_string():

    with pytest.raises(
        TypeError,
        match="expects a str",
    ):
        encode_base64(12345)


def test_decode_rejects_non_string():

    with pytest.raises(
        TypeError,
        match="expects a str",
    ):
        decode_base64(
            b"SGVsbG8="
        )


def test_decode_rejects_invalid_characters():

    with pytest.raises(
        ValueError,
        match="Invalid Base64",
    ):
        decode_base64(
            "!!!not-base64!!!"
        )


def test_decode_rejects_bad_padding():

    with pytest.raises(
        ValueError,
        match="Invalid Base64",
    ):
        decode_base64(
            "YWJ"
        )