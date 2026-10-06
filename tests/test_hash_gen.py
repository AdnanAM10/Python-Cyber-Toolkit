"""
Unit tests for modules/hash_gen.py
"""

import warnings

import pytest

from modules.hash_gen import (
    hash_data,
    list_supported_algorithms,
)


KNOWN_DIGESTS = {

    "sha256":
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",

    "sha512":
        "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca7"
        "2323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043",

    "sha1":
        "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",

    "md5":
        "5d41402abc4b2a76b9719d911017c592",
}


def test_sha256_known_digest():

    assert (
        hash_data(
            "hello",
            "sha256",
        )
        == KNOWN_DIGESTS["sha256"]
    )


def test_sha512_known_digest():

    assert (
        hash_data(
            "hello",
            "sha512",
        )
        == KNOWN_DIGESTS["sha512"]
    )


def test_sha1_known_digest():

    with pytest.warns(
        UserWarning,
        match="collision resistance",
    ):

        result = hash_data(
            "hello",
            "sha1",
        )

    assert result == KNOWN_DIGESTS["sha1"]


def test_md5_known_digest():

    with pytest.warns(
        UserWarning,
        match="collision resistance",
    ):

        result = hash_data(
            "hello",
            "md5",
        )

    assert result == KNOWN_DIGESTS["md5"]


def test_default_algorithm_is_sha256():

    assert (
        hash_data("hello")
        == KNOWN_DIGESTS["sha256"]
    )


def test_list_contains_all_four():

    algorithms = (
        list_supported_algorithms()
    )

    assert set(algorithms) == {
        "sha256",
        "sha512",
        "sha1",
        "md5",
    }


def test_list_returns_a_copy():

    algorithms = (
        list_supported_algorithms()
    )

    algorithms.append(
        "fake_algo"
    )

    assert (
        "fake_algo"
        not in list_supported_algorithms()
    )


def test_unsupported_algorithm_raises():

    with pytest.raises(
        ValueError,
        match="Unsupported algorithm",
    ):

        hash_data(
            "hello",
            "sha3-256",
        )


def test_non_string_data_raises():

    with pytest.raises(
        TypeError,
        match="expects a str",
    ):

        hash_data(
            12345,
            "sha256",
        )


def test_md5_emits_user_warning():

    with pytest.warns(
        UserWarning,
        match="collision resistance",
    ):

        hash_data(
            "hello",
            "md5",
        )


def test_sha1_emits_user_warning():

    with pytest.warns(
        UserWarning,
        match="collision resistance",
    ):

        hash_data(
            "hello",
            "sha1",
        )


def test_secure_algorithms_do_not_warn():

    with warnings.catch_warnings():

        warnings.simplefilter(
            "error"
        )

        hash_data(
            "hello",
            "sha256",
        )

        hash_data(
            "hello",
            "sha512",
        )