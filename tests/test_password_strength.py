"""
Unit tests for modules/password_strength.py
"""

import pytest

from modules.password_strength import (
    check_password_strength,
    _count_repeats,
    _score_to_rating,
)


def test_rejects_non_string():
    with pytest.raises(
        TypeError,
        match="expects a str",
    ):
        check_password_strength(
            12345
        )


def test_rejects_empty_string():
    with pytest.raises(
        ValueError,
        match="empty password",
    ):
        check_password_strength(
            ""
        )


def test_return_type_is_dict():
    result = check_password_strength(
        "abc"
    )

    assert isinstance(
        result,
        dict,
    )

    assert set(result.keys()) == {
        "score",
        "rating",
        "strengths",
        "suggestions",
    }


def test_score_is_integer():
    result = check_password_strength(
        "abc"
    )

    assert isinstance(
        result["score"],
        int,
    )


def test_rating_is_valid_string():
    valid_ratings = {
        "Weak",
        "Fair",
        "Good",
        "Strong",
    }

    result = check_password_strength(
        "abc"
    )

    assert (
        result["rating"]
        in valid_ratings
    )


def test_strengths_and_suggestions_are_lists():
    result = check_password_strength(
        "abc"
    )

    assert isinstance(
        result["strengths"],
        list,
    )

    assert isinstance(
        result["suggestions"],
        list,
    )


def test_all_character_classes_earn_points():
    result = check_password_strength(
        "aB1!"
    )

    assert result["score"] == 4
    assert result["rating"] == "Fair"


def test_missing_uppercase_suggests_adding_it():
    result = check_password_strength(
        "abcdef12"
    )

    assert any(
        "uppercase" in suggestion.lower()
        for suggestion in result["suggestions"]
    )


def test_missing_lowercase_suggests_adding_it():
    result = check_password_strength(
        "ABCDEFGH12"
    )

    assert any(
        "lowercase" in suggestion.lower()
        for suggestion in result["suggestions"]
    )


def test_missing_digit_suggests_adding_it():
    result = check_password_strength(
        "AbcdefghIJ"
    )

    assert any(
        "digit" in suggestion.lower()
        for suggestion in result["suggestions"]
    )


def test_missing_special_suggests_adding_it():
    result = check_password_strength(
        "Abcdefgh12"
    )

    assert any(
        "special" in suggestion.lower()
        for suggestion in result["suggestions"]
    )


def test_short_length_gives_no_length_bonus():
    result = check_password_strength(
        "aB1!xyz"
    )

    assert result["score"] == 4
    assert result["rating"] == "Fair"


def test_eight_char_length_earns_one_point():
    result = check_password_strength(
        "aB1!xyz9"
    )

    assert result["score"] == 5
    assert result["rating"] == "Good"


def test_twelve_char_length_earns_two_points():
    result = check_password_strength(
        "aB1!xyz9mnop"
    )

    assert result["score"] == 6
    assert result["rating"] == "Good"


def test_sixteen_char_length_earns_three_points():
    result = check_password_strength(
        "aB1!xyz9mnopqrst"
    )

    assert result["score"] == 7
    assert result["rating"] == "Strong"


def test_common_password_gets_penalty():
    result = check_password_strength(
        "password"
    )

    assert result["score"] == 0
    assert result["rating"] == "Weak"

    assert any(
        "common" in suggestion.lower()
        for suggestion in result["suggestions"]
    )


def test_common_password_is_case_insensitive():
    result = check_password_strength(
        "PASSWORD"
    )

    assert result["score"] == 0
    assert result["rating"] == "Weak"


def test_123456_is_common():
    result = check_password_strength(
        "123456"
    )

    assert any(
        "common" in suggestion.lower()
        for suggestion in result["suggestions"]
    )


def test_qwerty_is_common():
    result = check_password_strength(
        "qwerty"
    )

    assert any(
        "common" in suggestion.lower()
        for suggestion in result["suggestions"]
    )


def test_non_common_password_no_penalty():
    result = check_password_strength(
        "Xk9#mR2$vLp!"
    )

    assert not any(
        "common" in suggestion.lower()
        for suggestion in result["suggestions"]
    )


def test_repeated_characters_get_penalty():
    result = check_password_strength(
        "aaabB1!"
    )

    assert result["score"] == 2
    assert result["rating"] == "Weak"

    assert any(
        "run of" in suggestion.lower()
        for suggestion in result["suggestions"]
    )


def test_two_repeated_chars_do_not_penalty():
    result = check_password_strength(
        "ababB1!"
    )

    assert result["score"] == 4

    assert not any(
        "run of" in suggestion.lower()
        for suggestion in result["suggestions"]
    )


def test_count_repeats_helper():
    assert _count_repeats("abc") == 1
    assert _count_repeats("aab") == 2
    assert _count_repeats("aaa") == 3
    assert _count_repeats("aaabbb") == 3
    assert _count_repeats("aaabbbcccc") == 4
    assert _count_repeats("") == 1


def test_score_zero_is_weak():
    assert (
        _score_to_rating(0)
        == "Weak"
    )


def test_score_two_is_weak():
    assert (
        _score_to_rating(2)
        == "Weak"
    )


def test_score_three_is_fair():
    assert (
        _score_to_rating(3)
        == "Fair"
    )


def test_score_four_is_fair():
    assert (
        _score_to_rating(4)
        == "Fair"
    )


def test_score_five_is_good():
    assert (
        _score_to_rating(5)
        == "Good"
    )


def test_score_six_is_good():
    assert (
        _score_to_rating(6)
        == "Good"
    )


def test_score_seven_is_strong():
    assert (
        _score_to_rating(7)
        == "Strong"
    )


def test_score_above_seven_is_strong():
    assert (
        _score_to_rating(10)
        == "Strong"
    )


def test_very_weak_password():
    result = check_password_strength(
        "x"
    )

    assert result["rating"] == "Weak"
    assert result["score"] == 1


def test_strong_password_achieves_score_seven():
    result = check_password_strength(
        "Xk9#mR2$vLp!QzWt"
    )

    assert result["score"] == 7
    assert result["rating"] == "Strong"


def test_twelve_char_mixed_scores_six():
    result = check_password_strength(
        "Xk9#mR2$vLp!"
    )

    assert result["score"] == 6
    assert result["rating"] == "Good"


def test_password_is_never_in_output():
    secret = "MySup3rSecretP@ss"

    result = check_password_strength(
        secret
    )

    values = [
        str(result["score"]),
        result["rating"],
        *result["strengths"],
        *result["suggestions"],
    ]

    for value in values:
        assert secret not in value


def test_strengths_not_empty_for_good_input():
    result = check_password_strength(
        "aB1!xyz9"
    )

    assert len(
        result["strengths"]
    ) >= 1


def test_suggestions_not_empty_for_weak_input():
    result = check_password_strength(
        "x"
    )

    assert len(
        result["suggestions"]
    ) >= 1
