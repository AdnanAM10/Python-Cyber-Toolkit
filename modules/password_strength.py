"""
modules/password_strength.py
============================
Rule-based password strength evaluator (educational use).

This tool does NOT prove a password is secure. It applies a
small set of transparent, human-readable rules to give a rough
starting point for thinking about password quality.

The password is never printed, logged, or stored by the evaluator.

Standard library only: re
"""

import re


COMMON_WEAK_PASSWORDS: frozenset[str] = frozenset(
    p.lower()
    for p in [
        "password",
        "123456",
        "qwerty",
        "12345678",
        "123456789",
        "1234567890",
        "12345",
        "111111",
        "1234567",
        "123123",
        "000000",
        "abc123",
        "iloveyou",
        "admin",
        "letmein",
        "welcome",
        "monkey",
        "dragon",
        "sunshine",
        "princess",
        "login",
        "passw0rd",
    ]
)


MIN_LENGTH_GOOD: int = 8
MIN_LENGTH_STRONG: int = 12
MIN_LENGTH_EXCELLENT: int = 16

REPEAT_THRESHOLD: int = 3

RATING_TABLE: list[tuple[int, str]] = [
    (0, "Weak"),
    (3, "Fair"),
    (5, "Good"),
    (7, "Strong"),
]


_HAS_UPPER = re.compile(r"[A-Z]")
_HAS_LOWER = re.compile(r"[a-z]")
_HAS_DIGIT = re.compile(r"[0-9]")
_HAS_SPECIAL = re.compile(r"[^A-Za-z0-9_\s]")
_REPEAT_RUN = re.compile(
    r"(.)\1{" + str(REPEAT_THRESHOLD - 1) + r",}"
)


def _score_to_rating(score: int) -> str:
    """
    Map a numeric score to a human-readable rating.
    """

    for threshold, label in reversed(RATING_TABLE):
        if score >= threshold:
            return label

    return "Weak"


def _count_repeats(password: str) -> int:
    """
    Return the length of the longest run of consecutive identical characters.

    Returns 1 when there are no repeated consecutive characters.
    """

    if not password:
        return 1

    longest = 1
    current = 1

    for index in range(1, len(password)):
        if password[index] == password[index - 1]:
            current += 1
            longest = max(longest, current)
        else:
            current = 1

    return longest


def check_password_strength(password: str) -> dict:
    """
    Evaluate password strength using transparent rules.

    Returns a dictionary with:

    score
    rating
    strengths
    suggestions
    """

    if not isinstance(password, str):
        raise TypeError(
            f"check_password_strength() expects a str, "
            f"got {type(password).__name__}. "
            "Pass a plain-text string."
        )

    if len(password) == 0:
        raise ValueError(
            "check_password_strength() received an empty password. "
            "There is nothing to evaluate."
        )

    score = 0
    strengths: list[str] = []
    suggestions: list[str] = []

    has_upper = bool(
        _HAS_UPPER.search(password)
    )

    has_lower = bool(
        _HAS_LOWER.search(password)
    )

    has_digit = bool(
        _HAS_DIGIT.search(password)
    )

    has_special = bool(
        _HAS_SPECIAL.search(password)
    )

    if has_upper:
        score += 1
        strengths.append(
            "Contains uppercase letters."
        )
    else:
        suggestions.append(
            "Add at least one uppercase letter (A-Z)."
        )

    if has_lower:
        score += 1
        strengths.append(
            "Contains lowercase letters."
        )
    else:
        suggestions.append(
            "Add at least one lowercase letter (a-z)."
        )

    if has_digit:
        score += 1
        strengths.append(
            "Contains digits (0-9)."
        )
    else:
        suggestions.append(
            "Add at least one digit (0-9)."
        )

    if has_special:
        score += 1
        strengths.append(
            "Contains special characters (e.g. ! @ # $)."
        )
    else:
        suggestions.append(
            "Add at least one special character (! @ # $ ...)."
        )

    length = len(password)

    # Cumulative length bonuses.
    if length >= MIN_LENGTH_GOOD:
        score += 1

    if length >= MIN_LENGTH_STRONG:
        score += 1

    if length >= MIN_LENGTH_EXCELLENT:
        score += 1

    if length >= MIN_LENGTH_EXCELLENT:
        strengths.append(
            f"Length is {length} "
            f"(>= {MIN_LENGTH_EXCELLENT} characters)."
        )

    elif length >= MIN_LENGTH_STRONG:
        strengths.append(
            f"Length is {length} "
            f"(>= {MIN_LENGTH_STRONG} characters)."
        )

        suggestions.append(
            f"Extend to at least "
            f"{MIN_LENGTH_EXCELLENT} characters "
            "for even better strength."
        )

    elif length >= MIN_LENGTH_GOOD:
        strengths.append(
            f"Length is {length} "
            f"(>= {MIN_LENGTH_GOOD} characters)."
        )

        suggestions.append(
            f"Extend to at least "
            f"{MIN_LENGTH_STRONG} characters "
            "for better strength."
        )

    else:
        suggestions.append(
            f"Length is only {length} characters. "
            f"Use at least {MIN_LENGTH_GOOD}."
        )

    is_common = (
        password.lower()
        in COMMON_WEAK_PASSWORDS
    )

    if is_common:
        score -= 3

        suggestions.append(
            "This password is on a list of very common passwords. "
            "Choose something unique and unpredictable."
        )

    else:
        strengths.append(
            "Not a commonly used weak password."
        )

    longest_run = _count_repeats(
        password
    )

    if longest_run >= REPEAT_THRESHOLD:
        score -= 2

        suggestions.append(
            f"Contains a run of {longest_run} identical characters. "
            "Avoid long repetitions like 'aaa' or '111'."
        )

    score = max(
        0,
        score,
    )

    rating = _score_to_rating(
        score
    )

    return {
        "score": score,
        "rating": rating,
        "strengths": strengths,
        "suggestions": suggestions,
    }


if __name__ == "__main__":

    demo_password = "Xk9#mR2$vLp!QzWt"

    mask = "•" * len(
        demo_password
    )

    print(
        f"Evaluating: {mask} "
        f"({len(demo_password)} characters)\n"
    )

    result = check_password_strength(
        demo_password
    )

    print(
        f"Score : {result['score']} / 7"
    )

    print(
        f"Rating: {result['rating']}"
    )

    print()

    if result["strengths"]:

        print("Strengths:")

        for strength in result["strengths"]:
            print(
                f"  - {strength}"
            )

    if result["suggestions"]:

        print()

        print("Suggestions:")

        for suggestion in result["suggestions"]:
            print(
                f"  - {suggestion}"
            )

    print()

    print(
        "Reminder: this score is a rough heuristic, "
        "not proof of security."
    )

