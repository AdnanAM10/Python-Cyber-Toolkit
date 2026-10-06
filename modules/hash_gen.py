"""
modules/hash_gen.py
===================

Hash generation for educational comparison.

Supported algorithms:

sha256
sha512
sha1
md5

SHA-1 and MD5 are included only for historical and educational comparison.

Practical collision attacks exist against MD5 and SHA-1, so they should
not be used for modern security-sensitive applications.

Standard library only.
"""

import hashlib
import os
import sys
import warnings


# ---------------------------------------------------------------------------
# Make the project root available when this file is run directly:
#
# python modules/hash_gen.py
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
    )
)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


from config import (
    ALLOWED_HASH_ALGOS,
    DEFAULT_HASH_ALGO,
    INSECURE_ALGOS,
)


def list_supported_algorithms() -> list[str]:
    """
    Return the supported hash algorithms.
    """

    return list(ALLOWED_HASH_ALGOS)


def hash_data(
    data: str,
    algo: str = DEFAULT_HASH_ALGO,
) -> str:
    """
    Generate a hexadecimal hash digest.

    Parameters
    ----------
    data : str
        Text to hash.

    algo : str
        Hash algorithm to use.

    Returns
    -------
    str
        Hexadecimal hash digest.

    Raises
    ------
    TypeError
        If data is not a string.

    ValueError
        If the requested algorithm is unsupported.
    """

    if not isinstance(data, str):
        raise TypeError(
            f"hash_data() expects a str, got {type(data).__name__}. "
            "Pass a plain-text string."
        )

    if not isinstance(algo, str):
        raise ValueError(
            f"Unsupported algorithm: {algo!r}. "
            f"Choose one of: {', '.join(ALLOWED_HASH_ALGOS)}."
        )

    algo_lower = algo.lower()

    if algo_lower not in ALLOWED_HASH_ALGOS:
        raise ValueError(
            f"Unsupported algorithm: {algo!r}. "
            f"Choose one of: {', '.join(ALLOWED_HASH_ALGOS)}."
        )

    if algo_lower in INSECURE_ALGOS:
        warnings.warn(
            f"'{algo_lower.upper()}' has broken collision resistance "
            "and should not be used for modern security-sensitive tasks. "
            "It is included here only for educational comparison.",
            category=UserWarning,
            stacklevel=2,
        )

    hasher = hashlib.new(algo_lower)

    hasher.update(
        data.encode("utf-8")
    )

    return hasher.hexdigest()


if __name__ == "__main__":

    sample = "CyberSec 101"

    print(f"Hashing: {sample!r}\n")

    print(
        f"{'Algorithm':<10} "
        f"{'Hex chars':<10} "
        f"Hex Digest"
    )

    print("-" * 100)

    for algorithm in list_supported_algorithms():

        digest = hash_data(
            sample,
            algorithm,
        )

        print(
            f"{algorithm.upper():<10} "
            f"{len(digest):<10} "
            f"{digest}"
        )

    print(
        "\nReminder: MD5 and SHA-1 are included only for "
        "historical and educational comparison."
    )