"""
config.py
=========
Shared configuration constants for the Cyber Toolkit project.

Values that may need to be changed later are kept here so they only
need to be updated in one place.

Stage 1 only needs hash-related constants.
Later stages can add network settings, timeouts, safety settings, etc.
"""

# ---------------------------------------------------------------------------
# Hash generation
# ---------------------------------------------------------------------------

ALLOWED_HASH_ALGOS: list[str] = [
    "sha256",
    "sha512",
    "sha1",
    "md5",
]

DEFAULT_HASH_ALGO: str = "sha256"

# MD5 and SHA-1 are included only for historical and educational comparison.
# They should not be used for modern security-sensitive purposes.
INSECURE_ALGOS: set[str] = {
    "md5",
    "sha1",
}