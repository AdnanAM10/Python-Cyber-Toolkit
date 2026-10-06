"""
modules/base64_util.py
======================

Base64 encoding and decoding helpers.

Base64 converts binary data into plain ASCII text.

It is NOT encryption. Anyone can decode Base64 data.

Standard library only.
"""

import base64


def encode_base64(text: str) -> str:
    """
    Encode a UTF-8 string into Base64.

    Parameters
    ----------
    text : str
        Text to encode.

    Returns
    -------
    str
        Base64-encoded text.

    Raises
    ------
    TypeError
        If text is not a string.
    """

    if not isinstance(text, str):
        raise TypeError(
            f"encode_base64() expects a str, got {type(text).__name__}. "
            "Pass a plain-text string."
        )

    encoded_bytes = base64.b64encode(text.encode("utf-8"))

    return encoded_bytes.decode("utf-8")


def decode_base64(b64_str: str) -> str:
    """
    Decode a Base64 string back into UTF-8 text.

    Parameters
    ----------
    b64_str : str
        Base64 string to decode.

    Returns
    -------
    str
        Decoded text.

    Raises
    ------
    TypeError
        If b64_str is not a string.

    ValueError
        If the Base64 data is invalid or does not decode into UTF-8 text.
    """

    if not isinstance(b64_str, str):
        raise TypeError(
            f"decode_base64() expects a str, got {type(b64_str).__name__}. "
            "Pass a Base64 string."
        )

    stripped = b64_str.strip()

    # Empty input is valid Base64 and decodes to an empty string.
    if not stripped:
        return ""

    try:
        decoded_bytes = base64.b64decode(
            stripped,
            validate=True,
        )

    except Exception as exc:
        raise ValueError(
            f"Invalid Base64 string: {exc}. "
            "Make sure the input contains valid Base64 data."
        ) from exc

    try:
        return decoded_bytes.decode("utf-8")

    except UnicodeDecodeError as exc:
        raise ValueError(
            "The decoded data is not valid UTF-8 text. "
            "The input may represent binary data instead of text."
        ) from exc


if __name__ == "__main__":

    sample = "Hello, World! 123"

    print(f"Original : {sample!r}")

    encoded = encode_base64(sample)
    print(f"Base64   : {encoded}")

    decoded = decode_base64(encoded)
    print(f"Decoded  : {decoded!r}")

    print("\n--- Empty string example ---")

    print(f"encode('') -> {encode_base64('')!r}")
    print(f"decode('') -> {decode_base64('')!r}")

    print("\n--- Invalid input example ---")

    try:
        decode_base64("!!!not-base64!!!")

    except ValueError as err:
        print(f"Caught error: {err}")