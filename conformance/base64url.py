"""Base64url, and base64, as the proofs and credentials carry them.

Every decoder here is a named reading over one table (`_six_bits`). SPEC.md 7.4 reads a response
proof's JWS segments, and the `x` of its key, exactly as RFC 7515 section 2 writes base64url
(`strict_base64url_bytes`). SPEC.md 7.8 reads a credential's `proofValue` and a segment of a
VC-JWT by rules of its own, `signature_bytes` and `jws_segment_bytes`. A card proof's key and
signatures, and a status list's `encodedList`, are base64url with or without its padding
(`padded_base64url_bytes`).
"""

import base64
import re


def b64url_nopad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def std_b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


_BASE64URL = {character: value for value, character in enumerate(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")}
_BASE64_EITHER = {**_BASE64URL, "+": 62, "/": 63}
_BASE64URL_ONLY = re.compile("[A-Za-z0-9_-]*")
_BASE64URL_PADDED = re.compile("[A-Za-z0-9_-]*={0,2}")


def _six_bits(encoded: str, alphabet: dict):
    """The characters of `alphabet` in `encoded`, in order, six bits each.

    Returns the whole bytes they give, how many of them there are, and how many `=` follow the
    last. ASCII whitespace is passed over wherever it stands, and bits short of a byte are
    dropped. Any other character, or one of the alphabet after a `=`, raises ValueError.
    """
    out = bytearray()
    buffer = bits = characters = padding = 0
    for character in encoded:
        if character in " \t\n\r\f":
            continue
        if character == "=":
            padding += 1
            continue
        value = None if padding else alphabet.get(character)
        if value is None:
            raise ValueError("a character outside the alphabet, or one after `=`")
        characters += 1
        buffer = (buffer << 6) | value
        bits += 6
        if bits >= 8:
            bits -= 8
            out.append((buffer >> bits) & 0xFF)
            buffer &= (1 << bits) - 1
    return bytes(out), characters, padding


def signature_bytes(encoded: str) -> bytes:
    """SPEC.md 7.8, a `proofValue`: its base64 or base64url characters, six bits each, as bytes.

    `=` may only follow the last of those characters, as padding. So padding, the other
    alphabet, a line break and a last character's spare bits all read to the same signature.
    """
    return _six_bits(encoded, _BASE64_EITHER)[0]


def strict_base64url_bytes(encoded: str) -> bytes:
    """SPEC.md 7.4, a segment of a response proof's JWS, or the `x` of its key: base64url exactly
    as RFC 7515 section 2 writes it.

    The base64url alphabet alone, with no whitespace and no `=`. A last group of one character
    starts a byte and gives none of it, and is refused. Bits short of a byte are dropped.
    """
    readable = isinstance(encoded, str) and _BASE64URL_ONLY.fullmatch(encoded)
    if not readable or len(encoded) % 4 == 1:
        raise ValueError("a proof's JWS segment is base64url as RFC 7515 writes it")
    return _six_bits(encoded, _BASE64URL)[0]


def jws_segment_bytes(encoded: str) -> bytes:
    """SPEC.md 7.8, a segment of a VC-JWT: base64url read no more loosely than the JWS libraries
    that verify a VC-JWT read it.

    The base64url alphabet alone. `=` may only complete the last group of four characters: two
    after a group of two, one after a group of three, none otherwise. A last group of one
    character starts a byte and gives none of it, and is refused.
    """
    decoded, characters, padding = _six_bits(encoded, _BASE64URL)
    last_group = characters % 4
    if last_group == 1 or (padding and (last_group == 0 or padding != 4 - last_group)):
        raise ValueError("a JWS segment is base64url")
    return decoded


def padded_base64url_bytes(encoded: str) -> bytes:
    """A card proof's key and signatures, and a status list's `encodedList`: base64url, with or
    without its padding.

    The base64url alphabet alone, with no whitespace, and at most two `=` after the last
    character. A last group of one character starts a byte and gives none of it, and is refused.
    Bits short of a byte are dropped.
    """
    if not isinstance(encoded, str) or not _BASE64URL_PADDED.fullmatch(encoded):
        raise ValueError("base64url, with or without padding")
    decoded, characters, _ = _six_bits(encoded, _BASE64URL)
    if characters % 4 == 1:
        raise ValueError("base64url, with or without padding")
    return decoded
