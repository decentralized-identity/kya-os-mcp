"""SPEC.md 7.8: the id a delegation credential shows, and the reference it goes by.

A proof that binds a chain names the chain's last credential by that reference, as
`delegationRef`.
"""

import re

from base64url import jws_segment_bytes
from digests import DIGEST_FORM, sha256_digest
from signed_form import MAX_CREDENTIAL_NESTING_DEPTH
from strict_json import json_text_nests_deeper_than, read_json

# What an audit record names a delegation by when its credential shows no id.
NO_DELEGATION_ID = "unknown"

# The code points that do not print as themselves, first and last of each run: the control (Cc)
# and format (Cf) characters and the line and paragraph separators (Zl, Zp) of Unicode 16.0 and
# 17.0. Written out, not read from `unicodedata`, whose Unicode version is the interpreter's.
DO_NOT_PRINT = (
    (0x0000, 0x001F), (0x007F, 0x009F), (0x00AD, 0x00AD), (0x0600, 0x0605), (0x061C, 0x061C),
    (0x06DD, 0x06DD), (0x070F, 0x070F), (0x0890, 0x0891), (0x08E2, 0x08E2), (0x180E, 0x180E),
    (0x200B, 0x200F), (0x2028, 0x202E), (0x2060, 0x2064), (0x2066, 0x206F), (0xFEFF, 0xFEFF),
    (0xFFF9, 0xFFFB), (0x110BD, 0x110BD), (0x110CD, 0x110CD), (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A), (0xE0001, 0xE0001), (0xE0020, 0xE007F),
    (0xD800, 0xDFFF),   # a surrogate without its pair, once the pairs are read as one code point
)
_DOES_NOT_PRINT = re.compile(
    "[" + "".join(f"\\U{first:08x}-\\U{last:08x}" for first, last in DO_NOT_PRINT) + "]")


def _non_empty_string(value):
    return value if isinstance(value, str) and value else None


def _delegation_id(credential: dict):
    subject = credential.get("credentialSubject")
    delegation = subject.get("delegation") if isinstance(subject, dict) else None
    return _non_empty_string(delegation.get("id")) if isinstance(delegation, dict) else None


def delegation_credential_id(credential):
    """SPEC.md 7.8: the id a credential shows, in the form it was presented in, or None.

    A credential object: `id`, then `credentialSubject.delegation.id`. A compact VC-JWT whose
    payload is a JSON object with an object `vc`: `vc.id`, then `jti`, then
    `vc.credentialSubject.delegation.id`. The first that is a non-empty string. The payload is
    read strictly: as a JWS segment, as UTF-8, and as JSON. One whose arrays and objects nest
    more than 64 deep is not read as JSON at all, and shows no id: its text is counted before
    the parser is handed it, so the answer never turns on how deep a text the parser reads.
    """
    if isinstance(credential, str):
        segments = credential.split(".")
        if len(segments) != 3:
            return None
        try:
            text = jws_segment_bytes(segments[1]).decode("utf-8")
            if json_text_nests_deeper_than(text, MAX_CREDENTIAL_NESTING_DEPTH):
                return None
            claims = read_json(text)
        except ValueError:
            return None
        vc = claims.get("vc") if isinstance(claims, dict) else None
        if not isinstance(vc, dict):
            return None
        return (_non_empty_string(vc.get("id")) or _non_empty_string(claims.get("jti"))
                or _delegation_id(vc))
    if not isinstance(credential, dict):
        return None
    return _non_empty_string(credential.get("id")) or _delegation_id(credential)


def delegation_reference(identifier):
    """SPEC.md 7.8: the reference for a credential id, the id itself or the SHA-256 of it.

    The digest stands for an id of more than 256 UTF-16 code units, one that holds a character
    that does not print as itself (a control or format character, a line or paragraph separator,
    or a surrogate without its pair), one that already reads as such a digest, and `unknown`.
    It is taken over the id's UTF-8 bytes, a surrogate without its pair written as the three bytes
    of its code point (WTF-8). None for an empty id.

    The id is read as the UTF-16 code units JavaScript holds it in: a surrogate pair in a str is
    one character, as JSON text gives it.
    """
    if not isinstance(identifier, str) or not identifier:
        return None
    code_units = identifier.encode("utf-16-le", "surrogatepass")
    as_read = code_units.decode("utf-16-le", "surrogatepass")
    verbatim = (len(code_units) // 2 <= 256 and not _DOES_NOT_PRINT.search(as_read)
                and not DIGEST_FORM.fullmatch(as_read) and as_read != NO_DELEGATION_ID)
    return as_read if verbatim else sha256_digest(as_read.encode("utf-8", "surrogatepass"))


def delegation_ref_of(credential):
    """The reference a credential goes by: what a proof that binds its chain names it as."""
    identifier = delegation_credential_id(credential)
    return None if identifier is None else delegation_reference(identifier)
