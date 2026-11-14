"""The cases SPEC.md 7.8's readings of a credential are held to, beyond what the vectors carry.

Which values have a signed form, and so a digest, and which digest each comes to; which id a
credential shows, and the reference it goes by. The TypeScript tests hold their reading to the
same cases (`src/delegation/__tests__/chain-digest.test.ts` and `delegation-ref.test.ts`), so the
two implementations refuse alike and, where they do not refuse, agree.
"""

import sys
import unicodedata

from base64url import b64url_nopad, std_b64
from delegation_ref import UNSEEN_CODE_POINTS, delegation_credential_id, delegation_reference
from digests import sha256_digest
from signed_form import credential_digest
from strict_json import read_json


def _vc_jwt(payload: bytes, encode=b64url_nopad) -> str:
    return "eyJhbGciOiJFZERTQSJ9." + encode(payload) + ".c2lnbmF0dXJl"


def _signed_as(proof_value) -> dict:
    return {"id": "urn:uuid:1111-aaaa", "proof": {"proofValue": proof_value}}


def _signed_with_n(number: str) -> dict:
    """The signed credential, read from a JSON text that also gives it a member `n`, written `number`."""
    return read_json('{"id":"urn:uuid:1111-aaaa","proof":{"proofValue":"c2lnbmF0dXJl"},"n":' + number + "}")


# A credential object is level 1, so a member nested 63 deep makes it 64 deep, the bound.
def _arrays(levels: int):
    value = "leaf"
    for _ in range(levels):
        value = [value]
    return value


def _objects(levels: int):
    value = "leaf"
    for _ in range(levels):
        value = {"a": value}
    return value


def _digestible(value) -> bool:
    try:
        credential_digest(value)
    except ValueError:
        return False
    return True


def signed_form_cases_hold() -> bool:
    """What 7.8 refuses is what a lenient decoder or serializer lets through.

    Each value in the first table has no signed form, so no digest, whoever reads it; the ones
    in the second do, and show that the others are refused for what sets them apart.
    """
    jwt = "eyJhbGciOiJFZERTQSJ9.eyJ2YyI6e319."
    signed = _signed_as("c2lnbmF0dXJl")
    holds_itself = {**signed}
    holds_itself["self"] = holds_itself     # deeper than any bound

    no_signed_form = [
        jwt + "c2lnbmF0=dXJl",                  # `=` ahead of a base64 character
        jwt + "=c2lnbmF0dXJl",
        jwt + "c2lnbmF0dXJl*",                  # a character of neither alphabet
        jwt + "c2lnbmF0\vdXJl",                 # a vertical tab is not whitespace
        jwt + "c2ln+mF0dXJl",                   # base64 in a JWS, which is base64url
        jwt + "c2ln/mF0dXJl",
        jwt + "c2lnbmF0dXJl=",                  # padding that completes no group of four
        jwt + "c2lnbmF0dXI==",
        jwt + "c2lnbmF0dQ=",                    # one `=` after a last group of two, which takes two
        jwt + "c2lnbmF0dXJl====",               # more padding than a group has room for
        jwt + "c2lnbmF0d",                      # a last character that gives no byte
        jwt + "c",                              # no whole byte
        jwt,                                    # no signature
        ".eyJ2YyI6e319.c2lnbmF0dXJl",           # an empty header
        "eyJhbGciOiJFZERTQSJ9..c2lnbmF0dXJl",   # an empty payload
        "eyJhbGciOiJFZERTQSJ9.eyJ2YyI6e319",    # two segments
        "eyJhbGciOiJFZERTQSJ9.eyJ2YyI6e319.c2lnbmF0dXJl.c2ln",
        {"id": "urn:uuid:1111-aaaa"},           # no proof
        _signed_as(7),
        _signed_as("c2lnbmF0\vdXJl"),
        _signed_as("c2lnbmF0=dXJl"),
        # Only ASCII whitespace is read past: a no-break space, a byte order mark or a line
        # separator at either end of a signature is a character of no alphabet, in either kind.
        *(form(written) for form in (jwt.__add__, _signed_as)
          for space in ("\xa0", "\ufeff", "\u2028")
          for written in (space + "c2lnbmF0dXJl", "c2lnbmF0dXJl" + space)),
        {**signed, "n": 2 ** 53},               # an integer a receiver need not read exactly
        {**signed, "n": 1e16},                  # the same kind of number, written with an exponent
        {**signed, "n": float("inf")},
        # Integers past the largest double, read from JSON text, which JSON.parse makes
        # infinite: read exactly at 400 digits, and as infinite at 4301, past the digit limit.
        _signed_with_n("1" * 400),
        _signed_with_n("1" * 4301),
        # A number is read as a double before it is held to that, whatever its text: these are
        # no integers as written, and read as 9007199254740994 and, a tie gone to even, 2^53.
        _signed_with_n("9007199254740993.5"),
        _signed_with_n("9007199254740991.5"),
        {**signed, "s": "\ud800"},              # not well-formed Unicode
        {**signed, "n": _arrays(64)},           # nested 65 deep, one past the bound
        {**signed, "n": _objects(64)},
        {**signed, "proof": {**signed["proof"], "note": _arrays(63)}},  # 65 deep in `proof`
        {**signed, "n": _arrays(100_000)},      # deeper than any stack: counted, not recursed into
        holds_itself,
        ["eyJhbGciOiJFZERTQSJ9.eyJ2YyI6e319.c2lnbmF0dXJl"],
        None,
    ]
    has_signed_form = [
        # A JWS signature may be broken across lines, padded to a group of four, and have the
        # spare bits of its last character set: "I" and "J" end the same eight bytes.
        (jwt + "c2lnbmF0dXI",
         "sha256:54100f570455d7b0f955febea7bfb03961fae7ac4ec04091312d668eac5884e3"),
        (jwt + "c2lnbmF0\ndXJ =",
         "sha256:54100f570455d7b0f955febea7bfb03961fae7ac4ec04091312d668eac5884e3"),
        # A form feed is whitespace, read past in either kind of string, where a vertical tab
        # (above) is not.
        (jwt + "c2lnbmF0\fdXJl",
         "sha256:d612091f803bc695ce2977ea0a08d547d493048f1ee02895ac40af882256f0ce"),
        (_signed_as("c2lnbmF0\fdXJl"),
         "sha256:1e44f47096f50bb8d2f0a32ee74a182c41aaec5704fc3eeb3704a3dfc7ab18cf"),
        # A proofValue is read more loosely: either alphabet, and any padding after it.
        (_signed_as("-_-_"),
         "sha256:0f494896114a7e198939ef17be1459def88e5d7d5349f16259b08ce383deae22"),
        (_signed_as("+/+/\n==="),
         "sha256:0f494896114a7e198939ef17be1459def88e5d7d5349f16259b08ce383deae22"),
        ({**signed, "n": 2 ** 53 - 1},
         "sha256:0471052646eafa107e3ff1b8d079896cdc668b67da5443a718f2bcd306f4f49e"),
        # And so is the same number written with a fraction, which reads as it.
        (_signed_with_n("9007199254740991.0"),
         "sha256:0471052646eafa107e3ff1b8d079896cdc668b67da5443a718f2bcd306f4f49e"),
        ({**signed, "n": 1e-7, "s": "\U0001F600"},
         "sha256:dc7620f2c6a54d6d6c6940109e30228ec007f698723e16d94e9c950b4d8d6da0"),
        # Nested 64 deep, the bound: in arrays, in objects, and in `proof`, which is counted
        # and is no part of the digest.
        ({**signed, "n": _arrays(63)},
         "sha256:8cf2933e9f7d627c74f01097d951d53845dbfdbcf19d929ffb35fe3f19ec5068"),
        ({**signed, "n": _objects(63)},
         "sha256:f742418cf6b9b17356ca5127de22aea0fa61c3df3fd3185eabbfe38462d2584b"),
        ({**signed, "proof": {**signed["proof"], "note": _arrays(62)}},
         "sha256:1e44f47096f50bb8d2f0a32ee74a182c41aaec5704fc3eeb3704a3dfc7ab18cf"),
        # Read from a text that holds `id` and `proof` twice, it is the last of each.
        (read_json('{"id":"urn:uuid:2222-bbbb","proof":{"proofValue":"*"},'
                   '"id":"urn:uuid:1111-aaaa","proof":{"proofValue":"c2lnbmF0dXJl"}}'),
         "sha256:1e44f47096f50bb8d2f0a32ee74a182c41aaec5704fc3eeb3704a3dfc7ab18cf"),
        # A VC-JWT is digested by its segments, which are not read: however deep its payload.
        (_vc_jwt(b'{"vc":' + b"[" * 100_000 + b"]" * 100_000 + b"}"),
         "sha256:b4667a591db72dba8eb1eba941bec5bc79c817e9d92ab4c649aad03e81fe6967"),
        # And whatever the numbers in its payload hold.
        (_vc_jwt(b'{"vc":{"id":"urn:a"},"n":' + b"1" * 4301 + b"}"),
         "sha256:1b5bda68bf124649ffe0c3dd123f5baf1985f9d57124c31f87881db987c2e046"),
    ]
    return (not any(_digestible(value) for value in no_signed_form)
            and all(_digestible(value) and credential_digest(value) == digest
                    for value, digest in has_signed_form))


def _sha256_of(text: str) -> str:
    return sha256_digest(text.encode("utf-8"))


# The ids are read the same however the interpreter is run, so they are read again with its
# integer digit limit at the lowest it can be set to, where it has one (3.11 on).
def _at_lowest_digit_limit(check) -> bool:
    if not hasattr(sys, "set_int_max_str_digits"):
        return check()
    previous = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(sys.int_info.str_digits_check_threshold)
    try:
        return check()
    finally:
        sys.set_int_max_str_digits(previous)


def id_and_reference_cases_hold() -> bool:
    """The reference a credential goes by (7.8): the id it shows, or the SHA-256 of that id."""
    nested = {"credentialSubject": {"delegation": {"id": "del-1"}}}
    tilde = b'{"vc":{"id":"urn:~~~"}}'
    shown_ids = [
        ({"id": "urn:a", **nested}, "urn:a"),
        (nested, "del-1"),
        ({"id": 7, **nested}, "del-1"),         # an id that is not a string is none
        ({"id": "", **nested}, "del-1"),        # and so is an empty one
        ({"id": ""}, None),
        ({"credentialSubject": {"delegation": {"id": ""}}}, None),
        (read_json('{"id":"urn:a","id":"urn:b"}'), "urn:b"),   # of two ids read from JSON, the last
        ([{"id": "urn:a"}], None),
        (7, None),
        (_vc_jwt(b'{"vc":{"id":"urn:a"},"jti":"urn:b"}'), "urn:a"),
        (_vc_jwt(b'{"vc":{},"jti":"urn:b"}'), "urn:b"),
        (_vc_jwt(b'{"vc":{"credentialSubject":{"delegation":{"id":"del-1"}}}}'), "del-1"),
        (_vc_jwt(b'{"vc":{"credentialSubject":{"delegation":{"id":""}}},"jti":""}'), None),
        (_vc_jwt(b'{"jti":"urn:b"}'), None),    # no `vc`: not a credential's claims
        (_vc_jwt(b'{"vc":[],"jti":"urn:b"}'), None),
        # Of members that share a name the last is read, in the credential and around it.
        (_vc_jwt(b'{"vc":{"id":"urn:a","id":"urn:b"}}'), "urn:b"),
        (_vc_jwt(b'{"vc":{},"jti":"urn:a","jti":"urn:b"}'), "urn:b"),
        (_vc_jwt(b'{"vc":{"id":"urn:a"},"vc":{"id":"urn:b"}}'), "urn:b"),
        (_vc_jwt(b'{"vc":{"id":"urn:a"},"vc":[]}'), None),
        (_vc_jwt(b'{"vc":{"id":"urn:a"}} '), "urn:a"),
        (_vc_jwt(b'\xef\xbb\xbf{"vc":{"id":"urn:a"}}'), None),   # a byte order mark is not JSON
        (_vc_jwt(b'{"vc":{"id":"urn:\xff"}}'), None),            # not UTF-8
        (_vc_jwt(b'{"vc":{"id":"urn:a"},"n":NaN}'), None),       # not JSON
        # A number of any length is read, and plays no part in the id.
        (_vc_jwt(b'{"vc":{"id":"urn:a"},"n":' + b"1" * 400 + b"}"), "urn:a"),
        (_vc_jwt(b'{"vc":{"id":"urn:a"},"n":' + b"1" * 641 + b"}"), "urn:a"),
        (_vc_jwt(b'{"vc":{"id":"urn:a","n":-' + b"9" * 641 + b"}}"), "urn:a"),
        (_vc_jwt(b'{"vc":{"id":"urn:a"},"n":' + b"1" * 4301 + b"}"), "urn:a"),
        (_vc_jwt(tilde), "urn:~~~"),
        (_vc_jwt(tilde, lambda payload: std_b64(payload).rstrip("=")), None),   # base64, not base64url
        (_vc_jwt(b'{"vc":{"id":"urn:a"}}', lambda payload: std_b64(payload)[:8] + "\n" + std_b64(payload)[8:]),
         "urn:a"),                              # a line break, and the padding of a whole group
        ("eyJhbGciOiJFZERTQSJ9." + b64url_nopad(b'{"vc":{"id":"urn:a"}}'), None),
        # The payload is level 1 and `vc` level 2, so 62 more make 64, the bound.
        (_vc_jwt(b'{"vc":{"id":"urn:a","n":' + b"[" * 62 + b"]" * 62 + b"}}"), "urn:a"),
        (_vc_jwt(b'{"vc":{"id":"urn:a","n":' + b"[" * 63 + b"]" * 63 + b"}}"), None),
        (_vc_jwt(b'{"vc":{"id":"urn:a","n":' + b'{"a":' * 62 + b"1" + b"}" * 62 + b"}}"), "urn:a"),
        (_vc_jwt(b'{"vc":{"id":"urn:a","n":' + b'{"a":' * 63 + b"1" + b"}" * 63 + b"}}"), None),
        (_vc_jwt(b'{"vc":{"id":"urn:a"},"n":' + b"[" * 64 + b"]" * 64 + b"}"), None),   # 65 deep beside `vc`
        (_vc_jwt(b'{"vc":{"id":"urn:a","n":' + b"[" * 100_000 + b"]" * 100_000 + b"}}"), None),
        # A bracket in a string nests nothing, nor does one after an escaped quote.
        (_vc_jwt(b'{"vc":{"id":"urn:' + b"[" * 100 + b'"}}'), "urn:" + "[" * 100),
        (_vc_jwt(b'{"vc":{"id":"urn:a","s":"\\"' + b"[" * 100 + b'"}}'), "urn:a"),
        (_vc_jwt(b'{"vc":{"id":"urn:a","s":"\\\\","n":' + b"[" * 62 + b"]" * 62 + b"}}"), "urn:a"),
        (_vc_jwt(b'{"vc":{"id":"urn:a","s":"\\\\","n":' + b"[" * 63 + b"]" * 63 + b"}}"), None),
        # Only the payload is read for an id: a header nested too deep changes nothing here.
        (b64url_nopad(b'{"alg":"EdDSA","n":' + b"[" * 64 + b"]" * 64 + b"}") + "."
         + b64url_nopad(b'{"vc":{"id":"urn:a"}}') + ".c2lnbmF0dXJl", "urn:a"),
        # A credential object shows its id however deep it nests: no signed form, and still a name.
        ({"id": "urn:a", "n": _arrays(64), "proof": {"proofValue": "c2lnbmF0dXJl"}}, "urn:a"),
        ({"id": "urn:a", "n": _arrays(100_000)}, "urn:a"),
    ]
    long_id = "x" * 257
    astral = "\U0001F600" * 128                 # 128 characters, 256 UTF-16 code units
    digest_like = "sha256:" + "a" * 64
    references = [
        ("del-1", "del-1"),
        ("x" * 256, "x" * 256),
        (long_id, _sha256_of(long_id)),
        (astral, astral),
        (astral + "x", _sha256_of(astral + "x")),
        ("del\n1", _sha256_of("del\n1")),       # C0
        ("del\x7f1", _sha256_of("del\x7f1")),   # DEL
        ("del\x801", _sha256_of("del\x801")),   # C1, first and last
        ("del\x9f1", _sha256_of("del\x9f1")),
        ("del\xa01", "del\xa01"),               # past C1: a no-break space is no control
        ("\x1f", _sha256_of("\x1f")),           # the last of C0, alone
        (" ", " "),                             # the first character past C0, alone
        (digest_like, _sha256_of(digest_like)),     # an id that reads as a digest is not kept as one
        ("sha256:" + "A" * 64, "sha256:" + "A" * 64),
        ("sha256:" + "a" * 63, "sha256:" + "a" * 63),
        (digest_like + "0", digest_like + "0"),     # nor is one with a character after the digest
        ("", None),
        # Not well-formed Unicode: a surrogate without its pair is hashed as the three bytes of
        # its code point (WTF-8), a pair as the one code point it encodes.
        ("\ud800", sha256_digest(b"\xed\xa0\x80")),
        ("a\udc00b", sha256_digest(b"a\xed\xb0\x80b")),
        ("\udfff\ud800", sha256_digest(b"\xed\xbf\xbf\xed\xa0\x80")),
        ("\ud83d\ud83d\ude00", sha256_digest(b"\xed\xa0\xbd\xf0\x9f\x98\x80")),
        ("del\ud83d\ude001", "del\U0001F6001"),   # a pair, as JavaScript holds U+1F600
        # Characters that do not print as themselves: format characters and the separators.
        ("del\u202e1", _sha256_of("del\u202e1")),     # a right-to-left override
        ("del\u200b1", _sha256_of("del\u200b1")),     # a zero-width space
        ("\ufeffdel-1", _sha256_of("\ufeffdel-1")),   # a byte order mark
        ("del\u20281", _sha256_of("del\u20281")),     # the line and paragraph separators
        ("del\u20291", _sha256_of("del\u20291")),
        ("del\U000E00411", _sha256_of("del\U000E00411")),  # a tag character
        ("del\u202f1", "del\u202f1"),               # a narrow no-break space prints
        # The word an audit record names a credential that shows no id by.
        ("unknown", _sha256_of("unknown")),
        ("Unknown", "Unknown"),
        ("unknown-1", "unknown-1"),
    ]

    def ids_shown() -> bool:
        return all(delegation_credential_id(value) == shown for value, shown in shown_ids)

    return ("+" in std_b64(tilde)
            and ids_shown() and _at_lowest_digit_limit(ids_shown)
            and all(delegation_reference(value) == ref for value, ref in references)
            and _sha256_of(long_id) ==
            "sha256:15eb95a462ee20bd91a415ae2d4aed341288186ddaa2b37908f7d592f0c3f85f"
            and _do_not_print_is_unicode())


def _do_not_print_is_unicode() -> bool:
    """The table read as not printing counts what it says it holds, and holds every Cc, Cf, Zl and
    Zp of Unicode 16.0 and 17.0: checked against `unicodedata` where the interpreter has one of
    those versions, which has no Default_Ignorable_Code_Point to check the rest against."""
    listed = {code for first, last in UNSEEN_CODE_POINTS for code in range(first, last + 1)}
    if len(listed) != 4273 or any(0xD800 <= code <= 0xDFFF for code in listed):
        return False
    if unicodedata.unidata_version not in ("16.0.0", "17.0.0"):
        return True
    return listed >= {code for code in range(0x110000) if not 0xD800 <= code <= 0xDFFF
                      and unicodedata.category(chr(code)) in ("Cc", "Cf", "Zl", "Zp")}