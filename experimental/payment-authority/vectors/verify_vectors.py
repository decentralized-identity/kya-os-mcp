#!/usr/bin/env python3
"""Verifier of the Payment Authority Profile Core Authority vector corpus
(experimental/payment-authority/SPEC-PAYMENT-AUTHORITY.md).

Standard library only: it reproduces every vector's expected result from the
specification's rules and compares it with the corpus. To the `semantic`
vectors it applies checks V1 to V4 of section 8.7 and its own restatement of
the schema rules those vectors exercise (section 8.6); full JSON Schema
validation is `schemas.test.ts`'s.
Every grammar is matched in full (`re.fullmatch`), so a trailing newline is
never accepted; the one prefix test, for an HTTP(S) protocol locator, is a
`re.match` of the schema's own letters.

    python3 experimental/payment-authority/vectors/verify_vectors.py

Exit status 0 means every vector reproduced; any mismatch is printed and the
exit status is 1.
"""

from __future__ import annotations

import base64
import binascii
import calendar
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Optional

CORPUS = Path(__file__).with_name("payment-authority-vectors.json")
MAX_CHAIN = 10  # the profile's chain limit; SPEC.md 6.10 leaves a cap to verifier policy
MAX_MEMBERS = 256
MAX_CAVEAT_BYTES = 16 * 1024
INTENT_SKEW_MS = 60_000  # the profile's own clock skew for an intent's `createdAt` (section 7.1)
CONSTRAINT_TYPE = "org.kya-os/payment-constraints"
CONSTRAINT_VERSION = "1.0.0"
CONSTRAINTS_DOMAIN = "org.kya-os.payments.constraints.v1"
CREDENTIAL_DOMAIN = "org.kya-os.payments.credential.v1"
DELEGATION_CHAIN_DOMAIN = "org.kya-os.payments.delegation-chain.v1"
ANSWER_DOMAIN = "org.kya-os.payments.answer.v1"
INTENT_RULES = ("intent.businessAmount", "intent.payee", "intent.resources", "intent.rail",
                "intent.settlementAmount", "intent.quote", "intent.fees", "intent.approval", "intent.expiry")
APPROVAL_MODES = ("human-present", "human-not-present", "standing-policy")

# --------------------------------------------------------------------------
# RFC 8785 JSON Canonicalization over the profile's canonical values: no
# lone surrogate, finite numbers, and an integral number only as a safe
# integer; any other finite number in the ECMAScript form RFC 8785 §3.2.2.3
# prescribes.
# --------------------------------------------------------------------------

def _utf16_key(value: str) -> bytes:
    return value.encode("utf-16-be", "surrogatepass")


def data_model(value: Any) -> Any:
    """The JSON data model has one number type: an integer-valued number written
    as `2.0` or `2e0` is the integer 2, as a JavaScript parser reads it."""
    if isinstance(value, dict):
        return {key: data_model(item) for key, item in value.items()}
    if isinstance(value, list):
        return [data_model(item) for item in value]
    if isinstance(value, float) and value.is_integer() and abs(value) <= 2**53 - 1:
        return int(value)
    return value


def es_number(value: float) -> str:
    """ECMAScript Number::toString of a finite, non-integral double (RFC 8785
    §3.2.2.3). `repr` gives the shortest digits that round-trip, as ECMAScript
    does; only the layout differs, which this applies."""
    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError("non-finite number")
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    mantissa, _, exponent = repr(abs(value)).partition("e")
    whole, _, fraction = mantissa.partition(".")
    digits = (whole + fraction).lstrip("0")
    # Position of the decimal point relative to the first significant digit.
    n = len(whole) + (int(exponent) if exponent else 0) - (len(whole + fraction) - len((whole + fraction).lstrip("0")))
    digits = digits.rstrip("0")
    k = len(digits)
    if k <= n <= 21:
        text = digits + "0" * (n - k)
    elif 0 < n <= 21:
        text = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        text = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        text = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + text


def jcs(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > 2**53 - 1:
            raise ValueError("unsafe integer")
        return str(value)
    if isinstance(value, float):
        if value == value and value not in (float("inf"), float("-inf")) and value.is_integer():
            if abs(value) > 2**53 - 1:
                raise ValueError("unsafe integer")
            return str(int(value))  # an integral double is the integer it equals; -0 is 0
        return es_number(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(jcs(item) for item in value) + "]"
    if isinstance(value, dict):
        members = sorted(value.items(), key=lambda item: _utf16_key(item[0]))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + jcs(v) for k, v in members) + "}"
    raise TypeError(f"unsupported JSON value: {type(value).__name__}")


def jcs_bytes(value: Any) -> bytes:
    return jcs(value).encode("utf-8")


def domain_digest(domain: str, value: Any) -> str:
    return "sha256:" + hashlib.sha256(domain.encode("utf-8") + b"\x00" + jcs_bytes(value)).hexdigest()


def answer_covered(result: dict) -> dict:
    """The execution profile's answer digest covers the MCP result without its top-level `_meta`."""
    return {key: value for key, value in result.items() if key != "_meta"}


def octet_sorted(values: list) -> list:
    """Section 8.4.2: order set members by the unsigned octets of their RFC 8785 bytes."""
    return sorted(values, key=jcs_bytes)

# --------------------------------------------------------------------------
# Ed25519 verification (RFC 8032 reference algorithm, as in conformance/verify.py)
# --------------------------------------------------------------------------

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _point_add(p: tuple, q: tuple) -> tuple:
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _point_mul(s: int, p: tuple) -> tuple:
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _point_add(q, p)
        p = _point_add(p, p)
        s >>= 1
    return q


def _recover_x(y: int, sign: int) -> Optional[int]:
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    return _P - x if (x & 1) != sign else x


def _decompress(s: bytes) -> Optional[tuple]:
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


_BASE_Y = 4 * pow(5, _P - 2, _P) % _P
_BASE = (_recover_x(_BASE_Y, 0), _BASE_Y, 1, _recover_x(_BASE_Y, 0) * _BASE_Y % _P)


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a, r = _decompress(public_key), _decompress(signature[:32])
    s = int.from_bytes(signature[32:], "little")
    if a is None or r is None or s >= _L:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % _L
    left, right = _point_mul(s, _BASE), _point_add(r, _point_mul(h, a))
    return (left[0] * right[2] - right[0] * left[2]) % _P == 0 and (left[1] * right[2] - right[1] * left[2]) % _P == 0

# --------------------------------------------------------------------------
# ES256 verification (ECDSA over P-256 with SHA-256, FIPS 186-5), with the
# low-S rule of the execution profile's answer proof
# --------------------------------------------------------------------------

_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_P256_G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
           0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def _p256_add(p: Optional[tuple], q: Optional[tuple]) -> Optional[tuple]:
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % _P256_P == 0:
        return None
    if p == q:
        slope = (3 * p[0] * p[0] - 3) * pow(2 * p[1], -1, _P256_P) % _P256_P
    else:
        slope = (q[1] - p[1]) * pow(q[0] - p[0], -1, _P256_P) % _P256_P
    x = (slope * slope - p[0] - q[0]) % _P256_P
    return (x, (slope * (p[0] - x) - p[1]) % _P256_P)


def _p256_mul(k: int, point: Optional[tuple]) -> Optional[tuple]:
    result = None
    while k > 0:
        if k & 1:
            result = _p256_add(result, point)
        point = _p256_add(point, point)
        k >>= 1
    return result


def es256_verify(x: bytes, y: bytes, message: bytes, signature: bytes) -> bool:
    if len(x) != 32 or len(y) != 32 or len(signature) != 64:
        return False
    qx, qy = int.from_bytes(x, "big"), int.from_bytes(y, "big")
    if qx >= _P256_P or qy >= _P256_P or (qy * qy - (qx ** 3 - 3 * qx + _P256_B)) % _P256_P != 0:
        return False  # not a point on the curve
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    if not (1 <= r < _P256_N and 1 <= s <= _P256_N // 2):
        return False  # out of range, or the high s another spelling of the same signature
    z = int.from_bytes(hashlib.sha256(message).digest(), "big")
    w = pow(s, -1, _P256_N)
    point = _p256_add(_p256_mul(z * w % _P256_N, _P256_G), _p256_mul(r * w % _P256_N, (qx, qy)))
    return point is not None and point[0] % _P256_N == r

# --------------------------------------------------------------------------
# Answer proof (defined by the execution profile; carried in the corpus)
# --------------------------------------------------------------------------

ANSWER_PROFILE = "org.kya-os/payment-answer.v1"
ANSWER_CLAIMS = {"profile", "iss", "aud", "requestDigest", "requestNonce", "answerDigest", "iat"}
# W3C DID 1.0 syntax: the DIDs an answer names (the execution profile's answer proof).
DID_SYNTAX = re.compile(r"did:[a-z0-9]+:(?:(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})*:)*(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})+")
ANSWER_DIGEST = re.compile(r"sha256:[a-f0-9]{64}")


def b64url(text: str) -> Optional[bytes]:
    """Unpadded base64url that is the one encoding of its bytes (the execution profile's answer proof)."""
    if not re.fullmatch(r"[A-Za-z0-9_-]+", text):
        return None
    try:
        decoded = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        return None
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != text:
        return None
    return decoded


def verify_answer_proof(vector: dict) -> bool:
    """The client's answer check: header, exact payload bytes, binding, digest, signature."""
    result, binding, executor = vector["result"], vector["binding"], vector["executor"]
    proof = result.get("_meta", {}).get("org.kya-os/payment-answer") if isinstance(result.get("_meta"), dict) else None
    if not isinstance(proof, str) or proof.count(".") != 2:
        return False
    protected, payload, signature = proof.split(".")
    header_bytes, payload_bytes, signature_bytes = b64url(protected), b64url(payload), b64url(signature)
    if header_bytes is None or payload_bytes is None or signature_bytes is None:
        return False
    try:
        header = json.loads(header_bytes.decode("utf-8"))
        claims = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return False
    if (not isinstance(header, dict) or not {"alg", "kid"} <= set(header) <= {"alg", "kid", "typ"}
            or header["alg"] not in ("EdDSA", "ES256")
            or header.get("typ", "kya-payment-answer+jws") != "kya-payment-answer+jws"):
        return False
    if not isinstance(claims, dict) or set(claims) != ANSWER_CLAIMS or claims["profile"] != ANSWER_PROFILE:
        return False
    try:
        canonical = jcs_bytes(claims)
    except (ValueError, TypeError):
        return False  # a value section 10 does not canonicalize: a non-finite number, an unsafe integer
    if canonical != payload_bytes:
        return False  # exactly one byte sequence per claim set (the execution profile's answer proof)
    # The claims' syntax (the execution profile's answer proof): DIDs, a nonce of 1 to 512 code points, digests, an integer iat.
    if not all(isinstance(claims[k], str) and len(claims[k]) <= 2048 and DID_SYNTAX.fullmatch(claims[k]) for k in ("iss", "aud")):
        return False
    if not isinstance(claims["requestNonce"], str) or not 1 <= len(claims["requestNonce"]) <= 512:
        return False
    if not all(isinstance(claims[k], str) and ANSWER_DIGEST.fullmatch(claims[k]) for k in ("requestDigest", "answerDigest")):
        return False
    if type(claims["iat"]) is not int or not 0 <= claims["iat"] <= 2 ** 53 - 1:
        return False
    # kid = <iss>#<fragment>: exactly one "#", a fragment, at most 2,048 code points (the execution profile's answer proof).
    kid_parts = header["kid"].split("#") if isinstance(header["kid"], str) else []
    if len(kid_parts) != 2 or kid_parts[0] != claims["iss"] or kid_parts[1] == "" or len(header["kid"]) > 2048:
        return False
    if (claims["iss"] != executor or claims["aud"] != binding["requester"]
            or claims["requestDigest"] != binding["requestDigest"] or claims["requestNonce"] != binding["requestNonce"]):
        return False
    if claims["answerDigest"] != domain_digest(ANSWER_DOMAIN, answer_covered(result)):
        return False
    jwk, signing_input = vector["publicJwk"], f"{protected}.{payload}".encode("ascii")
    if header["alg"] == "ES256":
        # The key's type matches the algorithm (the execution profile's answer proof).
        if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
            return False
        x, y = b64url(jwk["x"]), b64url(jwk["y"])
        return x is not None and y is not None and es256_verify(x, y, signing_input, signature_bytes)
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        return False
    public_key = b64url(jwk["x"])
    return public_key is not None and ed25519_verify(public_key, signing_input, signature_bytes)

# --------------------------------------------------------------------------
# Request digest (section 10): card RFC 9421 form only.
# --------------------------------------------------------------------------

RFC9421 = re.compile(r"^sha-256=:([A-Za-z0-9+/]{43}=):$")


def request_digest(base: str) -> Optional[str]:
    rfc = RFC9421.fullmatch(base)
    if not rfc:
        return None
    try:
        raw = base64.b64decode(rfc.group(1), validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != rfc.group(1):
        return None
    return "sha256:" + raw.hex()

# --------------------------------------------------------------------------
# Exact money (section 7)
# --------------------------------------------------------------------------

def asset_key(amount: dict) -> tuple:
    return (amount["asset"]["namespace"], amount["asset"]["id"])


def compare_amounts(left: dict, right: dict) -> int:
    if asset_key(left) != asset_key(right):
        raise ValueError("asset mismatch")
    scale = max(left["scale"], right["scale"])
    lv = int(left["coefficient"]) * 10 ** (scale - left["scale"])
    rv = int(right["coefficient"]) * 10 ** (scale - right["scale"])
    return (lv > rv) - (lv < rv)


def normalize_amount(amount: dict) -> dict:
    coefficient, scale = amount["coefficient"], amount["scale"]
    if coefficient == "0":
        scale = 0
    else:
        while scale > 0 and coefficient.endswith("0"):
            coefficient, scale = coefficient[:-1], scale - 1
    return {"asset": {"namespace": amount["asset"]["namespace"], "id": amount["asset"]["id"]},
            "coefficient": coefficient, "scale": scale}


def amount_within(child: dict, parent: dict) -> bool:
    return asset_key(child) == asset_key(parent) and compare_amounts(child, parent) <= 0


def amounts_equal(left: dict, right: dict) -> bool:
    return asset_key(left) == asset_key(right) and compare_amounts(left, right) == 0

# --------------------------------------------------------------------------
# Time normalization (section 7.1)
# --------------------------------------------------------------------------

RFC3339 = re.compile(
    r"^([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,3}))?([Zz]|[+-][0-9]{2}:[0-9]{2})$")


def rfc3339_millis(value: str) -> Optional[int]:
    match = RFC3339.fullmatch(value)
    if not match:
        return None
    y, mo, d, h, mi, s = (int(part) for part in match.groups()[:6])
    fraction, offset = match.group(7), match.group(8)
    if not (1 <= mo <= 12 and 1 <= d <= 31 and h <= 23 and mi <= 59 and s <= 59):
        return None
    try:
        if d > calendar.monthrange(y, mo)[1]:
            return None
        epoch_seconds = calendar.timegm((y, mo, d, h, mi, s, 0, 0, 0))
    except (ValueError, OverflowError):
        return None  # year 0000 is outside Python's calendar, and before the epoch anyway
    millis_of_second = int(fraction.ljust(3, "0")) if fraction else 0
    offset_minutes = 0
    if offset not in ("Z", "z"):
        sign = -1 if offset.startswith("-") else 1
        oh, om = int(offset[1:3]), int(offset[4:6])
        if oh > 23 or om > 59:
            return None
        offset_minutes = sign * (oh * 60 + om)
    millis = epoch_seconds * 1000 + millis_of_second - offset_minutes * 60_000
    return millis if 0 <= millis <= 2**53 - 1 else None

# --------------------------------------------------------------------------
# Structural and semantic validation (sections 7, 8.4, 8.6)
# --------------------------------------------------------------------------

DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
INTEGER = re.compile(r"^(0|[1-9][0-9]*)$")
ISO4217 = re.compile(r"^[A-Z]{3}$")
CAIP19 = re.compile(r"^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}/[-a-z0-9]{3,8}:[-%.a-zA-Z0-9]{1,128}(?:/[-%.a-zA-Z0-9]{1,78})?$")
URI = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:[^\r\n]+$")
DID = re.compile(r"^did:[^\r\n]+$")
CONSTRAINT_KEYS = {"type", "version", "businessLimits", "payees", "resources", "rails",
                   "settlementLimits", "quoteAuthorities", "fees", "requireApproval", "expiresAt"}


def valid_amount(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) != {"asset", "coefficient", "scale"}:
        return False
    asset = value["asset"]
    if not isinstance(asset, dict) or set(asset) != {"namespace", "id"}:
        return False
    pattern = {"iso4217": ISO4217, "caip19": CAIP19, "uri": URI}.get(asset["namespace"])
    return (pattern is not None and isinstance(asset["id"], str) and bool(pattern.fullmatch(asset["id"]))
            and isinstance(value["coefficient"], str) and len(value["coefficient"]) <= 78
            and bool(INTEGER.fullmatch(value["coefficient"]))
            and type(value["scale"]) is int and 0 <= value["scale"] <= 255)


def valid_reference(value: Any, maximum: int = 2048) -> bool:
    """Section 8.6: lengths count Unicode code points, as JSON Schema does (len of a Python str)."""
    return isinstance(value, str) and 1 <= len(value) <= maximum


def valid_digest(value: Any) -> bool:
    return isinstance(value, str) and bool(DIGEST.fullmatch(value))


ACCOUNT_DIGEST_METHODS = ("opaque-token-sha256", "hmac-sha256", "issuer-attestation-sha256")


def valid_party(value: Any) -> bool:
    if not isinstance(value, dict) or "id" not in value or not set(value) <= {"id", "accountDigest", "accountDigestMethod"}:
        return False
    if ("accountDigest" in value) != ("accountDigestMethod" in value):
        return False
    return (valid_reference(value["id"])
            and ("accountDigest" not in value or valid_digest(value["accountDigest"]))
            and ("accountDigestMethod" not in value or value["accountDigestMethod"] in ACCOUNT_DIGEST_METHODS))


def valid_protocol(value: Any) -> bool:
    if not isinstance(value, dict) or not {"id", "version"} <= set(value) <= {"id", "version", "specDigest"}:
        return False
    if not valid_reference(value["id"]) or not valid_reference(value["version"], 128):
        return False
    if "specDigest" in value:
        return valid_digest(value["specDigest"])
    # Section 6: an HTTP(S) protocol identifier binds immutable specification bytes.
    return re.match(r"[Hh][Tt][Tt][Pp][Ss]?:", value["id"]) is None  # the schema's letters exactly, no case folding


def valid_rail_constraint(value: Any) -> bool:
    if not isinstance(value, dict) or "protocol" not in value or not set(value) <= {
            "protocol", "methodId", "handlerId", "scheme", "network", "transferMethod", "paymentFlow", "fundingAccount"}:
        return False
    return (valid_protocol(value["protocol"])
            and all(valid_reference(value[key]) for key in ("methodId", "handlerId") if key in value)
            and all(valid_reference(value[key], 128)
                    for key in ("scheme", "network", "transferMethod", "paymentFlow") if key in value)
            and ("fundingAccount" not in value or valid_reference(value["fundingAccount"], 256)))


def valid_resource_constraint(value: Any) -> bool:
    if not isinstance(value, dict) or "id" not in value or not set(value) <= {"id", "digest"}:
        return False
    return valid_reference(value["id"]) and ("digest" not in value or valid_digest(value["digest"]))


def valid_list(value: Any, check) -> bool:
    return isinstance(value, list) and 1 <= len(value) <= MAX_MEMBERS and all(check(item) for item in value)


def unique_by(values: list, key) -> bool:
    keys = [key(value) for value in values]
    return len(set(keys)) == len(keys)


def valid_constraints(value: Any) -> bool:
    """Structure plus the semantic rules of the constraints caveat (section 8.4)."""
    value = data_model(value)
    if not isinstance(value, dict) or not set(value) <= CONSTRAINT_KEYS or has_proto_member(value):
        return False
    try:
        if len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > MAX_CAVEAT_BYTES:
            return False
    except UnicodeEncodeError:
        return False  # ill-formed Unicode (a lone surrogate) is never canonical (section 10)
    if value.get("type") != CONSTRAINT_TYPE or value.get("version") != CONSTRAINT_VERSION:
        return False
    if not valid_list(value.get("businessLimits"), valid_amount) or not unique_by(value["businessLimits"], asset_key):
        return False
    if "settlementLimits" in value and (not valid_list(value["settlementLimits"], valid_amount)
                                        or not unique_by(value["settlementLimits"], asset_key)):
        return False
    for key, member in (("payees", valid_party), ("resources", valid_resource_constraint),
                        ("rails", valid_rail_constraint)):
        if key in value and (not valid_list(value[key], member) or not unique_by(value[key], jcs)):
            return False
    if "quoteAuthorities" in value and (not valid_list(value["quoteAuthorities"], valid_reference)
                                        or not unique_by(value["quoteAuthorities"], lambda q: q)):
        return False
    if "fees" in value:
        fees = value["fees"]
        if fees == {"mode": "prohibited"}:
            pass
        elif isinstance(fees, dict) and set(fees) == {"mode", "limits"} and fees["mode"] == "capped":
            if not valid_list(fees["limits"], valid_amount) or not unique_by(fees["limits"], asset_key):
                return False
        else:
            return False
    if "requireApproval" in value:
        requirement = value["requireApproval"]
        if (not isinstance(requirement, dict) or not set(requirement) <= {"modes", "approvers", "above"}
                or "modes" not in requirement):
            return False
        modes = requirement["modes"]
        if (not isinstance(modes, list) or not 1 <= len(modes) <= 3 or len(set(modes)) != len(modes)
                or not all(mode in APPROVAL_MODES for mode in modes)):
            return False
        if "approvers" in requirement and (
                not valid_list(requirement["approvers"], valid_reference)
                or not unique_by(requirement["approvers"], lambda a: a)):
            return False
        if "above" in requirement and (not valid_list(requirement["above"], valid_amount)
                                       or not unique_by(requirement["above"], asset_key)):
            return False
    if "expiresAt" in value and not (type(value["expiresAt"]) is int and 0 <= value["expiresAt"] <= 2**53 - 1):
        return False
    return True


MAX_EXTENSION_BYTES = 16 * 1024
MAX_EXTENSION_TOTAL_BYTES = 64 * 1024
MAX_EXTENSION_DEPTH = 16
MAX_EXTENSION_NODES = 1024


def measure(value: Any, depth: int = 1) -> tuple:
    if not isinstance(value, (dict, list)):
        return depth, 1
    children = value.values() if isinstance(value, dict) else value
    deepest, nodes = depth, 1
    for child in children:
        child_depth, child_nodes = measure(child, depth + 1)
        deepest, nodes = max(deepest, child_depth), nodes + child_nodes
    return deepest, nodes


def valid_extensions(extensions: Any) -> bool:
    """Section 8.6 kyaCanonicalJson / kyaCanonicalJsonCollection: bounded canonical extension data."""
    if extensions is None:
        return True
    total = 0
    for extension in extensions.values():
        data = extension["data"]
        try:
            size = len(jcs_bytes(data))
        except (TypeError, ValueError):
            return False
        depth, nodes = measure(data)
        if size > MAX_EXTENSION_BYTES or depth > MAX_EXTENSION_DEPTH or nodes > MAX_EXTENSION_NODES:
            return False
        total += size
    return total <= MAX_EXTENSION_TOTAL_BYTES


def has_proto_member(value: Any) -> bool:
    """Section 14, item 26: a member named `__proto__` anywhere, which a JavaScript parser can drop."""
    if isinstance(value, dict):
        return "__proto__" in value or any(has_proto_member(item) for item in value.values())
    if isinstance(value, list):
        return any(has_proto_member(item) for item in value)
    return False


def valid_intent_semantics(value: dict) -> bool:
    if has_proto_member(value):
        return False
    # Sections 8.1, 12.5 and 15: credentials others can redeem pay only an intent one agent
    # presents, from one account the intent signs.
    presenter_ok = ("presenter" in value if value["payment"].get("redeemableByOthers") is True else True)
    account_ok = ("fundingAccount" in value["payment"] if value["payment"].get("redeemableByOthers") is True else True)
    return (value["createdAt"] < value["expiresAt"]
            and unique_by(value["resources"], lambda resource: resource["id"])
            and isinstance(value.get("payer"), str) and bool(DID.fullmatch(value["payer"]))
            and ("presenter" not in value or (isinstance(value["presenter"], str) and bool(DID.fullmatch(value["presenter"]))))
            and presenter_ok
            and account_ok
            and valid_extensions(value.get("extensions")))


def valid_authorization_semantics(value: dict) -> bool:
    if has_proto_member(value):
        return False
    if value["createdAt"] >= value["expiresAt"]:
        return False
    approval = value.get("approval")
    if approval is not None and value["expiresAt"] > approval["expiresAt"]:
        return False
    # Section 8.2: an approval names the chain's delegates, and none of them approved.
    delegates = value["delegation"].get("delegates")
    if delegates is not None and (len(set(delegates)) != len(delegates) or value["actor"] not in delegates):
        return False
    if approval is not None:
        subject = approval.get("subject") or {}
        # A principal that is not the payer is a delegate whether or not the list names it.
        banned = None if delegates is None else (
            delegates + [value["principal"]] if value["principal"] != value["responsibleParty"] else delegates)
        if (banned is None or approval["issuer"] in banned
                or (subject.get("kind") == "did" and subject.get("id") in banned)):
            return False
    chain = value["delegation"].get("chainDigests")
    if not isinstance(chain, list) or not 1 <= len(chain) <= 10 or len(set(chain)) != len(chain):
        return False
    return unique_by(value["evidence"], lambda evidence: evidence["digest"])


def valid_outcome_semantics(value: dict) -> bool:
    if has_proto_member(value):
        return False
    state = value["state"]
    if (value["sequence"] == 0) != ("previousOutcomeDigest" not in value):
        return False
    if state == "settled" and ("transactionRef" not in value["rail"] or "effectAmount" not in value):
        return False
    if state != "settled" and "effectAmount" in value:
        return False
    if state == "settlement_pending" and "reconciliationRef" not in value["rail"]:
        return False
    if state == "failed" and "reason" not in value:
        return False
    # Every attempt exists only after authorization, so every observation names it (section 8.3).
    if "authorizationDigest" not in value:
        return False
    return unique_by(value["evidence"], lambda evidence: evidence["digest"])


SEMANTIC_VALIDATORS = {
    "intent": valid_intent_semantics,
    "authorization": valid_authorization_semantics,
    "outcome": valid_outcome_semantics,
    "constraints": valid_constraints,
}

# --------------------------------------------------------------------------
# Attenuation (section 8.4.2)
# --------------------------------------------------------------------------

QUALIFIERS = ("methodId", "handlerId", "scheme", "network", "transferMethod", "paymentFlow", "fundingAccount")


def party_within(child: dict, parent: dict) -> bool:
    if child["id"] != parent["id"]:
        return False
    if "accountDigest" not in parent:
        return True
    return (child.get("accountDigest") == parent["accountDigest"]
            and child.get("accountDigestMethod") == parent.get("accountDigestMethod"))


def resource_within(child: dict, parent: dict) -> bool:
    return child["id"] == parent["id"] and ("digest" not in parent or child.get("digest") == parent["digest"])


def rail_within(child: dict, parent: dict) -> bool:
    cp, pp = child["protocol"], parent["protocol"]
    if cp["id"] != pp["id"] or cp["version"] != pp["version"]:
        return False
    if "specDigest" in pp and cp.get("specDigest") != pp["specDigest"]:
        return False
    return all(q not in parent or child.get(q) == parent[q] for q in QUALIFIERS)


def every_within(child: list, parent: list, member_within) -> bool:
    return all(any(member_within(c, p) for p in parent) for c in child)


def allowlist_within(child, parent, member_within) -> bool:
    if parent is None:
        return True  # absent allowlist = unrestricted; a child may introduce one
    if child is None:
        return False  # dropping an allowlist widens
    return every_within(child, parent, member_within)


def grant_within(child, parent, member_within) -> bool:
    if child is None:
        return True  # dropping a grant is the narrowest state
    if parent is None:
        return False  # a grant absent from the parent can never be introduced
    return every_within(child, parent, member_within)


def effective_fees(fees):
    return fees if fees is not None else {"mode": "prohibited"}


def fees_within(child, parent) -> bool:
    child, parent = effective_fees(child), effective_fees(parent)
    if child["mode"] == "prohibited":
        return True
    if parent["mode"] == "prohibited":
        return False
    return every_within(child["limits"], parent["limits"], amount_within)


def requirement_within(child, parent) -> bool:
    if parent is None:
        return True  # a child may introduce a requirement
    if child is None:
        return False  # an inherited requirement can never be dropped
    if not all(mode in parent["modes"] for mode in child["modes"]):
        return False
    # Effective approver set: `approvers`, or {payer} when absent (the narrowest set). A
    # requirement without approvers fixes it for descendants; a listed set only shrinks.
    if "approvers" not in parent:
        if "approvers" in child:
            return False
    elif "approvers" not in child or not all(a in parent["approvers"] for a in child["approvers"]):
        return False
    # Exemption thresholds behave as a grant: drop or lower one, never add or raise one.
    if "above" not in parent:
        return "above" not in child
    if "above" not in child:
        return True
    return every_within(child["above"], parent["above"], amount_within)


def find_widening(parent: dict, child: dict) -> Optional[str]:
    if not every_within(child["businessLimits"], parent["businessLimits"], amount_within):
        return "attenuation.businessLimits"
    if not allowlist_within(child.get("payees"), parent.get("payees"), party_within):
        return "attenuation.payees"
    if not allowlist_within(child.get("resources"), parent.get("resources"), resource_within):
        return "attenuation.resources"
    if not allowlist_within(child.get("rails"), parent.get("rails"), rail_within):
        return "attenuation.rails"
    if not grant_within(child.get("settlementLimits"), parent.get("settlementLimits"), amount_within):
        return "attenuation.settlementLimits"
    if not grant_within(child.get("quoteAuthorities"), parent.get("quoteAuthorities"), lambda c, p: c == p):
        return "attenuation.quoteAuthorities"
    if not fees_within(child.get("fees"), parent.get("fees")):
        return "attenuation.fees"
    if not requirement_within(child.get("requireApproval"), parent.get("requireApproval")):
        return "attenuation.requireApproval"
    if "expiresAt" in parent and ("expiresAt" not in child or child["expiresAt"] > parent["expiresAt"]):
        return "attenuation.expiry"
    return None

# --------------------------------------------------------------------------
# Intent evaluation (section 8.4.4)
# --------------------------------------------------------------------------

def selection_within(selection: dict, rail: dict) -> bool:
    if selection["protocol"]["id"] != rail["protocol"]["id"]:
        return False
    if selection["protocol"]["version"] != rail["protocol"]["version"]:
        return False
    if "specDigest" in rail["protocol"] and selection["protocol"].get("specDigest") != rail["protocol"]["specDigest"]:
        return False
    return all(q not in rail or selection.get(q) == rail[q] for q in QUALIFIERS)


def party_match(intent_party: dict, allowed: dict) -> bool:
    return intent_party["id"] == allowed["id"] and (
        "accountDigest" not in allowed
        or (intent_party.get("accountDigest") == allowed["accountDigest"]
            and intent_party.get("accountDigestMethod") == allowed.get("accountDigestMethod")))


def fees_within_caps(fees: list, limits: list) -> bool:
    totals: dict = {}
    for fee in fees:
        key = asset_key(fee)
        if key not in totals:
            totals[key] = (int(fee["coefficient"]), fee["scale"])
        else:
            total, scale = totals[key]
            target = max(scale, fee["scale"])
            totals[key] = (total * 10 ** (target - scale) + int(fee["coefficient"]) * 10 ** (target - fee["scale"]),
                           target)
    for key, (total, scale) in totals.items():
        limit = next((l for l in limits if asset_key(l) == key), None)
        if limit is None:
            return False
        target = max(scale, limit["scale"])
        if total * 10 ** (target - scale) > int(limit["coefficient"]) * 10 ** (target - limit["scale"]):
            return False
    return True


def effective_settlement(intent: dict) -> dict:
    return intent["payment"].get("settlementAmount", intent["amount"])


def is_conversion(intent: dict) -> bool:
    settlement = intent["payment"].get("settlementAmount")
    return settlement is not None and not amounts_equal(settlement, intent["amount"])


def add_amounts(left: dict, right: dict) -> dict:
    scale = max(left["scale"], right["scale"])
    total = int(left["coefficient"]) * 10 ** (scale - left["scale"]) + int(right["coefficient"]) * 10 ** (scale - right["scale"])
    return {"asset": left["asset"], "coefficient": str(total), "scale": scale}


def approval_required(requirement: dict, intent: dict, fee_policy: dict) -> bool:
    """Exempt only when the business amount, and everything that can leave the funding
    source (the effective settlement amount plus the fee ceiling, per asset), are each at
    or below a threshold for their own exact asset (section 8.4.1)."""
    if "above" not in requirement:
        return True

    def exempt(amount: dict) -> bool:
        threshold = next((t for t in requirement["above"] if asset_key(t) == asset_key(amount)), None)
        return threshold is not None and compare_amounts(amount, threshold) <= 0

    if not exempt(intent["amount"]):
        return True
    debits: dict = {}
    for amount in [effective_settlement(intent)] + (fee_policy["limits"] if fee_policy["mode"] == "capped" else []):
        key = asset_key(amount)
        debits[key] = amount if key not in debits else add_amounts(debits[key], amount)
    return any(not exempt(amount) for amount in debits.values())


def quote_binds_conversion(c: dict, intent: dict, quote) -> bool:
    """A verified quote names the signed quote, converts exactly the business amount into
    exactly the settlement amount, and comes from a granted quote authority (section 8.4.4)."""
    settlement = intent["payment"].get("settlementAmount")
    return (quote is not None and settlement is not None and "quoteAuthorities" in c
            and quote["issuer"] in c["quoteAuthorities"]
            and quote["digest"] == intent["payment"].get("quoteDigest")
            and amounts_equal(quote["source"], intent["amount"])
            and amounts_equal(quote["target"], settlement))


def find_intent_denial(c: dict, intent: dict, facts: dict) -> Optional[str]:
    if intent["amount"]["coefficient"] == "0":
        return "intent.nonZeroAmount"
    limit = next((l for l in c["businessLimits"] if asset_key(l) == asset_key(intent["amount"])), None)
    if limit is None or compare_amounts(intent["amount"], limit) > 0:
        return "intent.businessAmount"
    if "payees" in c and not any(party_match(intent["payee"], p) for p in c["payees"]):
        return "intent.payee"
    if "resources" in c and not all(
            any(r["id"] == a["id"] and ("digest" not in a or r["digest"] == a["digest"]) for a in c["resources"])
            for r in intent["resources"]):
        return "intent.resources"
    if "rails" in c and not any(selection_within(intent["payment"], rail) for rail in c["rails"]):
        return "intent.rail"
    settlement = intent["payment"].get("settlementAmount")
    if settlement is not None and settlement["coefficient"] == "0":
        return "intent.nonZeroSettlement"
    if settlement is not None and is_conversion(intent):
        if "settlementLimits" not in c or not any(amount_within(settlement, l) for l in c["settlementLimits"]):
            return "intent.settlementAmount"
        if "quoteDigest" not in intent["payment"] or "quoteAuthorities" not in c:
            return "intent.quote"
        if not facts["defer"] and not quote_binds_conversion(c, intent, facts["quote"]):
            return "intent.quote"
    if not facts["defer"]:
        policy = effective_fees(c.get("fees"))
        charged = [fee for fee in facts["fees"] if fee["coefficient"] != "0"]
        if policy["mode"] == "prohibited" and charged:
            return "intent.fees"
        if policy["mode"] == "capped" and not fees_within_caps(charged, policy["limits"]):
            return "intent.fees"
    requirement = c.get("requireApproval")
    approval = facts["approval"]
    # Without `approvers` only the payer (the accountable root) may approve (section 8.4.1).
    accepted = requirement.get("approvers", [intent["payer"]]) if requirement is not None else []
    if requirement is not None and approval_required(requirement, intent, effective_fees(c.get("fees"))) and (
            approval is None or approval["mode"] not in requirement["modes"]
            or approval["issuer"] not in accepted):
        return "intent.approval"
    if "expiresAt" in c and (facts["now"] >= c["expiresAt"] or intent["expiresAt"] > c["expiresAt"]):
        return "intent.expiry"
    return None


def normalized_constraints(c: dict) -> dict:
    out = {"type": c["type"], "version": c["version"],
           "businessLimits": octet_sorted([normalize_amount(a) for a in c["businessLimits"]])}
    for key in ("payees", "resources", "rails"):
        if key in c:
            out[key] = octet_sorted(c[key])
    if "settlementLimits" in c:
        out["settlementLimits"] = octet_sorted([normalize_amount(a) for a in c["settlementLimits"]])
    if "quoteAuthorities" in c:
        out["quoteAuthorities"] = octet_sorted(c["quoteAuthorities"])
    if c.get("fees", {}).get("mode") == "capped":
        out["fees"] = {"mode": "capped", "limits": octet_sorted([normalize_amount(a) for a in c["fees"]["limits"]])}
    if "requireApproval" in c:
        requirement = {"modes": octet_sorted(c["requireApproval"]["modes"])}
        if "approvers" in c["requireApproval"]:
            requirement["approvers"] = octet_sorted(c["requireApproval"]["approvers"])
        if "above" in c["requireApproval"]:
            requirement["above"] = octet_sorted([normalize_amount(a) for a in c["requireApproval"]["above"]])
        out["requireApproval"] = requirement
    if "expiresAt" in c:
        out["expiresAt"] = c["expiresAt"]
    return out


def valid_quote(quote: Any) -> bool:
    return (isinstance(quote, dict) and set(quote) == {"issuer", "digest", "source", "target"}
            and isinstance(quote["issuer"], str) and 1 <= len(quote["issuer"]) <= 2048
            and isinstance(quote["digest"], str) and bool(DIGEST.fullmatch(quote["digest"]))
            and valid_amount(quote["source"]) and valid_amount(quote["target"]))


def valid_approval_facts(approval: Any) -> bool:
    return (isinstance(approval, dict) and approval.get("mode") in APPROVAL_MODES
            and isinstance(approval.get("issuer"), str) and len(approval["issuer"]) > 0)


INTENT_REQUIRED = {"schema", "profile", "intentId", "createdAt", "expiresAt", "audience", "action", "payee", "payer",
                   "amount", "resources", "payment"}
INTENT_MEMBERS = INTENT_REQUIRED | {"presenter", "commerce", "purpose", "extensions"}


def intent_members_ok(intent: Any) -> bool:
    """Section 8.4.4, check 2: the intent parses strictly — every required member, and no other."""
    return isinstance(intent, dict) and INTENT_REQUIRED <= set(intent) <= INTENT_MEMBERS


def evaluate(vector: dict) -> dict:
    chain, fees = vector["chain"], vector.get("fees", [])
    defer = vector.get("deferExecutionTerms") is True
    now = vector["now"]
    # Section 8.4.4, check 1: a decision time that is a safe non-negative integer, 1 to 10 caveats, at most 256 fees.
    now_ok = isinstance(now, int) and not isinstance(now, bool) and 0 <= now <= 2**53 - 1
    if not now_ok or not (1 <= len(chain) <= MAX_CHAIN) or len(fees) > MAX_MEMBERS:
        return {"valid": False, "code": "PAYMENT_CONSTRAINT_INVALID", "rule": "constraints.input"}
    if (not intent_members_ok(vector["intent"]) or not all(valid_constraints(c) for c in chain)
            or not all(valid_amount(f) for f in fees)
            or (defer and ("fees" in vector or "quote" in vector))
            or ("quote" in vector and not valid_quote(vector["quote"]))
            or ("approval" in vector and not valid_approval_facts(vector["approval"]))):
        return {"valid": False, "code": "PAYMENT_CONSTRAINT_INVALID", "rule": "constraints.structure"}
    effective = chain[0]
    for hop in range(1, len(chain)):
        rule = find_widening(effective, chain[hop])
        if rule is not None:
            return {"valid": False, "code": "PAYMENT_CONSTRAINT_WIDENING", "rule": rule, "hop": hop,
                    "effectiveConstraintsDigest": domain_digest(CONSTRAINTS_DOMAIN, normalized_constraints(effective))}
        effective = chain[hop]
    effective_digest = domain_digest(CONSTRAINTS_DOMAIN, normalized_constraints(effective))
    intent = vector["intent"]
    rule = find_intent_denial(effective, intent, {
        "fees": fees,
        "quote": vector.get("quote"),
        "defer": defer,
        "approval": vector.get("approval"),
        "now": vector["now"],
    })
    if rule is not None:
        code = "PAYMENT_APPROVAL_REQUIRED" if rule == "intent.approval" else "PAYMENT_CONSTRAINT_DENIED"
        return {"valid": False, "code": code, "rule": rule, "effectiveConstraintsDigest": effective_digest}
    # Rules whose inputs are rail facts are recorded as deferred, never as passed (section 8.4.4).
    deferred = [r for r in INTENT_RULES
                if defer and (r == "intent.fees" or (r == "intent.quote" and is_conversion(intent)))]
    result = {"valid": True, "effectiveConstraintsDigest": effective_digest}
    if deferred:
        result["deferred"] = deferred
    return result


def narrows(parent: Any, child: Any) -> bool:
    if not valid_constraints(parent) or not valid_constraints(child):
        return False
    return find_widening(parent, child) is None

# --------------------------------------------------------------------------
# Caveat evaluation (section 8.4.5)
# --------------------------------------------------------------------------

# Section 8.4.5 grammar: limit = "0" / %x31-39 0*59DIGIT, then optionally "." 1*18DIGIT.
MAX_AMOUNT_LIMIT = re.compile(r"(0|[1-9][0-9]{0,59})(?:\.([0-9]{1,18}))?")
BUILT_IN_MEMBERS = {"ValidUntil": {"type", "date"}, "MaxAmount": {"type", "limit", "currency"}}


def evaluate_caveats(chain_caveats: list, intent: dict, now: int) -> dict:
    for hop, caveats in enumerate(chain_caveats):
        for caveat in caveats:
            if not isinstance(caveat, dict) or not isinstance(caveat.get("type"), str):
                return {"valid": False, "code": "PAYMENT_DELEGATION_INVALID", "rule": "caveat.malformed", "hop": hop}
            kind = caveat["type"]
            if kind == CONSTRAINT_TYPE:
                continue
            if kind in BUILT_IN_MEMBERS and not set(caveat) <= BUILT_IN_MEMBERS[kind]:
                return {"valid": False, "code": "PAYMENT_CAVEAT_UNSUPPORTED", "rule": "caveat.members", "hop": hop}
            if kind == "ValidUntil":
                bound = rfc3339_millis(caveat["date"]) if isinstance(caveat.get("date"), str) else None
                if bound is None:
                    return {"valid": False, "code": "PAYMENT_DELEGATION_INVALID",
                            "rule": "caveat.validUntil.malformed", "hop": hop}
                if now >= bound:
                    return {"valid": False, "code": "PAYMENT_DELEGATION_INVALID",
                            "rule": "caveat.validUntil.expired", "hop": hop}
                continue
            if kind == "MaxAmount":
                limit = MAX_AMOUNT_LIMIT.fullmatch(caveat["limit"]) if isinstance(caveat.get("limit"), str) else None
                # A `currency` member that is present must be three uppercase letters; `null` is present.
                has_currency = "currency" in caveat
                currency = caveat.get("currency")
                if limit is None or (has_currency and (not isinstance(currency, str)
                                                       or not ISO4217.fullmatch(currency))):
                    return {"valid": False, "code": "PAYMENT_DELEGATION_INVALID",
                            "rule": "caveat.maxAmount.malformed", "hop": hop}
                # A decimal limit is an amount of one named currency: without `currency` it
                # bounds no payment, and it never bounds another asset.
                if (not has_currency or intent["amount"]["asset"]["namespace"] != "iso4217"
                        or intent["amount"]["asset"]["id"] != currency):
                    return {"valid": False, "code": "PAYMENT_CONSTRAINT_DENIED",
                            "rule": "caveat.maxAmount.currency", "hop": hop}
                fraction = limit.group(2) or ""
                ceiling = {"asset": intent["amount"]["asset"],
                           "coefficient": str(int(limit.group(1) + fraction)), "scale": len(fraction)}
                if compare_amounts(intent["amount"], ceiling) > 0:
                    return {"valid": False, "code": "PAYMENT_CONSTRAINT_DENIED", "rule": "caveat.maxAmount", "hop": hop}
                continue
            return {"valid": False, "code": "PAYMENT_CAVEAT_UNSUPPORTED", "rule": "caveat.unsupported", "hop": hop}
    return {"valid": True}

def admit(vector: dict) -> dict:
    """Section 8.4.6: the Executor's checks before step 1, which the request and the intent alone
    decide (section 4.2). The execution profile orders them; each refusal vector fails one."""
    intent, now = vector["intent"], vector["now"]
    if (intent["audience"] != vector["audience"] or intent["payee"]["id"] not in vector["payees"]
            or intent.get("presenter", vector["requester"]) != vector["requester"]):
        return {"valid": False, "code": "PAYMENT_INTENT_MISMATCH"}
    if intent["createdAt"] > now + INTENT_SKEW_MS:
        return {"valid": False, "code": "PAYMENT_REQUEST_INVALID"}
    if now >= intent["expiresAt"]:
        return {"valid": False, "code": "PAYMENT_AUTHORITY_EXPIRED"}
    # Check V5 of section 8.7, decided by an Executor with no extension handler.
    if any(extension["critical"] for extension in intent.get("extensions", {}).values()):
        return {"valid": False, "code": "PAYMENT_EXTENSION_UNSUPPORTED"}
    # Section 7.1: the base's seconds, in milliseconds; an exclusive end that no skew extends.
    if now >= vector["requestProofExpires"] * 1000:
        return {"valid": False, "code": "PROOF_INVALID"}
    return {"valid": True}

OUTCOME_DOMAIN = "org.kya-os.payments.outcome.v1"
TRANSITIONS = {"authorized": {"submitted", "failed"}, "submitted": {"settlement_pending", "settled", "failed"},
               "settlement_pending": {"settled", "failed"}, "settled": set(), "failed": set()}


def stream_binding(outcome: dict) -> tuple:
    """Section 8.3: the members every observation of one stream shares with the one before it."""
    rail = outcome["rail"]
    return (outcome["attemptId"], outcome["producer"], outcome["intentDigest"], outcome["authorizationDigest"],
            jcs(outcome["idempotency"]), rail["id"], rail["version"], rail.get("specDigest"))


def verify_stream(observations: list) -> dict:
    """Section 8.3: the seven stream checks of an Evidence Consumer, over observations in arrival order."""
    refused = {"valid": False, "code": "PAYMENT_OUTCOME_STREAM_INVALID"}
    accepted: dict = {}
    for outcome in observations:
        digest = domain_digest(OUTCOME_DOMAIN, outcome)
        if outcome["sequence"] in accepted:
            if accepted[outcome["sequence"]][1] != digest:
                return refused  # check 2: one sequence, two digests
            continue  # an exact retransmission
        accepted[outcome["sequence"]] = (outcome, digest)
    first = accepted.get(0)
    if first is None or first[0]["state"] not in ("authorized", "submitted"):
        return refused  # check 1: a bad start
    if sorted(accepted) != list(range(len(accepted))):
        return refused  # check 2: a gap
    corrected = False
    for sequence in range(1, len(accepted)):
        (previous, previous_digest), (outcome, _) = accepted[sequence - 1], accepted[sequence]
        if outcome.get("previousOutcomeDigest") != previous_digest:
            return refused  # check 3: a broken link, or a fork
        if stream_binding(outcome) != stream_binding(previous):
            return refused  # check 4: an unstable binding
        if outcome.get("correction") is True:
            reason = previous.get("reason", {})
            basis = reason.get("basis")
            if (corrected or previous["state"] != "failed" or reason.get("code") != "payment_failed" or basis is None
                    or (outcome["state"] == "settlement_pending" and basis != "close")):
                return refused  # check 6: a misplaced or second correction
            corrected = True
        elif outcome["state"] not in TRANSITIONS[previous["state"]]:
            return refused  # check 5: a disallowed transition
        if outcome["updatedAt"] < previous["updatedAt"]:
            return refused  # check 7: a time regression
    return {"valid": True}

# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------

def main() -> int:
    # Read as the JSON data model (section 10): `2`, `2.0`, and `2e0` are one integral value.
    corpus = data_model(json.loads(CORPUS.read_text(encoding="utf-8")))
    vectors = corpus["vectors"]
    failures: list = []
    checked = 0
    execution = 0  # checks of the answer and its proof, which the execution profile defines

    def check(label: str, expected: Any, actual: Any, execution_profile: bool = False) -> None:
        nonlocal checked, execution
        checked += 1
        execution += 1 if execution_profile else 0
        if expected != actual:
            failures.append(f"{label}: expected {expected!r}, got {actual!r}")

    check("corpusDigest", corpus["corpusDigest"], domain_digest(corpus["corpusDomain"], vectors))
    for v in vectors["artifactDigests"]:
        answer = "result" in v
        if answer:
            check(f"artifact {v['name']} covered", v["input"], answer_covered(v["result"]), True)
            check(f"artifact {v['name']} domain", ANSWER_DOMAIN, v["domain"], True)
        if "credentials" in v:
            check(f"artifact {v['name']} credential digests", v["input"],
                  [domain_digest(CREDENTIAL_DOMAIN, credential) for credential in v["credentials"]])
        hashed = normalized_constraints(v["input"]) if v["name"] == "constraints" else v["input"]
        if "normalized" in v:
            check(f"artifact {v['name']} normalized", v["normalized"], hashed)
        check(f"artifact {v['name']} canonical", v["canonical"], jcs(hashed), answer)
        check(f"artifact {v['name']} digest", v["digest"], domain_digest(v["domain"], hashed), answer)
    for v in vectors["requestDigests"]:
        check(f"requestDigest {v['name']}", v["requestDigest"], request_digest(v["baseRequestHash"]))
    for v in vectors["answerProofs"]:
        check(f"answer proof {v['name']}", v["verifies"], verify_answer_proof(v), True)
    for i, v in enumerate(vectors["amountComparisons"]):
        check(f"amountComparison {i}", v["compare"], compare_amounts(v["left"], v["right"]))
    for i, v in enumerate(vectors["normalization"]):
        check(f"normalization {i}", v["output"], normalize_amount(v["input"]))
    for v in vectors["time"]:
        check(f"time {v['input']}", v["millis"], rfc3339_millis(v["input"]))
    for v in vectors["constraints"]:
        check(f"constraints {v['name']}", v["expect"], evaluate(v))
    for v in vectors["narrowing"]:
        check(f"narrowing {v['name']}", v["narrows"], narrows(v["parent"], v["child"]))
    for v in vectors["caveats"]:
        check(f"caveats {v['name']}", v["expect"], evaluate_caveats(v["caveats"], v["intent"], v["now"]))
    for v in vectors["admission"]:
        check(f"admission {v['name']}", v["expect"], admit(v))
    for v in vectors["outcomeStreams"]:
        check(f"outcomeStream {v['name']}", v["expect"], verify_stream(v["observations"]))
    for v in vectors["semantic"]:
        check(f"semantic {v['name']}", v["valid"], SEMANTIC_VALIDATORS[v["artifact"]](v["input"]))

    if failures:
        print(f"FAIL: {len(failures)} of {checked} checks")
        for failure in failures:
            print("  " + failure)
        return 1
    print(f"OK: {checked - execution} Core Authority checks and {execution} execution-profile checks reproduced "
          f"by the Python verifier (corpus {corpus['corpusDigest']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
