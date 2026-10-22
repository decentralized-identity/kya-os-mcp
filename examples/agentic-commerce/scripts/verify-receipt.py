#!/usr/bin/env python3
"""Re-verify a merchant's signed receipt with NO SDK — pure Python stdlib.

"Any merchant, any language": the receipt the shipped @kya-os/mcp middleware
attaches to an allowed `place_order` is a detached compact JWS (EdDSA) whose
payload carries a SHA-256 over the RFC 8785 (JCS) canonical request and a
SHA-256 over the canonical response content. This script shares no code with
the TypeScript verifier. It reads one JSON document on stdin:

    { "receipt": { "proof": { "jws", "meta" }, "request": { "method", "params" }, "content": [...] },
      "merchant": { "did": "did:key:z6Mk…", "kid": "…", "publicKeyBase64": "…" } }

and re-derives everything: the merchant's Ed25519 key from its did:key (base58btc,
multicodec 0xed01), the JWS signing input, the Ed25519 signature (RFC 8032
reference math), and both bound hashes. Exit 0 on full agreement, 1 otherwise;
the JSON report on stdout lists every check that ran.

The Ed25519 and JCS routines are lifted from conformance/verify.py in the
kya-os-mcp repository so this file stays self-contained for the example.
"""
import base64
import hashlib
import json
import sys

# ── Ed25519 verification (RFC 8032 reference implementation, pure stdlib) ─────────
_p = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493


def _modp_inv(x):
    return pow(x, _p - 2, _p)


_d = -121665 * _modp_inv(121666) % _p
_modp_sqrt_m1 = pow(2, (_p - 1) // 4, _p)


def _sha512_modL(s):
    return int.from_bytes(hashlib.sha512(s).digest(), "little") % _L


def _point_add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % _p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % _p
    C = 2 * P[3] * Q[3] * _d % _p
    D = 2 * P[2] * Q[2] % _p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _p, G * H % _p, F * G % _p, E * H % _p)


def _point_mul(s, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _point_add(Q, P)
        P = _point_add(P, P)
        s >>= 1
    return Q


def _point_equal(P, Q):
    if (P[0] * Q[2] - Q[0] * P[2]) % _p != 0:
        return False
    if (P[1] * Q[2] - Q[1] * P[2]) % _p != 0:
        return False
    return True


def _recover_x(y, sign):
    if y >= _p:
        return None
    x2 = (y * y - 1) * _modp_inv(_d * y * y + 1) % _p
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_p + 3) // 8, _p)
    if (x * x - x2) % _p != 0:
        x = x * _modp_sqrt_m1 % _p
    if (x * x - x2) % _p != 0:
        return None
    if (x & 1) != sign:
        x = _p - x
    return x


_g_y = 4 * _modp_inv(5) % _p
_g_x = _recover_x(_g_y, 0)
_G = (_g_x, _g_y, 1, _g_x * _g_y % _p)


def _point_decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _p)


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    A = _point_decompress(public_key)
    if A is None:
        return False
    Rs = signature[:32]
    R = _point_decompress(Rs)
    if R is None:
        return False
    S = int.from_bytes(signature[32:], "little")
    if S >= _L:
        return False
    h = _sha512_modL(Rs + public_key + message)
    return _point_equal(_point_mul(S, _G), _point_add(R, _point_mul(h, A)))


# ── RFC 8785 (JCS) ────────────────────────────────────────────────────────────────
def _es_number(value) -> str:
    if isinstance(value, int):
        if abs(value) > 2 ** 53 - 1:
            raise ValueError("unsafe integer outside the admitted JCS space")
        return str(value)
    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError("non-finite number")
    if value == 0.0:
        return "0"
    sign = "-" if value < 0 else ""
    mantissa, _, exponent = repr(abs(value)).partition("e")
    exp10 = int(exponent) if exponent else 0
    integer_part, _, fraction = mantissa.partition(".")
    if integer_part != "0":
        n = len(integer_part) + exp10
    else:
        n = exp10 - (len(fraction) - len(fraction.lstrip("0")))
    digits = (integer_part + fraction).lstrip("0").rstrip("0") or "0"
    k = len(digits)
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + digits
    e = n - 1
    mantissa_out = digits[0] + ("." + digits[1:] if k > 1 else "")
    return f"{sign}{mantissa_out}e{'+' if e >= 0 else '-'}{abs(e)}"


def _jcs_serialize(value) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (int, float)):
        return _es_number(value)
    if isinstance(value, list):
        return "[" + ",".join(_jcs_serialize(item) for item in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda pair: pair[0].encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _jcs_serialize(v) for k, v in items) + "}"
    raise ValueError(f"unsupported JCS value type: {type(value).__name__}")


def jcs(value) -> bytes:
    return _jcs_serialize(value).encode("utf-8")


def sha256_tag(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ── did:key → Ed25519 public key (multicodec 0xed01, base58btc) ───────────────────
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58_decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + _B58.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + raw


def did_key_public_key(did: str) -> bytes:
    if not did.startswith("did:key:z"):
        raise ValueError("not a base58btc did:key")
    decoded = base58_decode(did[len("did:key:z"):])
    if len(decoded) != 34 or decoded[:2] != b"\xed\x01":
        raise ValueError("did:key is not an Ed25519 multicodec key")
    return decoded[2:]


# ── The verification ───────────────────────────────────────────────────────────────
def verify(doc: dict) -> dict:
    checks = []
    receipt = doc["receipt"]
    merchant = doc["merchant"]
    proof = receipt["proof"]
    meta = proof["meta"]
    jws = proof["jws"]

    # 1. the merchant's key, derived from its DID (not taken on trust from the server)
    pk = did_key_public_key(merchant["did"])
    if merchant.get("publicKeyBase64") and base64.b64decode(merchant["publicKeyBase64"]) != pk:
        raise ValueError("publicKeyBase64 disagrees with the key encoded in the merchant did:key")
    checks.append(f"key derived from {merchant['did'][:24]}… (did:key, multicodec ed25519)")

    # 2. JWS structure + header
    parts = jws.split(".")
    if len(parts) != 3:
        raise ValueError("JWS is not compact serialization")
    header = json.loads(b64url_decode(parts[0]))
    if header.get("alg") != "EdDSA":
        raise ValueError(f"unexpected alg {header.get('alg')}")
    if header.get("kid") != meta.get("kid") or not str(header.get("kid", "")).startswith(merchant["did"]):
        raise ValueError("kid in the JWS header is not the merchant's key")
    checks.append("JWS header: alg=EdDSA, kid is the merchant's key")

    # 3. the signature, over the JWS signing input, with RFC 8032 math
    signing_input = (parts[0] + "." + parts[1]).encode("ascii")
    if not ed25519_verify(pk, signing_input, b64url_decode(parts[2])):
        raise ValueError("Ed25519 signature does NOT verify")
    checks.append("Ed25519 signature verifies (RFC 8032, stdlib)")

    # 4. the claims
    payload = json.loads(b64url_decode(parts[1]))
    if payload.get("iss") != merchant["did"] or payload.get("sub") != merchant["did"]:
        raise ValueError("iss/sub are not the merchant DID")
    if payload.get("aud") != meta.get("audience"):
        raise ValueError("aud does not match proof.meta.audience")
    checks.append(f"claims: iss=sub=merchant, aud={str(payload.get('aud'))[:20]}…, nonce+ts present")

    # 5. the request binding: sha256(JCS({method, params}))
    request = receipt["request"]
    canonical_request = {"method": request["method"], **({"params": request["params"]} if request.get("params") else {})}
    expected_request_hash = sha256_tag(jcs(canonical_request))
    if payload.get("requestHash") != expected_request_hash or meta.get("requestHash") != expected_request_hash:
        raise ValueError("requestHash does not match the canonical request")
    checks.append("requestHash = sha256(JCS(request)) ✓")

    # 6. the response binding: sha256(JCS(content)) — body profile (no prf claim)
    if payload.get("prf"):
        raise ValueError("envelope-profile proofs are not handled by this script")
    expected_response_hash = sha256_tag(jcs(receipt["content"]))
    if payload.get("responseHash") != expected_response_hash or meta.get("responseHash") != expected_response_hash:
        raise ValueError("responseHash does not match the canonical response content")
    checks.append("responseHash = sha256(JCS(content)) ✓")

    # 7. the payload the signature covers is the JCS of the claims (no hidden bytes)
    if b64url_decode(parts[1]) != jcs(payload):
        raise ValueError("JWS payload is not RFC 8785 canonical")
    checks.append("payload bytes are RFC 8785 canonical")

    return {"ok": True, "checks": checks, "orderId": (receipt.get("body") or {}).get("orderId"), "kid": header.get("kid")}


def main() -> int:
    try:
        doc = json.load(sys.stdin)
        report = verify(doc)
    except Exception as err:  # noqa: BLE001 — every failure is a refusal
        print(json.dumps({"ok": False, "error": str(err)}))
        return 1
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
