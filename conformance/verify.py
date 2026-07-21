#!/usr/bin/env python3
"""KYA-OS Entity Card proof — INDEPENDENT cross-language conformance verifier.

The second-language complement to the TypeScript `ConformanceAdapter` contract: a pure-Python-stdlib
re-implementation of the `org.kya-os/proof@1` verification path that shares NO code with the reference
adapter. It reads the SAME framework vector file the runner does (`conformance/vectors/card-proof.json`),
selects the positive (`expected == "pass"`) vector, and against that self-contained artifact it re-derives
the RFC 8785 (JCS) canonicalization, recomputes the SHA-256 `requestHash`, and verifies BOTH the detached
EdDSA JWS and the RFC 9421 HTTP Message Signature sibling against the vector's embedded DID-keyed JWKS. A
green run proves cross-language canonicalization + Ed25519 signature parity — the JCS cross-language
guarantee the polyglot toolchain rests on.

The same run also verifies the positive audit-integrity vector using an
independent RFC 9162 Merkle implementation (leaf/node domain separation,
inclusion proof, and consistency proof).

Zero external dependencies: SHA-256 via `hashlib`, JCS via `json.dumps(sort_keys, separators,
ensure_ascii=False)` (exact for the string/integer vector structures), and Ed25519 verification via the
RFC 8032 reference implementation below. No pip install required.

    run:  python3 conformance/verify.py   (npm run conformance:verify:crosslang)
    exit: 0 on full parity, 1 on any mismatch.
"""

import base64
import hashlib
import json
import sys
from pathlib import Path

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
    Q = (0, 1, 1, 0)  # neutral element
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
    """Verify an Ed25519 signature (RFC 8032). Fail-closed on any malformed input."""
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
    sB = _point_mul(S, _G)
    hA = _point_mul(h, A)
    return _point_equal(sB, _point_add(R, hA))


# ── Encoding helpers ──────────────────────────────────────────────────────────────
def jcs(value) -> bytes:
    """RFC 8785 (JCS) canonical bytes — exact for the string/integer vector structures."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64url_nopad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def std_b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


# ── Verification steps ─────────────────────────────────────────────────────────────
def covered_claims(proof: dict) -> dict:
    """Every proof field except the signatures — the object the detached JWS actually signs."""
    claims = {k: proof[k] for k in
              ("prf", "alg", "did", "kid", "audience", "nonce", "created", "expires", "requestHash")}
    if "cnf" in proof:
        claims["cnf"] = proof["cnf"]
    return claims


def request_hash(request: dict) -> str:
    canonical = {"method": request["method"]}
    if request.get("params") is not None:
        canonical["params"] = request["params"]
    return "sha-256=:" + std_b64(hashlib.sha256(jcs(canonical)).digest()) + ":"


def http_signature_base(proof: dict) -> str:
    lines = [
        f'"content-digest": {proof["requestHash"]}',
        f'"kya-audience": {proof["audience"]}',
        f'"kya-nonce": {proof["nonce"]}',
    ]
    comps = '"content-digest" "kya-audience" "kya-nonce"'
    if "cnf" in proof:
        lines.append(f'"kya-cnf": {proof["cnf"]["jkt"]}')
        comps += ' "kya-cnf"'
    params = (f'created={proof["created"]};expires={proof["expires"]};'
              f'keyid="{proof["kid"]}";alg="ed25519"')
    lines.append(f'"@signature-params": ({comps});{params}')
    return "\n".join(lines)


def rfc7638_thumbprint(jwk: dict) -> str:
    return b64url_nopad(hashlib.sha256(jcs({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]})).digest())


def resolve_key(jwks: dict, kid: str) -> dict:
    for key in jwks["keys"]:
        if key.get("kid") == kid:
            return key
    raise SystemExit(f"FAIL: no JWKS key resolves kid {kid!r}")


def positive_vector(vector_file: dict) -> dict:
    """The card-proof.json vector a conformant verifier MUST ACCEPT — the golden proof."""
    for vector in vector_file["vectors"]:
        if vector.get("expected") == "pass":
            return vector["input"]
    raise SystemExit("FAIL: card-proof.json has no positive (expected: pass) vector")


def digest_bytes(value: str) -> bytes:
    prefix = "sha256:"
    if not value.startswith(prefix) or len(value) != len(prefix) + 64:
        raise ValueError("invalid sha256 digest")
    return bytes.fromhex(value[len(prefix):])


def audit_leaf_hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(b"\x00" + digest_bytes(value)).hexdigest()


def audit_node_hash(left: str, right: str) -> str:
    material = b"\x01" + digest_bytes(left) + digest_bytes(right)
    return "sha256:" + hashlib.sha256(material).hexdigest()


def audit_root(leaves: list[str]) -> str:
    if not leaves:
        return "sha256:" + hashlib.sha256(b"").hexdigest()
    if len(leaves) == 1:
        return audit_leaf_hash(leaves[0])
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    return audit_node_hash(audit_root(leaves[:split]), audit_root(leaves[split:]))


def audit_verify_inclusion(leaf: str, index: int, size: int, root: str, path: list[str]) -> bool:
    if size <= 0 or index < 0 or index >= size:
        return False
    leaf_pos, last_pos = index, size - 1
    calculated = audit_leaf_hash(leaf)
    for sibling in path:
        if last_pos == 0:
            return False
        if leaf_pos & 1 or leaf_pos == last_pos:
            calculated = audit_node_hash(sibling, calculated)
            while leaf_pos != 0 and not leaf_pos & 1:
                leaf_pos //= 2
                last_pos //= 2
        else:
            calculated = audit_node_hash(calculated, sibling)
        leaf_pos //= 2
        last_pos //= 2
    return last_pos == 0 and calculated == root


def audit_verify_consistency(old_size: int, new_size: int, old_root: str,
                             new_root: str, path: list[str]) -> bool:
    if old_size <= 0 or old_size > new_size:
        return False
    if old_size == new_size:
        return not path and old_root == new_root
    old_node, new_node = old_size - 1, new_size - 1
    while old_node & 1:
        old_node //= 2
        new_node //= 2
    path_index = 0
    if old_node == 0:
        old_calculated = new_calculated = old_root
    else:
        if not path:
            return False
        old_calculated = new_calculated = path[0]
        path_index = 1
    for sibling in path[path_index:]:
        if new_node == 0:
            return False
        if old_node & 1 or old_node == new_node:
            old_calculated = audit_node_hash(sibling, old_calculated)
            new_calculated = audit_node_hash(sibling, new_calculated)
            while old_node != 0 and not old_node & 1:
                old_node //= 2
                new_node //= 2
        else:
            new_calculated = audit_node_hash(new_calculated, sibling)
        old_node //= 2
        new_node //= 2
    return (new_node == 0 and old_calculated == old_root and
            new_calculated == new_root)


def main() -> int:
    here = Path(__file__).resolve().parent
    vector_file = json.loads((here / "vectors" / "card-proof.json").read_text())
    vector = positive_vector(vector_file)
    proof = vector["proof"]
    jwks = vector["jwks"]  # the DID-keyed JWKS is embedded in the self-contained vector

    key = resolve_key(jwks, proof["kid"])
    pub = b64url_decode(key["x"])

    results = []

    # 1. Re-derive requestHash from JCS({method, params}) + SHA-256.
    recomputed = request_hash(vector["request"])
    results.append(("requestHash JCS+SHA-256 recompute", recomputed == proof["requestHash"]))

    # 2. Verify the detached EdDSA JWS over JCS(coveredClaims).
    parts = proof["jws"].split(".")
    jws_ok = len(parts) == 3 and parts[1] == ""
    if jws_ok:
        signing_input = (parts[0] + "." + b64url_nopad(jcs(covered_claims(proof)))).encode("ascii")
        jws_ok = ed25519_verify(pub, signing_input, b64url_decode(parts[2]))
    results.append(("detached EdDSA JWS over JCS(coveredClaims)", jws_ok))

    # 3. Verify the RFC 9421 HTTP Message Signature sibling (raw Ed25519 over the signature base).
    http_ok = ed25519_verify(pub, http_signature_base(proof).encode("utf-8"), b64url_decode(proof["httpSig"]))
    results.append(("RFC 9421 httpSig over the signature base", http_ok))

    # 4. Re-derive the RFC 7638 cnf.jkt thumbprint of the resolved key.
    results.append(("RFC 7638 cnf.jkt thumbprint fusion",
                    rfc7638_thumbprint(key) == proof.get("cnf", {}).get("jkt")))

    audit_file = json.loads((here / "vectors" / "audit-integrity.json").read_text())
    audit = positive_vector(audit_file)
    audit_leaves = audit["leaves"]
    inclusion = audit["inclusion"]
    consistency = audit["consistency"]
    event_canonical = jcs(audit["event"])
    event_digest = "sha256:" + hashlib.sha256(
        b"org.kya-os.audit.event.v1\x00" + event_canonical
    ).hexdigest()
    results.append(("audit event JCS canonical bytes",
                    event_canonical.decode("utf-8") == audit["eventCanonical"]))
    results.append(("domain-separated audit event digest",
                    event_digest == audit["eventDigest"]))
    results.append(("RFC 9162 audit Merkle root",
                    audit_root(audit_leaves) == audit["root"]))
    results.append(("RFC 9162 audit inclusion proof",
                    audit_verify_inclusion(
                        audit_leaves[inclusion["leafIndex"]],
                        inclusion["leafIndex"], len(audit_leaves),
                        audit["root"], inclusion["auditPath"])))
    results.append(("RFC 9162 audit consistency proof",
                    audit_verify_consistency(
                        consistency["oldSize"], len(audit_leaves),
                        consistency["oldRoot"], audit["root"],
                        consistency["auditPath"])))

    print(f"KYA-OS cross-language verifier (Python {sys.version.split()[0]}, stdlib-only)")
    print(f"  proof: {proof['prf']}  did: {proof['did']}")
    for label, ok in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    ok = all(ok for _, ok in results)
    print(f"RESULT: {'PASS — cross-language JCS + Ed25519 parity confirmed' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
