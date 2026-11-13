"""The `org.kya-os/proof.v1` card proof: what its signatures cover, recomputed from the vector."""

import hashlib

from base64url import b64url_nopad, std_b64
from strict_json import jcs


def covered_claims(proof: dict) -> dict:
    """Every proof field except the signatures: the object the detached JWS actually signs."""
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
