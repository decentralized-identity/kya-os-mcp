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


def covered_request(request: dict) -> dict:
    """SPEC-ENTITY-CARD 8.3: `{method, params}` with the `_meta` member of `params` removed.

    `params` is left out where it is absent, null, or an object with no member once `_meta` is
    removed, so a call with no params is its method alone however it travels.
    """
    covered = {"method": request["method"]}
    params = request.get("params")
    if isinstance(params, dict):
        params = {name: value for name, value in params.items() if name != "_meta"}
        if not params:
            return covered
    if params is not None:
        covered["params"] = params
    return covered


def _digest_field(value: dict) -> str:
    return "sha-256=:" + std_b64(hashlib.sha256(jcs(value)).digest()) + ":"


def card_proof_request_hash(request: dict) -> str:
    """The `requestHash` of a card proof: `sha-256=:<base64>:` over JCS of the covered request.

    A response proof's `requestHash` is another rule, with another form:
    `response_proof_request_hash` in response_proof.py.
    """
    return _digest_field(covered_request(request))


def card_proof_request_hash_binds(request_hash: str, request: dict) -> bool:
    """Whether `request_hash` binds `request`: the hash of its covered request, or for the 1.x line,
    when that request has no params, the hash of the legacy form `{method, params: {}}`."""
    covered = covered_request(request)
    if request_hash == _digest_field(covered):
        return True
    return "params" not in covered and request_hash == _digest_field({"method": request["method"], "params": {}})


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
