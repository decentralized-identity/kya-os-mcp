"""SPEC.md 7.3 and 7.4: a response proof, and the request and response it binds, checked as the
TypeScript reference (`ProofVerifier.verifyProof`) checks them.

The proof is held to its form, as schemas/detached-proof.json has it, then to its signer, its
time and its signature. The signature is checked over the payload rebuilt from `meta`, as the
producer built it, so every claim of `meta` is held to what was signed. Each segment of the JWS
is read as RFC 7515 section 2 writes base64url (`strict_base64url_bytes`), and one that does not
read so, as base64url, as UTF-8 or as JSON, makes no proof. The key's `x` is read the same way. The request and the
response a verifier holds are then held to the hashes the proof binds.
"""

import math

from base64url import b64url_nopad, strict_base64url_bytes
from digests import DIGEST_FORM, sha256_digest
from ed25519 import ed25519_verify
from strict_json import jcs, read_json

ENVELOPE_PROFILE = "org.kya-os/response-proof.envelope"
OUTCOMES = ("allowed", "denied", "step_up_required", "needs_authorization")

_REQUIRED_STRINGS = ("did", "kid", "nonce", "audience", "sessionId")
_OPTIONAL_DIGESTS = ("responseHash", "delegationChainDigest")
_OPTIONAL_STRINGS = ("scopeId", "delegationRef", "clientDid", "reason")
# Signed only when not empty, in this order after the claims every proof signs (7.4).
_OPTIONAL_CLAIMS = ("scopeId", "delegationRef", "delegationChainDigest", "clientDid", "outcome", "reason", "prf")
# The members of `meta` its signature covers whatever they hold: `kid` in the protected header.
_ALWAYS_SIGNED = _REQUIRED_STRINGS + ("ts", "requestHash", "responseHash")


def _is_number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _as_double(number) -> float:
    """The IEEE 754 binary64 value JSON.parse reads a number as: one too large for it is infinite."""
    try:
        return float(number)
    except OverflowError:
        return float("inf") if number > 0 else float("-inf")


def _is_digest(value) -> bool:
    return isinstance(value, str) and DIGEST_FORM.fullmatch(value) is not None


def proof_of_its_form(proof) -> bool:
    """`proof` is a detached proof of the form schemas/detached-proof.json gives one.

    A non-empty `jws`, and a `meta` whose `did`, `kid`, `nonce`, `audience` and `sessionId` are
    non-empty strings, whose `ts` is a positive integer once read as a double, and whose
    `requestHash` is a digest. Each optional claim, where it is given, is of its form: a digest,
    a string, one of the four outcomes, or the envelope profile. A claim given as null is given,
    and is of none of these forms.
    """
    if not isinstance(proof, dict) or not isinstance(proof.get("jws"), str) or not proof["jws"]:
        return False
    meta = proof.get("meta")
    if not isinstance(meta, dict):
        return False
    if not all(isinstance(meta.get(name), str) and meta[name] for name in _REQUIRED_STRINGS):
        return False
    ts = meta.get("ts")
    if not _is_number(ts) or not _as_double(ts).is_integer() or ts <= 0:
        return False
    if not _is_digest(meta.get("requestHash")):
        return False
    return (all(name not in meta or _is_digest(meta[name]) for name in _OPTIONAL_DIGESTS)
            and all(name not in meta or isinstance(meta[name], str) for name in _OPTIONAL_STRINGS)
            and ("outcome" not in meta or meta["outcome"] in OUTCOMES)
            and ("prf" not in meta or meta["prf"] == ENVELOPE_PROFILE))


def signed_payload(meta: dict) -> bytes:
    """The payload a proof signs, rebuilt from its `meta` as the producer builds it (7.4)."""
    payload = {"aud": meta["audience"], "sub": meta["did"], "iss": meta["did"],
               "requestHash": meta["requestHash"]}
    if "responseHash" in meta:
        payload["responseHash"] = meta["responseHash"]
    payload.update(ts=meta["ts"], nonce=meta["nonce"], sessionId=meta["sessionId"])
    payload.update((name, meta[name]) for name in _OPTIONAL_CLAIMS if meta.get(name))
    return jcs(payload)


def signed_meta(meta: dict) -> dict:
    """The members of `meta` its signature covers, in the order `meta` gives them (7.4).

    Those every proof signs, `responseHash` where it is given, and each optional claim that is
    not empty. A verifier acts on these alone: a member the proof schema does not name, or an
    optional claim given as an empty string, says nothing.
    """
    return {name: value for name, value in meta.items()
            if name in _ALWAYS_SIGNED or (name in _OPTIONAL_CLAIMS and value)}


def jws_segment_json(segment: str):
    """The JSON a segment of a proof's JWS carries: read as base64url, as UTF-8, then as JSON.

    Raises ValueError for a segment that does not read so at any of the three.
    """
    return read_json(strict_base64url_bytes(segment).decode("utf-8"))


def _jwk_public_key(jwk, kid: str) -> bytes:
    """The key of an Ed25519 JWK for `kid`: `kty` OKP, `crv` Ed25519, `kid` the one given, and
    the key's bytes in `x`, read as the JWS segments are. Raises ValueError for any other value."""
    if not isinstance(jwk, dict) or (jwk.get("kty"), jwk.get("crv"), jwk.get("kid")) != ("OKP", "Ed25519", kid):
        raise ValueError("not the Ed25519 JWK of the key a proof names")
    x = jwk.get("x")
    if not isinstance(x, str):
        raise ValueError("an Ed25519 JWK carries its key in x")
    return strict_base64url_bytes(x)


def _signature_holds(proof: dict, jwk) -> bool:
    """The JWS is three segments and verifies under `jwk` over the payload rebuilt from `meta`.

    The header must name EdDSA and `meta.kid`, and so must the key. A payload segment, where
    the JWS carries one, must be the rebuilt payload, or verify under the same signature too.
    """
    meta = proof["meta"]
    segments = proof["jws"].split(".")
    if len(segments) != 3:
        return False
    header_segment, payload_segment, signature_segment = segments
    header = jws_segment_json(header_segment)
    # A payload segment the JWS carries is read too, as the reference reads it: one that is
    # not JSON makes no JWS, whatever its signature.
    if payload_segment:
        jws_segment_json(payload_segment)
    signature = strict_base64url_bytes(signature_segment)
    if not isinstance(header, dict) or header.get("alg") != "EdDSA" or header.get("kid") != meta["kid"]:
        return False
    key = _jwk_public_key(jwk, meta["kid"])
    rebuilt = b64url_nopad(signed_payload(meta))
    signed = [rebuilt] + ([payload_segment] if payload_segment not in ("", rebuilt) else [])
    return all(ed25519_verify(key, (header_segment + "." + payload).encode("utf-8"), signature)
               for payload in signed)


def proof_verifies(vector) -> bool:
    """The vector's proof is of its form, and its signer, its time and its signature hold.

    Its `kid`, where it is a DID URL, names a key of `meta.did`; its `ts` is within the
    vector's skew of its `now`; and its JWS verifies (`_signature_holds`). The vector gives
    `now` and `skewSeconds` as numbers, as the reference takes them, and a skew that is no
    finite number is refused as the reference refuses it. False, never an exception, for a
    proof any part of which does not read as base64url, UTF-8 or JSON.
    """
    proof = vector.get("proof") if isinstance(vector, dict) else None
    if not proof_of_its_form(proof):
        return False
    meta = proof["meta"]
    kid = meta["kid"]
    if kid.startswith("did:") and kid.split("#")[0] != meta["did"]:
        return False
    now, skew = vector.get("now"), vector.get("skewSeconds")
    if not _is_number(now) or not _is_number(skew) or not math.isfinite(_as_double(skew)):
        return False
    if not abs(_as_double(now) * 1000 - _as_double(meta["ts"]) * 1000) <= _as_double(skew) * 1000:
        return False
    try:
        return _signature_holds(proof, vector.get("publicKeyJwk"))
    except ValueError:
        return False


def verified_meta(vector) -> "dict | None":
    """The meta of the vector's proof as its signature covers it (`signed_meta`), where the proof
    verifies (`proof_verifies`); None where it does not."""
    return signed_meta(vector["proof"]["meta"]) if proof_verifies(vector) else None


def _js_truthy(value) -> bool:
    """Whether ECMAScript holds a JSON value true: all but null, false, 0 and the empty string."""
    return not (value is None or value is False or value == "" or (_is_number(value) and value == 0))


def response_proof_request_hash(request) -> str:
    """The `requestHash` of a response proof, for a request as given: `sha256:<hex>` over
    JCS({method, params}) (7.3).

    `params` is left out where ECMAScript holds it false, as the producer leaves it out. Raises
    ValueError for a request that is no object, or has no method. A card proof's `requestHash` is
    another rule, with another form: `card_proof_request_hash` in card_proof.py.
    """
    if not isinstance(request, dict) or "method" not in request:
        raise ValueError("a request is an object with a method")
    canonical = {"method": request["method"]}
    if _js_truthy(request.get("params")):
        canonical["params"] = request["params"]
    return sha256_digest(jcs(canonical))


def _without(members: dict, drop) -> dict:
    return {key: value for key, value in members.items() if not drop(key)}


def _other_shapes(request: dict) -> list:
    """The other shapes of the tool call `request` describes, which a verifier accepts (7.3).

    The covered `tools/call` request, without `params._meta` and without the `_kyaos` control
    arguments, and the legacy shape `{method: <tool name>, params: <arguments>}` with the
    arguments as given and without the control arguments. None for a request whose arguments
    are not an object.
    """
    method, params = request.get("method"), request.get("params")
    if method == "tools/call" and isinstance(params, dict) and isinstance(params.get("name"), str):
        name = params["name"]
        arguments = {} if params.get("arguments") is None else params["arguments"]
    else:
        name, arguments = method, ({} if params is None else params)
        params = {"name": method, "arguments": arguments}
    if not isinstance(arguments, dict):
        return []
    business = _without(arguments, lambda key: key.startswith("_kyaos"))
    covered = {**_without(params, lambda key: key == "_meta"), "arguments": business}
    return [{"method": "tools/call", "params": covered},
            {"method": name, "params": arguments},
            {"method": name, "params": business}]


def binds_request(meta: dict, request: dict) -> bool:
    """`meta.requestHash` is the hash of `request`, or of another shape of the same call."""
    if meta["requestHash"] == response_proof_request_hash(request):
        return True
    shapes = _other_shapes(request)
    return meta["requestHash"] in {response_proof_request_hash(shape) for shape in shapes}


def response_hash(response, profile) -> str:
    """The `responseHash` of a response: SHA-256 of JCS of its `data` (7.3).

    Under the envelope profile an object `data` is hashed without its top-level `_meta`.
    Raises ValueError for a response that is no object carrying `data`.
    """
    if not isinstance(response, dict) or "data" not in response:
        raise ValueError("a response is an object with data")
    data = response["data"]
    if profile == ENVELOPE_PROFILE and isinstance(data, dict):
        data = _without(data, lambda key: key == "_meta")
    return sha256_digest(jcs(data))


def response_binds(meta: dict, expected: dict, held_hash) -> bool:
    """A proof binds a response exactly when one is held, and then the one held."""
    if ("responseHash" in meta) != ("response" in expected):
        return False
    return "responseHash" not in meta or meta["responseHash"] == held_hash
