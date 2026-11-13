"""The cases a response proof is held to beyond the vectors (SPEC.md 7.3, 7.4 and 7.8).

Each case alters one thing of a vector whose proof binds, and gives the verdict chain_binding.py
must reach on it: something the verifier holds (its clock, its skew, the key, the request, the
response, the outcome it asks for, the chain), the JWS as received, or a claim of the proof. A
claim is altered and signed again with the test key of RFC 8032 7.1 (TEST 1), and the proof
checked with that key, so the case turns on the claim and on nothing its signature would catch.
What is signed is the payload 7.4 lists, written out here rather than taken from
response_proof.py, so that the payload the verifier rebuilds is held to the specification and
not to itself; the signer is held to the keys and the signatures the RFC gives; and each
signature forged under a key of small order is held to the verification equation, which it
satisfies under that key.

The TypeScript reference is held to the same cases, under the same names
(conformance/__tests__/proof-path-cases.test.ts): a case `bound` or `no-chain` here passes
there, and every other fails there where it fails here: on the request, on the response, on
the chain, or before any of them is compared.
"""

import copy

from base64url import b64url_nopad, strict_base64url_bytes
from chain_binding import chain_binding
from digests import sha256_digest
from ed25519 import L, ed25519_equation_holds, ed25519_public_key, ed25519_sign
from strict_json import jcs

# RFC 8032 7.1, TEST 1: a secret key any implementation can sign the cases with, the public key
# the RFC gives for it, and its signature of the empty message.
TEST_SECRET_KEY = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
TEST_PUBLIC_KEY = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
TEST_SIGNATURE = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                               "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
# Each secret key the RFC gives with its public key, and a message with its signature where the
# signature is an Ed25519 one: TEST 1 and TEST 3 of 7.1, and the key of the first test of 7.2,
# an Ed25519ctx key made as an Ed25519 key is (5.1.5). Their secret keys expand to scalars with
# other bits set, bit 255 for TEST 3 and bit 253 for that of 7.2, so a signer that prunes a
# scalar otherwise than 5.1.5 gives another key for one of them.
RFC_8032_KEYS = (
    (TEST_SECRET_KEY, TEST_PUBLIC_KEY, b"", TEST_SIGNATURE),
    (bytes.fromhex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"),
     bytes.fromhex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"),
     bytes.fromhex("af82"),
     bytes.fromhex("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
                   "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a")),
    (bytes.fromhex("0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6"),
     bytes.fromhex("dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292"),
     None, None),
)
# Two keys of small order, each with the signature R = the key and S = 0 forged under it: the
# identity (y = 1), under which it satisfies the verification equation for every message, and the
# point of order two (y = p - 1), under which it satisfies it for every message whose h is odd, as
# the payload of `chain-binding` is. forgeries_hold says they do.
IDENTITY = bytes([1]) + bytes(31)
ORDER_TWO = bytes([0xEC]) + bytes([0xFF]) * 30 + bytes([0x7F])
FORGERIES = tuple((key, key + bytes(32)) for key in (IDENTITY, ORDER_TWO))
LEFT_OUT = object()

# The claims a proof signs (SPEC.md 7.4): `aud`, `sub` and `iss`, named for the audience and the
# did of `meta`; the hashes, the time, the nonce and the session `meta` gives; and each optional
# claim that is not empty.
_NAMED = (("aud", "audience"), ("sub", "did"), ("iss", "did"))
_GIVEN = ("requestHash", "responseHash", "ts", "nonce", "sessionId")
_NOT_EMPTY = ("scopeId", "delegationRef", "delegationChainDigest", "clientDid", "outcome", "reason", "prf")


def _refused(secret: bytes) -> bool:
    """Whether the signer refuses `secret` as a secret key."""
    try:
        ed25519_public_key(secret)
    except ValueError:
        return True
    return False


def signer_holds() -> bool:
    """The signer of the cases gives the public keys and the signatures RFC 8032 gives, and takes
    a secret key of 32 bytes and no other length (5.1.5)."""
    return (all(ed25519_public_key(secret) == public
                and (message is None or ed25519_sign(secret, message) == signature)
                for secret, public, message, signature in RFC_8032_KEYS)
            and _refused(TEST_SECRET_KEY[:31]) and _refused(TEST_SECRET_KEY + b"\0"))


def forgeries_hold(bound: dict) -> bool:
    """Each signature of FORGERIES satisfies the verification equation under its key, over what
    the JWS of `bound` signs, so that the cases which send it are refused for the key alone."""
    header, payload, _ = bound["proof"]["jws"].split(".")
    signed = (header + "." + payload).encode("ascii")
    return all(ed25519_equation_holds(key, signed, forged) for key, forged in FORGERIES)


def _payload(meta: dict) -> str:
    """The payload segment of a proof whose meta is `meta`, its claims as SPEC.md 7.4 lists them."""
    claims = {claim: meta[member] for claim, member in _NAMED}
    claims.update((name, meta[name]) for name in _GIVEN if name in meta)
    claims.update((name, meta[name]) for name in _NOT_EMPTY if meta.get(name))
    return b64url_nopad(jcs(claims))


def _set(members: dict, **changes) -> dict:
    """A copy of `members` with each of `changes` set, or left out where it is LEFT_OUT."""
    altered = copy.deepcopy(members)
    for name, value in changes.items():
        if value is LEFT_OUT:
            altered.pop(name, None)
        else:
            altered[name] = value
    return altered


def _key(vector: dict, **changes) -> dict:
    return {**vector, "publicKeyJwk": _set(vector["publicKeyJwk"], **changes)}


def _held(vector: dict, **changes) -> dict:
    return {**vector, "expected": _set(vector["expected"], **changes)}


def _jws(vector: dict, jws) -> dict:
    return {**vector, "proof": {**vector["proof"], "jws": jws}}


def _meta(vector: dict, **changes) -> dict:
    return {**vector, "proof": {**vector["proof"], "meta": _set(vector["proof"]["meta"], **changes)}}


def _signed(vector: dict, **changes) -> dict:
    """The vector's proof with `changes` made to its meta and signed again with the test key,
    which the verifier is given for the proof's `kid`."""
    meta = _set(vector["proof"]["meta"], **changes)
    header = b64url_nopad(jcs({"alg": "EdDSA", "kid": meta["kid"]}))
    payload = _payload(meta)
    signature = b64url_nopad(ed25519_sign(TEST_SECRET_KEY, (header + "." + payload).encode("utf-8")))
    key = {"kty": "OKP", "crv": "Ed25519", "x": b64url_nopad(TEST_PUBLIC_KEY), "kid": meta["kid"]}
    return {**vector, "proof": {"jws": header + "." + payload + "." + signature, "meta": meta}, "publicKeyJwk": key}


def proof_cases(bound: dict, bare: dict) -> list:
    """Each case: its name, the vector it is, and its verdict.

    `bound` is the input of the vector `signed-proof/delegation-chain-binding`, and `bare` of
    `signed-proof/delegation-proof-request-without-params`.
    """
    meta = bound["proof"]["meta"]
    ts = meta["ts"]
    header, payload, signature = bound["proof"]["jws"].split(".")
    x = bound["publicKeyJwk"]["x"]
    request = bound["expected"]["request"]
    params = request["params"]
    another_payload = _payload({**meta, "nonce": "nonce-other"})
    (identity_key, forged), (order_two_key, forged_under_it) = (
        (b64url_nopad(key), b64url_nopad(signature)) for key, signature in FORGERIES)
    no_point = b64url_nopad(bytes([2]) + bytes(31))
    signature_bytes = strict_base64url_bytes(signature)
    r, s = signature_bytes[:32], int.from_bytes(signature_bytes[32:], "little")
    with_65th_byte = b64url_nopad(r + s.to_bytes(33, "little"))
    # S + L satisfies the verification equation as S does, so only the refusal of an S that is
    # not below L (RFC 8032 5.1.7) refuses it.
    malleated = b64url_nopad(r + (s + L).to_bytes(32, "little"))
    digest_in_capitals = "sha256:" + meta["requestHash"][len("sha256:"):].upper()
    data_with_meta = {"content": bound["expected"]["response"]["data"], "_meta": {"note": "kept"}}
    return [
        # The verifier's clock and skew.
        ("now as far after ts as the skew allows", {**bound, "now": ts + 300}, "bound"),
        ("now a second later than the skew allows", {**bound, "now": ts + 301}, "invalid"),
        ("now a quarter of a second later than the skew allows", {**bound, "now": ts + 300.25}, "invalid"),
        ("now a second earlier than the skew allows", {**bound, "now": ts - 301}, "invalid"),
        ("now given as a string", {**bound, "now": str(ts)}, "invalid"),
        ("skew zero, now at ts", {**bound, "now": ts, "skewSeconds": 0}, "bound"),
        ("skew negative", {**bound, "now": ts, "skewSeconds": -1}, "invalid"),
        ("skew that is no finite number", {**bound, "skewSeconds": float("inf")}, "invalid"),
        ("skew left out", _set(bound, skewSeconds=LEFT_OUT), "invalid"),
        # The key the proof is checked with.
        ("key x padded to complete its last group", _key(bound, x=x + "="), "invalid"),
        ("key x with a space inside it", _key(bound, x=x[:5] + " " + x[5:]), "invalid"),
        ("key x with a character outside base64url", _key(bound, x=x + "*"), "invalid"),
        ("key x of 31 bytes", _key(bound, x=b64url_nopad(strict_base64url_bytes(x)[:31])), "invalid"),
        ("key x of 32 bytes that encode no point, no x having y = 2", _key(bound, x=no_point), "invalid"),
        ("key x given as a number", _key(bound, x=7), "invalid"),
        ("key with no x", _key(bound, x=LEFT_OUT), "invalid"),
        ("key named by another kid", _key(bound, kid=meta["kid"] + "-other"), "invalid"),
        ("key on another curve", _key(bound, crv="X25519"), "invalid"),
        ("key of another type", _key(bound, kty="EC"), "invalid"),
        ("no key", _set(bound, publicKeyJwk=LEFT_OUT), "invalid"),
        ("key of small order, under which R = identity and S = 0 verify every payload",
         _jws(_key(bound, x=identity_key), header + "." + payload + "." + forged), "invalid"),
        ("key of order two, under which R = the key and S = 0 verify this payload",
         _jws(_key(bound, x=order_two_key), header + "." + payload + "." + forged_under_it), "invalid"),
        # The JWS as received.
        ("JWS with no payload segment, detached", _jws(bound, header + ".." + signature), "bound"),
        ("JWS whose payload segment is another proof's",
         _jws(bound, header + "." + another_payload + "." + signature), "invalid"),
        ("JWS whose payload segment is not JSON",
         _jws(bound, header + "." + b64url_nopad(b"not json") + "." + signature), "invalid"),
        ("JWS whose header is a JSON array", _jws(bound, b64url_nopad(b"[]") + "." + payload + "." + signature),
         "invalid"),
        ("JWS with an empty signature segment", _jws(bound, header + "." + payload + "."), "invalid"),
        ("JWS whose signature segment is padded to complete its last group",
         _jws(bound, header + "." + payload + "." + signature + "=="), "invalid"),
        ("JWS whose signature segment holds a line break",
         _jws(bound, header + "." + payload + "." + signature[:43] + "\n" + signature[43:]), "invalid"),
        ("JWS whose signature has a 65th byte, zero, which leaves S as it is",
         _jws(bound, header + "." + payload + "." + with_65th_byte), "invalid"),
        ("JWS whose signature has S + L for S, which satisfies the equation as S does",
         _jws(bound, header + "." + payload + "." + malleated), "invalid"),
        ("JWS given as a number", _jws(bound, 7), "invalid"),
        ("proof whose meta is null", {**bound, "proof": {**bound["proof"], "meta": None}}, "invalid"),
        ("proof whose ts is an integer past the largest double", _meta(bound, ts=10 ** 400), "invalid"),
        # The request the verifier sent.
        ("request in the legacy shape, the tool its method and the arguments its params",
         _held(bound, request={"method": params["name"], "params": params["arguments"]}), "bound"),
        ("request with params._meta and a control argument, which the hash leaves out",
         _held(bound, request={"method": "tools/call", "params": {
             **params, "_meta": {"progressToken": 1},
             "arguments": {**params["arguments"], "_kyaos_delegation": "a credential"}}}), "bound"),
        ("request with another argument",
         _held(bound, request={**request, "params": {**params, "arguments": {"recordId": "r-2"}}}), "request"),
        ("request whose arguments are an array",
         _held(bound, request={**request, "params": {**params, "arguments": ["r-1"]}}), "request"),
        ("request that is no object", _held(bound, request="tools/call"), "invalid"),
        ("request left out", _held(bound, request=LEFT_OUT), "invalid"),
        *((f"request without params, given as {written}",
           _held(bare, request={"method": "tools/call", "params": value}), "bound")
          for written, value in (("null", None), ("0", 0), ("an empty string", ""), ("false", False))),
        ("request without params, given as an empty object",
         _held(bare, request={"method": "tools/call", "params": {}}), "request"),
        ("request whose params is a number", _held(bare, request={"method": "tools/call", "params": 7}), "request"),
        # The response the verifier received, and what it asks.
        ("response left out", _held(bound, response=LEFT_OUT), "response"),
        ("response held, of a proof that binds none", _signed(bound, responseHash=LEFT_OUT), "response"),
        ("response with other data", _held(bound, response={"data": [{"type": "text", "text": "released r-2"}]}),
         "response"),
        ("response data an object with _meta, which the body profile hashes as it is",
         _held(_signed(bound, responseHash=sha256_digest(jcs(data_with_meta))), response={"data": data_with_meta}),
         "bound"),
        ("response given as null", _held(bound, response=None), "invalid"),
        ("response with no data", _held(bound, response={}), "invalid"),
        ("outcome asked for, allowed, as the proof records", _held(bound, outcome="allowed"), "bound"),
        ("nothing held of the call, so nothing is compared", _set(bound, expected=LEFT_OUT), "no-chain"),
        ("what is held of the call given as null", {**bound, "expected": None}, "invalid"),
        # The chain the verifier holds.
        ("chain held as an empty array, which no proof binds", _held(bound, delegationChain=[]), "no-signed-form"),
        ("chain held as a number, which no proof binds", _held(bound, delegationChain=7), "no-signed-form"),
        # The claims, each signed again with the test key.
        ("signed again with the test key, and checked with it", _signed(bound), "bound"),
        ("kid relative to meta.did", _signed(bound, kid="#key-1"), "bound"),
        ("kid empty", _signed(bound, kid=""), "invalid"),
        ("ts with a fraction", _signed(bound, ts=ts + 0.5), "invalid"),
        ("ts zero, checked at time zero", {**_signed(bound, ts=0), "now": 0}, "invalid"),
        ("ts one, checked at time one", {**_signed(bound, ts=1), "now": 1}, "bound"),
        ("ts given as true, checked at time one", {**_signed(bound, ts=True), "now": 1}, "invalid"),
        ("ts given as a string", _signed(bound, ts=str(ts)), "invalid"),
        ("did empty, with a relative kid", _signed(bound, did="", kid="#key-1"), "invalid"),
        ("nonce empty", _signed(bound, nonce=""), "invalid"),
        ("audience empty", _signed(bound, audience=""), "invalid"),
        ("sessionId empty", _signed(bound, sessionId=""), "invalid"),
        ("requestHash in capitals", _signed(bound, requestHash=digest_in_capitals), "invalid"),
        ("responseHash one digit short", _signed(bound, responseHash="sha256:" + "0" * 63), "invalid"),
        ("delegationChainDigest with a capital", _signed(bound, delegationChainDigest="sha256:" + "0" * 63 + "A"),
         "invalid"),
        ("delegationRef given as a number", _signed(bound, delegationRef=7), "invalid"),
        ("scopeId empty, which is not signed", _signed(bound, scopeId=""), "bound"),
        ("scopeId given, which is signed", _signed(bound, scopeId="scope-1"), "bound"),
        ("scopeId given as null", _signed(bound, scopeId=None), "invalid"),
        ("clientDid given, which is signed", _signed(bound, clientDid="did:web:client.example"), "bound"),
        ("clientDid given as a number", _signed(bound, clientDid=7), "invalid"),
        ("reason given, which is signed", _signed(bound, reason="within the delegated slice"), "bound"),
        ("reason given as a number", _signed(bound, reason=7), "invalid"),
        ("outcome given, allowed, which is signed", _signed(bound, outcome="allowed"), "bound"),
        ("outcome given as null", _signed(bound, outcome=None), "invalid"),
        ("outcome that is none of the four", _signed(bound, outcome="Allowed"), "invalid"),
        ("prf of the envelope profile, which is signed",
         _signed(bound, prf="org.kya-os/response-proof.envelope"), "bound"),
        ("prf of a profile no verifier knows", _signed(bound, prf="org.example/unknown-profile"), "invalid"),
        ("member the proof schema does not name", _signed(bound, note="x"), "bound"),
    ]


def proof_cases_hold(bound: dict, bare: dict) -> bool:
    """Every case has its verdict. Each that does not is printed, so a run says which."""
    held = True
    for name, vector, verdict in proof_cases(bound, bare):
        reached = chain_binding(vector)
        if reached != verdict:
            print(f"  proof case {name!r}: {reached}, not {verdict}")
            held = False
    return held
