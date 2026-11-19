"""SPEC.md 7.8: how a holder's request proof stands against the delegation its call presented.

A request proof covers the call, not the delegation beside it, so it states which credential the
call presents in its JWS protected header, under `org.kya-os/delegation`: the 7.8 digest of that
credential, in the form it is sent, or `none`. The proof is held first as the TypeScript reference
holds it (`response_proof.py`): its form, its signer, its time and its signature, then the request
it binds. Its signer is the holder: the did:key of the key the vector gives. Then what the proof
says of its delegation, read only from what its signature covers, in the order the reference
compares it: the `delegationRef` and the `delegationChainDigest` it signs, then the statement of
the protected header that verified.
"""

from base64url import strict_base64url_bytes
from delegation_ref import delegation_ref_of
from digests import DIGEST_FORM
from response_proof import binds_request, jws_segment_json, proof_verifies, signed_meta
from signed_form import NOT_STATED, chain_digest, credential_digest

HEADER_PARAMETER = "org.kya-os/delegation"
NO_DELEGATION = "none"

_BASE58BTC = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
# The multicodec prefix of an Ed25519 public key (SPEC.md 4.3).
_ED25519_MULTICODEC = b"\xed\x01"


def did_key_of(public_key: bytes) -> str:
    """The did:key of an Ed25519 public key (SPEC.md 4.3): `z` and the base58btc of 0xed01 and the key."""
    data = _ED25519_MULTICODEC + public_key
    number, encoded = int.from_bytes(data, "big"), ""
    while number:
        number, digit = divmod(number, 58)
        encoded = _BASE58BTC[digit] + encoded
    leading_zeros = len(data) - len(data.lstrip(b"\x00"))
    return "did:key:z" + _BASE58BTC[0] * leading_zeros + encoded


def stated_delegation(proof: dict):
    """What the protected header of `proof` states of its delegation: the value under the
    parameter, whatever it is, or `NOT_STATED` for a header without it. Of members that share
    the name the last is read, as `read_json` reads. It is read of a proof that has verified,
    never before: nothing binds the statement until the holder's signature covers it."""
    header = jws_segment_json(proof["jws"].split(".")[0])
    return header[HEADER_PARAMETER] if HEADER_PARAMETER in header else NOT_STATED


def request_binding(vector: dict, requires=None) -> str:
    """How the vector's request proof stands against the delegation its call presented.

    `invalid`: the proof is not of its form, its signer, time or signature does not hold, its
    signer is not the did:key of the key given, or a part of it does not read as base64url,
    UTF-8 or JSON. `request`: it binds another request than the one held. `no-signed-form`: the
    credential presented has no digest. `misnamed`: the proof signs a `delegationRef`, or a
    `delegationChainDigest`, that is not the presented credential's. `malformed`: its statement
    is neither a credential digest nor `none`. `mismatch`: it states another credential than
    the one presented. `none-stated`: the verifier requires a proof to name the credential
    presented, and the proof states `none` beside one. `unnamed`: the verifier requires it, and
    the proof states nothing. `bound` otherwise.

    The verifier requires naming when the vector asks for it (`expected.requestBinding` is
    `require`), or as `requires` says where it is given.

    `fault`: this verifier ran out of stack, which is no verdict (`chain_binding.py`).
    """
    try:
        return _request_binding(vector, requires)
    except RecursionError:
        return "fault"
    except ValueError:
        return "invalid"


def _request_binding(vector: dict, requires) -> str:
    if not proof_verifies(vector):
        return "invalid"
    proof = vector["proof"]
    meta = signed_meta(proof["meta"])
    if meta["did"] != did_key_of(strict_base64url_bytes(vector["publicKeyJwk"]["x"])):
        return "invalid"
    expected = vector["expected"]
    if not binds_request(meta, expected.get("request")):
        return "request"
    if requires is None:
        requires = expected.get("requestBinding") == "require"
    presented = expected["presentedDelegation"]
    digest = None
    if presented is not None:
        try:
            digest = credential_digest(presented)
        except ValueError:
            return "no-signed-form"
        if "delegationRef" in meta and meta["delegationRef"] != delegation_ref_of(presented):
            return "misnamed"
        if "delegationChainDigest" in meta and meta["delegationChainDigest"] != chain_digest([presented]):
            return "misnamed"
    stated = stated_delegation(proof)
    if stated is NOT_STATED:
        return "unnamed" if requires else "bound"
    if stated == NO_DELEGATION:
        return "none-stated" if requires and presented is not None else "bound"
    if not isinstance(stated, str) or DIGEST_FORM.fullmatch(stated) is None:
        return "malformed"
    return "bound" if digest is None or stated == digest else "mismatch"
