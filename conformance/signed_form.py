"""SPEC.md 7.8: a delegation credential's signed form, and the digests computed over it.

A credential is digested in its signed form: what its issuer's signature covers, and that
signature, written one way however it was written. A chain's digest is over the digests of its
credentials, root first.
"""

from base64url import b64url_nopad, jws_segment_bytes, signature_bytes
from digests import domain_digest
from strict_json import nests_deeper_than

CREDENTIAL_DIGEST_DOMAIN = b"org.kya-os.delegation.credential.v1\x00"
CHAIN_DIGEST_DOMAIN = b"org.kya-os.delegation.chain.v1\x00"


# The deepest the arrays and objects of a credential may nest (SPEC.md 7.8). The serializer
# and the JSON parser (strict_json.py) recurse, and run out of stack at a depth that differs
# from one interpreter to the next. What is nested deeper than this is never handed to either:
# it is counted first, by the two loops beside them, which take no stack.
MAX_CREDENTIAL_NESTING_DEPTH = 64


def canonical_signature(encoded, read=signature_bytes) -> str:
    """One value for a signature however it was written: base64url, no padding, of its bytes."""
    decoded = read(encoded) if isinstance(encoded, str) else b""
    if not decoded:
        raise ValueError("a signature that carries no byte has no signed form")
    return b64url_nopad(decoded)


def signed_form(credential) -> dict:
    """What the issuer's signature covers, and the signature. Nothing else of the copy is read.

    Raises ValueError for a value that has no signed form (SPEC.md 7.8): it is no credential,
    and has no digest.
    """
    if isinstance(credential, str):
        segments = credential.split(".")
        if len(segments) != 3 or not segments[0] or not segments[1]:
            raise ValueError("a VC-JWT is a compact JWS: header.payload.signature")
        return {"jwt": segments[0] + "." + segments[1],
                "signature": canonical_signature(segments[2], jws_segment_bytes)}
    proof = credential.get("proof") if isinstance(credential, dict) else None
    if not isinstance(proof, dict):
        raise ValueError("a credential object carries its signature in proof.proofValue")
    # Counted on the whole object, `proof` included, before anything below recurses into it.
    if nests_deeper_than(credential, MAX_CREDENTIAL_NESTING_DEPTH):
        raise ValueError(
            f"a credential object nests at most {MAX_CREDENTIAL_NESTING_DEPTH} levels deep")
    unsigned = {key: value for key, value in credential.items() if key != "proof"}
    return {"credential": unsigned, "signature": canonical_signature(proof.get("proofValue"))}


def credential_digest(credential) -> str:
    return domain_digest(CREDENTIAL_DIGEST_DOMAIN, signed_form(credential))


def chain_digest(chain: list) -> str:
    """Over the credentials' digests, root first. A chain of none, or no array, has no digest."""
    if not isinstance(chain, list) or not chain:
        raise ValueError("a delegation chain is an array of at least one credential")
    return domain_digest(CHAIN_DIGEST_DOMAIN, [credential_digest(credential) for credential in chain])


# What a hop that leaves a member out states of it: nothing, which no JSON value is.
NOT_STATED = object()


def parent_commitment(chain: list) -> str:
    """SPEC.md 6.2 and 6.10: how the hops of a chain, root first, commit to their parents.

    "root-states" when the root states a `parentCredentialDigest`, which it may not; "mismatch"
    when a later hop states one that is not the 7.8 digest of the hop before it; "committed" when
    a later hop states one and every one stated is its parent's; "uncommitted" when none states one.
    A hop states the member when it holds it, whatever its value: `null` is stated. A base
    profile credential (6.2) holds it in the delegation record its subject carries, and an
    Entity Card hop (6.10) in its subject.
    """
    def stated(hop) -> object:
        subject = hop.get("credentialSubject") if isinstance(hop, dict) else None
        if not isinstance(subject, dict):
            return NOT_STATED
        holder = subject["delegation"] if isinstance(subject.get("delegation"), dict) else subject
        return holder.get("parentCredentialDigest", NOT_STATED)

    if stated(chain[0]) is not NOT_STATED:
        return "root-states"
    committed = False
    for parent, hop in zip(chain, chain[1:]):
        digest = stated(hop)
        if digest is NOT_STATED:
            continue
        if digest != credential_digest(parent):
            return "mismatch"
        committed = True
    return "committed" if committed else "uncommitted"
