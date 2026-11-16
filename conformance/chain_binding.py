"""SPEC.md 7.8: how a response proof stands against the chain and the outcome its verifier holds.

The proof is held first as the TypeScript reference holds it (`response_proof.py`): its form,
signer, time and signature, then the request and the response it binds. Then the outcome, the
chain digest and the reference the proof signs, in the order 7.8 compares them.
"""

from delegation_ref import delegation_ref_of
from response_proof import binds_request, proof_verifies, response_binds, response_hash
from signed_form import chain_digest


def chain_binding(vector: dict) -> str:
    """How the proof stands against what the vector's verifier holds, in the order 7.8 compares.

    `invalid`: the proof is not of its form, its signer, time or signature does not hold, or a
    part of it or of what it is held against does not read as base64url, UTF-8 or JSON.
    `request`: it binds another request than the one held. `outcome`: it states another outcome
    than the one asked for, which is `allowed` when a chain is supplied and no outcome is.
    `response`: it binds another response than the one held, or binds one where none is held,
    or none where one is. `no-chain`: no chain was supplied. `unbound`: the proof binds none.
    `no-signed-form`: the supplied chain has no digest. `mismatch`: it has another digest.
    `misnamed`: the proof names another credential than the chain's last. `bound` otherwise.

    `fault`: this verifier ran out of stack. Nothing it reads of a credential nests deeper
    than 7.8 allows, so that is not a verdict on what it was given, and is never one a
    vector expects.
    """
    try:
        return _chain_binding(vector)
    except RecursionError:
        return "fault"
    except ValueError:
        return "invalid"


def _or(value, default):
    """`value`, or `default` when there is none: an empty string is a value."""
    return default if value is None else value


def _chain_binding(vector: dict) -> str:
    if not proof_verifies(vector):
        return "invalid"
    meta = vector["proof"]["meta"]
    if "expected" not in vector:
        return "no-chain"
    expected = vector["expected"]
    if not isinstance(expected, dict):
        raise ValueError("what a verifier holds of a call is an object")
    # Both hashes are taken of what is held before either is compared, as the reference does.
    held_response = response_hash(expected["response"], meta.get("prf")) if "response" in expected else None
    if not binds_request(meta, expected.get("request")):
        return "request"
    chain = expected.get("delegationChain")
    required = _or(expected.get("outcome"), "allowed" if chain is not None else None)
    if required is not None and _or(meta.get("outcome"), "allowed") != required:
        return "outcome"
    if not response_binds(meta, expected, held_response):
        return "response"
    if chain is None:
        return "no-chain"
    claimed = meta.get("delegationChainDigest")
    if claimed is None:
        return "unbound"
    try:
        digest = chain_digest(chain)
    except ValueError:
        return "no-signed-form"
    if claimed != digest:
        return "mismatch"
    # An empty delegationRef is not in the payload the signature covers: the proof names none.
    if (meta.get("delegationRef") or None) != delegation_ref_of(chain[-1]):
        return "misnamed"
    return "bound"
