"""Independent reading of SPEC §6.6, restricted to the status-list vector profile.

No TypeScript imports, generated verdict tables, or expected outcomes. This is
test tooling, not a general-purpose VC verifier: the vector profile uses
Ed25519Signature2020 over JCS(document minus proof), one-bit gzip lists, and
already-authorized per-credential root context. Chain admission is tested
separately; an input's trustedRootIssuer is NOT a proof of a chain.
"""

import base64
import gzip
import io
import json
import re
import sys


def issuer(value):
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and isinstance(value.get("id"), str):
        return value["id"]
    return None


def accepts(document, owner, root, services, url, purpose="revocation"):
    """A signer is authorized by identity, not by its position in a role table."""
    if not isinstance(document, dict) or not isinstance(owner, str) or not owner:
        return False
    signer = issuer(document.get("issuer"))
    if not signer:
        return False
    others = ([root] if root is not None else []) + services.get(owner, [])
    if signer != owner and signer not in others:
        return False
    # Only the id binds a list to its URL. The owner's list may leave it out only
    # when no other issuer is authorized, so it can stand in for no list but its own.
    if "id" in document:
        if not isinstance(document["id"], str) or document["id"] != url:
            return False
    elif signer != owner or any(other != owner for other in others):
        return False
    subject = document.get("credentialSubject")
    if not isinstance(subject, dict):
        return False
    declared = subject.get("statusPurpose")
    if isinstance(declared, str):
        return declared == purpose
    return (isinstance(declared, list) and len(declared) > 0
            and all(isinstance(p, str) for p in declared)
            and purpose in declared
            and isinstance(document.get("type"), list)
            and "BitstringStatusListCredential" in document["type"]
            and subject.get("type") == "BitstringStatusList")


def configuration(value):
    """The verifier configuration an input states, as the TypeScript loader holds it.

    A trustedRootIssuer, when present, is a non-empty string, and a statusListIssuers, when
    present, maps each issuer to a list of strings. Anything else raises ValueError.
    """
    root = value.get("trustedRootIssuer")
    if "trustedRootIssuer" in value and not (isinstance(root, str) and root):
        raise ValueError("trustedRootIssuer is not a non-empty string")
    services = value.get("statusListIssuers", {})
    if not isinstance(services, dict) or not all(
            isinstance(accepted, list) and all(isinstance(did, str) for did in accepted)
            for accepted in services.values()):
        raise ValueError("statusListIssuers does not map issuers to lists of strings")
    return root, services


def graph_case(case):
    """Project actual chain issuers + a pin, before applying the list rule.

    Continuity, hop signatures and policy admission are caller obligations.
    A pin unequal to the actual root cannot grant authority at any hop.
    """
    chain = case["chain"]
    owner = issuer(chain[case["hop"]]["issuer"])
    root = issuer(chain[0]["issuer"])
    pinned = root if case.get("pin") == root else None
    return accepts(case["list"], owner, pinned, case.get("services", {}), case["url"])


def decode64(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]*={0,2}", value):
        raise ValueError("invalid base64url")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def verify_document(document, documents, canonicalize, verify_signature):
    did = issuer(document.get("issuer"))
    did_document = documents[did]
    if did_document.get("id") != did:
        return False
    proof = document["proof"]
    if proof.get("type") != "Ed25519Signature2020" or proof.get("proofPurpose") != "assertionMethod":
        return False
    method = proof["verificationMethod"]
    keys = [key for key in did_document.get("verificationMethod", [])
            if isinstance(key, dict) and key.get("id") == method and key.get("controller") == did]
    if len(keys) != 1 or method not in did_document.get("assertionMethod", []):
        return False
    key = keys[0]["publicKeyJwk"]
    if key.get("kty") != "OKP" or key.get("crv") != "Ed25519":
        return False
    unsigned = {k: v for k, v in document.items() if k != "proof"}
    return verify_signature(decode64(key["x"]), canonicalize(unsigned), decode64(proof["proofValue"]))


def verify_input(value, canonicalize, verify_signature):
    """Re-derive authority, both proofs and the indexed bit, never expected labels."""
    try:
        credential = value["credential"]
        entry = credential["credentialStatus"]
        url = entry["statusListCredential"]
        document = value["statusLists"][url]
        purpose = entry["statusPurpose"]
        root, services = configuration(value)
        if not isinstance(purpose, str) or not accepts(
                document, issuer(credential["issuer"]), root, services, url, purpose):
            return False
        documents = value["didDocuments"]
        if not verify_document(credential, documents, canonicalize, verify_signature):
            return False
        if not verify_document(document, documents, canonicalize, verify_signature):
            return False
        raw_index = entry["statusListIndex"]
        if not isinstance(raw_index, str) or not re.fullmatch(r"[0-9]+", raw_index):
            return False
        # Leading zeros name no other bit, however many there are. int() refuses a string of more
        # than 4,300 digits, so they go first, and a value of more than 16 digits is past 2^53 - 1.
        digits = raw_index.lstrip("0") or "0"
        if len(digits) > 16:
            return False
        index = int(digits)
        if index > 2 ** 53 - 1:
            return False
        encoded = document["credentialSubject"]["encodedList"]
        compressed = decode64(encoded[1:] if encoded.startswith("u") else encoded)
        # Bound output while inflating, not after a gzip bomb has allocated it.
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
            bits = stream.read(16 * 1024 * 1024 + 1)
        if len(bits) > 16 * 1024 * 1024 or index >= len(bits) * 8:
            return False
        return not bool(bits[index // 8] & (128 >> (index % 8)))
    except (ValueError, TypeError, KeyError, IndexError, AttributeError, OSError, EOFError):
        return False


if __name__ == "__main__":
    # JSONL port used by the raw-chain differential tests; no subprocess per case.
    for line in sys.stdin.buffer:
        print(json.dumps(graph_case(json.loads(line))))
