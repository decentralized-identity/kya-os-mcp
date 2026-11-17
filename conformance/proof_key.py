"""Independent assertionMethod retrieval for the detached-proof JWK relationship vectors."""
from chain_binding import chain_binding


def _relative(identifier, did):
    if not isinstance(identifier, str):
        return None
    if identifier.startswith("#"):
        return identifier
    if identifier == did:
        return ""
    if identifier.startswith(did + "#"):
        return identifier[len(did):]
    return None


def assertion_key(document, did, name, named):
    """A uniquely defined method, owned by the signer and listed for assertions, or no key."""
    if not isinstance(document, dict) or document.get("id") != did or "#" in did:
        return None
    entries = document.get("assertionMethod")
    if not isinstance(entries, list):
        return None
    if not named:
        first = entries[0] if entries else None
        name = first.get("id") if isinstance(first, dict) else first
    elif not isinstance(name, str) or not name:
        return None
    elif not name.startswith(("did:", "#")):
        name = "#" + name
    target = _relative(name, did)
    if target is None:
        return None
    published = document.get("verificationMethod", [])
    published = published if isinstance(published, list) else []
    definitions = [entry for entry in published + entries if isinstance(entry, dict)
                   and _relative(entry.get("id"), did) == target]
    listed = any(_relative(entry.get("id") if isinstance(entry, dict) else entry, did) == target
                 for entry in entries)
    if not listed or len(definitions) != 1:
        return None
    method = definitions[0]
    if not all(isinstance(method.get(field), str) and method[field] for field in ("id", "type", "controller")):
        return None
    if method["controller"] != did:
        return None
    key = method.get("publicKeyJwk")
    if not isinstance(key, dict) or (key.get("kty"), key.get("crv")) != ("OKP", "Ed25519") or not key.get("x"):
        return None
    return {**key, "kid": key.get("kid") or method["id"]}


def verify_input(vector):
    """Retrieve first, then check the actual proof, its time and the content it binds."""
    proof = vector.get("proof")
    meta = proof.get("meta") if isinstance(proof, dict) else None
    did = meta.get("did") if isinstance(meta, dict) else None
    documents = vector.get("didDocuments")
    if not isinstance(did, str) or not isinstance(documents, dict):
        return False
    key = assertion_key(documents.get(did), did, vector.get("keyId"), "keyId" in vector)
    return key is not None and chain_binding({**vector, "publicKeyJwk": key}) in ("bound", "no-chain")
