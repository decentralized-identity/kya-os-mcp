"""Independent reading of SPEC §6.6, restricted to the status-list vector profile.

No TypeScript imports, generated verdict tables, or expected outcomes. This is
test tooling, not a general-purpose VC verifier: the vector profile uses
Ed25519Signature2020 over JCS(document minus proof), one-bit gzip lists, and
already-authorized per-credential root context. Chain admission is tested
separately; an input's trustedRootIssuer is NOT a proof of a chain.
"""

import gzip
import io
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

if __name__ == "__main__":
    # Run as a script, as the JSONL port below is, Python may leave this directory off the import
    # path (-I, -P); put it on, as verify.py does, so the module beside this one is found.
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from base64url import padded_base64url_bytes, signature_bytes, strict_base64url_bytes


def issuer(value):
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and isinstance(value.get("id"), str):
        return value["id"]
    return None


ORIGIN = re.compile(r"https://[a-z0-9.-]+(:[0-9]{1,5})?")
# An origin with a host in any case, and perhaps a "/" after it, which group 1 holds. Matched with
# fullmatch, never with $, which also matches before a final line feed.
ORIGIN_IN_ANY_FORM = re.compile(r"https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?(/?)")


def keeper(url, owner, root, root_list, services):
    """The one issuer whose list is read at url, and whether no binding names it.

    Unbound, it is the credential's issuer or the pinned root; a caller that lets a list
    leave out its id holds the root to being that same issuer.

    First match: the issuer the configuration binds the exact URL to; the issuer it binds
    the URL's https origin to, matched on the bytes as written; the pinned root, when its
    own credential names the URL; the credential's own issuer.
    """
    for did, bindings in services.items():
        if url in bindings:
            return did, False
    for did, bindings in services.items():
        for binding in bindings:
            if ORIGIN.fullmatch(binding) and any(url.startswith(binding + mark) for mark in "/?#"):
                return did, False
    if root is not None and root_list == url:
        return root, True
    return owner, True


def accepts(document, owner, root, services, url, purpose="revocation", root_list=None):
    """A list is read only from the keeper of its URL, never from whoever else is trusted."""
    if not isinstance(document, dict) or not isinstance(owner, str) or not owner:
        return False
    signer = issuer(document.get("issuer"))
    if not signer:
        return False
    kept_by, unbound = keeper(url, owner, root, root_list, services)
    if signer != kept_by:
        return False
    # Only the id binds a list to its URL. The owner's list may leave it out only where
    # nobody else keeps any URL: no other root is pinned and no other issuer is configured.
    if "id" in document:
        if not isinstance(document["id"], str) or document["id"] != url:
            return False
    elif not unbound or root not in (None, owner) or any(did != owner for did in services):
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


def mistaken_binding(binding):
    """The words a binding SPEC §6.6 says a verifier should refuse is refused in, or None.

    An origin followed by "/", an origin whose host has an upper-case letter A to Z, and any
    other binding that ends in "/". Read as written, each is an exact URL, but it is almost
    always an origin or a prefix written in a form §6.6 does not read as one. The rule is on the
    string as written, with no URL parsing, as the TypeScript loader applies it.
    """
    written = ORIGIN_IN_ANY_FORM.fullmatch(binding)
    if written and written.group(1) == "/":
        return 'statusListIssuers binds an origin followed by "/"'
    if written and re.search(r"[A-Z]", binding):
        return "statusListIssuers binds an origin whose host is not in lower case"
    if binding.endswith("/"):
        return 'statusListIssuers binds a URL that ends in "/"'
    return None


def configuration(value):
    """The verifier configuration an input states, as the TypeScript loader holds it.

    A trustedRootIssuer and a trustedRootStatusList, when present, are non-empty strings,
    and a statusListIssuers, when present, maps each issuer, a non-empty key, to a list of
    URLs, each a string that starts with https:// or http://, none of them one
    mistaken_binding refuses, and none under two issuers, checked binding by binding in that
    order, so each refusal is in the loader's words. Anything else raises ValueError. The
    root's URL counts only beside the root.
    """
    for member in ("trustedRootIssuer", "trustedRootStatusList"):
        if member in value and not (isinstance(value[member], str) and value[member]):
            raise ValueError(member + " is not a non-empty string")
    root = value.get("trustedRootIssuer")
    services = value.get("statusListIssuers", {})
    if not isinstance(services, dict):
        raise ValueError("statusListIssuers does not map issuers to lists of URLs")
    bound = {}
    for did, bindings in services.items():
        if not did or not isinstance(bindings, list):
            raise ValueError("statusListIssuers does not map issuers to lists of URLs")
        for binding in bindings:
            if not (isinstance(binding, str) and re.match(r"https?://", binding)):
                raise ValueError("statusListIssuers does not map issuers to lists of URLs")
            mistaken = mistaken_binding(binding)
            if mistaken:
                raise ValueError(mistaken)
            if bound.setdefault(binding, did) != did:
                raise ValueError("statusListIssuers binds one URL to two issuers")
    return root, value.get("trustedRootStatusList"), services


def graph_case(case):
    """Project actual chain issuers + a pin, before applying the list rule.

    Continuity, hop signatures and policy admission are caller obligations.
    A pin unequal to the actual root cannot grant authority at any hop.
    """
    chain = case["chain"]
    owner = issuer(chain[case["hop"]]["issuer"])
    root = issuer(chain[0]["issuer"])
    pinned = root if case.get("pin") == root else None
    return accepts(case["list"], owner, pinned, case.get("services", {}), case["url"],
                   root_list=case.get("rootList") if pinned is not None else None)


# An RFC 3339 date-time with its time zone (SPEC 6.6): a time with no zone names no single instant.
# T and Z may be small letters, as RFC 3339 allows; fromisoformat refuses a day no calendar has.
DATE_TIME = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt]([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]+)?"
    r"([Zz]|[+-]([01][0-9]|2[0-3]):[0-5][0-9])"
)


def window_bound(document, current, legacy):
    """The time a list's bound states, by its VC 2.0 member, or its VC 1.1 one when that is absent.

    None when the list states neither. A bound that is stated but is not a date raises ValueError:
    the list's window is then unknown, and it is not read.
    """
    member = current if current in document else legacy if legacy in document else None
    if member is None:
        return None
    stated = document[member]
    if not isinstance(stated, str) or not DATE_TIME.fullmatch(stated):
        raise ValueError(member + " is not a date")
    return datetime.fromisoformat(stated.upper().replace("Z", "+00:00"))


def within_window(document, now):
    """A list is read only inside the validity window it states (SPEC 6.6), its bounds included.

    Each bound is held exactly. SPEC 6.6 permits a clock tolerance of up to 600 seconds, which no
    vector needs: each bound a vector states is months or more from when it is run.
    """
    until = window_bound(document, "validUntil", "expirationDate")
    start = window_bound(document, "validFrom", "issuanceDate")
    return (until is None or now <= until) and (start is None or start <= now)


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
    # The key's x as SPEC.md 7.4 reads it, and the proofValue as 7.8 reads it, as the reference's
    # embedded-signature verifier reads both.
    return verify_signature(strict_base64url_bytes(key["x"]), canonicalize(unsigned),
                            signature_bytes(proof["proofValue"]))


def verify_input(value, canonicalize, verify_signature):
    """Re-derive authority, both proofs, the list's window and the indexed bit, never expected labels."""
    try:
        credential = value["credential"]
        entry = credential["credentialStatus"]
        url = entry["statusListCredential"]
        document = value["statusLists"][url]
        purpose = entry["statusPurpose"]
        root, root_list, services = configuration(value)
        if not isinstance(purpose, str) or not accepts(
                document, issuer(credential["issuer"]), root, services, url, purpose, root_list):
            return False
        documents = value["didDocuments"]
        if not verify_document(credential, documents, canonicalize, verify_signature):
            return False
        if not verify_document(document, documents, canonicalize, verify_signature):
            return False
        if not within_window(document, datetime.now(timezone.utc)):
            return False
        # One bit is read per entry. An entry that states a statusSize other than 1, the size of
        # an entry that states none, keeps its status in other bits than the one at its index.
        size = entry.get("statusSize", 1)
        if isinstance(size, bool) or size != 1:
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
        compressed = padded_base64url_bytes(encoded[1:] if encoded.startswith("u") else encoded)
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
