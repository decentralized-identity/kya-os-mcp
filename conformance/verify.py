#!/usr/bin/env python3
"""KYA-OS Entity Card proof — INDEPENDENT cross-language conformance verifier.

The second-language complement to the TypeScript `ConformanceAdapter` contract: a pure-Python-stdlib
re-implementation of the `org.kya-os/proof.v1` verification path that shares NO code with the reference
adapter. It reads the SAME framework vector file the runner does (`conformance/vectors/card-proof.json`),
selects the positive (`expected == "pass"`) vector, and against that self-contained artifact it re-derives
the RFC 8785 (JCS) canonicalization, recomputes the SHA-256 `requestHash`, and verifies BOTH the detached
EdDSA JWS and the RFC 9421 HTTP Message Signature sibling against the vector's embedded DID-keyed JWKS. A
green run proves cross-language canonicalization + Ed25519 signature parity — the JCS cross-language
guarantee the polyglot toolchain rests on.

The same run also verifies the positive audit-integrity vector using an
independent RFC 9162 Merkle implementation (leaf/node domain separation,
inclusion proof, and consistency proof), and the delegation chain binding of
SPEC.md 7.8 over the `signed-proof/delegation-*` vectors: it holds each
response proof as the TypeScript reference holds it (its form, its signer,
its time, its JWS read segment by segment and verified over the payload
rebuilt from its claims, then the request and the response it binds),
recomputes every credential digest and the chain digest from the signed
forms, derives the reference of the chain's last credential, and holds all of
it against the claims the proof signs. Every signed-proof vector must have the
verdict it expects, and the proof path is held to the cases of proof_cases.py,
which the TypeScript reference is held to as well, and their signer to the key
and signature RFC 8032 gives for its key. A copy of the chain that differs
in nothing signed must match, and so must a refusal held against the chain it
refused by a verifier that asks for a refusal. A chain with a re-issued hop, a
proof whose claim was stripped, a proof that binds no chain, a refusal held as
though the call was allowed, a chain whose VC-JWT has no signed form, and a
proof that names another credential than the one presented must each fail for
that reason and no other. A credential nested as deep as 7.8 allows must be
bound and one nested a level deeper must have no signed form, and a VC-JWT
whose payload is nested a level deeper than that must show no id. The values
7.8 gives no signed form must be refused a digest, and the ids 7.8 refers to
by digest must be, in tables the TypeScript tests
(`src/delegation/__tests__/chain-digest.test.ts` and `delegation-ref.test.ts`)
hold their reading to as well.
Every status-list vector is independently checked by status_list.py: authority,
both Ed25519 proofs, bounded gzip decoding and the strict indexed bit read.

Zero external dependencies: SHA-256 via `hashlib`, JCS via an exact RFC 8785 serializer
(ECMAScript number formatting and UTF-16 code-unit object-key ordering, covering the full admitted
value space including fractional numbers and non-BMP keys), and Ed25519 verification via the
RFC 8032 reference implementation. No pip install required.

This script is the driver: it reads the vector files, makes each check, and reports it under its
name. What it checks with is in the modules beside it, one job to each:

    ed25519.py           Ed25519 signatures, the RFC 8032 reference implementation
    strict_json.py       JSON written as RFC 8785 has it, and read as JSON.parse reads it
    base64url.py         base64url and base64, as the proofs and credentials carry them
    digests.py           the `sha256:` digest form, and the domain-separated digest
    card_proof.py        what the `org.kya-os/proof.v1` signatures cover
    audit_merkle.py      the RFC 9162 Merkle root, and its inclusion and consistency proofs
    signed_form.py       a credential's signed form, and the credential and chain digests (7.8)
    delegation_ref.py    the id a credential shows, and the reference it goes by (7.8)
    response_proof.py    a response proof, and the request and response it binds (7.3, 7.4)
    chain_binding.py     how a response proof stands against what its verifier holds (7.8)
    delegation_cases.py  the cases the readings of 7.8 are held to beyond the vectors
    proof_cases.py       the cases a response proof is held to beyond the vectors
    status_list.py       a status list's authority, its proofs and the bit an entry indexes

    run:  python3 conformance/verify.py   (npm run conformance:verify:crosslang)
    exit: 0 on full parity, 1 on any mismatch.
"""

import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent

# The modules beside this script are imported from its directory, which is put on the path even
# where Python leaves it off (-I, -P), and a run leaves no bytecode cache there.
sys.path.insert(0, str(HERE))
sys.dont_write_bytecode = True

from audit_merkle import audit_root, audit_verify_consistency, audit_verify_inclusion
from base64url import b64url_nopad, padded_base64url_bytes
from card_proof import (card_proof_request_hash, covered_claims, http_signature_base, resolve_key,
                        rfc7638_thumbprint)
from chain_binding import chain_binding
from delegation_cases import id_and_reference_cases_hold, signed_form_cases_hold
from digests import domain_digest
from ed25519 import ed25519_verify
from proof_cases import forgeries_hold, proof_cases_hold, signer_holds
from response_proof import jws_segment_json, proof_of_its_form
from status_list import verify_input as verify_status_input
from strict_json import jcs, read_json


def read_vector_file(path: Path) -> dict:
    """A vector file, read as `read_json` reads: as JSON and nothing looser."""
    return read_json(path.read_text(encoding="utf-8"))


def positive_vector(vector_file: dict) -> dict:
    """The card-proof.json vector a conformant verifier MUST ACCEPT — the golden proof."""
    for vector in vector_file["vectors"]:
        if vector.get("expected") == "pass":
            return vector["input"]
    raise SystemExit("FAIL: card-proof.json has no positive (expected: pass) vector")


def vector_by_id(vector_file: dict, vector_id: str) -> dict:
    for vector in vector_file["vectors"]:
        if vector.get("id") == vector_id:
            return vector["input"]
    raise SystemExit(f"FAIL: no vector {vector_id!r}")


def main() -> int:
    vector_file = read_vector_file(HERE / "vectors" / "card-proof.json")
    vector = positive_vector(vector_file)
    proof = vector["proof"]
    jwks = vector["jwks"]  # the DID-keyed JWKS is embedded in the self-contained vector

    key = resolve_key(jwks, proof["kid"])
    pub = padded_base64url_bytes(key["x"])

    results = []

    # 1. Re-derive requestHash from JCS({method, params}) + SHA-256.
    recomputed = card_proof_request_hash(vector["request"])
    results.append(("requestHash JCS+SHA-256 recompute", recomputed == proof["requestHash"]))

    # 2. Verify the detached EdDSA JWS over JCS(coveredClaims).
    parts = proof["jws"].split(".")
    jws_ok = len(parts) == 3 and parts[1] == ""
    if jws_ok:
        signing_input = (parts[0] + "." + b64url_nopad(jcs(covered_claims(proof)))).encode("ascii")
        jws_ok = ed25519_verify(pub, signing_input, padded_base64url_bytes(parts[2]))
    results.append(("detached EdDSA JWS over JCS(coveredClaims)", jws_ok))

    # 3. Verify the RFC 9421 HTTP Message Signature sibling (raw Ed25519 over the signature base).
    http_ok = ed25519_verify(pub, http_signature_base(proof).encode("utf-8"),
                             padded_base64url_bytes(proof["httpSig"]))
    results.append(("RFC 9421 httpSig over the signature base", http_ok))

    # 4. Re-derive the RFC 7638 cnf.jkt thumbprint of the resolved key.
    results.append(("RFC 7638 cnf.jkt thumbprint fusion",
                    rfc7638_thumbprint(key) == proof.get("cnf", {}).get("jkt")))

    audit_file = read_vector_file(HERE / "vectors" / "audit-integrity.json")
    audit = positive_vector(audit_file)
    audit_leaves = audit["leaves"]
    inclusion = audit["inclusion"]
    consistency = audit["consistency"]
    event_canonical = jcs(audit["event"])
    event_digest = domain_digest(b"org.kya-os.audit.event.v1\x00", audit["event"])
    results.append(("audit event JCS canonical bytes",
                    event_canonical.decode("utf-8") == audit["eventCanonical"]))
    canonicalization = audit.get("canonicalization")
    if canonicalization is not None:
        results.append(("full JCS value space (fractions, exponents, non-BMP keys)",
                        jcs(canonicalization["value"]).decode("utf-8") ==
                        canonicalization["canonical"]))
    results.append(("domain-separated audit event digest",
                    event_digest == audit["eventDigest"]))
    results.append(("RFC 9162 audit Merkle root",
                    audit_root(audit_leaves) == audit["root"]))
    results.append(("RFC 9162 audit inclusion proof",
                    audit_verify_inclusion(
                        audit_leaves[inclusion["leafIndex"]],
                        inclusion["leafIndex"], len(audit_leaves),
                        audit["root"], inclusion["auditPath"])))
    results.append(("RFC 9162 audit consistency proof",
                    audit_verify_consistency(
                        consistency["oldSize"], len(audit_leaves),
                        consistency["oldRoot"], audit["root"],
                        consistency["auditPath"])))

    # Every status-list vector, positive AND negative, has an independently
    # derived verdict: authority, credential/list signatures, gzip and bit read.
    for path in sorted((HERE / "vectors").glob("*.json")):
        vector_set = read_vector_file(path)
        if vector_set.get("category") == "status-list":
            for item in vector_set["vectors"]:
                accepted = verify_status_input(item["input"], jcs, ed25519_verify)
                results.append((item["id"], accepted == (item["expected"] == "pass")))

    proof_file = read_vector_file(HERE / "vectors" / "signed-proof.json")

    def delegation_vector(name: str) -> dict:
        return vector_by_id(proof_file, "signed-proof/delegation-" + name)

    def binding(name: str) -> str:
        return chain_binding(delegation_vector(name))

    results.append(("delegation chain digest signed by an allowed call's proof",
                    binding("chain-binding") == "bound"))
    results.append(("same digest for a copy of the chain that differs in nothing signed",
                    binding("chain-reserialized") == "bound"))
    results.append(("delegation chain digest signed by a refusal's proof, held as a refusal",
                    binding("chain-refused") == "bound"))
    results.append(("refusal's proof held against its chain with no outcome stated is no acceptance",
                    binding("chain-refused-outcome-unstated") == "outcome"))
    results.append(("re-issued hop under the same id changes the chain digest",
                    binding("chain-substituted") == "mismatch"))
    results.append(("chain digest stripped from meta no longer matches the signed payload",
                    binding("chain-digest-stripped") == "invalid"))
    results.append(("proof that only names a credential binds no chain",
                    binding("chain-unbound") == "unbound"))
    results.append(("chain whose VC-JWT signature is not base64url has no digest to bind",
                    binding("chain-no-signed-form") == "no-signed-form"))
    results.append(("proof that binds a chain and names another of its credentials",
                    binding("ref-substituted") == "misnamed"))
    results.append(("credential id too long to record is named by its SHA-256",
                    binding("ref-digest-form") == "bound"))
    results.append(("credential nested 64 levels deep, as deep as one may be, is bound",
                    binding("chain-nested-at-bound") == "bound"))
    results.append(("credential nested 65 levels deep has no signed form, so no digest to bind",
                    binding("chain-nested-past-bound") == "no-signed-form"))
    results.append(("VC-JWT whose payload nests 64 levels deep is named by the id it shows",
                    binding("ref-jwt-nested-at-bound") == "bound"))
    results.append(("VC-JWT whose payload nests 65 levels deep shows no id, and is still digested",
                    binding("ref-jwt-nested-past-bound") == "bound"))
    results.append(("VC-JWT whose payload holds an integer of 4301 digits is read, and named by its id",
                    binding("ref-jwt-long-number") == "bound"))
    results.append(("VC-JWT whose payload holds the credential id twice is named by the last",
                    binding("ref-jwt-duplicate-id") == "bound"))
    results.append(("credential holding 9007199254740993.5, an integer above 2^53 - 1 once read, has no signed form",
                    binding("chain-number-read-as-binary64") == "no-signed-form"))
    results.append(("credential id U+001F, the last C0 control character, is named by its SHA-256",
                    binding("ref-control-at-bound") == "bound"))
    results.append(("credential id U+0020, the first character past the C0 controls, is named as it is",
                    binding("ref-control-past-bound") == "bound"))
    results.append(("credential id that reads as a digest and has one more character is named as it is",
                    binding("ref-digest-form-suffixed") == "bound"))
    results.append(("credential id holding a bidi override or a zero-width space is named by its SHA-256",
                    all(binding(name) == "bound" for name in ("ref-bidi-override", "ref-zero-width"))))
    results.append(("credential id holding a code point that renders as nothing by default is named by its SHA-256",
                    all(binding(name) == "bound" for name in (
                        "ref-grapheme-joiner", "ref-hangul-filler", "ref-variation-selector",
                        "ref-variation-selector-supplement"))))
    results.append(("credential id that is the word unknown is named by its SHA-256",
                    binding("ref-unknown") == "bound"))
    results.append(("credential object whose issuer signed a __proto__ member is digested with it",
                    binding("chain-proto-member") == "bound"))

    # The proof as received: each segment of its JWS read as RFC 7515 section 2 writes base64url,
    # every claim of its meta held to the payload its signature covers, and the request it binds
    # held to the one the verifier sent.
    results.append(("JWS segment with characters outside base64url, or in the base64 alphabet, is none",
                    all(binding(name) == "invalid" for name in (
                        "proof-signature-stray-character", "proof-signature-stray-characters",
                        "proof-signature-base64", "proof-header-non-ascii"))))
    results.append(("JWS segment holding white space, or padded, is none",
                    all(binding(name) == "invalid" for name in (
                        "proof-signature-white-space", "proof-signature-padded"))))
    results.append(("JWS of four segments is no JWS",
                    binding("proof-fourth-segment") == "invalid"))
    results.append(("claim of meta altered after signing breaks the signature, whichever claim it is",
                    all(binding(name) == "invalid" for name in (
                        "proof-request-hash-altered", "proof-nonce-altered", "proof-session-altered"))))
    results.append(("proof held against another request than the one it binds",
                    binding("proof-request-substituted") == "request"))
    results.append(("JWS header that names another algorithm than EdDSA makes no proof",
                    binding("proof-header-algorithm") == "invalid"))
    results.append(("JWS header that names another key than meta.kid makes no proof",
                    binding("proof-header-key") == "invalid"))
    results.append(("kid that names a key of another DID than meta.did makes no proof",
                    binding("proof-signer-of-another-did") == "invalid"))
    results.append(("request with no params is bound by its method alone",
                    binding("proof-request-without-params") == "bound"))
    # A vector passes exactly when the proof is bound to the chain held, or no chain is held.
    results.append(("every signed-proof vector has the verdict it expects",
                    all((chain_binding(vector["input"]) in ("bound", "no-chain")) == (vector["expected"] == "pass")
                        for vector in proof_file["vectors"])))

    # A verifier that ran out of stack says so, and gives no verdict. Nothing a credential
    # holds can bring that about, since it is counted first, so it is brought about here.
    class OutOfStack(dict):
        def get(self, key, default=None):
            raise RecursionError

    results.append(("verifier that ran out of stack reports a fault, which is no verdict",
                    chain_binding(OutOfStack()) == "fault"))

    def restated(name: str, part: str, **members) -> str:
        """The verdict on a vector whose proof `meta`, or whose `expected`, states `members`."""
        vector = read_json(json.dumps(delegation_vector(name)))
        (vector["proof"]["meta"] if part == "meta" else vector["expected"]).update(members)
        return chain_binding(vector)

    # A claim `meta` gives as an empty string is one the signature does not cover, so it says
    # what leaving it out says. An outcome asked for as an empty string is asked for all the
    # same, and no proof states it.
    results.append(("empty delegationRef in meta names no credential, as leaving it out does",
                    restated("ref-jwt-nested-past-bound", "meta", delegationRef="") == "bound"))
    results.append(("outcome asked for as an empty string is asked for, and no proof states it",
                    restated("chain-binding", "expected", outcome="") == "outcome"))
    # A chain or an outcome the verifier gives as null is none: the chain is compared with
    # nothing, and no outcome is asked for. A claim `meta` gives as null, or out of its form,
    # makes no proof, as a proof that does not match its schema is none.
    results.append(("chain given as null is no chain, and asks no outcome of the proof",
                    restated("chain-binding", "expected", delegationChain=None) == "no-chain"
                    and restated("chain-refused", "expected", delegationChain=None) == "no-chain"
                    and restated("chain-refused", "expected", delegationChain=None,
                                 outcome=None) == "no-chain"
                    and restated("chain-refused", "expected", outcome=None) == "outcome"))
    # Each claim is one the signed payload of that vector leaves out, so it is its form alone
    # that makes no proof of it.
    results.append(("claim in meta given as null, or out of its form, makes no proof",
                    all(restated(name, "meta", **{claim: value}) == "invalid"
                        for name, claim, value in (
                            ("chain-unbound", "delegationChainDigest", None),
                            ("chain-unbound", "delegationChainDigest", ""),
                            ("ref-jwt-nested-past-bound", "delegationRef", None),
                            ("chain-unbound", "outcome", None),
                            ("chain-unbound", "outcome", "")))))
    # The forms are those schemas/detached-proof.json gives: a digest of exactly 64 lowercase
    # hex digits after `sha256:`, a reference that is a string, the empty one included, and
    # an outcome the schema lists. No vector signs a claim out of its form, so they are held
    # to it here, and signed in the cases of proof_cases.py.
    digest_of_form = "sha256:" + "0" * 64
    bound_proof = delegation_vector("chain-binding")["proof"]

    def of_its_form(**members) -> bool:
        return proof_of_its_form({**bound_proof, "meta": {**bound_proof["meta"], **members}})

    results.append(("claims in meta are held to the forms the proof schema gives them",
                    all(of_its_form(**members) for members in (
                        {},
                        {"delegationChainDigest": digest_of_form, "delegationRef": ""},
                        *({"outcome": outcome} for outcome in
                          ("allowed", "denied", "step_up_required", "needs_authorization"))))
                    and not any(of_its_form(**members) for members in (
                        {"delegationChainDigest": digest_of_form + "0"},
                        {"delegationChainDigest": "sha256:" + "0" * 63 + "A"},
                        {"delegationRef": 7},
                        {"outcome": "Allowed"}))))
    results.append(("signer of the proof cases gives the keys and signatures RFC 8032 gives",
                    signer_holds()))
    results.append(("forgeries of the proof cases satisfy the verification equation under their keys",
                    forgeries_hold(delegation_vector("chain-binding"))))
    results.append(("response proofs are held to what the TypeScript reference holds them to",
                    proof_cases_hold(delegation_vector("chain-binding"),
                                     delegation_vector("proof-request-without-params"))))

    # JSON is read as JSON and nothing looser wherever it is read: in a vector file, in a
    # segment of a proof's JWS, here a payload that holds NaN, and in a VC-JWT payload (among
    # the ids further down).
    def not_json(read) -> bool:
        try:
            read()
        except ValueError as error:
            return str(error).endswith("is not JSON")
        return False

    with tempfile.TemporaryDirectory() as scratch:
        loose = Path(scratch) / "vectors.json"
        loose.write_text('{"vectors": [], "weight": NaN}', encoding="utf-8")
        loose_file_refused = not_json(lambda: read_vector_file(loose))
    results.append(("NaN and Infinity are not JSON, in a vector file or in what a proof signs",
                    all(not_json(lambda text=text: read_json(text))
                        for text in ('{"n":NaN}', '{"n":Infinity}', '{"n":-Infinity}'))
                    and read_json('{"n":1e2}') == {"n": 100.0}
                    and loose_file_refused
                    and not_json(lambda: jws_segment_json("eyJvdXRjb21lIjpOYU59"))))

    # Of the members of one object that share a name the last is read (7.8), as JSON.parse
    # reads it, at any depth: in a VC-JWT payload (among the ids further down) and in a
    # credential object (among the digests).
    results.append(("of members that share a name the last is read, as JSON.parse reads it",
                    read_json('{"a":1,"b":{"c":2,"c":3},"a":[4]}') == {"a": [4], "b": {"c": 3}}))

    # The tables of delegation_cases.py, which the TypeScript tests hold their reading to as well.
    results.append(("values that have no signed form are refused a digest",
                    signed_form_cases_hold()))
    results.append(("credential ids are read, and referred to, as 7.8 has them",
                    id_and_reference_cases_hold()))

    print(f"KYA-OS cross-language verifier (Python {sys.version.split()[0]}, stdlib-only)")
    print(f"  proof: {proof['prf']}  did: {proof['did']}")
    for label, ok in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    ok = all(ok for _, ok in results)
    print(f"RESULT: {'PASS - cross-language JCS + Ed25519 parity confirmed' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
