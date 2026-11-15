/**
 * `delegationChainDigest` in a response proof (SPEC.md §7.8).
 *
 * A proof that names its delegation by `delegationRef` names a credential
 * id. The digest is what a verifier can hold a chain against: it is covered
 * by the signature, so it cannot be added, removed or altered after signing,
 * and a verifier that supplies a chain is told when it is not the one bound.
 */
import { createHash } from "node:crypto";
import { describe, it, expect } from "vitest";
import { ProofGenerator, buildProofJwsPayload } from "../generator.js";
import { PROOF_VERIFICATION_ERROR_CODES } from "../errors.js";
import { validateDetachedProof, type DetachedProof } from "../../types/protocol.js";
import { digestDelegationChain, type ReceivedCredential } from "../../delegation/chain-digest.js";
import { delegationRefOf } from "../../delegation/delegation-ref.js";
import { isCredentialDigestInput } from "../../__tests__/utils/digests.js";
import { nodeCrypto as cryptoProvider, nodeHash as hash } from "../../__tests__/utils/node-crypto-provider.js";
import type { Ed25519JWK } from "../../utils/crypto-service.js";
import {
  CHAIN,
  LEAF,
  MIDDLE,
  REQUEST,
  RESPONSE,
  ROOT,
  bound,
  boundTo,
  jwt,
  makeIdentity,
  makeSession,
  makeVerifier,
  payloadOf,
  signed,
} from "./helpers/chain-bound-proofs.js";

describe("delegationChainDigest is a signed claim", () => {
  it("is in the JWS payload and mirrored in meta", async () => {
    const { proof } = await bound();
    const { chain } = await digestDelegationChain(CHAIN, hash);
    expect(proof.meta.delegationChainDigest).toBe(chain);
    expect(payloadOf(proof)).toMatchObject({
      delegationRef: "urn:uuid:leaf",
      delegationChainDigest: chain,
    });
  });

  it("is left out of a proof that binds no chain, so that proof is byte-compatible with earlier verifiers", async () => {
    const { proof } = await signed({ delegationRef: "urn:uuid:leaf" });
    expect(proof.meta).not.toHaveProperty("delegationChainDigest");
    expect(payloadOf(proof)).not.toHaveProperty("delegationChainDigest");
    expect(buildProofJwsPayload(proof.meta)).not.toHaveProperty("delegationChainDigest");
  });

  it("verifies, with or without a chain to compare", async () => {
    const { proof, jwk } = await bound();
    expect((await makeVerifier().verifyProof(proof, jwk)).valid).toBe(true);
    const withContent = await makeVerifier().verifyProof(proof, jwk, { request: REQUEST, response: RESPONSE });
    expect(withContent.valid).toBe(true);
  });

  it("cannot be stripped after signing", async () => {
    const { proof, jwk } = await bound();
    const { delegationChainDigest: _stripped, ...meta } = proof.meta;
    const result = await makeVerifier().verifyProof({ ...proof, meta }, jwk);
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(PROOF_VERIFICATION_ERROR_CODES.INVALID_JWS_SIGNATURE);
  });

  it("cannot be added after signing", async () => {
    const { proof, jwk } = await signed({ delegationRef: "urn:uuid:leaf" });
    const { chain } = await digestDelegationChain(CHAIN, hash);
    const forged = { ...proof, meta: { ...proof.meta, delegationChainDigest: chain } };
    const result = await makeVerifier().verifyProof(forged, jwk);
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(PROOF_VERIFICATION_ERROR_CODES.INVALID_JWS_SIGNATURE);
  });

  it("cannot be swapped for another chain's after signing", async () => {
    const { proof, jwk } = await bound();
    const other = await digestDelegationChain([ROOT, LEAF], hash);
    const forged = { ...proof, meta: { ...proof.meta, delegationChainDigest: other.chain } };
    const result = await makeVerifier().verifyProof(forged, jwk);
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(PROOF_VERIFICATION_ERROR_CODES.INVALID_JWS_SIGNATURE);
  });

  it.each([
    ["not a digest", "urn:uuid:leaf"],
    ["uppercase hex", `sha256:${"A".repeat(64)}`],
    ["a short digest", `sha256:${"a".repeat(63)}`],
    ["a non-string", 7],
    ["empty", ""],
  ])("is rejected as malformed when it is %s", async (_name, value) => {
    const { proof, jwk } = await bound();
    const malformed = { ...proof, meta: { ...proof.meta, delegationChainDigest: value } } as DetachedProof;
    expect(validateDetachedProof(malformed)).toEqual({
      success: false,
      error: { message: "meta.delegationChainDigest must match sha256:<64 hex chars> when present" },
    });
    const result = await makeVerifier().verifyProof(malformed, jwk);
    expect(result.errorCode).toBe(PROOF_VERIFICATION_ERROR_CODES.INVALID_PROOF_STRUCTURE);
  });
});

describe("a verifier that holds the chain", () => {
  const expected = { request: REQUEST, response: RESPONSE };

  it("accepts the chain the proof binds", async () => {
    const { proof, jwk } = await bound();
    const result = await makeVerifier().verifyProof(proof, jwk, { ...expected, delegationChain: CHAIN });
    expect(result).toEqual({ valid: true });
  });

  it.each([
    ["a hop replaced by a credential with the same id", [ROOT, { ...MIDDLE, proof: { proofValue: "b3RoZXI" } }, LEAF]],
    ["a hop dropped", [ROOT, LEAF]],
    ["a hop added", [ROOT, MIDDLE, MIDDLE, LEAF]],
    ["the hops out of order", [MIDDLE, ROOT, LEAF]],
    ["another leaf with the same id", [ROOT, MIDDLE, jwt({ vc: { id: "urn:uuid:leaf" } }, "b3RoZXI")]],
  ])("rejects %s", async (_name, chain) => {
    const { proof, jwk } = await bound();
    const result = await makeVerifier().verifyProof(proof, jwk, { ...expected, delegationChain: chain });
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(PROOF_VERIFICATION_ERROR_CODES.DELEGATION_BINDING_MISMATCH);
    expect(result.details).toEqual({ binding: "delegation-chain" });
    expect(result.reason).toContain("not the one the server evaluated");
    expect(result.reason).toBe(
      "Delegation chain digest mismatch: the chain you supplied is not the one the server evaluated",
    );
  });

  it("rejects a proof that binds no chain: naming a credential id is not binding its bytes", async () => {
    const { proof, jwk } = await signed({ delegationRef: "urn:uuid:leaf" });
    const result = await makeVerifier().verifyProof(proof, jwk, { ...expected, delegationChain: CHAIN });
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(PROOF_VERIFICATION_ERROR_CODES.DELEGATION_BINDING_MISMATCH);
    expect(result.details).toEqual({ binding: "delegation-chain-unbound" });
    expect(result.reason).toBe("A delegation chain was supplied but the proof binds none (no delegationChainDigest)");
  });

  it("does not spend the proof's nonce on a chain mismatch", async () => {
    const { proof, jwk } = await bound();
    const verifier = makeVerifier();
    const wrong = await verifier.verifyProof(proof, jwk, { ...expected, delegationChain: [ROOT, LEAF] });
    expect(wrong.valid).toBe(false);
    const right = await verifier.verifyProof(proof, jwk, { ...expected, delegationChain: CHAIN });
    expect(right.valid).toBe(true);
  });

  it.each([
    ["an empty chain", []],
    // A chain that is not an array, as a caller that is not typed may supply,
    // is none: conformance/verify.py reads it so.
    ["a number for the chain", 42],
    ["an object for the chain", { 0: ROOT, length: 1 }],
    ["a string for the chain", "x"],
    ["a number for a credential", [ROOT, 42]],
    ["null for a credential", [null]],
    ["a credential with no signature", [ROOT, MIDDLE, { id: "urn:uuid:leaf" }]],
    ["a credential holding a number JSON cannot carry exactly", [{ ...ROOT, issued: 2 ** 53 }]],
  ])("rejects %s as a chain the proof does not bind: it has no digest", async (_name, chain) => {
    const { proof, jwk } = await bound();
    const result = await makeVerifier().verifyProof(proof, jwk, {
      ...expected,
      delegationChain: chain as never,
    });
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(PROOF_VERIFICATION_ERROR_CODES.DELEGATION_BINDING_MISMATCH);
    expect(result.details).toEqual({ binding: "delegation-chain" });
  });

  it("reports a hash provider that fails on the chain as a failure to verify, not as another chain", async () => {
    const { proof, jwk } = await bound();
    // The fault throws what a value with no signed form throws, a TypeError,
    // and is still nothing the chain did.
    const failing: typeof cryptoProvider = Object.assign(Object.create(cryptoProvider), {
      hash: async (bytes: Uint8Array) => {
        if (isCredentialDigestInput(bytes)) {
          throw new TypeError("hash service unavailable");
        }
        return cryptoProvider.hash(bytes);
      },
    });
    const verifier = makeVerifier(failing);

    const result = await verifier.verifyProof(proof, jwk, { ...expected, delegationChain: CHAIN });

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(PROOF_VERIFICATION_ERROR_CODES.VERIFICATION_ERROR);
    expect(result.details).toEqual({ errorMessage: "hash service unavailable" });
  });

  it("gives CONTENT_BINDING_MISMATCH for the request and the response, and says which", async () => {
    const { proof, jwk } = await bound();
    const verifier = makeVerifier();
    const otherRequest = await verifier.verifyProofArtifact(proof, jwk, {
      request: { method: "records.read", params: { recordId: "r-2" } },
      response: RESPONSE,
      delegationChain: CHAIN,
    });
    expect(otherRequest.errorCode).toBe(PROOF_VERIFICATION_ERROR_CODES.CONTENT_BINDING_MISMATCH);
    expect(otherRequest.details).toEqual({ binding: "request" });
    expect(otherRequest.reason).toBe("Request hash mismatch: the proof does not bind the request you supplied");
    const otherResponse = await verifier.verifyProofArtifact(proof, jwk, {
      request: REQUEST,
      response: { data: [{ type: "text", text: "withheld" }] },
      delegationChain: CHAIN,
    });
    expect(otherResponse.errorCode).toBe(PROOF_VERIFICATION_ERROR_CODES.CONTENT_BINDING_MISMATCH);
    expect(otherResponse.details).toEqual({ binding: "response" });
    expect(otherResponse.reason).toBe(
      "Response hash mismatch: received content differs from what the server signed (possible substitution / MITM)",
    );
    const noResponse = await verifier.verifyProofArtifact(proof, jwk, { request: REQUEST, delegationChain: CHAIN });
    expect(noResponse.errorCode).toBe(PROOF_VERIFICATION_ERROR_CODES.CONTENT_BINDING_MISMATCH);
    expect(noResponse.details).toEqual({ binding: "response-missing" });
    expect(noResponse.reason).toBe(
      "Proof binds a response (responseHash present) but no response was supplied to verify against: pass expected.response",
    );
    const unanswered = await bound({}, "nothing");
    const extraResponse = await verifier.verifyProofArtifact(unanswered.proof, unanswered.jwk, {
      request: REQUEST,
      response: RESPONSE,
      delegationChain: CHAIN,
    });
    expect(extraResponse.errorCode).toBe(PROOF_VERIFICATION_ERROR_CODES.CONTENT_BINDING_MISMATCH);
    expect(extraResponse.details).toEqual({ binding: "response-unexpected" });
    expect(extraResponse.reason).toBe("A response was supplied but the proof binds none: content/proof mismatch");
  });

  it("verifies a retained proof against its chain without replay state or a clock", async () => {
    const { proof, jwk } = await bound();
    const verifier = makeVerifier();
    const once = await verifier.verifyProofArtifact(proof, jwk, { ...expected, delegationChain: CHAIN });
    const twice = await verifier.verifyProofArtifact(proof, jwk, { ...expected, delegationChain: CHAIN });
    expect(once).toEqual({ valid: true });
    expect(twice).toEqual({ valid: true });
  });

  it("is checked by the generator's own verifyProof as part of the signed payload", async () => {
    const identity = await makeIdentity();
    const generator = new ProofGenerator(identity, cryptoProvider);
    const { chain } = await digestDelegationChain(CHAIN, hash);
    const proof = await generator.generateProof(REQUEST, RESPONSE, makeSession(), { delegationChainDigest: chain });
    expect(await generator.verifyProof(proof, REQUEST, RESPONSE)).toBe(true);
    const other = await digestDelegationChain([ROOT], hash);
    const forged = { ...proof, meta: { ...proof.meta, delegationChainDigest: other.chain } };
    expect(await generator.verifyProof(forged, REQUEST, RESPONSE)).toBe(false);
  });
});

// The digest pins the chain. `delegationRef` names its last credential, and a
// verifier that holds the chain can say what that name has to be.
describe("the credential a proof names, for a verifier that holds the chain", () => {
  const expected = { request: REQUEST, response: RESPONSE };
  const verify = (proof: DetachedProof, jwk: Ed25519JWK, chain: readonly ReceivedCredential[]) =>
    makeVerifier().verifyProofArtifact(proof, jwk, { ...expected, delegationChain: chain });
  const misnamed = {
    valid: false,
    errorCode: PROOF_VERIFICATION_ERROR_CODES.DELEGATION_BINDING_MISMATCH,
    details: { binding: "delegation-ref" },
    reason:
      "Delegation reference mismatch: the proof's delegationRef is not the reference of the last credential of the chain you supplied",
  };

  it.each([
    ["another credential", "urn:uuid:other"],
    ["an ancestor of the chain", "urn:uuid:root"],
    ["the leaf's id in another case", "URN:UUID:LEAF"],
  ])("rejects a proof that binds the chain and names %s", async (_name, delegationRef) => {
    const { proof, jwk } = await boundTo(CHAIN, { delegationRef });
    expect(await verify(proof, jwk, CHAIN)).toEqual(misnamed);
  });

  it("rejects a proof that binds the chain and names no credential, when its last credential shows an id", async () => {
    const { proof, jwk } = await boundTo(CHAIN);
    expect(proof.meta).not.toHaveProperty("delegationRef");
    expect(await verify(proof, jwk, CHAIN)).toEqual(misnamed);
  });

  it.each([
    ["a VC-JWT with no id", jwt({ vc: {} })],
    ["a VC-JWT whose id is empty", jwt({ vc: { id: "" }, jti: "" })],
    ["a credential object with no id", { issuer: "did:web:sub.example", proof: { proofValue: "bGVhZg" } }],
  ])("requires a proof to name none when the last credential is %s", async (_name, leaf) => {
    const chain = [ROOT, MIDDLE, leaf];
    const unnamed = await boundTo(chain);
    expect(await verify(unnamed.proof, unnamed.jwk, chain)).toEqual({ valid: true });
    const named = await boundTo(chain, { delegationRef: "urn:uuid:leaf" });
    expect(await verify(named.proof, named.jwk, chain)).toEqual(misnamed);
  });

  it("takes an empty delegationRef for none: the signature does not cover one", async () => {
    const chain = [ROOT, jwt({ vc: {} })];
    const { proof, jwk } = await boundTo(chain);
    const relayed = { ...proof, meta: { ...proof.meta, delegationRef: "" } };
    expect(await verify(relayed, jwk, chain)).toEqual({ valid: true });
  });

  it.each([
    ["longer than 256 UTF-16 code units", "urn:uuid:".padEnd(257, "a")],
    ["holding a control character", "urn:uuid:leaf\nforged: line"],
    ["holding a right-to-left override", "urn:uuid:\u202efael"],
    ["already written as a digest", `sha256:${"ab".repeat(32)}`],
    ["that is the word an audit record names a credential with no id by", "unknown"],
  ])("requires the digest of an id %s, and not the id", async (_name, id) => {
    const chain = [ROOT, { id, proof: { proofValue: "bGVhZg" } }];
    const reference = await delegationRefOf(chain[1], hash);
    expect(reference).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(reference).not.toBe(id);
    const byDigest = await boundTo(chain, { delegationRef: reference! });
    expect(await verify(byDigest.proof, byDigest.jwk, chain)).toEqual({ valid: true });
    const verbatim = await boundTo(chain, { delegationRef: id });
    expect(await verify(verbatim.proof, verbatim.jwk, chain)).toEqual(misnamed);
  });

  it("requires the digest of an id that is not well-formed Unicode, taken over its WTF-8 bytes", async () => {
    // JSON can spell half of a surrogate pair; it is hashed as the three
    // bytes of its code point, U+D800 as ED A0 80.
    const leaf = jwt({ vc: { id: "urn:\ud800" } });
    const chain = [ROOT, leaf];
    const reference = `sha256:${createHash("sha256").update(Buffer.from([...Buffer.from("urn:"), 0xed, 0xa0, 0x80])).digest("hex")}`;
    expect(await delegationRefOf(leaf, hash)).toBe(reference);
    const byDigest = await boundTo(chain, { delegationRef: reference });
    expect(await verify(byDigest.proof, byDigest.jwk, chain)).toEqual({ valid: true });
    const unnamed = await boundTo(chain);
    expect(await verify(unnamed.proof, unnamed.jwk, chain)).toEqual(misnamed);
  });

  it("is compared after the chain: a proof of another chain is reported as that", async () => {
    const { proof, jwk } = await boundTo(CHAIN, { delegationRef: "urn:uuid:other" });
    const result = await verify(proof, jwk, [ROOT, LEAF]);
    expect(result.details).toEqual({ binding: "delegation-chain" });
  });

  it("is compared with nothing when no chain is supplied", async () => {
    const { proof, jwk } = await boundTo(CHAIN, { delegationRef: "urn:uuid:other" });
    expect(await makeVerifier().verifyProofArtifact(proof, jwk, expected)).toEqual({ valid: true });
  });
});
