/**
 * The outcome a response proof records (SPEC.md §7.8).
 *
 * A refusal binds the chain it refused, so a chain that matches is no
 * evidence that the call was allowed: the outcome is. A verifier that holds a
 * chain, or asks for an outcome, is told when the proof records another.
 */
import { describe, it, expect } from "vitest";
import type { ProofBindingMismatch } from "../binding.js";
import { PROOF_VERIFICATION_ERROR_CODES } from "../errors.js";
import type { ReceivedCredential } from "../../delegation/chain-digest.js";
import {
  CHAIN,
  LEAF,
  REQUEST,
  RESPONSE,
  ROOT,
  bound,
  makeVerifier,
  signed,
} from "./helpers/chain-bound-proofs.js";

// A refusal is signed like any other proof, and binds the chain that was
// presented with the call it refused. Matching that chain is therefore no
// evidence that the server accepted it: the outcome is.
describe("a refusal that binds the chain it refused", () => {
  const REFUSAL = { outcome: "denied", reason: "Delegation leaf widens scopes beyond parent middle" } as const;
  const refused = () => bound(REFUSAL, "nothing");

  it("does not pass for a call that was allowed: a chain supplied with no outcome requires one", async () => {
    const { proof, jwk } = await refused();
    expect(proof.meta.responseHash).toBeUndefined();
    const result = await makeVerifier().verifyProof(proof, jwk, { request: REQUEST, delegationChain: CHAIN });
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(PROOF_VERIFICATION_ERROR_CODES.OUTCOME_MISMATCH);
    expect(result.details).toEqual({ binding: "outcome", outcome: "denied" });
    expect(result.reason).toContain("what was presented, not what the server accepted");
    expect(result.reason).toBe(
      "Outcome mismatch: the proof does not state the outcome required of it. What a refusal names of a " +
        "delegation is what was presented, not what the server accepted",
    );
    // The details are a ProofBindingMismatch, whose `outcome` is the proof's.
    const mismatch = result.details as ProofBindingMismatch;
    expect(mismatch.binding === "outcome" && mismatch.outcome).toBe("denied");
  });

  it("verifies for the caller that says it holds a refusal, and still against that chain alone", async () => {
    const { proof, jwk } = await refused();
    const verifier = makeVerifier();
    const held = await verifier.verifyProofArtifact(proof, jwk, {
      request: REQUEST,
      delegationChain: CHAIN,
      outcome: "denied",
    });
    expect(held).toEqual({ valid: true });
    const other = await verifier.verifyProofArtifact(proof, jwk, {
      request: REQUEST,
      delegationChain: [ROOT, LEAF],
      outcome: "denied",
    });
    expect(other.errorCode).toBe(PROOF_VERIFICATION_ERROR_CODES.DELEGATION_BINDING_MISMATCH);
    expect(other.details).toEqual({ binding: "delegation-chain" });
  });

  it.each(["denied", "step_up_required", "needs_authorization"] as const)(
    "reports the outcome the proof states: %s",
    async (outcome) => {
      const { proof, jwk } = await bound({ outcome }, "nothing");
      const verifier = makeVerifier();
      const result = await verifier.verifyProofArtifact(proof, jwk, { request: REQUEST, delegationChain: CHAIN });
      expect(result.errorCode).toBe(PROOF_VERIFICATION_ERROR_CODES.OUTCOME_MISMATCH);
      expect(result.details).toEqual({ binding: "outcome", outcome });
      const stated = await verifier.verifyProofArtifact(proof, jwk, { request: REQUEST, delegationChain: CHAIN, outcome });
      expect(stated).toEqual({ valid: true });
    },
  );

  it("is reported as a refusal whatever response is supplied with it: the outcome is compared before the response", async () => {
    const { proof, jwk } = await refused();
    const result = await makeVerifier().verifyProofArtifact(proof, jwk, {
      request: REQUEST,
      response: RESPONSE,
      delegationChain: CHAIN,
    });
    expect(result.details).toEqual({ binding: "outcome", outcome: "denied" });
  });

  it("is still a proof of another request first", async () => {
    const { proof, jwk } = await refused();
    const result = await makeVerifier().verifyProofArtifact(proof, jwk, {
      request: { method: "records.read", params: { recordId: "r-2" } },
      delegationChain: CHAIN,
    });
    expect(result.errorCode).toBe(PROOF_VERIFICATION_ERROR_CODES.CONTENT_BINDING_MISMATCH);
    expect(result.details).toEqual({ binding: "request" });
  });

  it("does not spend the proof's nonce on an outcome mismatch", async () => {
    const { proof, jwk } = await refused();
    const verifier = makeVerifier();
    const asAllowed = await verifier.verifyProof(proof, jwk, { request: REQUEST, delegationChain: CHAIN });
    expect(asAllowed.valid).toBe(false);
    const asRefused = await verifier.verifyProof(proof, jwk, {
      request: REQUEST,
      delegationChain: CHAIN,
      outcome: "denied",
    });
    expect(asRefused).toEqual({ valid: true });
  });
});

describe("a verifier that requires an outcome", () => {
  it("holds an allowed call to it: a proof that states no outcome records a call that was allowed", async () => {
    const { proof, jwk } = await bound();
    expect(proof.meta).not.toHaveProperty("outcome");
    const verifier = makeVerifier();
    const content = { request: REQUEST, response: RESPONSE };
    expect(await verifier.verifyProofArtifact(proof, jwk, { ...content, outcome: "allowed" })).toEqual({ valid: true });
    const asRefusal = await verifier.verifyProofArtifact(proof, jwk, { ...content, delegationChain: CHAIN, outcome: "denied" });
    expect(asRefusal.errorCode).toBe(PROOF_VERIFICATION_ERROR_CODES.OUTCOME_MISMATCH);
    expect(asRefusal.details).toEqual({ binding: "outcome", outcome: "allowed" });
  });

  it("accepts a proof that states allowed in so many words", async () => {
    const { proof, jwk } = await bound({ outcome: "allowed" });
    expect(proof.meta.outcome).toBe("allowed");
    const result = await makeVerifier().verifyProofArtifact(proof, jwk, {
      request: REQUEST,
      response: RESPONSE,
      delegationChain: CHAIN,
    });
    expect(result).toEqual({ valid: true });
  });

  it("can be required with no chain", async () => {
    const { proof, jwk } = await signed({ outcome: "denied", reason: "Insufficient scope" }, "nothing");
    const verifier = makeVerifier();
    const asAllowed = await verifier.verifyProofArtifact(proof, jwk, { request: REQUEST, outcome: "allowed" });
    expect(asAllowed.errorCode).toBe(PROOF_VERIFICATION_ERROR_CODES.OUTCOME_MISMATCH);
    expect(asAllowed.details).toEqual({ binding: "outcome", outcome: "denied" });
    expect(await verifier.verifyProofArtifact(proof, jwk, { request: REQUEST, outcome: "denied" })).toEqual({ valid: true });
  });

  it("is not required of a caller that states none and supplies no chain", async () => {
    const { proof, jwk } = await bound({ outcome: "denied", reason: "Insufficient scope" }, "nothing");
    expect(await makeVerifier().verifyProofArtifact(proof, jwk, { request: REQUEST })).toEqual({ valid: true });
  });

  // As conformance/verify.py reads it: a chain given as null is none, as an
  // outcome given as null is.
  it.each([
    ["a refusal that binds a chain", () => bound({ outcome: "denied", reason: "Insufficient scope" }, "nothing")],
    ["a refusal that binds none", () => signed({ outcome: "denied", reason: "Insufficient scope" }, "nothing")],
    ["an allowed call that binds a chain", () => bound({}, "nothing")],
    ["an allowed call that binds no chain", () => signed({}, "nothing")],
  ])("is not required of a caller that gives the chain as null, and the chain is compared with nothing: %s", async (_name, make) => {
    const { proof, jwk } = await make();
    const verifier = makeVerifier();
    const nullChain = { request: REQUEST, delegationChain: null as unknown as readonly ReceivedCredential[] };
    expect(await verifier.verifyProofArtifact(proof, jwk, nullChain)).toEqual({ valid: true });
    expect(await verifier.verifyProofArtifact(proof, jwk, { ...nullChain, outcome: null as never })).toEqual({ valid: true });
    const asAllowed = await verifier.verifyProofArtifact(proof, jwk, { ...nullChain, outcome: "allowed" });
    expect(asAllowed.valid).toBe(proof.meta.outcome === undefined);
  });
});
