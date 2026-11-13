/**
 * The credentials validateDelegationChain reports it evaluated (SPEC.md
 * §7.8): the chain a proof binds, root first, ending where the walk stopped.
 */
import { describe, it, expect, vi } from "vitest";
import { validateDelegationChain, type DelegationCredentialVerifierPort } from "../chain-enforcement.js";
import type { DelegationCredential } from "../../types/protocol.js";
import { SERVER, baseDeps, chainOfThree, cred, resolving } from "./helpers/chain-fixtures.js";

describe("validateDelegationChain: the credentials it reports", () => {
  const { root, middle, leaf } = chainOfThree();

  it("are the whole chain when it validates, root first and the presented credential last, whether the resolver returns ancestors or the whole chain", async () => {
    const ancestorsOnly = await validateDelegationChain(leaf, resolving([root, middle]));
    expect(ancestorsOnly.valid).toBe(true);
    expect(ancestorsOnly.evaluated).toEqual([root, middle, leaf]);

    // A resolver's own copy of the leaf never stands in for the one presented.
    const copy = structuredClone(leaf);
    const wholeChain = await validateDelegationChain(leaf, resolving([root, middle, copy]));
    expect(wholeChain.evaluated).toHaveLength(3);
    expect(wholeChain.evaluated![2]).toBe(leaf);
  });

  it("are a chain of one for a root credential", async () => {
    expect((await validateDelegationChain(root, baseDeps)).evaluated).toEqual([root]);
  });

  it("end, on a refusal, with the credential the walk stopped at, so the caller can say what was examined", async () => {
    // Refused at the leaf: every credential was reached.
    const widened = cred({ id: "leaf", issuerDid: "did:sub", subjectDid: "did:tool", parentId: "middle", scopes: ["read", "delete"], audience: SERVER });
    const result = await validateDelegationChain(widened, resolving([root, middle]));
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("widens scopes beyond parent middle");
    expect(result.evaluated).toEqual([root, middle, widened]);

    // Refused at an ancestor: nothing after it was reached, the leaf included.
    const failingAt = (refused: DelegationCredential): DelegationCredentialVerifierPort => ({
      verifyDelegationCredential: async (credential) =>
        credential === refused ? { valid: false, reason: "Signature verification failed" } : { valid: true },
    });
    const atMiddle = await validateDelegationChain(leaf, { ...resolving([root, middle]), verifier: failingAt(middle) });
    expect(atMiddle.valid).toBe(false);
    expect(atMiddle.evaluated).toEqual([root, middle]);
    const atRoot = await validateDelegationChain(leaf, { ...resolving([root, middle]), verifier: failingAt(root) });
    expect(atRoot.valid).toBe(false);
    expect(atRoot.evaluated).toEqual([root]);
  });

  it("are every credential when the refusal comes after the walk: one of them is revoked", async () => {
    const revoked = await validateDelegationChain(leaf, {
      ...resolving([root, middle]),
      revocationChecker: { isRevoked: async (id) => ({ revoked: id === "root" }) },
    });
    expect(revoked.valid).toBe(false);
    expect(revoked.evaluated).toEqual([root, middle, leaf]);
  });

  it("are absent when the walk never started", async () => {
    const malformed = await validateDelegationChain({} as DelegationCredential, baseDeps);
    expect(malformed).not.toHaveProperty("evaluated");
    const unresolvable = await validateDelegationChain(leaf, baseDeps);
    expect(unresolvable).not.toHaveProperty("evaluated");
    const throwing = await validateDelegationChain(leaf, {
      ...baseDeps,
      resolveDelegationChain: async () => {
        throw new Error("registry unreachable");
      },
    });
    expect(throwing).not.toHaveProperty("evaluated");
    expect(await validateDelegationChain(leaf, resolving([]))).not.toHaveProperty("evaluated");
    const leafFirst = await validateDelegationChain(leaf, resolving([structuredClone(leaf), middle]));
    expect(leafFirst.reason).toBe("Resolved delegation chain for leaf must end with the leaf credential");
    expect(leafFirst).not.toHaveProperty("evaluated");

    // A chain's links, and then its root's issuer, are checked before the walk starts.
    const unlinked = cred({ id: "middle", issuerDid: "did:rogue", subjectDid: "did:sub", parentId: "root", scopes: ["read"], audience: SERVER });
    const broken = await validateDelegationChain(leaf, resolving([root, unlinked]));
    expect(broken.reason).toBe("Delegation middle issued by did:rogue but parent subject is did:agent");
    expect(broken).not.toHaveProperty("evaluated");
    const untrusted = await validateDelegationChain(leaf, { ...resolving([root, middle]), trustedRootIssuers: ["did:other"] });
    expect(untrusted.reason).toContain("which is not a trusted root issuer");
    expect(untrusted).not.toHaveProperty("evaluated");
  });

  it.each([
    ["a number", 42],
    ["null", null],
    ["a string", "middle"],
    ["an object that is no credential", { id: "urn:uuid:middle" }],
    ["a credential whose delegation has no constraints", { credentialSubject: { delegation: { id: "middle" } } }],
  ])("refuses a resolved chain that holds %s, before any credential of the chain is verified", async (_name, value) => {
    const verify = vi.fn(async () => ({ valid: true }));
    for (const resolved of [[root, value], [value, middle], [root, middle, value]]) {
      const result = await validateDelegationChain(leaf, {
        ...resolving(resolved as DelegationCredential[]),
        verifier: { verifyDelegationCredential: verify },
      });
      // A refusal like any other, never a throw, and nothing was evaluated.
      expect(result).toEqual({
        valid: false,
        reason: "Resolved delegation chain for leaf holds a value that is not a delegation credential",
      });
    }
    expect(verify).not.toHaveBeenCalled();
  });

  it("are absent for a chain longer than maxChainLength: nothing in it was evaluated", async () => {
    const verify = vi.fn(async () => ({ valid: true }));
    const snapshotAncestor = vi.fn((ancestor: DelegationCredential) => structuredClone(ancestor));
    const result = await validateDelegationChain(leaf, {
      ...resolving([root, middle]),
      verifier: { verifyDelegationCredential: verify },
      maxChainLength: 2,
      snapshotAncestor,
    });
    expect(result).toEqual({
      valid: false,
      reason: "Delegation chain of 3 credentials exceeds the maximum of 2",
    });
    expect(verify).not.toHaveBeenCalled();
    // Each value was read, and only the presented leaf made the chain too long.
    expect(snapshotAncestor).toHaveBeenCalledTimes(2);

    // More values than the limit are refused before any of them is read.
    const beyond = await validateDelegationChain(leaf, {
      ...resolving([root, middle, structuredClone(leaf)]),
      verifier: { verifyDelegationCredential: verify },
      maxChainLength: 2,
      snapshotAncestor,
    });
    expect(beyond).toEqual({
      valid: false,
      reason: "Delegation chain of at least 3 credentials exceeds the maximum of 2",
    });
    expect(verify).not.toHaveBeenCalled();
    expect(snapshotAncestor).toHaveBeenCalledTimes(2);
  });
});
