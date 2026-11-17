/**
 * validateDelegationChain reads each value a resolver returns once, through
 * `snapshotAncestor`, before any of it is verified: what is checked, recorded
 * and bound is that one reading (SPEC.md §7.8).
 */
import { describe, it, expect, vi } from "vitest";
import { validateDelegationChain } from "../chain-enforcement.js";
import type { DelegationCredential } from "../../types/protocol.js";
import { SERVER, chainOfThree, cred, resolving } from "./helpers/chain-fixtures.js";

describe("validateDelegationChain: snapshotAncestor", () => {
  const { root, middle, leaf } = chainOfThree();

  it("is called once for each value the resolver returned, root first, and never for the presented leaf", async () => {
    const copied: DelegationCredential[] = [];
    const verified: DelegationCredential[] = [];
    const result = await validateDelegationChain(leaf, {
      ...resolving([root, middle]),
      verifier: {
        verifyDelegationCredential: async (credential) => {
          verified.push(credential);
          return { valid: true };
        },
      },
      snapshotAncestor: (ancestor) => {
        copied.push(ancestor);
        return structuredClone(ancestor);
      },
    });
    expect(result.valid).toBe(true);
    expect(copied).toHaveLength(2);
    expect(copied[0]).toBe(root);
    expect(copied[1]).toBe(middle);

    // What was verified, and what is reported, is the copy of each ancestor
    // and the leaf as presented.
    const evaluated = result.evaluated!;
    expect(evaluated).toEqual([root, middle, leaf]);
    expect(evaluated[0]).not.toBe(root);
    expect(evaluated[1]).not.toBe(middle);
    expect(evaluated[2]).toBe(leaf);
    expect(verified).toHaveLength(3);
    for (const [index, credential] of verified.entries()) expect(credential).toBe(evaluated[index]);
  });

  it("holds every check to the copy: an ancestor that changes after it was read is checked and reported as it was read", async () => {
    const shifting = (): DelegationCredential =>
      cred({ id: "middle", issuerDid: "did:agent", subjectDid: "did:sub", parentId: "root", scopes: ["read"], audience: SERVER });
    const deleting = cred({ id: "leaf", issuerDid: "did:sub", subjectDid: "did:tool", parentId: "middle", scopes: ["read", "delete"], audience: SERVER });
    // The resolver's value widens once the walk has taken it up.
    const widenAfter = (ancestor: DelegationCredential): void => {
      if (ancestor.credentialSubject.delegation.id === "middle") {
        ancestor.credentialSubject.delegation.scopes = ["read", "delete"];
      }
    };

    // Walked as it stands, the ancestor is whatever it says when each check
    // reads it: here it has widened past its own parent.
    const asItStands = await validateDelegationChain(deleting, {
      ...resolving([root, shifting()]),
      snapshotAncestor: (ancestor) => {
        widenAfter(ancestor);
        return ancestor;
      },
    });
    expect(asItStands.reason).toContain("middle widens scopes beyond parent root");

    // Copied, it is the credential that was read, for its own checks and for
    // the leaf held to it.
    const copied = await validateDelegationChain(deleting, {
      ...resolving([root, shifting()]),
      snapshotAncestor: (ancestor) => {
        const copy = structuredClone(ancestor);
        widenAfter(ancestor);
        return copy;
      },
    });
    expect(copied.valid).toBe(false);
    expect(copied.reason).toContain("leaf widens scopes beyond parent middle");
    expect(copied.evaluated![1]!.credentialSubject.delegation.scopes).toEqual(["read"]);
  });

  it("copies every value before any credential is verified, the resolver's copy of the leaf included", async () => {
    const order: string[] = [];
    const leafCopy = structuredClone(leaf);
    const result = await validateDelegationChain(leaf, {
      ...resolving([root, middle, leafCopy]),
      verifier: {
        verifyDelegationCredential: async (credential) => {
          order.push(`verify ${credential.credentialSubject.delegation.id}`);
          return credential.credentialSubject.delegation.id === "root"
            ? { valid: false, reason: "Signature verification failed" }
            : { valid: true };
        },
      },
      snapshotAncestor: (value) => {
        order.push(`copy ${value === leafCopy ? "leaf copy" : value.credentialSubject.delegation.id}`);
        return structuredClone(value);
      },
    });
    expect(result.valid).toBe(false);
    expect(order).toEqual(["copy root", "copy middle", "copy leaf copy", "verify root"]);
    // Copied is not examined: the walk stopped at the root.
    expect(result.evaluated).toEqual([root]);
  });

  it.each([
    ["throws", "could not be copied", 2, () => { throw new Error("DataCloneError"); }],
    ["returns a value that is no delegation credential", "is not a delegation credential", 3, () => ({ id: "middle" }) as never],
    ["returns nothing", "is not a delegation credential", 3, () => undefined as never],
  ])("refuses the chain when the copy of an ancestor %s, before any credential of it is verified", async (_name, unread, passedOn, failing) => {
    const verify = vi.fn(async () => ({ valid: true }));
    const leafCopy = structuredClone(leaf);
    const passed: unknown[] = [];
    const result = await validateDelegationChain(leaf, {
      ...resolving([root, middle, leafCopy]),
      verifier: { verifyDelegationCredential: verify },
      snapshotAncestor: (value) => {
        passed.push(value);
        return value === middle ? failing() : structuredClone(value);
      },
    });
    expect(result).toEqual({
      valid: false,
      reason: `Resolved delegation chain for leaf holds a value that ${unread}`,
      code: "delegation_malformed",
      transient: false,
    });
    // A value that could not be copied ends the reading there.
    expect(passed).toHaveLength(passedOn);
    for (const [index, value] of passed.entries()) expect(value).toBe([root, middle, leafCopy][index]);
    expect(verify).not.toHaveBeenCalled();
  });

  it.each([
    ["the credential it was copied from", "middle", true],
    ["the leaf", "leaf", false],
  ])("reads a value that would answer differently each time once, as %s, and holds every check to that", async (_name, firstAnswer, valid) => {
    let reads = 0;
    const answering = { ...middle };
    Object.defineProperty(answering, "credentialSubject", {
      enumerable: true,
      get: () => {
        reads += 1;
        const first = firstAnswer === "leaf" ? leaf : middle;
        return (reads === 1 ? first : firstAnswer === "leaf" ? middle : leaf).credentialSubject;
      },
    });
    const snapshotAncestor = vi.fn((value: DelegationCredential) => structuredClone(value));
    const result = await validateDelegationChain(leaf, { ...resolving([root, answering]), snapshotAncestor });
    // The one read is the copy's: each value the resolver returned was copied, and nothing read it again.
    expect(snapshotAncestor).toHaveBeenCalledTimes(2);
    expect(reads).toBe(1);
    expect(result.valid).toBe(valid);
    if (valid) {
      expect(result.evaluated).toEqual([root, middle, leaf]);
    } else {
      // Read as the leaf, it is the resolver's copy of the leaf and is set
      // aside: the leaf presented is then held to the root, which is not its
      // parent. Links are checked before any credential is verified, so none was.
      expect(result.reason).toBe("Delegation leaf references parent middle but expected root");
      expect(result).not.toHaveProperty("evaluated");
    }
  });

  it("walks the resolver's own values when it is omitted", async () => {
    const result = await validateDelegationChain(leaf, resolving([root, middle]));
    expect(result.evaluated![0]).toBe(root);
    expect(result.evaluated![1]).toBe(middle);
    expect(result.evaluated![2]).toBe(leaf);
  });
});
