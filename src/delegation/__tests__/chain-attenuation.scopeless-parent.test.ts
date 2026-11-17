/**
 * A delegation with no scopes of either kind grants no scope (SPEC.md §6.4): the delegation gate
 * grants a tool only on a scope a credential states. So a re-delegation under it may grant none
 * either. One that states no scope, as an identity-only or audience-only grant does, is admitted;
 * one that states a flat scope, a CRISP matcher or both is refused as `chain_invalid`, naming the
 * parent, and so is one whose scope fields cannot be read, since they could grant anything.
 */
import { describe, expect, it } from "vitest";
import { validateDelegationChain, validateScopeAttenuation } from "../chain-enforcement.js";
import type { CrispScope, DelegationCredential } from "../../types/protocol.js";
import { SERVER, cred, resolving } from "./helpers/chain-fixtures.js";

type Scopes = { scopes?: string[]; crisp?: CrispScope[] };

const parentOf = (scopes: Scopes = {}) => cred({ id: "p", issuerDid: "did:a", subjectDid: "did:b", ...scopes });
const childOf = (scopes: Scopes = {}) => cred({ id: "c", issuerDid: "did:b", subjectDid: "did:c", parentId: "p", ...scopes });

/** Each way a credential states no scope: no scope field at all, or empty lists. */
const NO_SCOPE: Scopes[] = [{}, { scopes: [] }, { crisp: [] }, { scopes: [], crisp: [] }];

const REFUSED = {
  valid: false,
  code: "chain_invalid",
  transient: false,
  reason: "Delegation c widens scopes beyond parent p, which grants no scope",
};

describe("a parent that grants no scope", () => {
  it("admits a child that grants none either, however each states it", () => {
    for (const parent of NO_SCOPE) {
      for (const child of NO_SCOPE) {
        expect(validateScopeAttenuation(parentOf(parent), childOf(child)), JSON.stringify({ parent, child })).toEqual({ valid: true });
      }
    }
  });

  it("refuses a child that states a flat scope", () => {
    for (const parent of NO_SCOPE) {
      expect(validateScopeAttenuation(parentOf(parent), childOf({ scopes: ["admin:delete"] })), JSON.stringify(parent)).toEqual(REFUSED);
    }
  });

  it("refuses a child that states a CRISP matcher", () => {
    for (const matcher of ["exact", "prefix", "path-prefix", "regex"] as const) {
      const child = childOf({ crisp: [{ resource: "admin:delete", matcher }] });
      expect(validateScopeAttenuation(parentOf(), child), matcher).toEqual(REFUSED);
    }
  });

  it("refuses a child that states both, or an empty list of one beside a scope of the other", () => {
    const children: Scopes[] = [
      { scopes: ["admin:delete"], crisp: [{ resource: "admin:", matcher: "prefix" }] },
      { scopes: [], crisp: [{ resource: "admin:", matcher: "prefix" }] },
      { scopes: ["admin:delete"], crisp: [] },
    ];
    for (const child of children) {
      expect(validateScopeAttenuation(parentOf({ scopes: [], crisp: [] }), childOf(child)), JSON.stringify(child)).toEqual(REFUSED);
    }
  });

  it("refuses, without throwing, a child whose scope fields are not lists", () => {
    const unreadable: Array<(child: DelegationCredential) => void> = [
      (child) => { child.credentialSubject.delegation.constraints.crisp = { scopes: {} } as never; },
      (child) => { child.credentialSubject.delegation.constraints.scopes = 42 as never; },
      (child) => { child.credentialSubject.delegation.scopes = {} as never; },
    ];
    for (const spoil of unreadable) {
      const child = childOf();
      spoil(child);
      expect(validateScopeAttenuation(parentOf(), child)).toEqual(REFUSED);
    }
  });

  it("is held at every hop of a chain, so a scope cannot appear below two hops that grant none", async () => {
    const root = cred({ id: "root", issuerDid: "did:user", subjectDid: "did:agent", scopes: [] });
    const middle = cred({ id: "middle", issuerDid: "did:agent", subjectDid: "did:sub", parentId: "root", scopes: [], audience: SERVER });
    const leafOf = (scopes: string[]) =>
      cred({ id: "leaf", issuerDid: "did:sub", subjectDid: "did:tool", parentId: "middle", scopes, audience: SERVER });

    expect(await validateDelegationChain(leafOf([]), resolving([root, middle]))).toMatchObject({ valid: true });
    expect(await validateDelegationChain(leafOf(["admin:delete"]), resolving([root, middle]))).toMatchObject({
      valid: false,
      code: "chain_invalid",
      reason: "Delegation leaf widens scopes beyond parent middle, which grants no scope",
    });
  });
});
