import { describe, it, expect } from "vitest";

import {
  validateDelegationChain,
  validateScopeAttenuation,
  getDelegationScopes,
  type ChainEnforcementDeps,
  type DelegationCredentialVerifierPort,
  type RevocationChecker,
} from "../chain-enforcement.js";
import type { CrispScope, DelegationCredential } from "../../types/protocol.js";

const SERVER = "did:web:server.example";

/** Minimal well-formed delegation credential for the chain-walk under test. */
function cred(opts: {
  id: string;
  issuerDid: string;
  subjectDid: string;
  parentId?: string;
  scopes?: string[];
  audience?: string | string[];
  crisp?: CrispScope[];
  withStatus?: boolean;
}): DelegationCredential {
  return {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    type: ["VerifiableCredential", "DelegationCredential"],
    issuer: opts.issuerDid,
    issuanceDate: "2026-01-01T00:00:00.000Z",
    credentialSubject: {
      id: opts.subjectDid,
      delegation: {
        id: opts.id,
        issuerDid: opts.issuerDid,
        subjectDid: opts.subjectDid,
        ...(opts.parentId ? { parentId: opts.parentId } : {}),
        ...(opts.scopes ? { scopes: opts.scopes } : {}),
        constraints: {
          ...(opts.audience !== undefined ? { audience: opts.audience } : {}),
          ...(opts.scopes ? { scopes: opts.scopes } : {}),
          ...(opts.crisp ? { crisp: { scopes: opts.crisp } } : {}),
        },
        status: "active",
      },
    },
    ...(opts.withStatus
      ? {
          credentialStatus: {
            id: "https://status.example/1#0",
            type: "StatusList2021Entry" as const,
            statusPurpose: "revocation" as const,
            statusListIndex: "0",
            statusListCredential: "https://status.example/1",
          },
        }
      : {}),
  };
}

const okVerifier: DelegationCredentialVerifierPort = {
  verifyDelegationCredential: async () => ({ valid: true }),
};

const baseDeps: ChainEnforcementDeps = {
  serverDid: SERVER,
  verifier: okVerifier,
  statusListConfigured: true,
};

describe("validateScopeAttenuation (pure)", () => {
  const parent = cred({ id: "p", issuerDid: "did:a", subjectDid: "did:b", scopes: ["read", "write"] });
  it("allows a subset", () => {
    const child = cred({ id: "c", issuerDid: "did:b", subjectDid: "did:c", scopes: ["read"] });
    expect(validateScopeAttenuation(parent, child).valid).toBe(true);
  });
  it("rejects widening", () => {
    const child = cred({ id: "c", issuerDid: "did:b", subjectDid: "did:c", scopes: ["read", "admin"] });
    expect(validateScopeAttenuation(parent, child).valid).toBe(false);
  });
  it("rejects a crisp matcher absent from the parent", () => {
    const child = cred({
      id: "c",
      issuerDid: "did:b",
      subjectDid: "did:c",
      scopes: ["read"],
      crisp: [{ resource: "", matcher: "prefix" }],
    });
    expect(validateScopeAttenuation(parent, child).valid).toBe(false);
  });
});

describe("getDelegationScopes", () => {
  it("unions delegation + constraint scopes", () => {
    const c = cred({ id: "x", issuerDid: "did:a", subjectDid: "did:b", scopes: ["read"] });
    expect(getDelegationScopes(c)).toEqual(["read"]);
  });
});

describe("validateDelegationChain", () => {
  it("rejects a malformed leaf without throwing", async () => {
    const r = await validateDelegationChain(
      { credentialSubject: {} } as unknown as DelegationCredential,
      baseDeps,
    );
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/Malformed/);
  });

  it("accepts a valid root credential", async () => {
    const root = cred({ id: "root", issuerDid: "did:a", subjectDid: "did:agent", scopes: ["read"] });
    expect((await validateDelegationChain(root, baseDeps)).valid).toBe(true);
  });

  it("rejects when the audience constraint excludes the server", async () => {
    const root = cred({ id: "root", issuerDid: "did:a", subjectDid: "did:agent", audience: "did:web:other" });
    const r = await validateDelegationChain(root, baseDeps);
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/audience does not include/);
  });

  it("rejects a re-delegation when no chain resolver is configured", async () => {
    const leaf = cred({ id: "leaf", issuerDid: "did:agent", subjectDid: "did:sub", parentId: "root", audience: SERVER });
    const r = await validateDelegationChain(leaf, baseDeps);
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/no resolveDelegationChain/);
  });

  it("rejects an empty resolved chain", async () => {
    const leaf = cred({ id: "leaf", issuerDid: "did:agent", subjectDid: "did:sub", parentId: "root", audience: SERVER });
    const r = await validateDelegationChain(leaf, { ...baseDeps, resolveDelegationChain: async () => [] });
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/resolved chain is empty/);
  });

  it("enforces the §11.6 re-delegation audience-constraint requirement", async () => {
    const root = cred({ id: "root", issuerDid: "did:a", subjectDid: "did:agent", scopes: ["read"] });
    const child = cred({ id: "child", issuerDid: "did:agent", subjectDid: "did:sub", parentId: "root", scopes: ["read"] }); // no audience
    const r = await validateDelegationChain(child, { ...baseDeps, resolveDelegationChain: async () => [root, child] });
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/MUST include an audience constraint/);
  });

  it("rejects a circular reference in the chain", async () => {
    // A duplicate ancestor id (root appears twice) trips the cycle guard before
    // the leaf is reached; the leaf itself stays distinct so the chain still
    // ends with it.
    const root = cred({ id: "root", issuerDid: "did:a", subjectDid: "did:agent", scopes: ["read"] });
    const leaf = cred({ id: "leaf", issuerDid: "did:agent", subjectDid: "did:sub", parentId: "root", audience: SERVER, scopes: ["read"] });
    const r = await validateDelegationChain(leaf, { ...baseDeps, resolveDelegationChain: async () => [root, root, leaf] });
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/circular reference/);
  });

  it("rejects an issuer that is not the parent's subject (confused-deputy linkage)", async () => {
    const root = cred({ id: "root", issuerDid: "did:a", subjectDid: "did:agent", scopes: ["read"] });
    const child = cred({ id: "child", issuerDid: "did:IMPOSTER", subjectDid: "did:sub", parentId: "root", audience: SERVER, scopes: ["read"] });
    const r = await validateDelegationChain(child, { ...baseDeps, resolveDelegationChain: async () => [root, child] });
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/parent subject is/);
  });

  it("rejects scope widening across a hop", async () => {
    const root = cred({ id: "root", issuerDid: "did:a", subjectDid: "did:agent", scopes: ["read"] });
    const child = cred({ id: "child", issuerDid: "did:agent", subjectDid: "did:sub", parentId: "root", audience: SERVER, scopes: ["read", "admin"] });
    const r = await validateDelegationChain(child, { ...baseDeps, resolveDelegationChain: async () => [root, child] });
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/widens scopes/);
  });

  it("accepts a properly attenuated, audience-bound, linked 2-hop chain", async () => {
    const root = cred({ id: "root", issuerDid: "did:a", subjectDid: "did:agent", scopes: ["read", "write"] });
    const child = cred({ id: "child", issuerDid: "did:agent", subjectDid: "did:sub", parentId: "root", audience: SERVER, scopes: ["read"] });
    const r = await validateDelegationChain(child, { ...baseDeps, resolveDelegationChain: async () => [root, child] });
    expect(r.valid).toBe(true);
  });

  it("rejects a credential carrying credentialStatus when no status resolver is configured", async () => {
    const root = cred({ id: "root", issuerDid: "did:a", subjectDid: "did:agent", scopes: ["read"], withStatus: true });
    const r = await validateDelegationChain(root, { ...baseDeps, statusListConfigured: false });
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/no statusListResolver/);
  });

  describe("graph-backed ancestor revocation (E3.1 wiring)", () => {
    const root = cred({ id: "root", issuerDid: "did:a", subjectDid: "did:agent", scopes: ["read"] });

    it("fails when an ancestor is revoked, even though the leaf's own status is clean", async () => {
      const checker: RevocationChecker = {
        isRevoked: async () => ({ revoked: true, reason: "Ancestor revoked", revokedAncestor: "root-parent" }),
      };
      const r = await validateDelegationChain(root, { ...baseDeps, revocationChecker: checker });
      expect(r.valid).toBe(false);
      expect(r.reason).toMatch(/revoked via ancestor root-parent/);
    });

    it("passes a clean chain through the revocation checker", async () => {
      const checker: RevocationChecker = { isRevoked: async () => ({ revoked: false }) };
      expect((await validateDelegationChain(root, { ...baseDeps, revocationChecker: checker })).valid).toBe(true);
    });
  });
});
