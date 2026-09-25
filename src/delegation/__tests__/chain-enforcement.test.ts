import { describe, it, expect, vi } from "vitest";

import {
  validateDelegationChain,
  validateScopeAttenuation,
  getDelegationScopes,
  type ChainEnforcementDeps,
  type DelegationCredentialVerifierPort,
  type RevocationChecker,
} from "../chain-enforcement.js";
import type { CrispScope, DelegationCredential } from "../../types/protocol.js";
import { scopeSatisfies } from "../scope-matcher.js";

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

describe("validateScopeAttenuation across scope representations (SPEC.md §6.3, §6.4)", () => {
  type Scopes = { scopes?: string[]; crisp?: CrispScope[] };
  const attenuate = (parent: Scopes, child: Scopes) =>
    validateScopeAttenuation(
      cred({ id: "p", issuerDid: "did:a", subjectDid: "did:b", ...parent }),
      cred({ id: "c", issuerDid: "did:b", subjectDid: "did:c", ...child }),
    );

  it("rejects a flat scope a parent restricted only by CRISP matchers does not grant", () => {
    const r = attenuate({ crisp: [{ resource: "safe:", matcher: "prefix" }] }, { scopes: ["admin:root"] });
    expect(r.valid).toBe(false);
    expect(r.reason).toContain("widens scopes beyond parent p: admin:root");
  });

  it("accepts authority the parent grants in the other representation", () => {
    expect(attenuate({ crisp: [{ resource: "safe:", matcher: "prefix" }] }, { scopes: ["safe:read"] }).valid).toBe(true);
    expect(attenuate({ scopes: ["read"] }, { crisp: [{ resource: "read", matcher: "exact" }] }).valid).toBe(true);
    expect(attenuate({ crisp: [{ resource: "repo:", matcher: "prefix" }] }, { crisp: [{ resource: "repo:read", matcher: "prefix" }] }).valid).toBe(true);
  });

  it("rejects a matcher the parent's scopes do not provably contain", () => {
    const r = attenuate({ scopes: ["repo:read"] }, { crisp: [{ resource: "repo:", matcher: "prefix" }] });
    expect(r.valid).toBe(false);
    expect(r.reason).toContain("crisp scope matcher");
    expect(attenuate({ crisp: [{ resource: "notes", matcher: "path-prefix" }] }, { crisp: [{ resource: "notes", matcher: "prefix" }] }).valid).toBe(false);
  });

  it("keeps a parent with no scopes of either kind unrestricted, and never lets an unscoped child attenuate a scoped parent", () => {
    expect(attenuate({}, { scopes: ["anything"] }).valid).toBe(true);
    expect(attenuate({ crisp: [{ resource: "safe:", matcher: "prefix" }] }, {}).valid).toBe(false);
  });

  it("fails closed on a malformed scope entry instead of throwing", () => {
    const bad = (...entries: unknown[]) => entries as CrispScope[];
    const safe: CrispScope[] = [{ resource: "safe:", matcher: "prefix" }];
    const cases: Array<[Scopes, Scopes, boolean]> = [
      [{ crisp: safe }, { crisp: bad({ resource: 42, matcher: "prefix" }) }, false],
      [{ crisp: safe }, { crisp: bad(null) }, false],
      [{ crisp: safe }, { scopes: bad(42) as unknown as string[] }, false],
      [{ crisp: bad({ resource: 42, matcher: "prefix" }) }, { scopes: ["safe:x"] }, false],
      [{ crisp: bad({ resource: 42, matcher: "prefix" }) }, { crisp: bad({ resource: 42, matcher: "prefix" }) }, false],
      [{ crisp: [...bad({ resource: 42, matcher: "prefix" }), ...safe] }, { crisp: [{ resource: "safe:read", matcher: "prefix" }] }, true],
    ];
    for (const [parent, child, valid] of cases) {
      expect(attenuate(parent, child).valid, JSON.stringify({ parent, child })).toBe(valid);
    }
  });

  it("rejects the bypass through the full chain walk", async () => {
    const root = cred({ id: "root", issuerDid: "did:a", subjectDid: "did:agent", crisp: [{ resource: "safe:", matcher: "prefix" }] });
    const leaf = cred({ id: "leaf", issuerDid: "did:agent", subjectDid: "did:sub", parentId: "root", audience: SERVER, scopes: ["admin:root"] });
    const r = await validateDelegationChain(leaf, { ...baseDeps, resolveDelegationChain: async () => [root, leaf] });
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/widens scopes beyond parent root: admin:root/);
  });

  it("is sound: every scope a valid child grants, its parent grants too", () => {
    const authorities: Scopes[] = [
      {}, { scopes: ["safe:read"] }, { scopes: ["admin:root"] },
      { crisp: [{ resource: "safe:", matcher: "prefix" }] }, { crisp: [{ resource: "safe:read", matcher: "exact" }] },
      { crisp: [{ resource: "notes", matcher: "path-prefix" }] }, { crisp: [{ resource: "safe:(read|x)", matcher: "regex" }] },
      { scopes: ["admin:root"], crisp: [{ resource: "notes", matcher: "prefix" }] },
    ];
    const values = ["safe:read", "safe:x", "admin:root", "notes", "notes/a", "notesx/b", "anything"];
    let accepted = 0;
    for (const parent of authorities) {
      if (!parent.scopes && !parent.crisp) continue; // unrestricted by definition
      for (const child of authorities) {
        if (!attenuate(parent, child).valid) continue;
        accepted += 1;
        const [p, c] = [cred({ id: "p", issuerDid: "did:a", subjectDid: "did:b", ...parent }), cred({ id: "c", issuerDid: "did:b", subjectDid: "did:c", ...child })];
        for (const v of values) {
          if (scopeSatisfies(v, c).satisfied) expect(scopeSatisfies(v, p).satisfied, `${JSON.stringify(child)} widens ${JSON.stringify(parent)} at ${v}`).toBe(true);
        }
      }
    }
    expect(accepted).toBeGreaterThan(authorities.length);
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
  it("only skips the presented leaf signature and never substitutes a resolver leaf", async () => {
    const root = cred({ id: "root", issuerDid: "did:a", subjectDid: "did:agent", scopes: ["read"] });
    const leaf = cred({ id: "leaf", issuerDid: "did:agent", subjectDid: "did:sub", parentId: "root", audience: SERVER, scopes: ["read"] });
    const resolverLeaf = structuredClone(leaf);
    const verifyDelegationCredential = vi.fn<DelegationCredentialVerifierPort["verifyDelegationCredential"]>(async () => ({ valid: true }));
    const result = await validateDelegationChain(leaf, {
      ...baseDeps, verifier: { verifyDelegationCredential }, resolveDelegationChain: async () => [root, resolverLeaf],
    }, { skipSignature: true });
    expect(result.valid).toBe(true);
    expect(verifyDelegationCredential).toHaveBeenNthCalledWith(1, root, {});
    expect(verifyDelegationCredential).toHaveBeenNthCalledWith(2, leaf, { skipSignature: true });
    expect(verifyDelegationCredential.mock.calls[1]?.[0]).toBe(leaf);
  });

  it("returns the earliest verified date or constraint across the chain", async () => {
    const root = cred({ id: "root", issuerDid: "did:a", subjectDid: "did:agent", scopes: ["read"] });
    const leaf = cred({ id: "leaf", issuerDid: "did:agent", subjectDid: "did:sub", parentId: "root", audience: SERVER, scopes: ["read"] });
    root.expirationDate = "2026-09-22T12:00:00.000Z";
    root.credentialSubject.delegation.constraints.notAfter = Date.parse(root.expirationDate) / 1000 + 60;
    leaf.credentialSubject.delegation.constraints.notAfter = Date.parse(root.expirationDate) / 1000 + 600;
    expect((await validateDelegationChain(leaf, { ...baseDeps, resolveDelegationChain: async () => [root] })).expiresAt).toBe(Date.parse(root.expirationDate));
  });

});

describe("validateDelegationChain: who actually issued each link", () => {
  const root = cred({ id: "root", issuerDid: "did:user", subjectDid: "did:agent", scopes: ["read"] });
  const chainDeps: ChainEnforcementDeps = { ...baseDeps, resolveDelegationChain: async () => [root] };

  it("accepts a re-delegation signed by the parent's subject", async () => {
    const leaf = cred({ id: "leaf", issuerDid: "did:agent", subjectDid: "did:sub", parentId: "root", audience: SERVER, scopes: ["read"] });
    expect((await validateDelegationChain(leaf, chainDeps)).valid).toBe(true);
  });

  it("rejects a leaf signed by an outsider that only claims the parent's subject as issuer", async () => {
    const forged = {
      ...cred({ id: "leaf", issuerDid: "did:agent", subjectDid: "did:mallory", parentId: "root", audience: SERVER, scopes: ["read"] }),
      issuer: "did:mallory",
    };
    const result = await validateDelegationChain(forged, chainDeps);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("is signed by did:mallory but parent subject is did:agent");
  });

  it("applies the signer check to a JWT leaf whose envelope was verified by the caller", async () => {
    const forged = {
      ...cred({ id: "leaf", issuerDid: "did:agent", subjectDid: "did:mallory", parentId: "root", audience: SERVER, scopes: ["read"] }),
      issuer: "did:mallory",
    };
    expect((await validateDelegationChain(forged, chainDeps, { skipSignature: true })).valid).toBe(false);
  });

  it("accepts a root whose claimed issuerDid is not its signer, and reports it", async () => {
    const mismatched = { ...cred({ id: "solo", issuerDid: "did:user", subjectDid: "did:agent", scopes: ["read"] }), issuer: "did:signing-key" };
    const result = await validateDelegationChain(mismatched, baseDeps);
    expect(result.valid).toBe(true);
    expect(result.warnings).toEqual(["Root delegation solo names issuerDid did:user but is signed by did:signing-key"]);
  });

  it("reports no warnings for a consistent chain", async () => {
    expect((await validateDelegationChain(root, baseDeps)).warnings).toBeUndefined();
  });

  describe("trustedRootIssuers", () => {
    it("accepts a root signed by a trusted issuer, and chains below it", async () => {
      const trusted = { ...chainDeps, trustedRootIssuers: ["did:user"] };
      const leaf = cred({ id: "leaf", issuerDid: "did:agent", subjectDid: "did:sub", parentId: "root", audience: SERVER, scopes: ["read"] });
      expect((await validateDelegationChain(root, trusted)).valid).toBe(true);
      expect((await validateDelegationChain(leaf, trusted)).valid).toBe(true);
    });

    it("rejects a self-issued root from an issuer outside the list", async () => {
      const selfIssued = cred({ id: "self", issuerDid: "did:rogue", subjectDid: "did:rogue", scopes: ["read"] });
      const result = await validateDelegationChain(selfIssued, { ...baseDeps, trustedRootIssuers: ["did:user"] });
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("did:rogue, which is not a trusted root issuer");
    });

    it("judges the root by its signer, not its claimed issuerDid", async () => {
      const claimsTrusted = { ...cred({ id: "claim", issuerDid: "did:user", subjectDid: "did:rogue", scopes: ["read"] }), issuer: "did:rogue" };
      expect((await validateDelegationChain(claimsTrusted, { ...baseDeps, trustedRootIssuers: ["did:user"] })).valid).toBe(false);
    });

    it("trusts no issuer when the list is empty", async () => {
      expect((await validateDelegationChain(root, { ...baseDeps, trustedRootIssuers: [] })).valid).toBe(false);
    });
  });
});
