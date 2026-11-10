import { describe, it, expect, vi } from "vitest";

import {
  attenuationWarnings,
  validateDelegationChain,
  validateScopeAttenuation,
  getDelegationScopes,
  type ChainEnforcementDeps,
  type DelegationCredentialVerifierPort,
  type RevocationChecker,
} from "../chain-enforcement.js";
import type { CrispScope, DelegationCredential } from "../../types/protocol.js";
import { scopeSatisfies } from "../scope-matcher.js";
import { statusListGzipCodec } from "../../utils/statuslist-gzip.js";
import { DelegationGraphManager } from "../delegation-graph.js";
import { MemoryDelegationGraphStorage } from "../storage/memory-graph-storage.js";
import { MemoryStatusListStorage } from "../storage/memory-statuslist-storage.js";
import { StatusList2021Manager } from "../statuslist-manager.js";
import { CascadingRevocationManager } from "../cascading-revocation.js";

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

  describe("maxChainLength", () => {
    /** A linked, audience-bound chain of `length` credentials, root first. */
    const linkedChain = (length: number): DelegationCredential[] =>
      Array.from({ length }, (_, i) =>
        cred({
          id: `c${i}`,
          issuerDid: i === 0 ? "did:a" : `did:h${i}`,
          subjectDid: `did:h${i + 1}`,
          ...(i > 0 ? { parentId: `c${i - 1}` } : {}),
          audience: SERVER,
          scopes: ["read"],
        }),
      );
    const depsFor = (chain: DelegationCredential[], verifier = okVerifier): ChainEnforcementDeps => ({
      ...baseDeps,
      verifier,
      resolveDelegationChain: async () => chain,
    });

    it("accepts a chain exactly at the bound", async () => {
      const chain = linkedChain(3);
      const r = await validateDelegationChain(chain[2]!, { ...depsFor(chain), maxChainLength: 3 });
      expect(r.valid).toBe(true);
    });

    it("rejects a longer chain before verifying any credential in it", async () => {
      const chain = linkedChain(4);
      const verify = vi.fn(async () => ({ valid: true }));
      const r = await validateDelegationChain(chain[3]!, {
        ...depsFor(chain, { verifyDelegationCredential: verify }),
        maxChainLength: 3,
      });
      expect(r.valid).toBe(false);
      expect(r.reason).toBe("Delegation chain of 4 credentials exceeds the maximum of 3");
      expect(verify).not.toHaveBeenCalled();
    });

    it("bounds a single root credential too", async () => {
      const [root] = linkedChain(1);
      expect((await validateDelegationChain(root!, { ...baseDeps, maxChainLength: 1 })).valid).toBe(true);
    });

    it("leaves chain length unbounded when unset", async () => {
      const chain = linkedChain(12);
      expect((await validateDelegationChain(chain[11]!, depsFor(chain))).valid).toBe(true);
    });

    it.each([0, -1, 1.5, Number.NaN])("rejects every chain when the bound is %s", async (bound) => {
      const [root] = linkedChain(1);
      const r = await validateDelegationChain(root!, { ...baseDeps, maxChainLength: bound });
      expect(r.valid).toBe(false);
      expect(r.reason).toMatch(/maxChainLength must be a positive integer/);
    });
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

    const parent = cred({ id: "p", issuerDid: "did:user", subjectDid: "did:a", scopes: ["read"], audience: SERVER });
    const freshChild = cred({ id: "fresh-child", issuerDid: "did:a", subjectDid: "did:b", parentId: "p", scopes: ["read"], audience: SERVER });

    it("rejects a leaf the graph has never seen when an ancestor in its chain is revoked", async () => {
      const statusList = new StatusList2021Manager(
        new MemoryStatusListStorage(),
        { getDid: () => "did:web:issuer.example", getKeyId: () => "did:web:issuer.example#k" },
        async () => ({ type: "Ed25519Signature2020", proofValue: "x" }),
        statusListGzipCodec,
        statusListGzipCodec,
        { statusListBaseUrl: "https://status.example", defaultListSize: 1024 },
      );
      const graph = new DelegationGraphManager(new MemoryDelegationGraphStorage());
      const revocation = new CascadingRevocationManager(graph, statusList);
      await graph.registerDelegation({
        id: "p",
        parentId: null,
        issuerDid: "did:user",
        subjectDid: "did:a",
        credentialStatusId: (await statusList.allocateStatusEntry("revocation")).id,
      });
      await revocation.revokeDelegation("p");

      // Minted by p's subject after the revocation, so never registered.
      const r = await validateDelegationChain(freshChild, {
        ...baseDeps,
        resolveDelegationChain: async () => [parent],
        revocationChecker: revocation,
      });
      expect(r.valid).toBe(false);
      expect(r.reason).toBe("Delegation fresh-child is revoked via ancestor p");
    });

    it("asks about every credential in the verified chain, root first, and names the one revoked", async () => {
      const asked: string[] = [];
      const checker: RevocationChecker = {
        isRevoked: async (id) => {
          asked.push(id);
          return { revoked: false };
        },
      };
      const deps = { ...baseDeps, resolveDelegationChain: async () => [parent] };
      const r = await validateDelegationChain(freshChild, { ...deps, revocationChecker: checker });
      expect(r.valid).toBe(true);
      expect(asked).toEqual(["p", "fresh-child"]);

      // Only the leaf revoked: reported as revoked itself, with the checker's reason when it gives one.
      const leafOnly = (reason?: string): RevocationChecker => ({
        isRevoked: async (id) => (id === "fresh-child" ? { revoked: true, ...(reason ? { reason } : {}) } : { revoked: false }),
      });
      expect(await validateDelegationChain(freshChild, { ...deps, revocationChecker: leafOnly("Directly revoked") })).toEqual({
        valid: false,
        reason: "Delegation fresh-child is revoked: Directly revoked",
      });
      expect(await validateDelegationChain(freshChild, { ...deps, revocationChecker: leafOnly() })).toEqual({
        valid: false,
        reason: "Delegation fresh-child is revoked",
      });
    });

    it("fails closed, without throwing, when the revocation checker throws", async () => {
      const checker: RevocationChecker = {
        isRevoked: async () => {
          throw new Error("status list unavailable");
        },
      };
      const r = await validateDelegationChain(root, { ...baseDeps, revocationChecker: checker });
      expect(r).toEqual({
        valid: false,
        reason: "Revocation check failed for delegation root: status list unavailable",
      });

      const throwsNonError: RevocationChecker = {
        isRevoked: async () => {
          throw "unavailable";
        },
      };
      expect(await validateDelegationChain(root, { ...baseDeps, revocationChecker: throwsNonError })).toEqual({
        valid: false,
        reason: "Revocation check failed for delegation root: Unknown error",
      });
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

describe("attenuationWarnings (SPEC.md §6.4)", () => {
  type Extra = {
    scopes?: string[];
    crisp?: CrispScope[];
    audience?: string | string[];
    notAfter?: number;
    expirationDate?: string;
  };
  const link = (id: string, parentId: string | undefined, extra: Extra): DelegationCredential => {
    const base = cred({
      id,
      issuerDid: parentId ? "did:agent" : "did:user",
      subjectDid: parentId ? "did:sub" : "did:agent",
      ...(parentId ? { parentId } : {}),
      ...(extra.scopes ? { scopes: extra.scopes } : {}),
      ...(extra.crisp ? { crisp: extra.crisp } : {}),
      ...(extra.audience !== undefined ? { audience: extra.audience } : {}),
    });
    if (extra.notAfter !== undefined) base.credentialSubject.delegation.constraints.notAfter = extra.notAfter;
    return { ...base, ...(extra.expirationDate ? { expirationDate: extra.expirationDate } : {}) };
  };
  const warn = (parent: Extra, child: Extra) =>
    attenuationWarnings(link("p", undefined, { scopes: ["read"], ...parent }), link("c", "p", { scopes: ["read"], ...child }));

  it("says nothing about a child that narrows every dimension", () => {
    const limit = { maxRows: 100, columns: ["a", "b"] };
    expect(
      warn(
        { scopes: [], crisp: [{ resource: "notes", matcher: "path-prefix", constraints: limit }], audience: [SERVER, "did:web:other.example"], notAfter: 2000 },
        { scopes: [], crisp: [{ resource: "notes/2026", matcher: "path-prefix", constraints: limit }], audience: SERVER, notAfter: 1000 },
      ),
    ).toEqual([]);
  });

  describe("expiry", () => {
    it("reports a child that expires after its parent", () => {
      expect(warn({ notAfter: 1000 }, { notAfter: 1001 })).toEqual(["Delegation c expires after parent p"]);
    });
    it("reports a child with no expiry under a parent that has one", () => {
      expect(warn({ notAfter: 1000 }, {})).toEqual(["Delegation c states no expiry but parent p does"]);
    });
    it("reads the earlier of expirationDate and notAfter on both sides", () => {
      const parent = { notAfter: 5000, expirationDate: new Date(1000 * 1000).toISOString() };
      expect(warn(parent, { notAfter: 1000 })).toEqual([]);
      expect(warn(parent, { notAfter: 1001 })).toEqual(["Delegation c expires after parent p"]);
      expect(warn(parent, { notAfter: 9000, expirationDate: new Date(999 * 1000).toISOString() })).toEqual([]);
    });
    it("accepts an equal expiry, and any expiry under a parent without one", () => {
      expect(warn({ notAfter: 1000 }, { notAfter: 1000 })).toEqual([]);
      expect(warn({}, { notAfter: 1000 })).toEqual([]);
      expect(warn({}, {})).toEqual([]);
    });
    it("ignores an unreadable expirationDate, which the per-credential check refuses on its own", () => {
      expect(warn({ expirationDate: "not a date", notAfter: 1000 }, { notAfter: 1000 })).toEqual([]);
      expect(warn({ expirationDate: "not a date" }, {})).toEqual([]);
    });
  });

  describe("audience", () => {
    it("reports each audience the parent does not name", () => {
      expect(warn({ audience: SERVER }, { audience: [SERVER, "did:web:b.example", "did:web:c.example"] })).toEqual([
        "Delegation c names an audience parent p does not: did:web:b.example, did:web:c.example",
      ]);
    });
    it("reports a child with no audience under a parent that names one", () => {
      expect(warn({ audience: [SERVER] }, {})).toEqual(["Delegation c names no audience but parent p does"]);
    });
    it("accepts a subset in either form, and any audience under a parent without one", () => {
      expect(warn({ audience: [SERVER, "did:web:b.example"] }, { audience: SERVER })).toEqual([]);
      expect(warn({ audience: SERVER }, { audience: [SERVER] })).toEqual([]);
      expect(warn({}, { audience: "did:web:anywhere.example" })).toEqual([]);
    });
  });

  describe("per-scope constraints", () => {
    const constrained = (constraints: Record<string, unknown>, resource = "notes"): CrispScope => ({
      resource,
      matcher: "path-prefix",
      constraints,
    });
    const dropped = "Delegation c scope path-prefix:notes/2026 does not repeat the constraints parent p places on it";

    it("reports a child scope that drops its parent's constraints", () => {
      expect(
        warn({ scopes: [], crisp: [constrained({ maxRows: 100 })] }, { scopes: [], crisp: [{ resource: "notes/2026", matcher: "path-prefix" }] }),
      ).toEqual([dropped]);
    });
    it("reports a changed value, since the verifier cannot tell tighter from looser", () => {
      expect(
        warn({ scopes: [], crisp: [constrained({ maxRows: 100 })] }, { scopes: [], crisp: [constrained({ maxRows: 50 }, "notes/2026")] }),
      ).toEqual([dropped]);
    });
    it("reports a missing key even when the others are repeated", () => {
      expect(
        warn(
          { scopes: [], crisp: [constrained({ maxRows: 100, region: "eu" })] },
          { scopes: [], crisp: [constrained({ maxRows: 100 }, "notes/2026")] },
        ),
      ).toEqual([dropped]);
    });
    it("accepts every key repeated with an equal value, in any key order, with keys of its own", () => {
      expect(
        warn(
          { scopes: [], crisp: [constrained({ window: { from: 1, to: 2 }, maxRows: 100 })] },
          { scopes: [], crisp: [constrained({ maxRows: 100, window: { to: 2, from: 1 }, purpose: "audit" }, "notes/2026")] },
        ),
      ).toEqual([]);
    });
    it("reports a flat child scope that only a constrained parent scope covers", () => {
      expect(warn({ scopes: [], crisp: [{ resource: "read", matcher: "exact", constraints: { maxRows: 1 } }] }, {})).toEqual([
        "Delegation c scope exact:read does not repeat the constraints parent p places on it",
      ]);
    });
    it("says nothing when a flat parent scope or an unconstrained matcher also covers the child scope", () => {
      const child = { scopes: ["notes/2026"], crisp: [{ resource: "notes/2026", matcher: "path-prefix" as const }] };
      expect(warn({ scopes: ["notes/2026"], crisp: [constrained({ maxRows: 100 })] }, { ...child, crisp: [] })).toEqual([]);
      expect(
        warn({ scopes: [], crisp: [constrained({ maxRows: 100 }), { resource: "notes", matcher: "path-prefix", constraints: {} }] }, { ...child, scopes: [] }),
      ).toEqual([]);
    });
    it("is satisfied by repeating any one covering parent scope's constraints", () => {
      expect(
        warn(
          { scopes: [], crisp: [constrained({ maxRows: 100 }), constrained({ region: "eu" }, "notes/2026")] },
          { scopes: [], crisp: [constrained({ region: "eu" }, "notes/2026/q3")] },
        ),
      ).toEqual([]);
    });
    it("says nothing about a scope the parent does not cover, which scope attenuation already refuses", () => {
      expect(warn({ scopes: [], crisp: [constrained({ maxRows: 100 })] }, { scopes: ["admin"] })).toEqual([]);
    });
    it("reports a constraint value that cannot be canonicalized, rather than throwing", () => {
      expect(
        warn({ scopes: [], crisp: [constrained({ cap: 10n })] }, { scopes: [], crisp: [constrained({ cap: 10n }, "notes/2026")] }),
      ).toEqual([dropped]);
    });
  });

  it("reports one scope once however many times the child lists it", () => {
    // cred() writes each flat scope to both delegation.scopes and constraints.scopes.
    expect(warn({ scopes: [], crisp: [{ resource: "read", matcher: "exact", constraints: { maxRows: 1 } }] }, { scopes: ["read"] })).toHaveLength(1);
  });

  it("never throws on a malformed credential", () => {
    const withConstraints = (constraints: unknown, scopes?: unknown) => ({ credentialSubject: { delegation: { ...(scopes !== undefined ? { scopes } : {}), constraints } } });
    const malformed = [
      undefined,
      null,
      {},
      { credentialSubject: {} },
      withConstraints({ audience: 7, crisp: { scopes: [null, 3, {}] } }),
      // Scope fields that are not lists: the shipped readers spread them.
      withConstraints({}, 5),
      withConstraints({ scopes: 5 }),
      withConstraints({ crisp: { scopes: {} } }),
      withConstraints({ crisp: { scopes: 5 } }),
      withConstraints({ notAfter: {}, audience: [null, {}] }),
    ];
    for (const parent of malformed) {
      for (const child of malformed) {
        expect(() => attenuationWarnings(parent as unknown as DelegationCredential, child as unknown as DelegationCredential)).not.toThrow();
      }
    }
  });

  describe("in validateDelegationChain", () => {
    const root = link("root", undefined, { scopes: ["read", "write"], audience: SERVER, notAfter: 1000 });
    const deps = (ancestors: DelegationCredential[]): ChainEnforcementDeps => ({ ...baseDeps, resolveDelegationChain: async () => ancestors });

    it("validates the chain and returns the warnings, hop by hop, root first", async () => {
      const middle = { ...link("middle", "root", { scopes: ["read"], audience: SERVER, notAfter: 2000 }), issuer: "did:agent" };
      const leaf = {
        ...cred({ id: "leaf", issuerDid: "did:sub", subjectDid: "did:leaf", parentId: "middle", scopes: ["read"], audience: [SERVER, "did:web:b.example"] }),
      };
      const result = await validateDelegationChain(leaf, deps([root, middle]));
      expect(result.valid).toBe(true);
      expect(result.expiresAt).toBe(1000 * 1000);
      expect(result.warnings).toEqual([
        "Delegation middle expires after parent root",
        "Delegation leaf states no expiry but parent middle does",
        "Delegation leaf names an audience parent middle does not: did:web:b.example",
      ]);
    });

    it("returns no warnings for a chain that narrows", async () => {
      const leaf = link("leaf", "root", { scopes: ["read"], audience: SERVER, notAfter: 500 });
      expect(await validateDelegationChain(leaf, deps([root]))).toEqual({ valid: true, expiresAt: 500 * 1000 });
    });

    it("still validates a chain whose scope fields it cannot read", async () => {
      // An unrestricted parent accepts any child without reading the child's scopes,
      // so this chain validated before the warnings existed and must not throw now.
      const openRoot = link("root", undefined, { audience: SERVER });
      openRoot.credentialSubject.delegation.constraints = { audience: SERVER };
      delete openRoot.credentialSubject.delegation.scopes;
      const leaf = link("leaf", "root", { audience: SERVER });
      leaf.credentialSubject.delegation.constraints = { audience: SERVER, crisp: { scopes: {} } } as never;
      delete leaf.credentialSubject.delegation.scopes;
      expect(await validateDelegationChain(leaf, deps([openRoot]))).toEqual({ valid: true });
    });

    it("returns no warnings with a refusal", async () => {
      const leaf = link("leaf", "root", { scopes: ["admin"], audience: SERVER, notAfter: 2000 });
      const result = await validateDelegationChain(leaf, deps([root]));
      expect(result.valid).toBe(false);
      expect(result.warnings).toBeUndefined();
    });
  });
});
