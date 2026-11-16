/**
 * Test helper: delegation credentials for the chain walk, and the deps it
 * runs with, a server that resolves them included.
 */
import type { ChainEnforcementDeps, DelegationCredentialVerifierPort } from "../../chain-enforcement.js";
import type { CrispScope, DelegationCredential } from "../../../types/protocol.js";

export const SERVER = "did:web:server.example";

/** Minimal well-formed delegation credential for the chain-walk under test. */
export function cred(opts: {
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

export const okVerifier: DelegationCredentialVerifierPort = {
  verifyDelegationCredential: async () => ({ valid: true }),
};

export const baseDeps: ChainEnforcementDeps = {
  serverDid: SERVER,
  verifier: okVerifier,
  statusListConfigured: true,
};

/**
 * A chain of three, user to agent to sub-agent to tool, that narrows to
 * `read` for SERVER: the leaf is presented, the root and middle resolved.
 */
export function chainOfThree() {
  const root = cred({ id: "root", issuerDid: "did:user", subjectDid: "did:agent", scopes: ["read", "list"] });
  const middle = cred({ id: "middle", issuerDid: "did:agent", subjectDid: "did:sub", parentId: "root", scopes: ["read"], audience: SERVER });
  const leaf = cred({ id: "leaf", issuerDid: "did:sub", subjectDid: "did:tool", parentId: "middle", scopes: ["read"], audience: SERVER });
  return { root, middle, leaf };
}

/** The base deps, with a resolver that returns `resolved`. */
export const resolving = (resolved: DelegationCredential[]): ChainEnforcementDeps => ({
  ...baseDeps,
  resolveDelegationChain: async () => resolved,
});
