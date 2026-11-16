/**
 * KYA-OS Middleware — pure, dependency-free helpers.
 *
 * Referentially-transparent utilities used by `createKyaOsMiddleware`, split out
 * of `./with-kya-os.ts` so the factory module stays focused on wiring. No shared
 * mutable state, no I/O — safe to unit test in isolation.
 */

import type { DelegationCredential } from "../types/protocol.js";
import { getDelegationScopes } from "../delegation/chain-enforcement.js";
/** The one copy of a call without its control arguments, for the gates in this folder. */
export { withoutControlArgs } from "../proof/covered-request.js";

// The delegation verifier sanitizes text with it too, so it is defined below both, in utils.
export { sanitizeForMessage, type MessageText } from "../utils/message-text.js";

/**
 * The argument that carries approval grants by default, and the one
 * `wrapWithDelegation` forwards to a composed policy gate in the call context.
 */
export const DEFAULT_APPROVALS_KEY = "_kyaos_approvals";

/**
 * What a `_kyaos_delegation` argument that nothing verified claims about its caller, for a
 * `withPolicyGate` that no `wrapWithDelegation` precedes: the subject the credential names and the
 * scopes it lists, both only claims of whoever wrote the argument. It names no Responsible Party:
 * that is the root issuer of a verified chain (SPEC.md §2), which only the delegation gate
 * establishes, and the `controller` a credential states is a DID its author chose.
 */
export function extractPolicyPrincipal(del: unknown): {
  agentDid: string;
  delegatedScopes: string[];
} {
  if (!del || typeof del !== "object") {
    return { agentDid: "unknown", delegatedScopes: [] };
  }
  try {
    const vc = del as DelegationCredential;
    const subject = vc.credentialSubject as unknown as {
      id?: string;
      delegation?: { subjectDid?: string };
    };
    const agentDid = subject?.delegation?.subjectDid ?? subject?.id ?? "unknown";
    let delegatedScopes: string[] = [];
    try {
      delegatedScopes = getDelegationScopes(vc);
    } catch {
      delegatedScopes = [];
    }
    return { agentDid, delegatedScopes };
  } catch {
    return { agentDid: "unknown", delegatedScopes: [] };
  }
}
