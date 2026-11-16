/**
 * KYA-OS Middleware — pure, dependency-free helpers.
 *
 * Referentially-transparent utilities used by `createKyaOsMiddleware`, split out
 * of `./with-kya-os.ts` so the factory module stays focused on wiring. No shared
 * mutable state, no I/O — safe to unit test in isolation.
 */

import type { DelegationCredential } from "../types/protocol.js";
import { getDelegationScopes } from "../delegation/chain-enforcement.js";
import { isKyaOsControlArg } from "../proof/covered-request.js";

// The delegation verifier sanitizes text with it too, so it is defined below both, in utils.
export { sanitizeForMessage, type MessageText } from "../utils/message-text.js";

/**
 * The argument that carries approval grants by default, and the one
 * `wrapWithDelegation` forwards to a composed policy gate in the call context.
 */
export const DEFAULT_APPROVALS_KEY = "_kyaos_approvals";

/**
 * `args` without the reserved `_kyaos*` control arguments: the call as its
 * handler sees it, and as a gate's request hash binds it.
 */
export function withoutControlArgs(
  args: Record<string, unknown>,
): Record<string, unknown> {
  const clean: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(args)) {
    if (!isKyaOsControlArg(key)) clean[key] = value;
  }
  return clean;
}

/** Best-effort projection of a delegation VC into policy principal facts. */
export function extractPolicyPrincipal(del: unknown): {
  agentDid: string;
  responsibleParty?: string;
  delegatedScopes: string[];
} {
  if (!del || typeof del !== "object") {
    return { agentDid: "unknown", delegatedScopes: [] };
  }
  try {
    const vc = del as DelegationCredential;
    const subject = vc.credentialSubject as unknown as {
      id?: string;
      delegation?: { subjectDid?: string; controller?: string };
    };
    const agentDid = subject?.delegation?.subjectDid ?? subject?.id ?? "unknown";
    const responsibleParty = subject?.delegation?.controller;
    let delegatedScopes: string[] = [];
    try {
      delegatedScopes = getDelegationScopes(vc);
    } catch {
      delegatedScopes = [];
    }
    return {
      agentDid,
      ...(responsibleParty ? { responsibleParty } : {}),
      delegatedScopes,
    };
  } catch {
    return { agentDid: "unknown", delegatedScopes: [] };
  }
}
