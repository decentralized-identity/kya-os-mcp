/**
 * KYA-OS Middleware — pure, dependency-free helpers.
 *
 * Referentially-transparent utilities used by `createKyaOsMiddleware`, split out
 * of `./with-kya-os.ts` so the factory module stays focused on wiring. No shared
 * mutable state, no I/O — safe to unit test in isolation.
 */

import type { DelegationCredential } from "../types/protocol.js";
import { getDelegationScopes } from "../delegation/chain-enforcement.js";

/**
 * Strip control characters and cap length on caller-derived values before they
 * are interpolated into client-facing reasons or log lines. A hostile
 * credential could otherwise embed newlines / control chars in an id or scope to
 * forge or corrupt log entries (log injection) or break a terminal. The fixed
 * parts of a reason contain no control chars, so sanitizing the whole assembled
 * string at the emission boundary is equivalent to sanitizing each interpolated
 * value, and is idempotent.
 */
export function sanitizeForMessage(value: unknown, maxLen = 256): string {
  const s = typeof value === "string" ? value : String(value);
  // Replace C0/C1 control chars (incl. CR, LF, TAB, ESC, DEL) with U+FFFD so a
  // hostile id/scope cannot forge log lines or break a terminal. Filtered by
  // code point to keep this source ASCII-only (no literal control chars).
  let out = "";
  for (const ch of s) {
    const code = ch.codePointAt(0) ?? 0;
    out += code <= 0x1f || (code >= 0x7f && code <= 0x9f) ? "\uFFFD" : ch;
  }
  return out.length > maxLen ? `${out.slice(0, maxLen)}\u2026` : out;
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
