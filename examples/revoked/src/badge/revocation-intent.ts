/**
 * Revocation intent + its content hash — the thing a badge assertion is bound to.
 *
 * The WebAuthn challenge IS sha256(canonical intent). A verified assertion
 * therefore proves the badge holder approved THIS specific revocation (this
 * status list, this index), not a generic login — RFC-style intent binding.
 * The intent is server-built and server-held, so a client cannot substitute a
 * different one; the hash equality is defense-in-depth and an audit anchor.
 */
import { createHash } from 'node:crypto';
import { canonicalizeJSON } from '@kya-os/mcp';

export interface RevocationIntent {
  action: 'revoke';
  statusListUrl: string;
  index: number;
  nonce: string;
  ts: number;
}

export interface BuiltIntent {
  intent: RevocationIntent;
  /** 32-byte SHA-256 of the canonical intent — passed as the WebAuthn challenge. */
  digest: Uint8Array<ArrayBuffer>;
  /** base64url(digest) — the `expectedChallenge` for verifyAuthenticationResponse. */
  challengeB64u: string;
}

export function hashIntent(intent: RevocationIntent): BuiltIntent {
  const canonical = canonicalizeJSON(intent as unknown as Record<string, unknown>);
  const digest = createHash('sha256').update(canonical, 'utf8').digest();
  return {
    intent,
    // Uint8Array.from allocates a fresh ArrayBuffer (not ArrayBufferLike), which
    // is what @simplewebauthn's challenge option requires.
    digest: Uint8Array.from(digest),
    challengeB64u: digest.toString('base64url'),
  };
}

export function buildRevocationIntent(options: {
  statusListUrl: string;
  index: number;
  nonce: string;
  ts: number;
}): BuiltIntent {
  return hashIntent({
    action: 'revoke',
    statusListUrl: options.statusListUrl,
    index: options.index,
    nonce: options.nonce,
    ts: options.ts,
  });
}
