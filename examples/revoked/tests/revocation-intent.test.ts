/**
 * Intent-binding is the security property of badge-gated revocation: the
 * WebAuthn challenge IS sha256(canonical intent), so a verified assertion is
 * bound to THIS revocation. These tests pin that binding without hardware.
 */
import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { canonicalizeJSON } from '@kya-os/mcp';
import { buildRevocationIntent, hashIntent, type RevocationIntent } from '../src/badge/revocation-intent.js';

const base = {
  statusListUrl: 'https://resolver.cheqd.net/1.0/identifiers/did:cheqd:testnet:abc?resourceName=kya-statuslist-demo&resourceType=StatusListCredential',
  index: 94,
  nonce: 'fixed-nonce-aaaa',
  ts: 1786150000000,
};

describe('revocation intent hashing', () => {
  it('challenge is base64url(sha256(canonical intent))', () => {
    const built = buildRevocationIntent(base);
    const canonical = canonicalizeJSON({ action: 'revoke', ...base } as unknown as Record<string, unknown>);
    const expected = createHash('sha256').update(canonical, 'utf8').digest();
    expect(built.challengeB64u).toBe(expected.toString('base64url'));
    expect(Buffer.from(built.digest)).toEqual(expected);
    expect(built.challengeB64u).toMatch(/^[A-Za-z0-9_-]{43}$/); // 32 bytes → 43 base64url chars
  });

  it('is deterministic for identical intent', () => {
    expect(buildRevocationIntent(base).challengeB64u).toBe(buildRevocationIntent(base).challengeB64u);
  });

  it('changes if the index changes (bind to THIS revocation, not a generic login)', () => {
    const a = buildRevocationIntent(base).challengeB64u;
    const b = buildRevocationIntent({ ...base, index: 95 }).challengeB64u;
    expect(a).not.toBe(b);
  });

  it('changes if the status list URL, nonce, or timestamp changes', () => {
    const a = buildRevocationIntent(base).challengeB64u;
    expect(buildRevocationIntent({ ...base, statusListUrl: base.statusListUrl + 'x' }).challengeB64u).not.toBe(a);
    expect(buildRevocationIntent({ ...base, nonce: 'other-nonce-bbbb' }).challengeB64u).not.toBe(a);
    expect(buildRevocationIntent({ ...base, ts: base.ts + 1 }).challengeB64u).not.toBe(a);
  });

  it('tampering any field yields a hash that would fail the badge-signed challenge', () => {
    const genuine = buildRevocationIntent(base);
    const tampered: RevocationIntent = { ...genuine.intent, index: 999 };
    // The badge signs over `genuine.challengeB64u`; the verifier recomputes from
    // the (server-held) intent. A swapped intent → different hash → assertion
    // cannot verify against expectedChallenge.
    expect(hashIntent(tampered).challengeB64u).not.toBe(genuine.challengeB64u);
  });
});
