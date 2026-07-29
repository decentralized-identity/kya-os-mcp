/**
 * The response-proof `_meta` carrier key and its acceptance window (SPEC §7.5-§7.6).
 *
 * The canonical key is role-named (`org.kya-os/response-proof`) so it cannot be
 * misread as a version sibling of the request proof's `org.kya-os/request-proof`.
 * Two prior keys stay read-accepted for one major version: the namespaced
 * `org.kya-os/proof` (canonical from 1.1 until the rename) and the original
 * bare `proof`. The newest canonical form wins when several are present.
 */

import { describe, it, expect } from 'vitest';
import {
  KYA_OS_PROOF_META_KEY,
  LEGACY_NAMESPACED_PROOF_META_KEY,
  LEGACY_PROOF_META_KEY,
} from '../generator.js';
import { extractProofFromMeta, validateMetaStructure } from '../verifier.js';

const proofAt = (label: string) => ({
  jws: `eyJhbGciOiJFZERTQSJ9.e30.${label}`,
  meta: {
    did: 'did:web:server.example.com',
    kid: 'did:web:server.example.com#key-1',
    ts: 1782820800,
    nonce: `nonce-${label}`,
    audience: 'did:web:server.example.com',
    sessionId: 'kyaos_compat-test',
    requestHash: 'sha256:' + 'a'.repeat(64),
    responseHash: 'sha256:' + 'b'.repeat(64),
  },
});

describe('response-proof _meta carrier key', () => {
  it('is role-named and grammar-legal (no @; alnum/-/_/. only)', () => {
    expect(KYA_OS_PROOF_META_KEY).toBe('org.kya-os/response-proof');
    const name = KYA_OS_PROOF_META_KEY.split('/')[1];
    expect(name).toMatch(/^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$/);
  });

  it('extracts from the canonical key', () => {
    const r = extractProofFromMeta({ [KYA_OS_PROOF_META_KEY]: proofAt('new') });
    expect(r.success).toBe(true);
  });

  it('falls back to the prior namespaced key (one-major-version window)', () => {
    const r = extractProofFromMeta({ [LEGACY_NAMESPACED_PROOF_META_KEY]: proofAt('prior') });
    expect(r.success).toBe(true);
    if (r.success) expect(r.proof.meta.nonce).toBe('nonce-prior');
  });

  it('still falls back to the original bare key', () => {
    const r = extractProofFromMeta({ [LEGACY_PROOF_META_KEY]: proofAt('bare') });
    expect(r.success).toBe(true);
    if (r.success) expect(r.proof.meta.nonce).toBe('nonce-bare');
  });

  it('the newest canonical form wins when several keys are present', () => {
    const r = extractProofFromMeta({
      [LEGACY_PROOF_META_KEY]: proofAt('bare'),
      [LEGACY_NAMESPACED_PROOF_META_KEY]: proofAt('prior'),
      [KYA_OS_PROOF_META_KEY]: proofAt('new'),
    });
    expect(r.success).toBe(true);
    if (r.success) expect(r.proof.meta.nonce).toBe('nonce-new');
    const r2 = extractProofFromMeta({
      [LEGACY_PROOF_META_KEY]: proofAt('bare'),
      [LEGACY_NAMESPACED_PROOF_META_KEY]: proofAt('prior'),
    });
    expect(r2.success).toBe(true);
    if (r2.success) expect(r2.proof.meta.nonce).toBe('nonce-prior');
  });

  it('strict metaPolicy treats all three as the proof key (no extraKeys)', () => {
    const result = validateMetaStructure(
      {
        [KYA_OS_PROOF_META_KEY]: proofAt('new'),
        [LEGACY_NAMESPACED_PROOF_META_KEY]: proofAt('prior'),
        [LEGACY_PROOF_META_KEY]: proofAt('bare'),
        traceparent: '00-abc-def-01',
      },
      'allow-extensions',
    );
    expect(result.valid).toBe(true);
    expect(result.extraKeys).toEqual(['traceparent']);
  });
});
