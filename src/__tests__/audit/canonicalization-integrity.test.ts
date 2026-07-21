/**
 * Canonicalization Integrity Audit Tests
 *
 * Verifies that JSON canonicalization (RFC 8785 JCS) produces deterministic
 * output, that assertJsonSafe rejects dangerous inputs, and that
 * canonicalization is consistent across modules.
 */

import { describe, it, expect } from 'vitest';
import { canonicalizeJSON } from '../../delegation/utils.js';
import { canonicalize } from 'json-canonicalize';
import { ProofGenerator } from '../../proof/generator.js';
import { NodeCryptoProvider } from '../utils/node-crypto-provider.js';
import { MemoryIdentityProvider } from '../../providers/memory.js';

describe('Canonicalization Integrity Audit', () => {
  // ── Determinism ───────────────────────────────────────────────

  describe('deterministic output', () => {
    it('should produce identical output regardless of key insertion order', () => {
      const a = canonicalizeJSON({ b: 1, a: 2 });
      const b = canonicalizeJSON({ a: 2, b: 1 });
      expect(a).toBe(b);
    });

    it('should produce identical output for nested objects with different key orders', () => {
      const a = canonicalizeJSON({
        z: { y: 1, x: 2 },
        a: { c: 3, b: 4 },
      });
      const b = canonicalizeJSON({
        a: { b: 4, c: 3 },
        z: { x: 2, y: 1 },
      });
      expect(a).toBe(b);
    });

    it('should handle arrays with objects in deterministic order', () => {
      const a = canonicalizeJSON([
        { z: 1, a: 2 },
        { b: 3, a: 4 },
      ]);
      const b = canonicalizeJSON([
        { a: 2, z: 1 },
        { a: 4, b: 3 },
      ]);
      expect(a).toBe(b);
    });

    it('should handle deeply nested structures deterministically', () => {
      const a = canonicalizeJSON({
        level1: {
          level2: {
            level3: { c: 3, b: 2, a: 1 },
          },
        },
      });
      const b = canonicalizeJSON({
        level1: {
          level2: {
            level3: { a: 1, b: 2, c: 3 },
          },
        },
      });
      expect(a).toBe(b);
    });
  });

  // ── assertJsonSafe Guards ─────────────────────────────────────

  describe('assertJsonSafe rejection of non-JSON values', () => {
    it('should reject Infinity', () => {
      expect(() => canonicalizeJSON({ val: Infinity })).toThrow(TypeError);
    });

    it('should reject -Infinity', () => {
      expect(() => canonicalizeJSON({ val: -Infinity })).toThrow(TypeError);
    });

    it('should reject NaN', () => {
      expect(() => canonicalizeJSON({ val: NaN })).toThrow(TypeError);
    });

    it('should reject undefined', () => {
      expect(() => canonicalizeJSON(undefined)).toThrow(TypeError);
    });

    it('should reject functions', () => {
      expect(() => canonicalizeJSON({ fn: () => {} })).toThrow(TypeError);
    });

    it('should reject symbols', () => {
      expect(() => canonicalizeJSON({ sym: Symbol('test') })).toThrow(TypeError);
    });

    it('should reject bigint', () => {
      expect(() => canonicalizeJSON({ big: BigInt(42) })).toThrow(TypeError);
    });

    it('should reject nested non-finite values', () => {
      expect(() =>
        canonicalizeJSON({ nested: { deep: { val: NaN } } })
      ).toThrow(TypeError);
    });

    it('should reject non-finite values in arrays', () => {
      expect(() => canonicalizeJSON([1, 2, Infinity])).toThrow(TypeError);
    });

    it('should reject integers that cannot be represented exactly by JavaScript', () => {
      expect(() => canonicalizeJSON({ sequence: Number.MAX_SAFE_INTEGER + 1 })).toThrow(
        'Cannot canonicalize unsafe integer at $.sequence',
      );
    });

    it('should reject cyclic objects with a stable path-aware error', () => {
      const cyclic: Record<string, unknown> = {};
      cyclic['self'] = cyclic;

      expect(() => canonicalizeJSON(cyclic)).toThrow(
        'Cannot canonicalize cyclic reference at $.self',
      );
    });
  });

  // ── Valid JSON Values ─────────────────────────────────────────

  describe('valid JSON values are accepted', () => {
    it('should accept null', () => {
      expect(() => canonicalizeJSON(null)).not.toThrow();
    });

    it('should accept booleans', () => {
      expect(() => canonicalizeJSON(true)).not.toThrow();
      expect(() => canonicalizeJSON(false)).not.toThrow();
    });

    it('should accept finite numbers', () => {
      expect(() => canonicalizeJSON(42)).not.toThrow();
      expect(() => canonicalizeJSON(-0.5)).not.toThrow();
      expect(() => canonicalizeJSON(0)).not.toThrow();
    });

    it('should accept strings', () => {
      expect(() => canonicalizeJSON('hello')).not.toThrow();
    });

    it('should accept empty objects and arrays', () => {
      expect(() => canonicalizeJSON({})).not.toThrow();
      expect(() => canonicalizeJSON([])).not.toThrow();
    });
  });

  // ── Cross-Module Consistency ──────────────────────────────────

  describe('cross-module consistency', () => {
    it('should match json-canonicalize output for safe inputs', () => {
      const input = {
        method: 'tools/call',
        params: { name: 'test-tool', arguments: { x: 1, y: 'hello' } },
      };

      const fromUtils = canonicalizeJSON(input);
      const fromLib = canonicalize(input);

      expect(fromUtils).toBe(fromLib);
    });

    it('should match for VC-like structures', () => {
      const vcLike = {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential', 'DelegationCredential'],
        issuer: 'did:key:z6MkTest',
        credentialSubject: {
          id: 'did:key:z6MkSubject',
          delegation: {
            scopes: ['tools:read'],
            constraints: { notAfter: 1234567890 },
          },
        },
      };

      expect(canonicalizeJSON(vcLike)).toBe(canonicalize(vcLike));
    });
  });

  // ── ProofGenerator Hash Determinism ───────────────────────────

  describe('ProofGenerator hash determinism across key orderings', () => {
    it('should produce same requestHash for objects with different key orders', async () => {
      const crypto = new NodeCryptoProvider();
      const identityProvider = new MemoryIdentityProvider(crypto);
      const agent = await identityProvider.getIdentity();

      const gen = new ProofGenerator(
        { did: agent.did, kid: agent.kid, privateKey: agent.privateKey, publicKey: agent.publicKey },
        crypto
      );

      const session = {
        sessionId: 'sess_canon_test',
        audience: 'did:web:server.example.com',
        nonce: 'test-nonce-canon',
        timestamp: Math.floor(Date.now() / 1000),
        createdAt: Math.floor(Date.now() / 1000),
        lastActivity: Math.floor(Date.now() / 1000),
        ttlMinutes: 30,
        identityState: 'anonymous' as const,
      };

      const request1 = { method: 'tools/call', params: { x: 1, y: 2, z: 3 } };
      const request2 = { method: 'tools/call', params: { z: 3, x: 1, y: 2 } };
      const response = { data: { result: 'ok' } };

      const proof1 = await gen.generateProof(request1, response, session);
      const proof2 = await gen.generateProof(request2, response, session);

      expect(proof1.meta.requestHash).toBe(proof2.meta.requestHash);
    });

    it('should produce different hashes for genuinely different inputs', async () => {
      const crypto = new NodeCryptoProvider();
      const identityProvider = new MemoryIdentityProvider(crypto);
      const agent = await identityProvider.getIdentity();

      const gen = new ProofGenerator(
        { did: agent.did, kid: agent.kid, privateKey: agent.privateKey, publicKey: agent.publicKey },
        crypto
      );

      const session = {
        sessionId: 'sess_diff_test',
        audience: 'did:web:server.example.com',
        nonce: 'test-nonce-diff',
        timestamp: Math.floor(Date.now() / 1000),
        createdAt: Math.floor(Date.now() / 1000),
        lastActivity: Math.floor(Date.now() / 1000),
        ttlMinutes: 30,
        identityState: 'anonymous' as const,
      };

      const response = { data: { result: 'ok' } };

      const proof1 = await gen.generateProof(
        { method: 'tools/call', params: { input: 'alice' } },
        response,
        session
      );
      const proof2 = await gen.generateProof(
        { method: 'tools/call', params: { input: 'bob' } },
        response,
        session
      );

      expect(proof1.meta.requestHash).not.toBe(proof2.meta.requestHash);
    });
  });
});
