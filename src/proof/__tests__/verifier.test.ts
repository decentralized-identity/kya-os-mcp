/**
 * Tests for ProofVerifier
 *
 * Comprehensive security test coverage for proof verification service.
 * Tests nonce replay protection, timestamp skew validation, canonical payload reconstruction,
 * and various security attack scenarios.
 *
 * Test Coverage Requirements: 100% - All security-critical code paths
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  ProofVerifier,
  validateMetaStructure,
  extractProofFromMeta,
  DEFAULT_CLOCK_SKEW_SECONDS,
  MIN_CLOCK_SKEW_SECONDS,
  MAX_CLOCK_SKEW_SECONDS,
} from '../verifier.js';
import {
  KYA_OS_PROOF_META_KEY,
  LEGACY_PROOF_META_KEY,
} from '../generator.js';
import { isReservedMcpMetaKey } from '../verifier.js';
import { CryptoService, type Ed25519JWK } from '../../utils/crypto-service.js';
import type {
  CryptoProvider,
  ClockProvider,
  NonceCacheProvider,
  FetchProvider,
} from '../../providers/base.js';
import type { DetachedProof, MetaPolicy } from '../../types/protocol.js';
import { validateDetachedProof } from '../../types/protocol.js';
import {
  ProofVerificationError,
  PROOF_VERIFICATION_ERROR_CODES,
} from '../errors.js';

describe('ProofVerifier Security', () => {
  let proofVerifier: ProofVerifier;
  let mockCryptoProvider: CryptoProvider;
  let mockClockProvider: ClockProvider;
  let mockNonceCache: NonceCacheProvider;
  let mockFetchProvider: FetchProvider;
  let cryptoService: CryptoService;

  const validJwk: Ed25519JWK = {
    kty: 'OKP',
    crv: 'Ed25519',
    x: 'VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ',
    kid: 'did:key:z123#z123',
  };

  const createValidProof = (): DetachedProof => {
    const header = { alg: 'EdDSA', typ: 'JWT', kid: 'did:key:z123#z123' };
    // Create a proper JSON payload that matches the meta structure
    const payload = {
      aud: 'test-audience',
      sub: 'did:key:z123',
      iss: 'did:key:z123',
      nonce: 'nonce123',
      ts: Math.floor(Date.now() / 1000),
      sessionId: 'session123',
      requestHash: 'sha256:' + 'a'.repeat(64),
      responseHash: 'sha256:' + 'b'.repeat(64),
    };
    // Use btoa for base64 encoding (available in test environment via polyfill)
    const headerB64 = btoa(JSON.stringify(header))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    const payloadB64 = btoa(JSON.stringify(payload))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    const signatureB64 = btoa('signature')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    const jws = `${headerB64}.${payloadB64}.${signatureB64}`;

    return {
      jws,
      meta: {
        did: 'did:key:z123',
        kid: 'did:key:z123#z123',
        ts: Math.floor(Date.now() / 1000),
        nonce: 'nonce123',
        audience: 'test-audience',
        sessionId: 'session123',
        requestHash: 'sha256:' + 'a'.repeat(64),
        responseHash: 'sha256:' + 'b'.repeat(64),
      },
    };
  };

  beforeEach(() => {
    mockCryptoProvider = {
      sign: vi.fn(),
      verify: vi.fn().mockResolvedValue(true),
      generateKeyPair: vi.fn(),
      hash: vi.fn(),
      randomBytes: vi.fn(),
    };

    cryptoService = new CryptoService(mockCryptoProvider);

    mockClockProvider = {
      now: vi.fn().mockReturnValue(Date.now()), // Return milliseconds
      isWithinSkew: vi.fn().mockReturnValue(true),
      hasExpired: vi.fn(),
      calculateExpiry: vi.fn((ttlSeconds: number) => Date.now() + (ttlSeconds * 1000)), // Return milliseconds
      format: vi.fn(),
    };

    mockNonceCache = {
      has: vi.fn().mockResolvedValue(false),
      add: vi.fn().mockResolvedValue(undefined),
      cleanup: vi.fn().mockResolvedValue(undefined),
      destroy: vi.fn().mockResolvedValue(undefined),
    };

    mockFetchProvider = {
      resolveDID: vi.fn().mockResolvedValue({
        verificationMethod: [{
          id: 'did:key:z123#z123',
          publicKeyJwk: validJwk,
        }],
      }),
      fetchStatusList: vi.fn(),
      fetchDelegationChain: vi.fn(),
      fetch: vi.fn(),
    };

    proofVerifier = new ProofVerifier({
      cryptoProvider: mockCryptoProvider,
      clockProvider: mockClockProvider,
      nonceCacheProvider: mockNonceCache,
      fetchProvider: mockFetchProvider,
      timestampSkewSeconds: 120,
      nonceTtlSeconds: 300,
    });
  });

  describe('Nonce Replay Protection', () => {
    it('reconstructs the canonical payload for denial proofs (outcome/reason, no responseHash)', () => {
      const denialMeta = {
        did: 'did:key:z123',
        kid: 'did:key:z123#z123',
        ts: 1,
        nonce: 'n',
        audience: 'aud',
        sessionId: 's',
        requestHash: 'sha256:' + 'a'.repeat(64),
        outcome: 'denied' as const,
        reason: 'insufficient_scope',
      };
      const payload = proofVerifier.buildCanonicalPayload(denialMeta);
      expect(payload).toContain('"outcome":"denied"');
      expect(payload).toContain('"reason":"insufficient_scope"');
      expect(payload).not.toContain('responseHash');

      const allowedPayload = proofVerifier.buildCanonicalPayload({
        ...denialMeta,
        responseHash: 'sha256:' + 'b'.repeat(64),
        outcome: undefined,
        reason: undefined,
      });
      expect(allowedPayload).toContain('responseHash');
      expect(allowedPayload).not.toContain('outcome');
    });

    it('should prevent nonce replay attacks', async () => {
      const proof = createValidProof();

      // First verification should succeed
      const result1 = await proofVerifier.verifyProof(proof, validJwk);
      expect(result1.valid).toBe(true);
      expect(mockNonceCache.has).toHaveBeenCalledWith('nonce123', 'did:key:z123');
      expect(mockNonceCache.add).toHaveBeenCalled();

      // Reset mock to simulate second attempt
      mockNonceCache.has = vi.fn().mockResolvedValue(true);

      // Second verification with same nonce should fail
      const result2 = await proofVerifier.verifyProof(proof, validJwk);
      expect(result2.valid).toBe(false);
      expect(result2.reason).toContain('replay');
    });

    it('should add nonce to cache after successful verification', async () => {
      const proof = createValidProof();

      await proofVerifier.verifyProof(proof, validJwk);

      expect(mockNonceCache.add).toHaveBeenCalledWith(
        'nonce123',
        expect.any(Number),
        'did:key:z123'
      );
    });
  });

  describe('Historical artifact verification', () => {
    it('verifies cryptographic evidence without consuming live replay or freshness state', async () => {
      const proof = createValidProof();
      proof.meta.ts = 1;
      mockNonceCache.has = vi.fn().mockResolvedValue(true);
      mockClockProvider.isWithinSkew = vi.fn().mockReturnValue(false);

      const result = await proofVerifier.verifyProofArtifact(proof, validJwk);

      expect(result.valid).toBe(true);
      expect(mockNonceCache.has).not.toHaveBeenCalled();
      expect(mockNonceCache.add).not.toHaveBeenCalled();
      expect(mockClockProvider.isWithinSkew).not.toHaveBeenCalled();
      expect(mockCryptoProvider.verify).toHaveBeenCalled();
    });
  });

  describe('Timestamp Skew Validation', () => {
    it('should enforce timestamp skew limits', async () => {
      const proof = createValidProof();
      const currentTime = Date.now(); // milliseconds

      // Set clock to 5 minutes in the future
      mockClockProvider.now = vi.fn().mockReturnValue(currentTime);
      mockClockProvider.isWithinSkew = vi.fn().mockReturnValue(false);

      const result = await proofVerifier.verifyProof(proof, validJwk);

      expect(result.valid).toBe(false);
      expect(result.reason).toContain('skew');
      // isWithinSkew is called with timestamp in milliseconds (converted from seconds)
      expect(mockClockProvider.isWithinSkew).toHaveBeenCalledWith(
        proof.meta.ts * 1000, // Convert seconds to milliseconds
        120
      );
    });

    it('should accept timestamps within skew window', async () => {
      const proof = createValidProof();
      mockClockProvider.isWithinSkew = vi.fn().mockReturnValue(true);

      const result = await proofVerifier.verifyProof(proof, validJwk);

      expect(result.valid).toBe(true);
    });

    it('should use custom timestamp skew seconds', async () => {
      const customProofVerifier = new ProofVerifier({
        cryptoProvider: mockCryptoProvider,
        clockProvider: mockClockProvider,
        nonceCacheProvider: mockNonceCache,
        fetchProvider: mockFetchProvider,
        timestampSkewSeconds: 300, // 5 minutes
        nonceTtlSeconds: 300,
      });

      const proof = createValidProof();
      mockClockProvider.isWithinSkew = vi.fn().mockReturnValue(false);

      await customProofVerifier.verifyProof(proof, validJwk);

      // isWithinSkew is called with timestamp in milliseconds (converted from seconds)
      expect(mockClockProvider.isWithinSkew).toHaveBeenCalledWith(
        proof.meta.ts * 1000, // Convert seconds to milliseconds
        300
      );
    });
  });

  describe('Canonical Payload Reconstruction', () => {
    it('should reconstruct canonical payload from meta', async () => {
      const proof = createValidProof();

      await proofVerifier.verifyProof(proof, validJwk);

      // Verify that verifyJWS was called with detached payload
      expect(mockCryptoProvider.verify).toHaveBeenCalled();
    });

    it('should validate canonical payload ordering determinism', () => {
      const meta1 = {
        z: 1,
        a: 2,
        m: 3,
        did: 'did:test',
        kid: 'kid',
        ts: 123,
        nonce: 'nonce',
        audience: 'aud',
        sessionId: 'session',
        requestHash: 'sha256:' + 'a'.repeat(64),
        responseHash: 'sha256:' + 'b'.repeat(64),
      };
      const meta2 = {
        a: 2,
        m: 3,
        z: 1,
        did: 'did:test',
        kid: 'kid',
        ts: 123,
        nonce: 'nonce',
        audience: 'aud',
        sessionId: 'session',
        requestHash: 'sha256:' + 'a'.repeat(64),
        responseHash: 'sha256:' + 'b'.repeat(64),
      };

      const canonical1 = proofVerifier.buildCanonicalPayload(meta1);
      const canonical2 = proofVerifier.buildCanonicalPayload(meta2);

      // Should be identical despite different key order
      expect(canonical1).toBe(canonical2);
    });

    it('should handle detached JWS reconstruction', async () => {
      const header = { alg: 'EdDSA', kid: 'did:key:z123#z123' };
      const headerB64 = btoa(JSON.stringify(header))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const signatureB64 = btoa('signature')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const detachedJws = `${headerB64}..${signatureB64}`;

      const proof: DetachedProof = {
        jws: detachedJws,
        meta: createValidProof().meta,
      };

      const result = await proofVerifier.verifyProof(proof, validJwk);

      // Should call verifyJWS with detached payload
      expect(mockCryptoProvider.verify).toHaveBeenCalled();
      expect(result.valid).toBe(true);
    });
  });

  describe('Proof Structure Validation', () => {
    it('should reject invalid proof structure', async () => {
      const invalidProof = {
        jws: 'invalid',
        meta: {
          // Missing required fields
          did: 'did:test',
        },
      } as any;

      const result = await proofVerifier.verifyProof(invalidProof, validJwk);

      expect(result.valid).toBe(false);
      expect(result.reason).toContain('Invalid proof structure');
    });

    it('should reject proof with missing required meta fields', async () => {
      const invalidProof: DetachedProof = {
        jws: 'header.payload.signature',
        meta: {
          did: 'did:test',
          kid: 'kid',
          ts: 123,
          nonce: 'nonce',
          audience: 'aud',
          sessionId: 'session',
          // Missing requestHash and responseHash
          requestHash: '' as any,
          responseHash: '' as any,
        },
      };

      const result = await proofVerifier.verifyProof(invalidProof, validJwk);

      expect(result.valid).toBe(false);
    });

    it('validateDetachedProof rejects an unknown meta.outcome enum value', () => {
      const proof = createValidProof();
      (proof.meta as Record<string, unknown>)['outcome'] = 'bogus';
      const result = validateDetachedProof(proof);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error?.message).toContain('outcome');
      }
    });

    it('validateDetachedProof rejects a non-string optional meta field', () => {
      const proof = createValidProof();
      (proof.meta as Record<string, unknown>)['scopeId'] = 123;
      const result = validateDetachedProof(proof);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error?.message).toContain('scopeId');
      }
    });

    it('extractProofFromMeta flags a structurally invalid inner proof', () => {
      const result = extractProofFromMeta({
        proof: { jws: 'a.b.c', meta: { did: 'did:key:z123' } },
      });
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.errorCode).toBe(
          PROOF_VERIFICATION_ERROR_CODES.INVALID_PROOF_STRUCTURE,
        );
      }
    });
  });

  describe('Signature Verification', () => {
    it('should reject proof with invalid signature', async () => {
      const proof = createValidProof();
      mockCryptoProvider.verify = vi.fn().mockResolvedValue(false);

      const result = await proofVerifier.verifyProof(proof, validJwk);

      expect(result.valid).toBe(false);
      expect(result.reason).toContain('Invalid JWS signature');
    });

    it('should handle signature verification errors gracefully', async () => {
      const proof = createValidProof();
      mockCryptoProvider.verify = vi.fn().mockRejectedValue(
        new Error('Crypto error')
      );

      const result = await proofVerifier.verifyProof(proof, validJwk);

      expect(result.valid).toBe(false);
      expect(result.reason).toBeDefined();
      // Should not throw, should return error result
    });
  });

  describe('verifyProofDetached', () => {
    it('should verify proof with string canonical payload', async () => {
      const proof = createValidProof();
      const canonicalPayload = proofVerifier.buildCanonicalPayload(proof.meta);

      const result = await proofVerifier.verifyProofDetached(
        proof,
        canonicalPayload,
        validJwk
      );

      expect(result.valid).toBe(true);
    });

    it('should verify proof with Uint8Array canonical payload', async () => {
      const proof = createValidProof();
      const canonicalPayload = proofVerifier.buildCanonicalPayload(proof.meta);
      const canonicalPayloadBytes = new TextEncoder().encode(canonicalPayload);

      const result = await proofVerifier.verifyProofDetached(
        proof,
        canonicalPayloadBytes,
        validJwk
      );

      expect(result.valid).toBe(true);
    });

    it('should prevent nonce replay in verifyProofDetached', async () => {
      const proof = createValidProof();
      const canonicalPayload = proofVerifier.buildCanonicalPayload(proof.meta);

      // First verification
      const result1 = await proofVerifier.verifyProofDetached(
        proof,
        canonicalPayload,
        validJwk
      );
      expect(result1.valid).toBe(true);

      // Second verification should fail
      mockNonceCache.has = vi.fn().mockResolvedValue(true);
      const result2 = await proofVerifier.verifyProofDetached(
        proof,
        canonicalPayload,
        validJwk
      );
      expect(result2.valid).toBe(false);
      expect(result2.reason).toContain('replay');
    });
  });

  describe('Error Handling', () => {
    it('should never throw on verification errors', async () => {
      const proof = createValidProof();

      // Simulate various error conditions
      mockNonceCache.has = vi.fn().mockRejectedValue(new Error('Cache error'));

      const result = await proofVerifier.verifyProof(proof, validJwk);

      // Should return error result, not throw
      expect(result.valid).toBe(false);
      expect(result.reason).toBeDefined();
    });

    it('should handle clock provider errors gracefully', async () => {
      const proof = createValidProof();
      mockClockProvider.isWithinSkew = vi.fn().mockImplementation(() => {
        throw new Error('Clock error');
      });

      const result = await proofVerifier.verifyProof(proof, validJwk);

      expect(result.valid).toBe(false);
      expect(result.reason).toBeDefined();
    });
  });

  describe('fetchPublicKeyFromDID', () => {
    it('should fetch public key from DID document', async () => {
      const jwk = await proofVerifier.fetchPublicKeyFromDID('did:key:z123', 'z123');

      expect(jwk).toEqual(validJwk);
      expect(mockFetchProvider.resolveDID).toHaveBeenCalledWith('did:key:z123');
    });

    it('should throw ProofVerificationError if DID document not found', async () => {
      mockFetchProvider.resolveDID = vi.fn().mockResolvedValue(null);

      await expect(
        proofVerifier.fetchPublicKeyFromDID('did:key:z123')
      ).rejects.toThrow(ProofVerificationError);

      try {
        await proofVerifier.fetchPublicKeyFromDID('did:key:z123');
      } catch (error) {
        expect(error).toBeInstanceOf(ProofVerificationError);
        expect((error as ProofVerificationError).code).toBe(
          PROOF_VERIFICATION_ERROR_CODES.DID_DOCUMENT_NOT_FOUND
        );
      }
    });

    it('should throw ProofVerificationError if verification method not found', async () => {
      mockFetchProvider.resolveDID = vi.fn().mockResolvedValue({
        verificationMethod: [],
      });

      await expect(
        proofVerifier.fetchPublicKeyFromDID('did:key:z123', 'key-1')
      ).rejects.toThrow(ProofVerificationError);

      try {
        await proofVerifier.fetchPublicKeyFromDID('did:key:z123', 'key-1');
      } catch (error) {
        expect(error).toBeInstanceOf(ProofVerificationError);
        expect((error as ProofVerificationError).code).toBe(
          PROOF_VERIFICATION_ERROR_CODES.VERIFICATION_METHOD_NOT_FOUND
        );
      }
    });

    it('throws VERIFICATION_METHOD_NOT_FOUND when the kid matches no method', async () => {
      mockFetchProvider.resolveDID = vi.fn().mockResolvedValue({
        verificationMethod: [
          { id: 'did:key:z123#other', publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAA' } },
        ],
      });

      await expect(
        proofVerifier.fetchPublicKeyFromDID('did:key:z123', 'no-such-kid'),
      ).rejects.toThrow(ProofVerificationError);
      try {
        await proofVerifier.fetchPublicKeyFromDID('did:key:z123', 'no-such-kid');
      } catch (error) {
        expect((error as ProofVerificationError).code).toBe(
          PROOF_VERIFICATION_ERROR_CODES.VERIFICATION_METHOD_NOT_FOUND,
        );
      }
    });

    it('throws PUBLIC_KEY_NOT_FOUND when the verification method has no publicKeyJwk', async () => {
      mockFetchProvider.resolveDID = vi.fn().mockResolvedValue({
        verificationMethod: [{ id: 'did:key:z123#z123' }],
      });

      await expect(
        proofVerifier.fetchPublicKeyFromDID('did:key:z123'),
      ).rejects.toThrow(ProofVerificationError);
      try {
        await proofVerifier.fetchPublicKeyFromDID('did:key:z123');
      } catch (error) {
        expect((error as ProofVerificationError).code).toBe(
          PROOF_VERIFICATION_ERROR_CODES.PUBLIC_KEY_NOT_FOUND,
        );
      }
    });

    it('should throw ProofVerificationError if JWK is not Ed25519', async () => {
      mockFetchProvider.resolveDID = vi.fn().mockResolvedValue({
        verificationMethod: [{
          id: 'did:key:z123#z123',
          publicKeyJwk: {
            kty: 'RSA',
            crv: 'RS256',
            n: 'invalid',
          },
        }],
      });

      await expect(
        proofVerifier.fetchPublicKeyFromDID('did:key:z123')
      ).rejects.toThrow(ProofVerificationError);

      try {
        await proofVerifier.fetchPublicKeyFromDID('did:key:z123');
      } catch (error) {
        expect(error).toBeInstanceOf(ProofVerificationError);
        expect((error as ProofVerificationError).code).toBe(
          PROOF_VERIFICATION_ERROR_CODES.INVALID_JWK_FORMAT
        );
      }
    });

    it('throws DID_RESOLUTION_FAILED when DID resolution itself throws', async () => {
      mockFetchProvider.resolveDID = vi.fn().mockRejectedValue(new Error('network boom'));

      await expect(
        proofVerifier.fetchPublicKeyFromDID('did:key:z123')
      ).rejects.toThrow(ProofVerificationError);

      try {
        await proofVerifier.fetchPublicKeyFromDID('did:key:z123');
      } catch (error) {
        expect(error).toBeInstanceOf(ProofVerificationError);
        expect((error as ProofVerificationError).code).toBe(
          PROOF_VERIFICATION_ERROR_CODES.DID_RESOLUTION_FAILED
        );
      }
    });
  });

  describe('Clock Skew Negotiation', () => {
    it('should use default clock skew when not configured', () => {
      expect(proofVerifier.getTimestampSkew()).toBe(120);
    });

    it('should allow updating clock skew from server-advertised value', () => {
      proofVerifier.setTimestampSkew(60);
      expect(proofVerifier.getTimestampSkew()).toBe(60);
    });

    it('should clamp clock skew to minimum (30s)', () => {
      proofVerifier.setTimestampSkew(10);
      expect(proofVerifier.getTimestampSkew()).toBe(MIN_CLOCK_SKEW_SECONDS);
    });

    it('should clamp clock skew to maximum (600s)', () => {
      proofVerifier.setTimestampSkew(1000);
      expect(proofVerifier.getTimestampSkew()).toBe(MAX_CLOCK_SKEW_SECONDS);
    });

    it('should ignore non-finite values', () => {
      const original = proofVerifier.getTimestampSkew();
      proofVerifier.setTimestampSkew(NaN);
      expect(proofVerifier.getTimestampSkew()).toBe(original);
      proofVerifier.setTimestampSkew(Infinity);
      expect(proofVerifier.getTimestampSkew()).toBe(original);
    });

    it('should reject timestamp outside server-advertised 60s window', async () => {
      proofVerifier.setTimestampSkew(60);
      const proof = createValidProof();
      // Timestamp 90s old
      proof.meta.ts = Math.floor(Date.now() / 1000) - 90;

      mockClockProvider.isWithinSkew = vi.fn().mockReturnValue(false);

      const result = await proofVerifier.verifyProof(proof, validJwk);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('skew');
      expect(mockClockProvider.isWithinSkew).toHaveBeenCalledWith(
        proof.meta.ts * 1000,
        60
      );
    });

    it('should accept timestamp within default 120s window', async () => {
      const proof = createValidProof();
      // Timestamp 90s old - rejected at 60s, accepted at 120s
      proof.meta.ts = Math.floor(Date.now() / 1000) - 90;

      mockClockProvider.isWithinSkew = vi.fn().mockReturnValue(true);

      const result = await proofVerifier.verifyProof(proof, validJwk);
      expect(result.valid).toBe(true);
      expect(mockClockProvider.isWithinSkew).toHaveBeenCalledWith(
        proof.meta.ts * 1000,
        120
      );
    });
  });
});

describe('Meta Policy Validation', () => {
  describe('validateMetaStructure', () => {
    it('should accept _meta with only proof in strict mode', () => {
      const meta = { proof: { jws: 'test', meta: {} } };
      const result = validateMetaStructure(meta, 'strict');
      expect(result.valid).toBe(true);
    });

    it('IGNORES (does not reject) non-KYA-OS keys in strict mode (SEP-414)', () => {
      const meta = { proof: { jws: 'test', meta: {} }, extra: 'evil' };
      const result = validateMetaStructure(meta, 'strict');
      // strict no longer rejects foreign keys — it discards them.
      expect(result.valid).toBe(true);
      expect(result.extraKeys).toBeUndefined();
    });

    it('strict tolerates MCP-reserved _meta keys (must not reject conformant RC traffic)', () => {
      const meta = {
        [KYA_OS_PROOF_META_KEY]: { jws: 'test', meta: {} },
        'io.modelcontextprotocol/foo': { any: 'thing' },
        traceparent: '00-abc-def-01',
        tracestate: 'vendor=1',
        baggage: 'k=v',
      };
      const result = validateMetaStructure(meta, 'strict');
      expect(result.valid).toBe(true);
    });

    it('surfaces non-KYA-OS keys in allow-extensions mode', () => {
      const meta = { proof: { jws: 'test', meta: {} }, extra: 'allowed' };
      const result = validateMetaStructure(meta, 'allow-extensions');
      expect(result.valid).toBe(true);
      expect(result.extraKeys).toContain('extra');
    });

    it('allow-extensions with no extra keys surfaces nothing', () => {
      const meta = { [KYA_OS_PROOF_META_KEY]: { jws: 'test', meta: {} } };
      const result = validateMetaStructure(meta, 'allow-extensions');
      expect(result.valid).toBe(true);
      expect(result.extraKeys).toBeUndefined();
    });

    it('should default to strict (ignore) mode', () => {
      const meta = { proof: { jws: 'test', meta: {} }, extra: 'evil' };
      const result = validateMetaStructure(meta);
      expect(result.valid).toBe(true);
      expect(result.extraKeys).toBeUndefined();
    });

    it('should accept the namespaced proof key in strict mode (SEP-414)', () => {
      const meta = { [KYA_OS_PROOF_META_KEY]: { jws: 'test', meta: {} } };
      const result = validateMetaStructure(meta, 'strict');
      expect(result.valid).toBe(true);
    });

    it('treats the namespaced key as the proof key, not an extra', () => {
      // A response carrying ONLY the namespaced proof key is not "extra keys".
      const meta = { [KYA_OS_PROOF_META_KEY]: { jws: 'test', meta: {} } };
      const result = validateMetaStructure(meta, 'strict');
      expect(result.extraKeys ?? []).not.toContain(KYA_OS_PROOF_META_KEY);
    });
  });

  describe('isReservedMcpMetaKey', () => {
    it('recognizes the io.modelcontextprotocol/* reserved namespace', () => {
      expect(isReservedMcpMetaKey('io.modelcontextprotocol/anything')).toBe(true);
    });

    it('recognizes the W3C trace-context keys', () => {
      expect(isReservedMcpMetaKey('traceparent')).toBe(true);
      expect(isReservedMcpMetaKey('tracestate')).toBe(true);
      expect(isReservedMcpMetaKey('baggage')).toBe(true);
    });

    it('does not flag the KYA-OS proof key or arbitrary keys', () => {
      expect(isReservedMcpMetaKey(KYA_OS_PROOF_META_KEY)).toBe(false);
      expect(isReservedMcpMetaKey('proof')).toBe(false);
      expect(isReservedMcpMetaKey('whatever')).toBe(false);
    });
  });

  describe('extractProofFromMeta', () => {
    const validProof = {
      jws: 'eyJhbGciOiJFZERTQSJ9.e30.sig',
      meta: {
        did: 'did:key:z123',
        kid: 'did:key:z123#keys-1',
        ts: Math.floor(Date.now() / 1000),
        nonce: 'nonce123',
        audience: 'test',
        sessionId: 'session123',
        requestHash: 'sha256:' + 'a'.repeat(64),
        responseHash: 'sha256:' + 'b'.repeat(64),
      },
    };

    it('should extract proof from valid _meta', () => {
      const meta = { proof: validProof };
      const result = extractProofFromMeta(meta, 'strict');
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.proof).toEqual(validProof);
      }
    });

    it('extracts the proof even when foreign _meta keys coexist in strict mode', () => {
      // strict ignores non-KYA-OS keys rather than rejecting (SEP-414).
      const meta = { proof: validProof, extra: 'evil', traceparent: '00-a-b-01' };
      const result = extractProofFromMeta(meta, 'strict');
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.proof).toEqual(validProof);
      }
    });

    it('should accept _meta with extra keys in allow-extensions mode', () => {
      const meta = { proof: validProof, extra: 'allowed' };
      const result = extractProofFromMeta(meta, 'allow-extensions');
      expect(result.success).toBe(true);
    });

    it('should reject _meta without proof', () => {
      const meta = { other: 'data' };
      const result = extractProofFromMeta(meta, 'strict');
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.errorCode).toBe(PROOF_VERIFICATION_ERROR_CODES.MISSING_REQUIRED_FIELD);
      }
    });

    it('extracts the proof from the namespaced key (SEP-414)', () => {
      const meta = { [KYA_OS_PROOF_META_KEY]: validProof };
      const result = extractProofFromMeta(meta, 'strict');
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.proof).toEqual(validProof);
      }
    });

    it('still accepts a proof published under the legacy bare key (back-compat)', () => {
      const meta = { [LEGACY_PROOF_META_KEY]: validProof };
      const result = extractProofFromMeta(meta, 'strict');
      expect(result.success).toBe(true);
    });

    it('prefers the namespaced key when both are present (namespaced wins)', () => {
      const legacyOnly = { ...validProof, jws: 'legacy.jws.sig' };
      const meta = {
        [KYA_OS_PROOF_META_KEY]: validProof,
        [LEGACY_PROOF_META_KEY]: legacyOnly,
      };
      const result = extractProofFromMeta(meta, 'strict');
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.proof.jws).toBe(validProof.jws);
      }
    });

    it('reads a dual-emitted response (both keys, identical value)', () => {
      // The default producer mirrors the proof under both keys; a verifier reads
      // it cleanly (namespaced wins, identical value) with no policy violation.
      const meta = { [KYA_OS_PROOF_META_KEY]: validProof, [LEGACY_PROOF_META_KEY]: validProof };
      const result = extractProofFromMeta(meta, 'strict');
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.proof).toEqual(validProof);
      }
    });
  });
});
