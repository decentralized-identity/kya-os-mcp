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
import { CryptoService, type Ed25519JWK } from '../../utils/crypto-service.js';
import type {
  CryptoProvider,
  ClockProvider,
  NonceCacheProvider,
  FetchProvider,
} from '../../providers/base.js';
import type { DetachedProof, MetaPolicy } from '../../types/protocol.js';
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
    const header = { alg: 'EdDSA', typ: 'JWT' };
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
      const header = { alg: 'EdDSA' };
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

    it('should reject _meta with extra keys in strict mode', () => {
      const meta = { proof: { jws: 'test', meta: {} }, extra: 'evil' };
      const result = validateMetaStructure(meta, 'strict');
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('extra');
      expect(result.extraKeys).toContain('extra');
    });

    it('should accept _meta with extra keys in allow-extensions mode', () => {
      const meta = { proof: { jws: 'test', meta: {} }, extra: 'allowed' };
      const result = validateMetaStructure(meta, 'allow-extensions');
      expect(result.valid).toBe(true);
    });

    it('should default to strict mode', () => {
      const meta = { proof: { jws: 'test', meta: {} }, extra: 'evil' };
      const result = validateMetaStructure(meta);
      expect(result.valid).toBe(false);
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

    it('should reject _meta with extra keys in strict mode', () => {
      const meta = { proof: validProof, extra: 'evil' };
      const result = extractProofFromMeta(meta, 'strict');
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.errorCode).toBe(PROOF_VERIFICATION_ERROR_CODES.META_POLICY_VIOLATION);
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
  });
});
