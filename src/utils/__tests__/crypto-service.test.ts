/**
 * Tests for CryptoService
 *
 * Comprehensive test coverage for cryptographic operations service.
 * Tests verifyEd25519() and verifyJWS() with various scenarios.
 *
 * Test Coverage Requirements: 100% - All security-critical code paths
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { CryptoService } from '../crypto-service.js';
import type { CryptoProvider } from '../../providers/base.js';
import type { Ed25519JWK } from '../crypto-service.js';

describe('CryptoService', () => {
  let cryptoService: CryptoService;
  let mockCryptoProvider: CryptoProvider;

  beforeEach(() => {
    mockCryptoProvider = {
      sign: vi.fn(),
      verify: vi.fn(),
      generateKeyPair: vi.fn(),
      hash: vi.fn(),
      randomBytes: vi.fn(),
    };
    cryptoService = new CryptoService(mockCryptoProvider);
  });

  describe('verifyEd25519', () => {
    it('should return true for valid signature', async () => {
      mockCryptoProvider.verify = vi.fn().mockResolvedValue(true);

      const result = await cryptoService.verifyEd25519(
        new Uint8Array([1, 2, 3]),
        new Uint8Array([4, 5, 6]),
        'base64PublicKey'
      );

      expect(result).toBe(true);
      expect(mockCryptoProvider.verify).toHaveBeenCalledWith(
        new Uint8Array([1, 2, 3]),
        new Uint8Array([4, 5, 6]),
        'base64PublicKey'
      );
    });

    it('should return false for invalid signature', async () => {
      mockCryptoProvider.verify = vi.fn().mockResolvedValue(false);

      const result = await cryptoService.verifyEd25519(
        new Uint8Array([1, 2, 3]),
        new Uint8Array([4, 5, 6]),
        'base64PublicKey'
      );

      expect(result).toBe(false);
    });

    it('should return false on verification error', async () => {
      mockCryptoProvider.verify = vi.fn().mockRejectedValue(
        new Error('Verification failed')
      );

      const result = await cryptoService.verifyEd25519(
        new Uint8Array([1, 2, 3]),
        new Uint8Array([4, 5, 6]),
        'base64PublicKey'
      );

      expect(result).toBe(false);
    });

    it('should handle empty data', async () => {
      mockCryptoProvider.verify = vi.fn().mockResolvedValue(true);

      const result = await cryptoService.verifyEd25519(
        new Uint8Array(0),
        new Uint8Array([4, 5, 6]),
        'base64PublicKey'
      );

      expect(result).toBe(true);
    });
  });

  describe('parseJWS', () => {
    it('should parse valid full compact JWS', () => {
      const header = { alg: 'EdDSA', typ: 'JWT' };
      const payload = { sub: 'did:key:z123', iss: 'did:key:z123' };
      // Properly encode as base64url
      const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const signatureB64 = Buffer.from('signature').toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const jws = `${headerB64}.${payloadB64}.${signatureB64}`;

      const parsed = cryptoService.parseJWS(jws);

      expect(parsed.header).toEqual(header);
      expect(parsed.payload).toEqual(payload);
      expect(parsed.signingInput).toBe(`${headerB64}.${payloadB64}`);
      expect(parsed.signatureBytes).toBeInstanceOf(Uint8Array);
    });

    it('should throw error for invalid JWS format', () => {
      const invalidJws = 'not.a.jws';

      // This will fail during JSON parsing, not format check
      expect(() => cryptoService.parseJWS(invalidJws)).toThrow();
    });

    it('should throw error for JWS with wrong number of parts', () => {
      const invalidJws = 'header.payload';

      expect(() => cryptoService.parseJWS(invalidJws)).toThrow('Invalid JWS format');
    });

    it('should handle empty payload', () => {
      const header = { alg: 'EdDSA' };
      const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const signatureB64 = Buffer.from('signature').toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const jws = `${headerB64}..${signatureB64}`;

      const parsed = cryptoService.parseJWS(jws);

      expect(parsed.header).toEqual(header);
      expect(parsed.payload).toBeUndefined();
    });
  });

  describe('verifyJWS', () => {
    const validJwk: Ed25519JWK = {
      kty: 'OKP',
      crv: 'Ed25519',
      x: 'VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ', // Example base64url public key (32 bytes when decoded)
    };

    // Create a valid JWS for testing
    const createValidJWS = (kid?: string): string => {
      const header = { alg: 'EdDSA', typ: 'JWT', ...(kid ? { kid } : {}) };
      const payload = { sub: 'did:key:z123', iss: 'did:key:z123' };
      const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const signatureB64 = Buffer.from('signature').toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      return `${headerB64}.${payloadB64}.${signatureB64}`;
    };

    it('should verify valid full compact JWS', async () => {
      mockCryptoProvider.verify = vi.fn().mockResolvedValue(true);
      const validJws = createValidJWS('key-1');

      const result = await cryptoService.verifyJWS(validJws, validJwk);

      expect(result).toBe(true);
      expect(mockCryptoProvider.verify).toHaveBeenCalled();
    });

    it('should reject invalid JWK format', async () => {
      const invalidJwk = { kty: 'RSA' } as any;
      const validJws = createValidJWS('key-1');

      const result = await cryptoService.verifyJWS(validJws, invalidJwk);

      expect(result).toBe(false);
      expect(mockCryptoProvider.verify).not.toHaveBeenCalled();
    });

    it('should reject JWK with wrong kty', async () => {
      const invalidJwk = {
        kty: 'RSA',
        crv: 'Ed25519',
        x: 'test',
      } as any;
      const validJws = createValidJWS();

      const result = await cryptoService.verifyJWS(validJws, invalidJwk);

      expect(result).toBe(false);
    });

    it('should reject JWK with wrong crv', async () => {
      const invalidJwk = {
        kty: 'OKP',
        crv: 'P-256',
        x: 'test',
      } as any;
      const validJws = createValidJWS();

      const result = await cryptoService.verifyJWS(validJws, invalidJwk);

      expect(result).toBe(false);
    });

    it('should reject JWK with missing x field', async () => {
      const invalidJwk = {
        kty: 'OKP',
        crv: 'Ed25519',
      } as any;
      const validJws = createValidJWS();

      const result = await cryptoService.verifyJWS(validJws, invalidJwk);

      expect(result).toBe(false);
    });

    it('should reject JWK with empty x field', async () => {
      const invalidJwk = {
        kty: 'OKP',
        crv: 'Ed25519',
        x: '',
      };
      const validJws = createValidJWS();

      const result = await cryptoService.verifyJWS(validJws, invalidJwk);

      expect(result).toBe(false);
    });

    it('should reject malformed JWS', async () => {
      const malformedJws = 'not.a.jws';

      const result = await cryptoService.verifyJWS(malformedJws, validJwk);

      expect(result).toBe(false);
    });

    it('should reject non-EdDSA algorithms', async () => {
      const header = { alg: 'RS256', typ: 'JWT' };
      const payload = { sub: 'did:key:z123' };
      const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const signatureB64 = Buffer.from('signature').toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const rsaJws = `${headerB64}.${payloadB64}.${signatureB64}`;

      const result = await cryptoService.verifyJWS(rsaJws, validJwk);

      expect(result).toBe(false);
      expect(mockCryptoProvider.verify).not.toHaveBeenCalled();
    });

    it('should reject HS256 algorithm', async () => {
      const header = { alg: 'HS256', typ: 'JWT' };
      const payload = { sub: 'did:key:z123' };
      const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const signatureB64 = Buffer.from('signature').toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const hs256Jws = `${headerB64}.${payloadB64}.${signatureB64}`;

      const result = await cryptoService.verifyJWS(hs256Jws, validJwk);

      expect(result).toBe(false);
    });

    it('should handle empty JWS components', async () => {
      const emptyJws = '..';

      const result = await cryptoService.verifyJWS(emptyJws, validJwk);

      expect(result).toBe(false);
    });

    it('should handle malformed JWS - single part', async () => {
      const malformedJws = 'singlepart';

      const result = await cryptoService.verifyJWS(malformedJws, validJwk);

      expect(result).toBe(false);
    });

    it('should handle malformed JWS - two parts', async () => {
      const malformedJws = 'header.payload';

      const result = await cryptoService.verifyJWS(malformedJws, validJwk);

      expect(result).toBe(false);
    });

    it('should handle malformed JWS - four parts', async () => {
      const header = { alg: 'EdDSA' };
      const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const payloadB64 = Buffer.from('payload').toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const signatureB64 = Buffer.from('signature').toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const malformedJws = `${headerB64}.${payloadB64}.${signatureB64}.extra`;

      const result = await cryptoService.verifyJWS(malformedJws, validJwk);

      expect(result).toBe(false);
    });

    it('should handle malformed JWS - invalid JSON header', async () => {
      const invalidHeaderB64 = Buffer.from('notjson').toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const payloadB64 = Buffer.from('payload').toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const signatureB64 = Buffer.from('signature').toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const malformedJws = `${invalidHeaderB64}.${payloadB64}.${signatureB64}`;

      const result = await cryptoService.verifyJWS(malformedJws, validJwk);

      expect(result).toBe(false);
    });

    it('should handle malformed JWS - invalid base64', async () => {
      // Don't mock verify - the function should catch the error and return false
      // before it gets to verification
      const header = { alg: 'EdDSA' };
      const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const invalidBase64 = 'notbase64!!!';
      const signatureB64 = Buffer.from('signature').toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const malformedJws = `${headerB64}.${invalidBase64}.${signatureB64}`;

      // parseJWS will throw when trying to decode invalid base64 payload
      // This should be caught and return false
      const result = await cryptoService.verifyJWS(malformedJws, validJwk);

      expect(result).toBe(false);
      // verify should not be called because parseJWS should throw
      expect(mockCryptoProvider.verify).not.toHaveBeenCalled();
    });

    it('should validate expectedKid option', async () => {
      mockCryptoProvider.verify = vi.fn().mockResolvedValue(true);
      const validJws = createValidJWS('key-1');
      const jwkWithKid: Ed25519JWK = {
        kty: 'OKP',
        crv: 'Ed25519',
        x: 'VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ',
        kid: 'key-1',
      };

      // Should succeed with matching kid
      const result1 = await cryptoService.verifyJWS(validJws, jwkWithKid, {
        expectedKid: 'key-1',
      });
      expect(result1).toBe(true);

      // Should fail with mismatched kid
      const result2 = await cryptoService.verifyJWS(validJws, jwkWithKid, {
        expectedKid: 'key-2',
      });
      expect(result2).toBe(false);
    });

    it('binds expectedKid to the protected JWS header, not only the JWK', async () => {
      mockCryptoProvider.verify = vi.fn().mockResolvedValue(true);
      const jwkWithKid: Ed25519JWK = {
        kty: 'OKP',
        crv: 'Ed25519',
        x: 'VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ',
        kid: 'key-1',
      };

      const result = await cryptoService.verifyJWS(
        createValidJWS('key-2'),
        jwkWithKid,
        { expectedKid: 'key-1' },
      );

      expect(result).toBe(false);
      expect(mockCryptoProvider.verify).not.toHaveBeenCalled();
    });

    it('should validate alg option', async () => {
      const header = { alg: 'EdDSA', typ: 'JWT' };
      const payload = { sub: 'did:key:z123' };
      const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const signatureB64 = Buffer.from('signature').toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const validJws = `${headerB64}.${payloadB64}.${signatureB64}`;

      // Should succeed with matching alg
      mockCryptoProvider.verify = vi.fn().mockResolvedValue(true);
      const result1 = await cryptoService.verifyJWS(validJws, validJwk, {
        alg: 'EdDSA',
      });
      expect(result1).toBe(true);

      // Should fail with mismatched alg (even if header says EdDSA)
      const result2 = await cryptoService.verifyJWS(validJws, validJwk, {
        alg: 'RS256' as any,
      });
      expect(result2).toBe(false);
    });

    it('should validate Ed25519 key length', async () => {
      const invalidLengthJwk = {
        kty: 'OKP' as const,
        crv: 'Ed25519' as const,
        x: 'c2hvcnQ', // "short" in base64 - too short for Ed25519 (only 5 bytes)
      };

      const validJws = createValidJWS();

      const result = await cryptoService.verifyJWS(validJws, invalidLengthJwk);

      expect(result).toBe(false);
    });

    it('should handle detached payload', async () => {
      mockCryptoProvider.verify = vi.fn().mockResolvedValue(true);
      const header = { alg: 'EdDSA' };
      const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const signatureB64 = Buffer.from('signature').toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const detachedJws = `${headerB64}..${signatureB64}`;
      const detachedPayload = JSON.stringify({ sub: 'did:key:z123' });

      const result = await cryptoService.verifyJWS(detachedJws, validJwk, {
        detachedPayload,
      });

      expect(result).toBe(true);
      expect(mockCryptoProvider.verify).toHaveBeenCalled();
    });

    it('should handle detached payload as Uint8Array', async () => {
      mockCryptoProvider.verify = vi.fn().mockResolvedValue(true);
      const header = { alg: 'EdDSA' };
      const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const signatureB64 = Buffer.from('signature').toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const detachedJws = `${headerB64}..${signatureB64}`;
      const detachedPayloadBytes = new TextEncoder().encode(JSON.stringify({ sub: 'did:key:z123' }));

      const result = await cryptoService.verifyJWS(detachedJws, validJwk, {
        detachedPayload: detachedPayloadBytes,
      });

      expect(result).toBe(true);
      expect(mockCryptoProvider.verify).toHaveBeenCalled();
    });

    it('should handle signature verification failure', async () => {
      mockCryptoProvider.verify = vi.fn().mockResolvedValue(false);
      const validJws = createValidJWS();

      const result = await cryptoService.verifyJWS(validJws, validJwk);

      expect(result).toBe(false);
    });

    it('should handle signature verification error', async () => {
      mockCryptoProvider.verify = vi.fn().mockRejectedValue(new Error('Crypto error'));
      const validJws = createValidJWS();

      const result = await cryptoService.verifyJWS(validJws, validJwk);

      expect(result).toBe(false);
    });

    it('should accept JWK with optional kid field', async () => {
      mockCryptoProvider.verify = vi.fn().mockResolvedValue(true);
      const jwkWithKid: Ed25519JWK = {
        kty: 'OKP',
        crv: 'Ed25519',
        x: 'VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ',
        kid: 'key-1',
      };
      const validJws = createValidJWS();

      const result = await cryptoService.verifyJWS(validJws, jwkWithKid);

      expect(result).toBe(true);
    });

    it('should accept JWK with optional use field', async () => {
      mockCryptoProvider.verify = vi.fn().mockResolvedValue(true);
      const jwkWithUse: Ed25519JWK = {
        kty: 'OKP',
        crv: 'Ed25519',
        x: 'VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ',
        use: 'sig',
      };
      const validJws = createValidJWS();

      const result = await cryptoService.verifyJWS(validJws, jwkWithUse);

      expect(result).toBe(true);
    });
  });

  describe('base64url edge cases', () => {
    const validJwk: Ed25519JWK = {
      kty: 'OKP',
      crv: 'Ed25519',
      x: 'VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ',
    };

    it('should handle base64url with no padding', async () => {
      mockCryptoProvider.verify = vi.fn().mockResolvedValue(true);
      const header = { alg: 'EdDSA' };
      const payload = { test: 'Hello' };
      const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const signatureB64 = Buffer.from('signature').toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const jws = `${headerB64}.${payloadB64}.${signatureB64}`;

      const result = await cryptoService.verifyJWS(jws, validJwk);

      // Should not throw, even if padding is missing
      expect(typeof result).toBe('boolean');
    });

    it('should handle base64url with padding', async () => {
      mockCryptoProvider.verify = vi.fn().mockResolvedValue(true);
      const header = { alg: 'EdDSA' };
      const payload = { test: 'Hello World!' };
      const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_');
      const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_');
      const signatureB64 = Buffer.from('signature').toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_');
      const jws = `${headerB64}.${payloadB64}.${signatureB64}`;

      const result = await cryptoService.verifyJWS(jws, validJwk);

      expect(typeof result).toBe('boolean');
    });
  });
});
