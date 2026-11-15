/**
 * VC-JWT Tests
 *
 * Tests for createUnsignedVCJWT, completeVCJWT, and parseVCJWT — the public
 * API used by mcp-i-cloudflare's consent service to issue and verify
 * delegation tokens as W3C VC-JWTs.
 *
 * These functions had 0% test coverage in mcp-i-core despite being
 * load-bearing public API consumed by production services.
 */

import { describe, it, expect, beforeAll, vi } from 'vitest';
import {
  createUnsignedVCJWT,
  completeVCJWT,
  parseVCJWT,
  type VCJWTHeader,
  type VCJWTPayload,
} from '../utils.js';
import { wrapDelegationAsVC } from '../../types/protocol.js';
import type { DelegationRecord } from '../../types/protocol.js';
import type { AgentIdentity } from '../../providers/base.js';
import {
  createRealCryptoProvider,
  createRealIdentity,
} from '../../__tests__/audit/helpers/crypto-helpers.js';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { base64urlEncodeFromBytes } from '../../utils/base64.js';

describe('VC-JWT', () => {
  let crypto: NodeCryptoProvider;
  let issuer: AgentIdentity;
  let subject: AgentIdentity;

  beforeAll(async () => {
    crypto = createRealCryptoProvider();
    issuer = await createRealIdentity(crypto);
    subject = await createRealIdentity(crypto);
  });

  function makeDelegation(): DelegationRecord {
    return {
      id: 'del-jwt-test',
      issuerDid: issuer.did,
      subjectDid: subject.did,
      vcId: 'urn:uuid:jwt-test-001',
      constraints: { scopes: ['tools:read', 'tools:write'] },
      signature: '',
      status: 'active',
      createdAt: Date.now(),
    };
  }

  function makeVC(delegation?: DelegationRecord) {
    return wrapDelegationAsVC(delegation ?? makeDelegation());
  }

  // ── createUnsignedVCJWT ───────────────────────────────────────

  describe('createUnsignedVCJWT', () => {
    it('should produce EdDSA header with JWT type', () => {
      const { header } = createUnsignedVCJWT(makeVC() as Record<string, unknown>);

      expect(header.alg).toBe('EdDSA');
      expect(header.typ).toBe('JWT');
    });

    it('should include kid in header when provided', () => {
      const { header } = createUnsignedVCJWT(
        makeVC() as Record<string, unknown>,
        { keyId: issuer.kid }
      );

      expect(header.kid).toBe(issuer.kid);
    });

    it('should not include kid when not provided', () => {
      const { header } = createUnsignedVCJWT(makeVC() as Record<string, unknown>);

      expect(header.kid).toBeUndefined();
    });

    it('should extract issuer DID as iss claim', () => {
      const { payload } = createUnsignedVCJWT(makeVC() as Record<string, unknown>);

      expect(payload.iss).toBe(issuer.did);
    });

    it('should extract issuer from object-form issuer', () => {
      const vc = makeVC() as Record<string, unknown>;
      vc['issuer'] = { id: 'did:web:example.com' };

      const { payload } = createUnsignedVCJWT(vc);

      expect(payload.iss).toBe('did:web:example.com');
    });

    it('should extract subject DID as sub claim', () => {
      const { payload } = createUnsignedVCJWT(makeVC() as Record<string, unknown>);

      expect(payload.sub).toBe(subject.did);
    });

    it('should set jti from VC id', () => {
      const { payload } = createUnsignedVCJWT(makeVC() as Record<string, unknown>);

      expect(payload.jti).toBe('urn:uuid:jwt-test-001');
    });

    it('should convert expirationDate to exp (unix seconds)', () => {
      const delegation = makeDelegation();
      delegation.constraints.notAfter = Math.floor(Date.now() / 1000) + 3600;
      const vc = makeVC(delegation) as Record<string, unknown>;

      const { payload } = createUnsignedVCJWT(vc);

      expect(payload.exp).toBeDefined();
      expect(payload.exp).toBe(delegation.constraints.notAfter);
    });

    it('should convert issuanceDate to iat (unix seconds)', () => {
      const vc = makeVC() as Record<string, unknown>;
      const { payload } = createUnsignedVCJWT(vc);

      expect(payload.iat).toBeDefined();
      expect(typeof payload.iat).toBe('number');
    });

    it('should embed the VC without proof in the vc claim', () => {
      const vc = makeVC() as Record<string, unknown>;
      vc['proof'] = { type: 'Ed25519Signature2020', proofValue: 'should-be-stripped' };

      const { payload } = createUnsignedVCJWT(vc);

      expect(payload.vc).toBeDefined();
      expect(payload.vc['proof']).toBeUndefined();
      expect(payload.vc['@context']).toBeDefined();
    });

    it('should produce a valid base64url-encoded signingInput', () => {
      const { signingInput, encodedHeader, encodedPayload } = createUnsignedVCJWT(
        makeVC() as Record<string, unknown>
      );

      expect(signingInput).toBe(`${encodedHeader}.${encodedPayload}`);
      // base64url: no +, /, or = characters
      expect(signingInput).not.toMatch(/[+/=]/);
    });

    it('should produce decodable header and payload', () => {
      const { encodedHeader, encodedPayload } = createUnsignedVCJWT(
        makeVC() as Record<string, unknown>
      );

      const header = JSON.parse(atob(encodedHeader.replace(/-/g, '+').replace(/_/g, '/')));
      const payload = JSON.parse(atob(encodedPayload.replace(/-/g, '+').replace(/_/g, '/')));

      expect(header.alg).toBe('EdDSA');
      expect(payload.iss).toBe(issuer.did);
    });
  });

  // ── completeVCJWT ─────────────────────────────────────────────

  describe('completeVCJWT', () => {
    it('should append signature to signingInput', () => {
      const { signingInput } = createUnsignedVCJWT(makeVC() as Record<string, unknown>);
      const jwt = completeVCJWT(signingInput, 'fake-signature');

      expect(jwt).toBe(`${signingInput}.fake-signature`);
    });

    it('should produce a 3-part JWT string', () => {
      const { signingInput } = createUnsignedVCJWT(makeVC() as Record<string, unknown>);
      const jwt = completeVCJWT(signingInput, 'sig123');

      const parts = jwt.split('.');
      expect(parts.length).toBe(3);
    });
  });

  // ── parseVCJWT ────────────────────────────────────────────────

  describe('parseVCJWT', () => {
    it('should parse a valid VC-JWT round-trip', () => {
      const vc = makeVC() as Record<string, unknown>;
      const { signingInput, header: originalHeader, payload: originalPayload } =
        createUnsignedVCJWT(vc, { keyId: issuer.kid });
      const jwt = completeVCJWT(signingInput, 'test-signature');

      const parsed = parseVCJWT(jwt);

      expect(parsed).not.toBeNull();
      expect(parsed!.header.alg).toBe(originalHeader.alg);
      expect(parsed!.header.kid).toBe(originalHeader.kid);
      expect(parsed!.payload.iss).toBe(originalPayload.iss);
      expect(parsed!.payload.sub).toBe(originalPayload.sub);
      expect(parsed!.payload.jti).toBe(originalPayload.jti);
      expect(parsed!.payload.vc).toBeDefined();
      expect(parsed!.signature).toBe('test-signature');
      expect(parsed!.signingInput).toBe(signingInput);
    });

    it('should return null for non-3-part string', () => {
      expect(parseVCJWT('only-one-part')).toBeNull();
      expect(parseVCJWT('two.parts')).toBeNull();
      expect(parseVCJWT('four.parts.here.extra')).toBeNull();
    });

    it('should return null for invalid base64url in header', () => {
      expect(parseVCJWT('!!!invalid.payload.sig')).toBeNull();
    });

    it('should return null for invalid JSON in header', () => {
      const notJson = btoa('not json').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      expect(parseVCJWT(`${notJson}.${notJson}.sig`)).toBeNull();
    });

    it('should return null for empty string', () => {
      expect(parseVCJWT('')).toBeNull();
    });

    it('should preserve signingInput for verification', () => {
      const { signingInput } = createUnsignedVCJWT(makeVC() as Record<string, unknown>);
      const jwt = completeVCJWT(signingInput, 'sig');

      const parsed = parseVCJWT(jwt);
      expect(parsed!.signingInput).toBe(signingInput);
    });

    // SPEC §7.8: a header or a payload whose arrays and objects nest more than
    // 64 deep is not read as JSON. Each is counted from its own outermost
    // object, which is level 1. Each JWT ends in `sig`, which is no signature:
    // the parser checks none.
    describe('a header or a payload nested as deep as a credential may be', () => {
      const segment = (json: string): string => base64urlEncodeFromBytes(new TextEncoder().encode(json));
      const nestedTo = (levels: number): string => `{"n":${'['.repeat(levels - 1)}${']'.repeat(levels - 1)}}`;
      const header = segment('{"alg":"EdDSA","typ":"JWT"}');
      const payload = segment('{"vc":{}}');

      it.each<[string, (json: string) => string]>([
        ['payload', (json) => `${header}.${segment(json)}.sig`],
        ['header', (json) => `${segment(json)}.${payload}.sig`],
      ])('reads a %s nested 64 levels deep, and none nested 65', (_name, jwtWith) => {
        expect(parseVCJWT(jwtWith(nestedTo(64)))).not.toBeNull();
        expect(parseVCJWT(jwtWith(nestedTo(65)))).toBeNull();
      });

      it.each<[string, (json: string) => string]>([
        ['payload', (json) => `${header}.${segment(json)}.sig`],
        ['header', (json) => `${segment(json)}.${payload}.sig`],
      ])('hands no parser either segment when the %s nests deeper than that', (_name, jwtWith) => {
        const parse = vi.spyOn(JSON, 'parse');
        let parsed: unknown;
        let calls: number;
        try {
          parsed = parseVCJWT(jwtWith(nestedTo(200_000)));
          calls = parse.mock.calls.length;
        } finally {
          parse.mockRestore();
        }
        expect(parsed).toBeNull();
        expect(calls).toBe(0);
      });

      it('counts what is nested, and not a bracket a string holds', () => {
        const brackets = `${'['.repeat(100)}\\"${'{'.repeat(100)}`;
        const holding = (levels: number): string =>
          `{"vc":{},"s":"${brackets}","n":${'['.repeat(levels - 1)}${']'.repeat(levels - 1)}}`;
        expect(parseVCJWT(`${header}.${segment(holding(64))}.sig`)!.payload).toEqual(JSON.parse(holding(64)));
        expect(parseVCJWT(`${header}.${segment(holding(65))}.sig`)).toBeNull();
      });
    });
  });

  // ── Full Round-Trip with Real Crypto ──────────────────────────

  describe('full round-trip with real Ed25519 signing', () => {
    it('should create → sign → parse → verify a VC-JWT', async () => {
      // Step 1: Create unsigned JWT (same as consent.service.ts)
      const vc = makeVC() as Record<string, unknown>;
      const { signingInput } = createUnsignedVCJWT(vc, { keyId: issuer.kid });

      // Step 2: Sign with real Ed25519
      const signingInputBytes = new TextEncoder().encode(signingInput);
      const signatureBytes = await crypto.sign(signingInputBytes, issuer.privateKey);
      const signature = base64urlEncodeFromBytes(new Uint8Array(signatureBytes));

      // Step 3: Complete the JWT
      const jwt = completeVCJWT(signingInput, signature);

      // Step 4: Parse it back
      const parsed = parseVCJWT(jwt);
      expect(parsed).not.toBeNull();
      expect(parsed!.header.alg).toBe('EdDSA');
      expect(parsed!.payload.iss).toBe(issuer.did);

      // Step 5: Verify the signature
      const verifyInput = new TextEncoder().encode(parsed!.signingInput);
      // Decode base64url signature back to bytes
      const sigBase64 = parsed!.signature.replace(/-/g, '+').replace(/_/g, '/');
      const sigPadded = sigBase64 + '='.repeat((4 - sigBase64.length % 4) % 4);
      const sigBuf = Uint8Array.from(atob(sigPadded), c => c.charCodeAt(0));

      const isValid = await crypto.verify(verifyInput, sigBuf, issuer.publicKey);
      expect(isValid).toBe(true);
    });

    it('should reject tampered JWT via signature verification', async () => {
      const vc = makeVC() as Record<string, unknown>;
      const { signingInput } = createUnsignedVCJWT(vc, { keyId: issuer.kid });

      const signatureBytes = await crypto.sign(
        new TextEncoder().encode(signingInput),
        issuer.privateKey
      );
      const signature = base64urlEncodeFromBytes(new Uint8Array(signatureBytes));
      const jwt = completeVCJWT(signingInput, signature);

      // Tamper: replace the payload portion
      const parts = jwt.split('.');
      const tamperedPayload = btoa('{"iss":"did:key:evil","vc":{}}')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const tamperedJwt = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

      const parsed = parseVCJWT(tamperedJwt);
      expect(parsed).not.toBeNull();

      // Signature should NOT verify against tampered content
      const verifyInput = new TextEncoder().encode(parsed!.signingInput);
      const sigBase64 = parsed!.signature.replace(/-/g, '+').replace(/_/g, '/');
      const sigPadded = sigBase64 + '='.repeat((4 - sigBase64.length % 4) % 4);
      const sigBuf = Uint8Array.from(atob(sigPadded), c => c.charCodeAt(0));

      const isValid = await crypto.verify(verifyInput, sigBuf, issuer.publicKey);
      expect(isValid).toBe(false);
    });

    it('should reject JWT signed by wrong key', async () => {
      const vc = makeVC() as Record<string, unknown>;
      const { signingInput } = createUnsignedVCJWT(vc);

      // Sign with issuer's key
      const signatureBytes = await crypto.sign(
        new TextEncoder().encode(signingInput),
        issuer.privateKey
      );
      const signature = base64urlEncodeFromBytes(new Uint8Array(signatureBytes));
      const jwt = completeVCJWT(signingInput, signature);

      // Verify with subject's key — should fail
      const parsed = parseVCJWT(jwt);
      const verifyInput = new TextEncoder().encode(parsed!.signingInput);
      const sigBase64 = parsed!.signature.replace(/-/g, '+').replace(/_/g, '/');
      const sigPadded = sigBase64 + '='.repeat((4 - sigBase64.length % 4) % 4);
      const sigBuf = Uint8Array.from(atob(sigPadded), c => c.charCodeAt(0));

      const isValid = await crypto.verify(verifyInput, sigBuf, subject.publicKey);
      expect(isValid).toBe(false);
    });
  });
});
