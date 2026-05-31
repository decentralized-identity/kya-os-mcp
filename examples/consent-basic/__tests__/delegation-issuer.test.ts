/**
 * Unit Tests: delegation-issuer.ts
 *
 * Validates the factory for creating DelegationCredentialIssuers
 * from identity config. Covers VC structure, proof, and constraints.
 *
 * Spec coverage: §3.1 (VC structure), §4.1 (DelegationRecord), §4.2 (constraints)
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { createDelegationIssuerFromIdentity, type DelegationIssuerFactory } from '../src/delegation-issuer.js';
import { NodeCryptoProvider, generateDidKeyFromBase64, type DelegationCredential } from '@kya-os/mcp';

const crypto = new NodeCryptoProvider();

let factory: DelegationIssuerFactory;
let vc: DelegationCredential;

describe('createDelegationIssuerFromIdentity', () => {
  beforeAll(async () => {
    const keyPair = await crypto.generateKeyPair();
    const did = generateDidKeyFromBase64(keyPair.publicKey);
    const kid = `${did}#${did.replace('did:key:', '')}`;

    factory = createDelegationIssuerFromIdentity(crypto, {
      did,
      kid,
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey,
    });

    vc = await factory.issuer.createAndIssueDelegation({
      id: 'test-delegation-001',
      issuerDid: did,
      subjectDid: 'did:key:z6MkTestSubject',
      constraints: {
        scopes: ['cart:write', 'cart:read'],
        notAfter: Math.floor(Date.now() / 1000) + 3600,
      },
    });
  });

  // §3.1 — VC structure
  it('should produce a VC with correct type array', () => {
    expect(vc.type).toContain('VerifiableCredential');
    expect(vc.type).toContain('DelegationCredential');
  });

  it('should include W3C context', () => {
    expect(vc['@context']).toContain('https://www.w3.org/2018/credentials/v1');
  });

  it('should have an issuer matching the identity DID', () => {
    expect(vc.issuer).toBe(factory.identity.did);
  });

  it('should set credentialSubject.id to the subject DID', () => {
    expect(vc.credentialSubject.id).toBe('did:key:z6MkTestSubject');
  });

  // §3.1 — Proof
  it('should include an Ed25519Signature2020 proof', () => {
    expect(vc.proof).toBeDefined();
    expect(vc.proof!.type).toBe('Ed25519Signature2020');
  });

  it('should have proofValue in the proof', () => {
    expect(vc.proof!['proofValue']).toBeDefined();
    expect(typeof vc.proof!['proofValue']).toBe('string');
  });

  it('should set verificationMethod to the kid', () => {
    expect(vc.proof!['verificationMethod']).toBe(factory.identity.kid);
  });

  it('should set proofPurpose to assertionMethod', () => {
    expect(vc.proof!.proofPurpose).toBe('assertionMethod');
  });

  // §4.1 — DelegationRecord
  it('should embed the delegation record in credentialSubject', () => {
    const delegation = vc.credentialSubject.delegation;
    expect(delegation).toBeDefined();
    expect(delegation.id).toBe('test-delegation-001');
    expect(delegation.issuerDid).toBe(factory.identity.did);
    expect(delegation.subjectDid).toBe('did:key:z6MkTestSubject');
  });

  // §4.2 — Constraints
  it('should include scopes in constraints', () => {
    const scopes = vc.credentialSubject.delegation.constraints.scopes;
    expect(scopes).toEqual(['cart:write', 'cart:read']);
  });

  it('should include notAfter in constraints', () => {
    const notAfter = vc.credentialSubject.delegation.constraints.notAfter;
    expect(notAfter).toBeDefined();
    expect(notAfter).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  // Factory identity
  it('should return the identity in the factory', () => {
    expect(factory.identity.did).toBeDefined();
    expect(factory.identity.did.startsWith('did:key:')).toBe(true);
    expect(factory.identity.kid).toMatch(/#z[\w]+$/);
  });
});
