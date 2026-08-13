/**
 * VC Verifier Integration Tests (Real Crypto)
 *
 * Companion to vc-verifier.test.ts — these tests use real Ed25519 signatures
 * and real validation functions instead of mocking the verification pipeline.
 *
 * The mocked unit tests verify pipeline logic and error paths.
 * These integration tests verify that real VCs are correctly accepted/rejected.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  DelegationCredentialVerifier,
  type DIDResolver,
  type StatusListResolver,
} from '../vc-verifier.js';
import { DelegationCredentialIssuer } from '../vc-issuer.js';
import { createDidKeyResolver } from '../did-key-resolver.js';
import type { AgentIdentity } from '../../providers/base.js';
import type { DelegationRecord, DelegationCredential } from '../../types/protocol.js';
import {
  createRealCryptoProvider,
  createRealIdentity,
  createRealSigningFunction,
  createRealSignatureVerifier,
} from '../../__tests__/audit/helpers/crypto-helpers.js';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';

describe('DelegationCredentialVerifier (real crypto)', () => {
  let crypto: NodeCryptoProvider;
  let issuerIdentity: AgentIdentity;
  let subjectIdentity: AgentIdentity;
  let issuer: DelegationCredentialIssuer;
  let verifier: DelegationCredentialVerifier;
  let didResolver: DIDResolver;

  beforeAll(async () => {
    crypto = createRealCryptoProvider();
    issuerIdentity = await createRealIdentity(crypto);
    subjectIdentity = await createRealIdentity(crypto);

    didResolver = createDidKeyResolver();

    issuer = new DelegationCredentialIssuer(
      {
        getDid: () => issuerIdentity.did,
        getKeyId: () => issuerIdentity.kid,
        getPrivateKey: () => issuerIdentity.privateKey,
      },
      createRealSigningFunction(crypto, issuerIdentity)
    );

    verifier = new DelegationCredentialVerifier({
      didResolver,
      signatureVerifier: createRealSignatureVerifier(crypto),
    });
  });

  async function issueVC(overrides?: Partial<DelegationRecord>): Promise<DelegationCredential> {
    return issuer.issueDelegationCredential({
      id: 'del-verifier-test',
      issuerDid: issuerIdentity.did,
      subjectDid: subjectIdentity.did,
      vcId: `urn:uuid:verifier-test-${Date.now()}`,
      constraints: {
        scopes: ['tools:read'],
        notBefore: Math.floor(Date.now() / 1000) - 3600,
        notAfter: Math.floor(Date.now() / 1000) + 3600,
      },
      signature: '',
      status: 'active',
      createdAt: Date.now(),
      ...overrides,
    });
  }

  // ── Basic Validation (real validateDelegationCredential) ──────

  it('should accept a valid VC through all stages', async () => {
    const vc = await issueVC();

    const result = await verifier.verifyDelegationCredential(vc, {
      skipStatus: true,
      skipCache: true,
    });

    expect(result.valid).toBe(true);
    expect(result.stage).toBe('complete');
    expect(result.checks?.basicValid).toBe(true);
    expect(result.checks?.signatureValid).toBe(true);
  });

  it('should reject an expired VC via real expiry check', async () => {
    const vc = await issueVC({
      constraints: {
        scopes: ['tools:read'],
        notAfter: Math.floor(Date.now() / 1000) - 60, // expired 1 minute ago
      },
    });

    const result = await verifier.verifyDelegationCredential(vc, {
      skipStatus: true,
      skipCache: true,
    });

    expect(result.valid).toBe(false);
    expect(result.stage).toBe('basic');
    expect(result.reason).toContain('expired');
  });

  it('should reject a VC with revoked status field', async () => {
    const vc = await issueVC({ status: 'revoked' });

    const result = await verifier.verifyDelegationCredential(vc, {
      skipStatus: true,
      skipCache: true,
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toContain('revoked');
  });

  // ── Signature Verification (real Ed25519) ─────────────────────

  it('should reject a tampered VC via real signature verification', async () => {
    const vc = await issueVC();
    const tampered = structuredClone(vc);
    tampered.credentialSubject.delegation.scopes = ['admin:*'];

    const result = await verifier.verifyDelegationCredential(tampered, {
      skipStatus: true,
      skipCache: true,
    });

    expect(result.valid).toBe(false);
    expect(result.checks?.signatureValid).toBe(false);
  });

  it('should reject when issuer DID is swapped', async () => {
    const vc = await issueVC();
    const tampered = structuredClone(vc);
    tampered.issuer = subjectIdentity.did;

    const result = await verifier.verifyDelegationCredential(tampered, {
      skipStatus: true,
      skipCache: true,
    });

    expect(result.valid).toBe(false);
  });

  it('should reject when DID resolver cannot find issuer', async () => {
    const vc = await issueVC();

    const nullVerifier = new DelegationCredentialVerifier({
      didResolver: { resolve: async () => null },
      signatureVerifier: createRealSignatureVerifier(crypto),
    });

    const result = await nullVerifier.verifyDelegationCredential(vc, {
      skipStatus: true,
      skipCache: true,
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toContain('resolve');
  });

  // ── Missing Proof ─────────────────────────────────────────────

  it('should reject VC without proof at basic stage', async () => {
    const vc = await issueVC();
    const noProof = { ...vc } as Record<string, unknown>;
    delete noProof['proof'];

    const result = await verifier.verifyDelegationCredential(
      noProof as DelegationCredential,
      { skipStatus: true, skipCache: true }
    );

    expect(result.valid).toBe(false);
    expect(result.stage).toBe('basic');
  });

  // ── Revocation freshness (the 2026-08 fail-open regression) ───

  it('denies the very next call after a mid-session revocation — warm cache, no clears', async () => {
    let revoked = false;
    const flipResolver: StatusListResolver = {
      checkStatus: async () => revoked,
    };

    const gated = new DelegationCredentialVerifier({
      didResolver,
      signatureVerifier: createRealSignatureVerifier(crypto),
      statusListResolver: flipResolver,
    });

    const vc = await issuer.issueDelegationCredential(
      {
        id: 'del-revocation-freshness',
        issuerDid: issuerIdentity.did,
        subjectDid: subjectIdentity.did,
        vcId: 'urn:uuid:revocation-freshness',
        constraints: {
          scopes: ['tools:read'],
          notBefore: Math.floor(Date.now() / 1000) - 3600,
          notAfter: Math.floor(Date.now() / 1000) + 3600,
        },
        signature: '',
        status: 'active',
        createdAt: Date.now(),
      },
      {
        credentialStatus: {
          id: 'https://status.example/1#94',
          type: 'StatusList2021Entry',
          statusPurpose: 'revocation',
          statusListIndex: '94',
          statusListCredential: 'https://status.example/1',
        },
      },
    );

    const before = await gated.verifyDelegationCredential(vc);
    expect(before.valid).toBe(true);

    revoked = true; // the on-chain bit flips mid-session

    const after = await gated.verifyDelegationCredential(vc);
    expect(after.valid).toBe(false);
    expect(after.statusOutcome).toBe('revoked');
    expect(after.cached).toBe(true); // signature from cache — status still caught it
  });

  // ── Metrics ───────────────────────────────────────────────────

  it('should report timing metrics for all stages', async () => {
    const vc = await issueVC();

    const result = await verifier.verifyDelegationCredential(vc, {
      skipStatus: true,
      skipCache: true,
    });

    expect(result.metrics).toBeDefined();
    expect(result.metrics?.totalMs).toBeGreaterThanOrEqual(0);
    expect(result.metrics?.basicCheckMs).toBeGreaterThanOrEqual(0);
    expect(result.metrics?.signatureCheckMs).toBeGreaterThanOrEqual(0);
  });
});
