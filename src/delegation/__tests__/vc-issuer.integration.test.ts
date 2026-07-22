/**
 * VC Issuer Integration Tests (Real Crypto)
 *
 * Companion to vc-issuer.test.ts — these tests use real Ed25519 signing
 * instead of mocking wrapDelegationAsVC and canonicalizeJSON.
 *
 * The mocked unit tests verify argument passing and error propagation.
 * These integration tests verify that issued VCs are structurally valid
 * and cryptographically verifiable.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  DelegationCredentialIssuer,
  createDelegationIssuer,
} from '../vc-issuer.js';
import { DelegationCredentialVerifier } from '../vc-verifier.js';
import { createDidKeyResolver } from '../did-key-resolver.js';
import { canonicalizeJSON } from '../utils.js';
import type { AgentIdentity } from '../../providers/base.js';
import type { DelegationRecord } from '../../types/protocol.js';
import {
  createRealCryptoProvider,
  createRealIdentity,
  createRealSigningFunction,
  createRealSignatureVerifier,
} from '../../__tests__/audit/helpers/crypto-helpers.js';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';

describe('DelegationCredentialIssuer (real crypto)', () => {
  let crypto: NodeCryptoProvider;
  let issuerIdentity: AgentIdentity;
  let subjectIdentity: AgentIdentity;
  let issuer: DelegationCredentialIssuer;

  beforeAll(async () => {
    crypto = createRealCryptoProvider();
    issuerIdentity = await createRealIdentity(crypto);
    subjectIdentity = await createRealIdentity(crypto);

    issuer = createDelegationIssuer(
      {
        getDid: () => issuerIdentity.did,
        getKeyId: () => issuerIdentity.kid,
        getPrivateKey: () => issuerIdentity.privateKey,
      },
      createRealSigningFunction(crypto, issuerIdentity)
    );
  });

  function makeDelegation(overrides?: Partial<DelegationRecord>): DelegationRecord {
    return {
      id: 'del-integration-001',
      issuerDid: issuerIdentity.did,
      subjectDid: subjectIdentity.did,
      vcId: 'urn:uuid:integration-vc-001',
      constraints: { scopes: ['tools:read'] },
      signature: '',
      status: 'active',
      createdAt: Date.now(),
      ...overrides,
    };
  }

  it('should produce a VC with valid W3C structure', async () => {
    const vc = await issuer.issueDelegationCredential(makeDelegation());

    expect(vc['@context']).toContain('https://www.w3.org/2018/credentials/v1');
    expect(vc.type).toContain('VerifiableCredential');
    expect(vc.type).toContain('DelegationCredential');
    expect(vc.issuer).toBe(issuerIdentity.did);
    expect(vc.credentialSubject.id).toBe(subjectIdentity.did);
    expect(vc.proof).toBeDefined();
    expect(vc.proof?.type).toBe('Ed25519Signature2020');
    expect(vc.proof?.proofValue).toBeTruthy();
  });

  it('should produce a VC that passes real signature verification', async () => {
    const vc = await issuer.issueDelegationCredential(makeDelegation());

    const verifier = new DelegationCredentialVerifier({
      didResolver: createDidKeyResolver(),
      signatureVerifier: createRealSignatureVerifier(crypto),
    });

    const result = await verifier.verifyDelegationCredential(vc, {
      skipStatus: true,
      skipCache: true,
    });

    expect(result.valid).toBe(true);
    expect(result.checks?.signatureValid).toBe(true);
  });

  it('should issue and verify a credential with a fractional budget constraint', async () => {
    const vc = await issuer.issueDelegationCredential(makeDelegation({
      constraints: {
        scopes: ['payments:send'],
        crisp: {
          budget: { unit: 'USD', cap: 49.99 },
          scopes: [],
        },
      },
    }));
    const verifier = new DelegationCredentialVerifier({
      didResolver: createDidKeyResolver(),
      signatureVerifier: createRealSignatureVerifier(crypto),
    });

    const result = await verifier.verifyDelegationCredential(vc, {
      skipStatus: true,
      skipCache: true,
    });

    expect(vc.credentialSubject.delegation.constraints.crisp?.budget?.cap).toBe(49.99);
    expect(result.valid).toBe(true);
    expect(result.checks?.signatureValid).toBe(true);
  });

  it('should produce deterministic canonicalization for the same input', async () => {
    const delegation = makeDelegation();
    const vc1 = await issuer.issueDelegationCredential(delegation);
    const vc2 = await issuer.issueDelegationCredential(delegation);

    const strip = (vc: Record<string, unknown>) => {
      const copy = { ...vc };
      delete copy['proof'];
      return copy;
    };

    expect(canonicalizeJSON(strip(vc1))).toBe(canonicalizeJSON(strip(vc2)));
  });

  it('should produce different signatures for different delegations', async () => {
    const vc1 = await issuer.issueDelegationCredential(makeDelegation({ id: 'del-A' }));
    const vc2 = await issuer.issueDelegationCredential(makeDelegation({ id: 'del-B' }));

    expect(vc1.proof?.proofValue).not.toBe(vc2.proof?.proofValue);
  });

  it('createAndIssueDelegation should produce a verifiable VC', async () => {
    const vc = await issuer.createAndIssueDelegation({
      id: 'del-create-issue',
      issuerDid: issuerIdentity.did,
      subjectDid: subjectIdentity.did,
      constraints: { scopes: ['tools:write'] },
    });

    const verifier = new DelegationCredentialVerifier({
      didResolver: createDidKeyResolver(),
      signatureVerifier: createRealSignatureVerifier(crypto),
    });

    const result = await verifier.verifyDelegationCredential(vc, {
      skipStatus: true,
      skipCache: true,
    });

    expect(result.valid).toBe(true);
  });
});
