import { describe, expect, it } from 'vitest';
import {
  extractDelegationFromVC,
  isSupportedCredentialProofType,
  readCredentialProofValue,
  SUPPORTED_CREDENTIAL_PROOF_TYPES,
  type DelegationCredential,
} from '../protocol.js';

const baseDelegation = {
  id: 'urn:delegation:1',
  issuerDid: 'did:key:zIssuer',
  subjectDid: 'did:key:zSubject',
  controller: 'did:key:zIssuer',
} as const;

function credentialWithProof(proof: Record<string, unknown> | undefined): DelegationCredential {
  return {
    id: 'urn:vc:1',
    credentialSubject: { delegation: { ...baseDelegation } },
    ...(proof ? { proof } : {}),
  } as unknown as DelegationCredential;
}

describe('readCredentialProofValue', () => {
  it('reads the signature from proofValue, the only credential-proof signature field', () => {
    expect(readCredentialProofValue({ type: 'Ed25519Signature2020', proofValue: 'sig-abc' })).toBe(
      'sig-abc',
    );
  });

  it('does not read jws: that field belongs to the detached tool-response proof, not a credential', () => {
    expect(readCredentialProofValue({ type: 'Ed25519Signature2020', jws: 'jws-xyz' })).toBe('');
  });

  it('does not read the legacy signatureValue field', () => {
    expect(readCredentialProofValue({ signatureValue: 'legacy' })).toBe('');
  });

  it('returns an empty string for a missing or non-string proof value', () => {
    expect(readCredentialProofValue(undefined)).toBe('');
    expect(readCredentialProofValue(null)).toBe('');
    expect(readCredentialProofValue({})).toBe('');
    expect(readCredentialProofValue({ proofValue: 42 })).toBe('');
  });
});

describe('extractDelegationFromVC signature agreement', () => {
  it('extracts the signature from proofValue', () => {
    const record = extractDelegationFromVC(
      credentialWithProof({ type: 'Ed25519Signature2020', proofValue: 'sig-abc' }),
    );
    expect(record.signature).toBe('sig-abc');
  });

  it('agrees with the verifier: a proof carrying only jws extracts no signature', () => {
    // The verifier rejects a credential proof without proofValue. Extraction must
    // not populate a signature from jws, or the extracted record misleads any
    // caller that inspects it before verification (issue #152).
    const record = extractDelegationFromVC(
      credentialWithProof({ type: 'Ed25519Signature2020', jws: 'jws-xyz' }),
    );
    expect(record.signature).toBe('');
  });

  it('extracts no signature when the credential has no proof', () => {
    const record = extractDelegationFromVC(credentialWithProof(undefined));
    expect(record.signature).toBe('');
  });
});

describe('isSupportedCredentialProofType', () => {
  it('accepts the suites the verifier can actually check', () => {
    expect(isSupportedCredentialProofType('Ed25519Signature2020')).toBe(true);
    expect(isSupportedCredentialProofType('DataIntegrityProof')).toBe(true);
    for (const type of SUPPORTED_CREDENTIAL_PROOF_TYPES) {
      expect(isSupportedCredentialProofType(type)).toBe(true);
    }
  });

  it('rejects an unknown suite: naming it must not pass verification (#151)', () => {
    expect(isSupportedCredentialProofType('BogusSuite2099')).toBe(false);
    // jws-based suites are not verifiable here; the verifier checks proofValue.
    expect(isSupportedCredentialProofType('JsonWebSignature2020')).toBe(false);
  });

  it('rejects a missing or non-string proof.type', () => {
    expect(isSupportedCredentialProofType(undefined)).toBe(false);
    expect(isSupportedCredentialProofType(null)).toBe(false);
    expect(isSupportedCredentialProofType(42)).toBe(false);
    expect(isSupportedCredentialProofType('')).toBe(false);
  });
});
