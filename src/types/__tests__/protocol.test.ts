import { describe, expect, it } from 'vitest';
import {
  extractDelegationFromVC,
  readCredentialProofValue,
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
