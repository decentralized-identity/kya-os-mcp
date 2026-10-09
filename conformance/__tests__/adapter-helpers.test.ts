/**
 * `isUsableEd25519Document` decides whether a resolved DID document gives the
 * reference adapter a usable Ed25519 signing key. It must accept the key in
 * whichever form the document publishes it, as the verifiers do.
 */

import { describe, it, expect } from 'vitest';
import { isUsableEd25519Document } from '../adapter-helpers.js';
import type { DIDDocument, VerificationMethod } from '../../src/index.js';

const did = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const multibase = did.slice('did:key:'.length);
const vmId = `${did}#${multibase}`;

function docWith(method: Omit<VerificationMethod, 'id' | 'controller'>): DIDDocument {
  return { id: did, verificationMethod: [{ id: vmId, controller: did, ...method }] };
}

describe('isUsableEd25519Document', () => {
  it('accepts an Ed25519 key published as publicKeyJwk', () => {
    expect(
      isUsableEd25519Document(
        docWith({ type: 'JsonWebKey2020', publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAA' } }),
      ),
    ).toBe(true);
  });

  it('accepts an Ed25519 key published only as publicKeyMultibase', () => {
    expect(
      isUsableEd25519Document(docWith({ type: 'Ed25519VerificationKey2020', publicKeyMultibase: multibase })),
    ).toBe(true);
  });

  it('rejects a document whose only key is not an Ed25519 key', () => {
    expect(
      isUsableEd25519Document(
        docWith({
          type: 'X25519KeyAgreementKey2020',
          publicKeyMultibase: 'z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc',
        }),
      ),
    ).toBe(false);
    expect(
      isUsableEd25519Document(
        docWith({ type: 'JsonWebKey2020', publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' } }),
      ),
    ).toBe(false);
  });

  it('rejects a missing document or one with no verification method', () => {
    expect(isUsableEd25519Document(null)).toBe(false);
    expect(isUsableEd25519Document({ id: did })).toBe(false);
  });
});
