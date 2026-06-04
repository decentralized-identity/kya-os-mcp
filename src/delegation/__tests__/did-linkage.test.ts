import { describe, it, expect, vi } from 'vitest';
import {
  updateCheqdAlsoKnownAs,
  verifyDidLinkage,
} from '../did-linkage.js';
import type { DIDDocument } from '../vc-verifier.js';
import type { CheqdDidRegistrarClient } from '../../cheqd/registrar.js';

describe('verifyDidLinkage', () => {
  const didWeb = 'did:web:agent.example.com';
  const didCheqd = 'did:cheqd:testnet:11111111-1111-4111-8111-111111111111';

  const webDoc: DIDDocument = {
    id: didWeb,
    alsoKnownAs: [didCheqd],
  };
  const cheqdDoc: DIDDocument = {
    id: didCheqd,
    alsoKnownAs: [didWeb],
  };

  it('accepts valid bidirectional alsoKnownAs linkage', () => {
    const result = verifyDidLinkage({
      primaryDid: didWeb,
      secondaryDid: didCheqd,
      primaryDidDocument: webDoc,
      secondaryDidDocument: cheqdDoc,
    });

    expect(result.valid).toBe(true);
    expect(result.checks.primaryReferencesSecondary).toBe(true);
    expect(result.checks.secondaryReferencesPrimary).toBe(true);
  });

  it('rejects one-way linkage when bidirectional linkage is required', () => {
    const result = verifyDidLinkage({
      primaryDid: didWeb,
      secondaryDid: didCheqd,
      primaryDidDocument: webDoc,
      secondaryDidDocument: { id: didCheqd },
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toContain('Bidirectional');
  });

  it('allows one-way linkage when bidirectional linkage is not required', () => {
    expect(
      verifyDidLinkage({
        primaryDid: didWeb,
        secondaryDid: didCheqd,
        primaryDidDocument: webDoc,
        secondaryDidDocument: { id: didCheqd },
        requireBidirectional: false,
      }).valid,
    ).toBe(true);
  });

  it('rejects missing, malformed, and mismatched documents', () => {
    expect(
      verifyDidLinkage({
        primaryDid: didWeb,
        secondaryDid: didCheqd,
        primaryDidDocument: undefined,
        secondaryDidDocument: cheqdDoc,
      }).valid,
    ).toBe(false);

    expect(
      verifyDidLinkage({
        primaryDid: didWeb,
        secondaryDid: didCheqd,
        primaryDidDocument: { id: didWeb, alsoKnownAs: [didCheqd] },
        secondaryDidDocument: { id: 'did:cheqd:testnet:wrong', alsoKnownAs: [didWeb] },
      }).valid,
    ).toBe(false);

    expect(
      verifyDidLinkage({
        primaryDid: didWeb,
        secondaryDid: didCheqd,
        primaryDidDocument: { id: didWeb, alsoKnownAs: ['did:cheqd:testnet:other', 'did:cheqd:testnet:other'] },
        secondaryDidDocument: cheqdDoc,
      }).valid,
    ).toBe(false);

    expect(
      verifyDidLinkage({
        primaryDid: didWeb,
        secondaryDid: didCheqd,
        primaryDidDocument: { id: didWeb, alsoKnownAs: [{ uri: didCheqd }] } as unknown as DIDDocument,
        secondaryDidDocument: cheqdDoc,
      }).valid,
    ).toBe(false);
  });
});

describe('updateCheqdAlsoKnownAs', () => {
  const didWeb = 'did:web:agent.example.com';
  const didCheqd = 'did:cheqd:testnet:11111111-1111-4111-8111-111111111111';

  it('preserves existing document fields and submits an update when linkage is missing', async () => {
    const didDocument: DIDDocument = {
      id: didCheqd,
      verificationMethod: [
        {
          id: `${didCheqd}#key-1`,
          type: 'Ed25519VerificationKey2020',
          controller: didCheqd,
        },
      ],
      alsoKnownAs: ['did:web:existing.example.com'],
    };
    const updateDid = vi.fn().mockResolvedValue({
      success: true,
      operation: 'update',
      stage: 'complete',
    });

    const result = await updateCheqdAlsoKnownAs({
      didWeb,
      didCheqd,
      resolver: { resolve: vi.fn().mockResolvedValue(didDocument) },
      registrar: { updateDid } as unknown as CheqdDidRegistrarClient,
      signer: vi.fn(),
      verificationMethodId: `${didCheqd}#key-1`,
    });

    expect(result.changed).toBe(true);
    expect(updateDid).toHaveBeenCalledWith({
      did: didCheqd,
      didDocument: {
        ...didDocument,
        alsoKnownAs: ['did:web:existing.example.com', didWeb],
      },
      signer: expect.any(Function),
      verificationMethodId: `${didCheqd}#key-1`,
    });
  });

  it('does not submit an update when the linkage already exists', async () => {
    const updateDid = vi.fn();

    const result = await updateCheqdAlsoKnownAs({
      didWeb,
      didCheqd,
      resolver: { resolve: vi.fn().mockResolvedValue({ id: didCheqd, alsoKnownAs: [didWeb] }) },
      registrar: { updateDid } as unknown as CheqdDidRegistrarClient,
      signer: vi.fn(),
    });

    expect(result.changed).toBe(false);
    expect(updateDid).not.toHaveBeenCalled();
  });
});
