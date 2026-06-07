import { describe, it, expect, vi } from 'vitest';
import { updateCheqdAlsoKnownAs } from '../linkage.js';
import type { DIDDocument } from '../../../delegation/vc-verifier.js';
import type { CheqdDidRegistrarClient } from '../registrar.js';

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
