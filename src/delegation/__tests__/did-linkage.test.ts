import { describe, it, expect } from 'vitest';
import { verifyDidLinkage } from '../did-linkage.js';
import type { DIDDocument } from '../vc-verifier.js';

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
