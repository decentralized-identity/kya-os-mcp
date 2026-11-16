/**
 * The delegation gate refuses a delegation whose revocation checker gives an answer that cannot be
 * read, with the reason chain enforcement gives for it. An answer with a getter that throws is such
 * an answer: the gate names the member that threw, as it names a `revoked` that is not a boolean,
 * and never falls back on the reason it keeps for an error nothing foresaw.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import { delegationRecord, keyOf, signedCredential } from '../../__tests__/utils/delegation-credentials.js';
import { issuerDidDocument, methodOf } from '../../__tests__/utils/did-documents.js';
import { NOT_BOOLEAN_ANSWERS, NOT_OBJECT_ANSWERS, THROWING_ANSWERS } from '../../__tests__/utils/revocation-answers.js';
import type { RevocationChecker } from '../../delegation/chain-enforcement.js';
import type { AgentIdentity } from '../../providers/base.js';
import { createMiddleware, served } from './helpers/received-proof.js';

const SCOPE = 'orders:place';
let root: AgentIdentity;
beforeAll(async () => {
  root = await keyOf('did:web:root.example', 'key');
});

/** What the gate answers a call with a delegation the root issued, when its checker answers `answer`. */
async function gateAnswer(answer: unknown): Promise<string> {
  const kyaos = await served(
    await createMiddleware({
      delegation: {
        trustedRootIssuers: [root.did],
        didResolver: { resolve: async (did: string) => (did === root.did ? issuerDidDocument(methodOf(root)) : null) },
        revocationChecker: { isRevoked: async () => answer } as RevocationChecker,
      },
    }),
  );
  const handler = kyaos.wrapWithDelegation('orders.place', { scopeId: SCOPE, consentUrl: 'https://root.example/consent' }, async () => ({
    content: [{ type: 'text', text: 'placed' }],
  }));
  const delegation = await signedCredential(root, {
    record: delegationRecord(root.did, {
      id: 'del-1',
      constraints: { scopes: [SCOPE], audience: kyaos.identity.did, notAfter: Math.floor(Date.now() / 1000) + 3600 },
    }),
  });
  return (await handler({ _kyaos_delegation: delegation }, undefined)).content[0]!.text;
}

describe('the delegation gate reading a revocation answer', () => {
  it('runs the tool on an answer whose revoked is the literal false', async () => {
    expect(await gateAnswer({ revoked: false })).toBe('placed');
  });

  it.each([...NOT_OBJECT_ANSWERS, ...NOT_BOOLEAN_ANSWERS, ...THROWING_ANSWERS])(
    'refuses the call with the unreadable-status reason when the checker answers %s',
    async (_label, answer, why) => {
      expect(JSON.parse(await gateAnswer(answer))).toEqual({
        error: 'delegation_invalid',
        reason: `Revocation status of delegation "del-1" could not be read: ${why}`,
      });
    },
  );
});
