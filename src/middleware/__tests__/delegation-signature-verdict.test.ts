/**
 * The delegation gate checks a credential's proof with the `CryptoProvider` the host gives the
 * middleware. The signature verifies only when that provider's `verify` answers the literal `true`:
 * any other answer, which untyped code or a fault can give, is a signature that did not verify.
 */

import { beforeAll, describe, expect, it } from 'vitest';
import { delegationRecord, keyOf, signedCredential } from '../../__tests__/utils/delegation-credentials.js';
import { issuerDidDocument, methodOf } from '../../__tests__/utils/did-documents.js';
import { NOT_TRUE } from '../../__tests__/utils/verdict-answers.js';
import type { AgentIdentity, CryptoProvider } from '../../providers/base.js';
import type { DelegationCredential } from '../../types/protocol.js';
import { createDelegationVerification } from '../with-kya-os.delegation-verify.js';
import type { MiddlewareDeps } from '../with-kya-os.deps.js';

const SERVER = 'did:web:server.example';
let root: AgentIdentity;
let credential: DelegationCredential;
beforeAll(async () => {
  root = await keyOf('did:web:root.example', 'key');
  credential = await signedCredential(root, {
    record: delegationRecord(root.did, {
      id: 'del-leaf',
      constraints: { scopes: ['tools:read'], audience: SERVER, notAfter: Math.floor(Date.now() / 1000) + 3600 },
    }),
  });
});

/** The gate's verdict on the root's credential when the crypto provider's `verify` answers `answer`. */
const verdictWhen = (answer: unknown) =>
  createDelegationVerification({
    identity: { ...root, did: SERVER },
    cryptoProvider: { verify: async () => answer } as unknown as CryptoProvider,
    delegationConfig: {
      trustedRootIssuers: [root.did],
      didResolver: { resolve: async (did: string) => (did === root.did ? issuerDidDocument(methodOf(root)) : null) },
    },
  } as unknown as MiddlewareDeps).verifyDelegation(credential);

describe("the delegation gate's signature check", () => {
  it('verifies the credential when the crypto provider answers the literal true', async () => {
    expect(await verdictWhen(true)).toMatchObject({ valid: true });
  });

  it.each(NOT_TRUE)('finds the signature failed when the crypto provider answers %s', async (_label, answer) => {
    expect(await verdictWhen(answer)).toMatchObject({
      valid: false,
      reason: 'Delegation del-leaf invalid: Signature verification failed',
    });
  });
});
