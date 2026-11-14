import { describe, expect, it } from 'vitest';
import { withStatusCache } from '../status-cache.js';
import { DelegationCredentialVerifier, type StatusListResolver } from '../vc-verifier.js';
import { createDidKeyResolver } from '../did-key-resolver.js';
import { createRevocationChecker } from '../../card/revocation.js';
import { createStatusListProofVerifier } from '../../card/status-list-proof.js';
import { identity, statusList, serve, STATUS_URL } from '../../card/__tests__/signed-chain-helpers.js';
import { createRealSignatureVerifier } from '../../__tests__/audit/helpers/crypto-helpers.js';
import { credentialJwt, delegationRecord, keyFromJwk, signedCredential } from '../../__tests__/utils/delegation-credentials.js';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import type { CredentialStatus, DelegationCredential } from '../../types/protocol.js';

describe('status caching preserves omitted versus malformed purposes', () => {
  it.each(['object', 'JWT'] as const)('%s: cannot reuse an omitted-purpose allow for an explicit null', async form => {
    const issuer = identity();
    const didResolver = createDidKeyResolver();
    const checker = createRevocationChecker({
      fetch: serve(statusList(issuer)),
      verifyStatusList: createStatusListProofVerifier({ didResolver }),
    });
    // A common adapter between the two exported status-check interfaces.
    const resolver: StatusListResolver = {
      checkStatus: async (status, context) => (await checker(status, context)).revoked,
    };
    const cached = withStatusCache(resolver, { maxStalenessMs: 60_000 });
    const makeVerifier = (statusListResolver: StatusListResolver) => new DelegationCredentialVerifier({
      didResolver, statusListResolver, signatureVerifier: createRealSignatureVerifier(new NodeCryptoProvider()),
    });
    const key = keyFromJwk(issuer.did, issuer.method, issuer.privateJwk);
    const credential = (status: CredentialStatus): Promise<DelegationCredential> =>
      signedCredential(key, {
        record: delegationRecord(issuer.did, {
          id: 'del-cache-purpose', subjectDid: 'did:example:holder', constraints: { scopes: ['read'] },
        }),
        credentialStatus: status,
      });
    const run = async (verifier: DelegationCredentialVerifier, status: CredentialStatus) => {
      const vc = await credential(status);
      return form === 'object' ? verifier.verifyDelegationCredential(vc) : verifier.verifyDelegationJwt(await credentialJwt(vc, key));
    };
    // The checker deliberately accepts absence (Card entries use it), while
    // explicit null must be refused. Both inputs and proofs are real JSON.
    const omitted = { type: 'BitstringStatusListEntry', statusListCredential: STATUS_URL, statusListIndex: '7' } as CredentialStatus;
    const malformed = { ...omitted, statusPurpose: null } as unknown as CredentialStatus;
    expect((await run(makeVerifier(resolver), omitted)).valid).toBe(true);
    expect((await run(makeVerifier(resolver), malformed)).valid).toBe(false);
    const verifier = makeVerifier(cached);
    expect((await run(verifier, omitted)).valid).toBe(true);
    expect((await run(verifier, malformed)).valid).toBe(false);
    expect((await run(verifier, omitted)).valid).toBe(true);
  });
});
