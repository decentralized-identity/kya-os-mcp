/**
 * Delegation verification — `verificationCache` config threading.
 *
 * Proves `KyaOsDelegationConfig.verificationCache` reaches the
 * `DelegationCredentialVerifier` through `createDelegationVerification`,
 * observed from OUTSIDE the verifier: with the default cache, the second
 * verification of the same credential serves the signature from cache (the
 * custom DID resolver is consulted once); with `ttlMs: 0`, signature caching
 * is disabled and the resolver is consulted on every call.
 */
import { describe, it, expect } from 'vitest';
import { createDelegationVerification } from '../with-kya-os.delegation-verify.js';
import type { MiddlewareDeps } from '../with-kya-os.deps.js';
import type { KyaOsDelegationConfig } from '../with-kya-os.config-types.js';
import { DelegationCredentialIssuer } from '../../delegation/vc-issuer.js';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import {
  createRealCryptoProvider,
  createRealIdentity,
  createRealSigningFunction,
} from '../../__tests__/audit/helpers/crypto-helpers.js';

async function setup(
  verificationCache?: NonNullable<KyaOsDelegationConfig['verificationCache']>,
) {
  const crypto = createRealCryptoProvider();
  const issuerIdentity = await createRealIdentity(crypto);
  const subjectIdentity = await createRealIdentity(crypto);
  const issuer = new DelegationCredentialIssuer(
    {
      getDid: () => issuerIdentity.did,
      getKeyId: () => issuerIdentity.kid,
      getPrivateKey: () => issuerIdentity.privateKey,
    },
    createRealSigningFunction(crypto, issuerIdentity),
  );
  const vc = await issuer.issueDelegationCredential({
    id: 'del-cache-config-test',
    issuerDid: issuerIdentity.did,
    subjectDid: subjectIdentity.did,
    vcId: 'urn:uuid:cache-config-test',
    constraints: {
      scopes: ['tools:read'],
      notBefore: Math.floor(Date.now() / 1000) - 3600,
      notAfter: Math.floor(Date.now() / 1000) + 3600,
    },
    signature: '',
    status: 'active',
    createdAt: Date.now(),
  });

  const didKey = createDidKeyResolver();
  let resolves = 0;
  const deps = {
    identity: {
      did: issuerIdentity.did,
      kid: issuerIdentity.kid,
      privateKey: issuerIdentity.privateKey,
      publicKey: issuerIdentity.publicKey,
    },
    cryptoProvider: crypto,
    delegationConfig: {
      didResolver: {
        async resolve(did: string) {
          resolves += 1;
          return didKey.resolve(did);
        },
      },
      ...(verificationCache ? { verificationCache } : {}),
    },
  } as unknown as MiddlewareDeps;

  const verification = createDelegationVerification(deps);
  return { verification, vc, resolveCount: () => resolves };
}

describe('verificationCache config threading', () => {
  it('serves the signature from cache on the second call by default', async () => {
    const { verification, vc, resolveCount } = await setup();
    expect((await verification.validateDelegationChain(vc)).valid).toBe(true);
    expect((await verification.validateDelegationChain(vc)).valid).toBe(true);
    expect(resolveCount()).toBe(1);
  });

  it('ttlMs: 0 disables signature caching (resolver consulted every call)', async () => {
    const { verification, vc, resolveCount } = await setup({ ttlMs: 0 });
    expect((await verification.validateDelegationChain(vc)).valid).toBe(true);
    expect((await verification.validateDelegationChain(vc)).valid).toBe(true);
    expect(resolveCount()).toBe(2);
  });
});
