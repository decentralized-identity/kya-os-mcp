/**
 * Every refusal reason of the delegation verifier that interpolates text it did not write, the
 * message of an error a resolver, a chain resolver, a revocation checker or `jose` throws, or the
 * reason a revocation checker gives, writes that text through `sanitizeForMessage`: cut after 256
 * UTF-16 code units, with control characters and lone surrogates read as U+FFFD, so the reason is
 * bounded, well-formed text on either proof path.
 */
import { describe, it, expect, vi } from 'vitest';

const josePlan = vi.hoisted(() => ({ failure: undefined as Error | undefined }));
vi.mock('jose', async (original) => {
  const actual = await original<typeof import('jose')>();
  return {
    ...actual,
    compactVerify: (async (...args: Parameters<typeof actual.compactVerify>) => {
      if (josePlan.failure !== undefined) throw josePlan.failure;
      return actual.compactVerify(...args);
    }) as typeof actual.compactVerify,
  };
});

import { DelegationCredentialVerifier } from '../vc-verifier.js';
import { validateDelegationChain, type ChainEnforcementDeps } from '../chain-enforcement.js';
import { wrapDelegationAsVC, type DelegationCredential } from '../../types/protocol.js';
import {
  createRealCryptoProvider,
  createRealIdentity,
  createRealSignatureVerifier,
} from '../../__tests__/audit/helpers/crypto-helpers.js';
import { delegationRecord, signedCredential, signedJwt } from '../../__tests__/utils/delegation-credentials.js';
import { createDidKeyResolver } from '../did-key-resolver.js';

const crypto = createRealCryptoProvider();
/** Text no verifier wrote: a line break, a control, a lone surrogate, and far more than 256 units. */
const HOSTILE = `no document\n\u001b[31m \uD800 ${'x'.repeat(1_000)}`;
/** The longest reason here: a fixed prefix, the 256 units the sanitizer keeps, and its mark. */
const LONGEST = 128 + 256 + 1;

const isWellFormed = (text: string): boolean => (text as unknown as { isWellFormed(): boolean }).isWellFormed();

function expectSanitized(reason: string | undefined, prefix: string): void {
  const text = String(reason);
  expect({
    prefixed: text.startsWith(prefix),
    wellFormed: isWellFormed(text),
    bounded: text.length <= LONGEST,
    controls: /[\u0000-\u001f]/.test(text),
    cut: text.endsWith('\u2026'),
  }, text.slice(0, 120)).toEqual({ prefixed: true, wellFormed: true, bounded: true, controls: false, cut: true });
}

/** A delegation `issuer` signs with a Data Integrity proof, and the same one as a VC-JWT naming its key. */
async function signedBothWays() {
  const issuer = await createRealIdentity(crypto);
  const record = delegationRecord(issuer.did, { id: 'del-1' });
  const credential = await signedCredential(issuer, { record });
  const jwt = await signedJwt(issuer, { record, kid: issuer.kid });
  return { issuer, credential, jwt };
}

describe('a refusal reason that quotes an error the verifier did not write', () => {
  it('is bounded, well-formed text when the issuer DID resolver throws, on either proof path', async () => {
    const { issuer, credential, jwt } = await signedBothWays();
    const verifier = new DelegationCredentialVerifier({
      didResolver: { resolve: async () => { throw new Error(HOSTILE); } },
      signatureVerifier: createRealSignatureVerifier(crypto),
    });
    const embedded = await verifier.verifyDelegationCredential(credential, { skipCache: true });
    expectSanitized(embedded.reason, 'Signature verification error: no document\uFFFD\uFFFD[31m \uFFFD x');
    const enveloped = await verifier.verifyDelegationJwt(jwt, { skipCache: true });
    expectSanitized(enveloped.reason, `Could not resolve issuer DID ${JSON.stringify(issuer.did)}: no document\uFFFD\uFFFD[31m \uFFFD x`);
  });

  it('is bounded, well-formed text when the JWT signature check throws', async () => {
    const { jwt } = await signedBothWays();
    const verifier = new DelegationCredentialVerifier({ didResolver: createDidKeyResolver(), signatureVerifier: createRealSignatureVerifier(crypto) });
    josePlan.failure = new Error(HOSTILE);
    try {
      const enveloped = await verifier.verifyDelegationJwt(jwt, { skipCache: true });
      expectSanitized(enveloped.reason, 'JWT envelope signature is not valid: no document\uFFFD');
    } finally {
      josePlan.failure = undefined;
    }
  });

  describe('in the chain walk', () => {
    const leaf = (parentId?: string): DelegationCredential => ({
      ...wrapDelegationAsVC(delegationRecord('did:web:acme.example', { id: 'del-1', ...(parentId ? { parentId } : {}) })),
      proof: { type: 'Ed25519Signature2020', proofValue: 'z', verificationMethod: 'did:web:acme.example#k' },
    }) as DelegationCredential;
    const deps: ChainEnforcementDeps = {
      serverDid: 'did:web:server.example',
      verifier: { verifyDelegationCredential: async () => ({ valid: true }) },
      statusListConfigured: true,
    };

    it('is bounded, well-formed text when the chain resolver throws', async () => {
      const result = await validateDelegationChain(leaf('del-0'), {
        ...deps, resolveDelegationChain: async () => { throw new Error(HOSTILE); },
      });
      expectSanitized(result.reason, 'Failed to resolve delegation chain: no document\uFFFD');
    });

    it('is bounded, well-formed text when the revocation checker throws, or names its reason', async () => {
      const thrown = await validateDelegationChain(leaf(), {
        ...deps, revocationChecker: { isRevoked: async () => { throw new Error(HOSTILE); } },
      });
      expectSanitized(thrown.reason, 'Revocation check failed for delegation "del-1": no document\uFFFD');
      const revoked = await validateDelegationChain(leaf(), {
        ...deps, revocationChecker: { isRevoked: async () => ({ revoked: true, reason: HOSTILE }) },
      });
      expectSanitized(revoked.reason, 'Delegation "del-1" is revoked: no document\uFFFD');
    });
  });
});
