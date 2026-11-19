/**
 * Which subjects holder binding applies to, and what it answers for each. A did:key encodes its key,
 * so binding applies to every did:key subject. A request proof is EdDSA, so only an Ed25519 did:key
 * can be bound: any other did:key, a P-256 one as a hardware-backed agent key often is, or one that
 * does not decode, is unbound, never deferred as a did:web subject is.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import {
  assertHolderBinding,
  generateRequestProof,
  HOLDER_BINDING_ERROR,
  isHolderBindingApplicable,
  toHolderBindingRequest,
} from '../holder-binding.js';
import { ProofVerifier } from '../../proof/verifier.js';
import type { AgentIdentity } from '../../providers/base.js';
import {
  createRealCryptoProvider,
  createRealIdentity,
  MemoryNonceCacheProvider,
  RealClockProvider,
  RealFetchProvider,
} from '../../__tests__/audit/helpers/crypto-helpers.js';

const crypto = createRealCryptoProvider();
const AUDIENCE = 'did:web:server.example.com';
/** The P-256 did:key of the did:key method's own test vectors. */
const P256_DID_KEY = 'did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169';
/** A did:key whose multibase value does not decode to a key. */
const UNDECODABLE_DID_KEY = 'did:key:z6Mk';

const verifier = () =>
  new ProofVerifier({
    cryptoProvider: crypto,
    clockProvider: new RealClockProvider(),
    nonceCacheProvider: new MemoryNonceCacheProvider(),
    fetchProvider: new RealFetchProvider(),
    timestampSkewSeconds: 300,
  });

describe('holder binding and the key a subject DID encodes', () => {
  let agent: AgentIdentity;

  beforeAll(async () => {
    agent = await createRealIdentity(crypto);
  });

  it('applies to every did:key subject, and to no subject of another method', () => {
    expect([agent.did, P256_DID_KEY, UNDECODABLE_DID_KEY].map(isHolderBindingApplicable)).toEqual([true, true, true]);
    expect(['did:web:agent.example', 'not-a-did', 'did:keys:z6Mk'].map(isHolderBindingApplicable)).toEqual([false, false, false]);
  });

  it.each([
    ['a P-256 did:key subject', P256_DID_KEY],
    ['a did:key subject that does not decode', UNDECODABLE_DID_KEY],
  ])('answers unbound, not deferred, for %s, whatever proof is presented', async (_label, subjectDid) => {
    const args = { path: '/secret' };
    // The proof claims the subject, but no Ed25519 key can be read from its DID to check it with.
    const proof = await generateRequestProof({ identity: agent, crypto, toolName: 't', args, audience: AUDIENCE });
    const result = await assertHolderBinding({
      proof: { ...proof, meta: { ...proof.meta, did: subjectDid } },
      subjectDid,
      request: toHolderBindingRequest('t', args),
      proofVerifier: verifier(),
    });

    expect(result).toEqual({
      status: 'unbound',
      errorCode: HOLDER_BINDING_ERROR,
      reason: 'The did:key subject does not encode an Ed25519 key, the only key a request proof is checked with',
      cause: 'unsupported_subject_key',
    });
  });
});
