/**
 * A proof's meta as its signature covers it (SPEC §7.4). A member no signature covers, one the
 * proof schema does not name or an optional claim written as "", may ride on a proof in 1.x and
 * the proof still verifies; but the verifier hands back, and acts on, only the meta its signature
 * covers. The generator writes no such member.
 */

import { beforeAll, describe, expect, it } from 'vitest';
import {
  createRealCryptoProvider,
  createRealIdentity,
  MemoryNonceCacheProvider,
  RealClockProvider,
  RealFetchProvider,
} from '../../__tests__/audit/helpers/crypto-helpers.js';
import type { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { extractPublicKeyFromDidKey, publicKeyToJwk } from '../../delegation/did-key-resolver.js';
import type { AgentIdentity } from '../../providers/base.js';
import type { DetachedProof, ProofMeta } from '../../types/protocol.js';
import type { Ed25519JWK } from '../../utils/crypto-service.js';
import { KYA_OS_PROOF_META_KEY, ProofGenerator, type ProofOptions } from '../generator.js';
import { signedProofMeta } from '../payload.js';
import { extractProofFromMeta, ProofVerifier } from '../verifier.js';

const request = { method: 'tools/call', params: { name: 'payments.refund', arguments: { amount: 5 } } };
const response = { data: [{ type: 'text', text: 'refunded' }] };
const now = Math.floor(Date.now() / 1000);
const session = {
  sessionId: 'kyaos_session', audience: 'did:web:server.example', nonce: 'handshake-nonce', timestamp: now,
  createdAt: now, lastActivity: now, ttlMinutes: 30, identityState: 'anonymous' as const,
};
/** Members no signature covers: two the schema does not name, and an optional claim written as "". */
const unsigned = { toolName: 'payments.refund', submissionOutcome: 'success', scopeId: '' };

let crypto: NodeCryptoProvider;
let server: AgentIdentity;
let generator: ProofGenerator;
let key: Ed25519JWK;

beforeAll(async () => {
  crypto = createRealCryptoProvider();
  server = await createRealIdentity(crypto);
  generator = new ProofGenerator(
    { did: server.did, kid: server.kid, privateKey: server.privateKey, publicKey: server.publicKey },
    crypto,
  );
  key = { ...(publicKeyToJwk(extractPublicKeyFromDidKey(server.did)!) as Ed25519JWK), kid: server.kid };
});

const verifier = (): ProofVerifier => new ProofVerifier({
  cryptoProvider: crypto,
  clockProvider: new RealClockProvider(),
  nonceCacheProvider: new MemoryNonceCacheProvider(),
  fetchProvider: new RealFetchProvider(),
});

/** A genuine proof with `members` added to its meta after signing. */
async function carrying(members: Record<string, unknown>): Promise<{ proof: DetachedProof; signed: ProofMeta }> {
  const genuine = await generator.generateProof(request, response, session, { clientDid: 'did:web:client.example' });
  return { proof: { jws: genuine.jws, meta: { ...genuine.meta, ...members } as ProofMeta }, signed: genuine.meta };
}

describe('the meta a verifier hands back', () => {
  it('is the meta the signature covers, without members it does not', async () => {
    const { proof, signed } = await carrying(unsigned);

    const live = await verifier().verifyProof(proof, key, { request, response });
    const retained = await verifier().verifyProofArtifact(proof, key, { request, response });

    expect(live).toEqual({ valid: true, meta: signed });
    expect(retained).toEqual({ valid: true, meta: signed });
  });

  it('reads an optional claim written as "" as absent', async () => {
    const { proof, signed } = await carrying({ delegationRef: '', reason: '', scopeId: '' });

    expect(await verifier().verifyProof(proof, key)).toEqual({ valid: true, meta: signed });
  });

  it('is the same through the deprecated detached path', async () => {
    const { proof, signed } = await carrying(unsigned);
    const ours = verifier();

    const result = await ours.verifyProofDetached(proof, ours.buildCanonicalPayload(proof.meta), key);

    expect(result).toEqual({ valid: true, meta: signed });
  });

  it('is absent from a refusal', async () => {
    const { proof } = await carrying({ requestHash: `sha256:${'0'.repeat(64)}` });

    expect(await verifier().verifyProof(proof, key)).not.toHaveProperty('meta');
  });
});

describe('a proof read from a result\'s _meta', () => {
  it('carries only the meta its signature covers', async () => {
    const { proof, signed } = await carrying(unsigned);

    expect(extractProofFromMeta({ [KYA_OS_PROOF_META_KEY]: proof })).toEqual({
      success: true,
      proof: { jws: proof.jws, meta: signed },
    });
  });
});

describe('the meta the generator writes', () => {
  it('holds no member the schema does not name and no optional claim written as ""', async () => {
    const options = { ...unsigned, delegationRef: '', clientDid: '', reason: '' } as unknown as ProofOptions;

    const proof = await generator.generateProof(request, response, session, options);

    expect(Object.keys(proof.meta).sort()).toEqual(
      ['audience', 'did', 'kid', 'nonce', 'requestHash', 'responseHash', 'sessionId', 'ts'],
    );
    expect(await verifier().verifyProof(proof, key, { request, response }))
      .toEqual({ valid: true, meta: proof.meta });
    expect(await generator.verifyProof({ ...proof, meta: { ...proof.meta, ...unsigned } }, request, response))
      .toBe(true);
  });
});

describe('signedProofMeta', () => {
  it('keeps each claim the payload signs, and only those', () => {
    const meta = {
      did: 'did:web:a.example', kid: 'did:web:a.example#k', ts: 1, nonce: 'n', audience: 'aud',
      sessionId: 's', requestHash: `sha256:${'1'.repeat(64)}`, scopeId: 'scope', delegationRef: 'ref',
      delegationChainDigest: `sha256:${'2'.repeat(64)}`, clientDid: 'did:web:c.example', outcome: 'denied',
      reason: 'r', prf: 'org.kya-os/response-proof.envelope',
    } as ProofMeta;

    expect(signedProofMeta({ ...meta, ...unsigned, scopeId: 'scope' } as ProofMeta)).toEqual(meta);
  });
});
