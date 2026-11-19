/**
 * Parameters a proof's JWS protected header carries beside `alg` and `kid`. The header is part of
 * the signing input, so the signature covers them; a request proof states its delegation there
 * (SPEC.md §7.8). They are written after the generator's own two, never in place of them, and never
 * into `meta`, so a verifier that knows none of them rebuilds the same payload and verifies the proof.
 */
import { decodeProtectedHeader } from 'jose';
import { describe, expect, it } from 'vitest';
import { nodeCrypto as crypto } from '../../__tests__/utils/node-crypto-provider.js';
import { MemoryNonceCacheProvider, RealClockProvider, RealFetchProvider } from '../../__tests__/audit/helpers/crypto-helpers.js';
import { extractPublicKeyFromDidKey, publicKeyToJwk } from '../../delegation/did-key-resolver.js';
import type { SessionContext } from '../../types/protocol.js';
import type { Ed25519JWK } from '../../utils/crypto-service.js';
import { generateDidKeyFromBase64, didKeyFragment } from '../../utils/did-helpers.js';
import { PROTECTED_HEADER_PARAMETERS, ProofGenerator, type InternalProofOptions } from '../generator.js';
import { ProofVerifier } from '../verifier.js';

const REQUEST = { method: 'tools/call', params: { name: 'echo', arguments: { msg: 'hi' } } };

async function generator() {
  const { publicKey, privateKey } = await crypto.generateKeyPair();
  const did = generateDidKeyFromBase64(publicKey);
  const kid = `${did}#${didKeyFragment(did)}`;
  const now = Math.floor(Date.now() / 1000);
  const session: SessionContext = {
    sessionId: 'sess-1',
    audience: 'did:web:server.example.com',
    nonce: 'n-1',
    timestamp: now,
    createdAt: now,
    lastActivity: now,
    ttlMinutes: 30,
    identityState: 'anonymous',
  };
  const proofWith = (parameters?: Record<string, string>) => {
    const options: InternalProofOptions = parameters === undefined ? {} : { [PROTECTED_HEADER_PARAMETERS]: parameters };
    return new ProofGenerator({ did, kid, publicKey, privateKey }, crypto).generateProof(REQUEST, undefined, session, options);
  };
  const key = { ...(publicKeyToJwk(extractPublicKeyFromDidKey(did)!) as Ed25519JWK), kid };
  return { kid, proofWith, key };
}

const verifier = (): ProofVerifier =>
  new ProofVerifier({
    cryptoProvider: crypto,
    clockProvider: new RealClockProvider(),
    nonceCacheProvider: new MemoryNonceCacheProvider(),
    fetchProvider: new RealFetchProvider(),
    timestampSkewSeconds: 300,
  });

describe('protected header parameters of a generated proof', () => {
  it('are written after alg and kid, in a proof that verifies as one without them does', async () => {
    const { kid, proofWith, key } = await generator();
    const proof = await proofWith({ 'org.example/note': 'kept' });

    expect(Object.entries(decodeProtectedHeader(proof.jws))).toEqual([['alg', 'EdDSA'], ['kid', kid], ['org.example/note', 'kept']]);
    expect(await verifier().verifyProof(proof, key, { request: REQUEST })).toMatchObject({ valid: true });
  });

  it('never replace the generator\'s own alg and kid', async () => {
    const { kid, proofWith, key } = await generator();
    const proof = await proofWith({ alg: 'none', kid: 'did:web:other.example#key-9', 'org.example/note': 'kept' });

    expect(decodeProtectedHeader(proof.jws)).toEqual({ alg: 'EdDSA', kid, 'org.example/note': 'kept' });
    expect(await verifier().verifyProof(proof, key, { request: REQUEST })).toMatchObject({ valid: true });
  });

  it('are in the header alone: the meta and the payload are those of a proof without them', async () => {
    const { kid, proofWith } = await generator();
    const [plain, stating] = await Promise.all([proofWith(), proofWith({ 'org.example/note': 'kept' })]);

    expect(decodeProtectedHeader(plain.jws)).toEqual({ alg: 'EdDSA', kid });
    expect(Object.keys(stating.meta)).toEqual(Object.keys(plain.meta));
    expect(Object.getOwnPropertySymbols(stating.meta)).toEqual([]);
  });
});
