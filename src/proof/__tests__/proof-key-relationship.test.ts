import { beforeAll, describe, expect, it, vi } from 'vitest';
import { ProofGenerator } from '../generator.js';
import { ProofVerifier } from '../verifier.js';
import { NodeCryptoProvider } from '../../providers/node-crypto.js';
import { SystemClockProvider } from '../../providers/system-clock.js';
import { MemoryNonceCacheProvider } from '../../providers/memory.js';
import { NoopFetchProvider } from '../../providers/runtime-fetch.js';
import { methodOf } from '../../__tests__/utils/did-documents.js';
import type { DIDDocument, VerificationMethod } from '../../delegation/vc-verifier.types.js';
import type { DetachedProof } from '../../types/protocol.js';

const did = 'did:web:proof.example';
const kid = `${did}#proof`;
const crypto = new NodeCryptoProvider();
const request = { method: 'records.read', params: { id: 'one' } };
const response = { data: [{ type: 'text' as const, text: 'record one' }] };
let method: VerificationMethod;
let proof: DetachedProof;

beforeAll(async () => {
  const identity = { did, kid, ...await crypto.generateKeyPair() };
  method = methodOf(identity);
  proof = await new ProofGenerator(identity, crypto).generateProof(request, response, {
    sessionId: 'relationship-test', audience: 'records.example', nonce: 'relationship-nonce',
    timestamp: Math.floor(Date.now() / 1000), createdAt: Date.now(), lastActivity: Date.now(),
    ttlMinutes: 10, identityState: 'anonymous',
  });
});

function verifier(document: DIDDocument) {
  const fetch = new NoopFetchProvider();
  fetch.resolveDID = vi.fn(async () => document);
  return {
    fetch,
    reader: new ProofVerifier({ cryptoProvider: crypto, clockProvider: new SystemClockProvider(),
      nonceCacheProvider: new MemoryNonceCacheProvider(), fetchProvider: fetch }),
  };
}

/** The public example's path: resolve the signer's key, then verify the actual response proof. */
async function verifyResponse(document: DIDDocument) {
  const { reader } = verifier(document);
  const key = await reader.fetchPublicKeyFromDID(proof.meta.did, proof.meta.kid);
  if (!key) throw new Error('No proof key');
  return reader.verifyProof(proof, key, { request, response });
}

describe('detached response proof key purpose', () => {
  it.each(['authentication', 'unlisted'])('refuses a genuine proof with an %s key', async (relationship) => {
    const document = { id: did, verificationMethod: [method],
      ...(relationship === 'authentication' ? { authentication: [kid] } : {}) };
    await expect(verifyResponse(document)).rejects.toMatchObject({
      code: 'VERIFICATION_METHOD_NOT_FOUND', message: expect.stringContaining('assertionMethod'),
    });
  });

  it.each(['reference', 'embedded'])('verifies a proof with an assertion key by %s', async (form) => {
    const document = form === 'reference'
      ? { id: did, verificationMethod: [method], assertionMethod: ['#proof'] }
      : { id: did, assertionMethod: [method] };
    expect(await verifyResponse(document)).toMatchObject({ valid: true });
  });

  it.each(['duplicate', 'no type', 'no controller'])('refuses a %s method', async (problem) => {
    const changed = { ...method } as Partial<VerificationMethod>;
    if (problem === 'no type') delete changed.type;
    if (problem === 'no controller') delete changed.controller;
    const document = { id: did, verificationMethod: [changed],
      assertionMethod: problem === 'duplicate' ? [method] : [kid] } as DIDDocument;
    await expect(verifyResponse(document)).rejects.toMatchObject({ code: 'VERIFICATION_METHOD_NOT_FOUND' });
  });

  it.each(['controller', 'document'])('refuses another DID as the %s', async (member) => {
    const document = { id: member === 'document' ? 'did:web:other.example' : did,
      verificationMethod: [{ ...method, controller: member === 'controller' ? 'did:web:other.example' : did }],
      assertionMethod: [kid] };
    await expect(verifyResponse(document)).rejects.toMatchObject({ code: 'KID_DID_MISMATCH' });
  });

  it('refuses a kid of another DID before resolving', async () => {
    const { reader, fetch } = verifier({ id: did, assertionMethod: [method] });
    await expect(reader.fetchPublicKeyFromDID(did, 'did:web:other.example#proof'))
      .rejects.toMatchObject({ code: 'KID_DID_MISMATCH' });
    expect(fetch.resolveDID).not.toHaveBeenCalled();
  });

  it('takes the first assertion entry, not the first published key, when no kid is given', async () => {
    const login = { ...method, id: `${did}#login`, publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'OTHER' } };
    const { reader } = verifier({ id: did, verificationMethod: [login, method], assertionMethod: [kid, login.id] });
    expect(await reader.fetchPublicKeyFromDID(did)).toMatchObject({ x: method.publicKeyJwk!.x, kid });
  });

  it('does not skip an unusable first assertion entry', async () => {
    const { reader } = verifier({ id: did, verificationMethod: [method], assertionMethod: ['#missing', kid] });
    await expect(reader.fetchPublicKeyFromDID(did)).rejects.toMatchObject({
      code: 'VERIFICATION_METHOD_NOT_FOUND', message: expect.stringContaining('first entry'),
    });
  });

  it('does not mutate a frozen document or key', async () => {
    const frozen = Object.freeze({ ...method, publicKeyJwk: Object.freeze({ ...method.publicKeyJwk }) });
    const { reader } = verifier(Object.freeze({ id: did, assertionMethod: Object.freeze([frozen]) }) as unknown as DIDDocument);
    expect(await reader.fetchPublicKeyFromDID(did, kid)).toMatchObject({ kid });
    expect(frozen.publicKeyJwk).not.toHaveProperty('kid');
  });
});
