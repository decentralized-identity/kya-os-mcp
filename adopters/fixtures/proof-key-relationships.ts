/** Public response verification and CIMD projection against the installed tarball. */
import assert from 'node:assert/strict';
import { ProofGenerator, ProofVerifier, RuntimeFetchProvider, SystemClockProvider, MemoryNonceCacheProvider } from '@kya-os/mcp';
import { didKeyedJwks } from '@kya-os/mcp/card';
import { crypto, didDocumentOf, didWebParty } from './shared/keys.js';
import { runCases } from './shared/cases.js';

const party = await didWebParty('did:web:proof.example');
const document = didDocumentOf(party);
const request = { method: 'records.read', params: { id: 'one' } };
const response = { data: [{ type: 'text', text: 'one' }] };
const now = Date.now();
const proof = await new ProofGenerator(party, crypto).generateProof(request, response, {
  sessionId: 'adopter-proof-key', nonce: 'adopter-nonce', audience: 'reader.example',
  timestamp: Math.floor(now / 1000), createdAt: now, lastActivity: now, ttlMinutes: 10, identityState: 'anonymous',
});
const verifier = (doc = document) => new ProofVerifier({
  cryptoProvider: crypto, clockProvider: new SystemClockProvider(), nonceCacheProvider: new MemoryNonceCacheProvider(),
  fetchProvider: new RuntimeFetchProvider({ didResolvers: { web: { resolve: async () => doc } } }),
});

await runCases('proof-key-relationships', 'builder keys verify; purpose-restricted keys stay in their relationship', [
  { name: 'buildDidWebDocument supports response verification and client authentication', run: async () => {
    const reader = verifier();
    const key = await reader.fetchPublicKeyFromDID(proof.meta.did, proof.meta.kid);
    assert.ok(key);
    assert.equal((await reader.verifyProof(proof, key, { request, response })).valid, true);
    assert.equal(didKeyedJwks(document).keys.length, 1);
  } },
  { name: 'a hand-written authentication-only document cannot verify an assertion', run: async () => {
    const doc = { ...document, assertionMethod: [] };
    await assert.rejects(verifier(doc).fetchPublicKeyFromDID(proof.meta.did, proof.meta.kid),
      { code: 'VERIFICATION_METHOD_NOT_FOUND', message: /assertionMethod/ });
    assert.equal(didKeyedJwks(doc).keys.length, 1);
  } },
  { name: 'an assertion-only key is not projected for client authentication', run: () => {
    assert.deepEqual(didKeyedJwks({ ...document, authentication: [] }), { keys: [] });
  } },
]);
