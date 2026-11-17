/** Detached proof key retrieval vectors. Regeneration mints fresh keys and needs a suite bump. */
import { pathToFileURL } from 'node:url';
import { NodeCryptoProvider } from '../src/providers/node-crypto.js';
import { ProofGenerator } from '../src/proof/generator.js';
import { ed25519VerificationMethod, signProofMeta } from './crypto-kit.js';
import { SUITE_VERSION, writeVectorFile } from './vector-files.js';
import type { ConformanceVector, VectorFile } from './types.js';

export async function proofKeyRelationshipVectors(): Promise<VectorFile> {
  const crypto = new NodeCryptoProvider();
  const did = 'did:web:proof.example';
  const kid = `${did}#assert`;
  const identity = { did, kid, ...await crypto.generateKeyPair() };
  const method = ed25519VerificationMethod(kid, did, Buffer.from(identity.publicKey, 'base64'));
  const now = 1_750_000_000;
  const request = { method: 'records.read', params: { id: 'one' } };
  const response = { data: [{ type: 'text', text: 'one' }] };
  const draft = await new ProofGenerator(identity, crypto).generateProof(request, response, {
    sessionId: 'proof-key-relationship', nonce: 'nonce-proof-key', audience: 'verifier.example',
    timestamp: now, createdAt: now * 1000, lastActivity: now * 1000, ttlMinutes: 10, identityState: 'anonymous',
  });
  const proof = await signProofMeta(identity, { ...draft.meta, ts: now });
  const base = { id: did, verificationMethod: [method], assertionMethod: [kid] };
  const vectors: ConformanceVector[] = [];
  const add = (name: string, document: unknown, expected: 'pass' | 'fail', reason: string, keyId: string | null = kid) => {
    vectors.push({ id: `signed-proof/key-relationship-${name}`, category: 'signed-proof',
      description: reason, expected, reason,
      input: { proof, didDocuments: { [did]: document }, ...(keyId === null ? {} : { keyId }),
        now, skewSeconds: 120, expected: { request, response } },
    });
  };
  add('reference', base, 'pass', 'The signer lists its proof key by reference under assertionMethod.');
  add('embedded', { id: did, assertionMethod: [method] }, 'pass', 'An embedded assertion method is sufficient.');
  add('authentication-only', { id: did, verificationMethod: [method], authentication: [kid] }, 'fail', 'An authentication key is not an assertion key.');
  add('unlisted', { id: did, verificationMethod: [method] }, 'fail', 'A published key needs an assertion relationship.');
  add('duplicate', { ...base, assertionMethod: [method] }, 'fail', 'Two definitions of the same method are ambiguous.');
  add('foreign-controller', { ...base, verificationMethod: [{ ...method, controller: 'did:web:other.example' }] }, 'fail', 'The method must be controlled by the signer.');
  add('foreign-document', { ...base, id: 'did:web:other.example' }, 'fail', 'The document must identify the signer.');
  add('foreign-kid', base, 'fail', 'A kid of another DID cannot select the signer key.', 'did:web:other.example#assert');
  // Explicitly omit keyId for callers that retrieve without naming a key; proof.meta.kid stays signed.
  const first = { ...base, verificationMethod: [{ ...method, id: `${did}#unlisted` }, method] };
  add('first-usable', first, 'pass', 'Without a kid, use the first assertion entry rather than the first published method.', null);
  add('first-unusable', { ...base, assertionMethod: ['#missing', kid] }, 'fail', 'Without a kid, an unusable first assertion entry is not skipped.', null);
  return { version: SUITE_VERSION, category: 'signed-proof', vectors };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  writeVectorFile(await proofKeyRelationshipVectors(), 'signed-proof-key-relationship.json');
}
