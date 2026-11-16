/**
 * The `signed-proof/delegation-proof-*` vectors (suite 1.5.0) hold a verifier
 * to the proof as it receives it (SPEC.md §7.3, §7.4). Each but the last
 * alters one thing of `signed-proof/delegation-chain-binding` and must fail
 * for it, so each is shown here to differ from that vector in the one thing
 * alone, and to be what a verifier that skipped the rule it turns on would
 * accept: a lenient decoder reads the bound signature's bytes from it, or its
 * signature verifies under the server's key whatever its header says.
 */

import { createHash, createPublicKey, verify as verifyEd25519, type webcrypto } from 'node:crypto';
import { canonicalize } from 'json-canonicalize';
import { describe, it, expect } from 'vitest';
import { byId, inputOf, proofOf, verify } from './helpers/delegation-vectors.js';

const bound = inputOf('chain-binding');
const boundProof = proofOf('chain-binding');
const [header, payload, signature] = boundProof.jws.split('.') as [string, string, string];
const serverKey = createPublicKey({ key: bound.publicKeyJwk as webcrypto.JsonWebKey, format: 'jwk' });

/** The vector's input but its proof, which is what each vector that alters the proof leaves as it was. */
function besidesProof(id: string): Record<string, unknown> {
  const { proof: _proof, ...rest } = inputOf(id);
  return rest;
}

/** A segment's bytes as Node's base64 decoder reads it: either alphabet, and other characters passed over. */
const leniently = (segment: string): Buffer => Buffer.from(segment, 'base64');

/** Whether a JWS's signature verifies under the server's key over its first two segments, its header unread. */
function signatureVerifies(jws: string): boolean {
  const [signedHeader, signedPayload, written] = jws.split('.') as [string, string, string];
  return verifyEd25519(null, Buffer.from(`${signedHeader}.${signedPayload}`), serverKey, leniently(written));
}

const decoded = (segment: string): unknown => JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));

describe('signed-proof/delegation-proof-* vectors', () => {
  it('are refused by the reference, all but the proof of a request without params', async () => {
    const reasons = {
      'proof-signature-stray-character': 'Invalid JWS signature',
      'proof-signature-stray-characters': 'Invalid JWS signature',
      'proof-signature-base64': 'Invalid JWS signature',
      'proof-signature-white-space': 'Invalid JWS signature',
      'proof-signature-padded': 'Invalid JWS signature',
      'proof-fourth-segment': 'Invalid JWS signature',
      'proof-header-non-ascii': 'Invalid JWS signature',
      'proof-request-hash-altered': 'Invalid JWS signature',
      'proof-nonce-altered': 'Invalid JWS signature',
      'proof-session-altered': 'Invalid JWS signature',
      'proof-request-substituted': 'Request hash mismatch: the proof does not bind the request you supplied',
      'proof-header-algorithm': 'Invalid JWS signature',
      'proof-header-key': 'Invalid JWS signature',
      'proof-signer-of-another-did': 'Proof kid names a key of a different DID than meta.did',
    };
    for (const [id, detail] of Object.entries(reasons)) {
      expect(byId(id).expected).toBe('fail');
      expect(await verify(inputOf(id)), id).toEqual({ outcome: 'fail', detail });
    }
    expect(byId('proof-request-without-params').expected).toBe('pass');
    expect(await verify(inputOf('proof-request-without-params'))).toEqual({ outcome: 'pass' });
  });

  it.each([
    ['proof-signature-stray-character', /^[\w-]*\*[\w-]*$/],
    ['proof-signature-stray-characters', /^[\w-]*\*!\*![\w-]*$/],
    ['proof-signature-base64', /^[\w+/]*[+/][\w+/]*=+$/],
    ['proof-signature-white-space', /^[\w-]{43}\n[\w-]{43}$/],
    ['proof-signature-padded', /^[\w-]{86}==$/],
  ])('%s: the bound signature, written so that a lenient decoder reads its bytes', (id, written) => {
    const [signedHeader, signedPayload, rewritten] = proofOf(id).jws.split('.') as [string, string, string];
    expect(`${signedHeader}.${signedPayload}`).toBe(`${header}.${payload}`);
    expect(rewritten).toMatch(written);
    expect(leniently(rewritten)).toEqual(Buffer.from(signature, 'base64url'));
    expect(signatureVerifies(proofOf(id).jws)).toBe(true);
    expect(proofOf(id).meta).toEqual(boundProof.meta);
    expect(besidesProof(id)).toEqual(besidesProof('chain-binding'));
  });

  it('proof-header-non-ascii: the bound header with a character a lenient decoder passes over', () => {
    const [rewritten, signedPayload, written] = proofOf('proof-header-non-ascii').jws.split('.') as [string, string, string];
    expect(rewritten).toBe(`${header}é`);
    expect(leniently(rewritten)).toEqual(Buffer.from(header, 'base64url'));
    expect([signedPayload, written]).toEqual([payload, signature]);
    expect(proofOf('proof-header-non-ascii').meta).toEqual(boundProof.meta);
    expect(besidesProof('proof-header-non-ascii')).toEqual(besidesProof('chain-binding'));
  });

  it('proof-fourth-segment: the bound JWS, and one segment more', () => {
    const { jws, meta } = proofOf('proof-fourth-segment');
    expect(jws).toBe(`${boundProof.jws}.x`);
    expect(meta).toEqual(boundProof.meta);
    expect(besidesProof('proof-fourth-segment')).toEqual(besidesProof('chain-binding'));
  });

  it.each([
    ['proof-request-hash-altered', { requestHash: `sha256:${'0'.repeat(64)}` }],
    ['proof-nonce-altered', { nonce: 'nonce-other' }],
    ['proof-session-altered', { sessionId: 'sess_other' }],
  ])('%s: the bound JWS, under a meta with one claim altered since it was signed', (id, altered) => {
    expect(proofOf(id)).toEqual({ jws: boundProof.jws, meta: { ...boundProof.meta, ...altered } });
    expect(besidesProof(id)).toEqual(besidesProof('chain-binding'));
  });

  it('proof-request-substituted: the bound proof and chain, held against another call', async () => {
    const { expected, ...rest } = inputOf('proof-request-substituted');
    const { expected: boundExpected, ...boundRest } = bound;
    expect(rest).toEqual(boundRest);
    expect({ ...expected, request: boundExpected!.request }).toEqual(boundExpected);
    expect(expected!.request).not.toEqual(boundExpected!.request);
    // Held against the call it proves, the same proof binds.
    expect(await verify({ ...inputOf('proof-request-substituted'), expected: boundExpected })).toEqual({ outcome: 'pass' });
  });

  it.each([
    ['proof-header-algorithm', { alg: 'HS256', kid: boundProof.meta['kid'] }],
    ['proof-header-key', { alg: 'EdDSA', kid: `${String(boundProof.meta['did'])}#another-key` }],
  ])('%s: the bound claims, signed again with the server key under another header', (id, signedHeader) => {
    const { jws, meta } = proofOf(id);
    const [rewritten, signedPayload] = jws.split('.') as [string, string];
    expect(decoded(rewritten)).toEqual(signedHeader);
    expect(decoded(header)).toEqual({ alg: 'EdDSA', kid: boundProof.meta['kid'] });
    expect(signedPayload).toBe(payload);
    expect(meta).toEqual(boundProof.meta);
    expect(signatureVerifies(jws)).toBe(true);
    expect(besidesProof(id)).toEqual(besidesProof('chain-binding'));
  });

  it('proof-signer-of-another-did: the bound claims with another did, signed again with the server key', () => {
    const { jws, meta } = proofOf('proof-signer-of-another-did');
    expect(meta['did']).not.toBe(boundProof.meta['did']);
    expect(meta).toEqual({ ...boundProof.meta, did: meta['did'] });
    expect(String(meta['did'])).toMatch(/^did:/);
    expect(String(meta['kid']).split('#')[0]).toBe(boundProof.meta['did']);
    const [signedHeader, signedPayload] = jws.split('.') as [string, string];
    expect(signedHeader).toBe(header);
    expect(decoded(signedPayload)).toMatchObject({ iss: meta['did'], sub: meta['did'] });
    expect(signatureVerifies(jws)).toBe(true);
    expect(besidesProof('proof-signer-of-another-did')).toEqual(besidesProof('chain-binding'));
  });

  it('proof-request-without-params: binds the method alone, and the chain the bound proof binds', () => {
    const { expected, proof: _proof, ...rest } = inputOf('proof-request-without-params');
    const { expected: boundExpected, proof: _boundProof, ...boundRest } = bound;
    const { meta } = proofOf('proof-request-without-params');
    expect(expected!.request).toEqual({ method: 'tools/call' });
    const digest = createHash('sha256').update(canonicalize({ method: 'tools/call' })).digest('hex');
    expect(meta['requestHash']).toBe(`sha256:${digest}`);
    expect(meta['delegationChainDigest']).toBe(boundProof.meta['delegationChainDigest']);
    expect(meta['delegationRef']).toBe(boundProof.meta['delegationRef']);
    expect({ ...expected, request: boundExpected!.request }).toEqual(boundExpected);
    expect(rest).toEqual(boundRest);
  });
});
