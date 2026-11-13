/**
 * A response proof's JWS is base64url as RFC 7515 §2 writes it (SPEC.md
 * §7.4): the URL-safe alphabet alone, with no white space and no `=`. Each
 * way this package verifies a proof refuses a segment written otherwise,
 * though a lenient decoder reads the signer's bytes from it, so that one
 * proof has one string and every verifier one verdict on it.
 */
import { describe, expect, it } from 'vitest';
import type { DetachedProof } from '../../types/protocol.js';
import { canonicalizeJson } from '../../utils/canonical-json.js';
import { buildProofJwsPayload, ProofGenerator } from '../generator.js';
import {
  REQUEST,
  RESPONSE,
  cryptoProvider,
  jwkFor,
  makeIdentity,
  makeSession,
  makeVerifier,
} from './helpers/chain-bound-proofs.js';

/** A proof and the four verdicts on it: `verifyProof`, `verifyProofArtifact`, `ProofGenerator.verifyProof`, `verifyProofDetached`. */
async function verdicts(edit: (jws: string) => string): Promise<boolean[]> {
  const identity = await makeIdentity();
  const generator = new ProofGenerator(identity, cryptoProvider);
  const signed = await generator.generateProof(REQUEST, RESPONSE, makeSession());
  const proof: DetachedProof = { ...signed, jws: edit(signed.jws) };
  const jwk = jwkFor(identity);
  const expected = { request: REQUEST, response: RESPONSE };
  const payload = canonicalizeJson(buildProofJwsPayload(proof.meta));
  return [
    (await makeVerifier().verifyProof(proof, jwk, expected)).valid,
    (await makeVerifier().verifyProofArtifact(proof, jwk, expected)).valid,
    await generator.verifyProof(proof, REQUEST, RESPONSE),
    (await makeVerifier().verifyProofDetached(proof, payload, jwk)).valid,
  ];
}

/** The JWS with its signature segment rewritten by `write`. */
const signature = (write: (segment: string) => string) => (jws: string): string => {
  const at = jws.lastIndexOf('.');
  return `${jws.slice(0, at)}.${write(jws.slice(at + 1))}`;
};

describe('a response proof whose JWS signature segment is not base64url as RFC 7515 §2 writes it', () => {
  it('verifies as signed, each of the four ways', async () => {
    expect(await verdicts((jws) => jws)).toEqual([true, true, true, true]);
  });

  it.each([
    ['a space inside it', (segment: string) => `${segment.slice(0, 10)} ${segment.slice(10)}`],
    ['a line feed at its end', (segment: string) => `${segment}\n`],
    ['a tab at its end', (segment: string) => `${segment}\t`],
    ['two spaces inside it, which 1.22.0 passed over', (segment: string) => `${segment.slice(0, 10)}  ${segment.slice(10)}`],
    ['a line break inside it', (segment: string) => `${segment.slice(0, 43)}\r\n${segment.slice(43)}`],
    ['the padding that completes its last group, which 1.22.0 accepted', (segment: string) => `${segment}==`],
  ])('is refused with %s, each of the four ways', async (_name, write) => {
    expect(await verdicts(signature(write))).toEqual([false, false, false, false]);
  });
});
