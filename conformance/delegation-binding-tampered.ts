/**
 * The chain-binding proof as a verifier may receive it (SPEC.md §7.3, §7.4,
 * §7.8).
 *
 * Each vector but the last alters one thing of
 * `signed-proof/delegation-chain-binding`, and each must fail. Its JWS is
 * read as RFC 7515 §2 writes base64url, so a segment with a character outside
 * the base64url alphabet, white space or padding, or one written in the
 * base64 alphabet, is no segment, though a lenient decoder reads the same
 * bytes from it. Every claim of its `meta` is
 * held to the payload the signature covers, rebuilt from it, so a claim
 * altered since signing breaks the signature, whichever claim it is. The
 * request it binds is held to the one the verifier sent. And a proof signed
 * again with the server's key, under a header that names another algorithm
 * or another key, or over a `meta` that claims another DID, verifies as a
 * signature and is still no proof of the server's.
 *
 * The last is a proof of a request without `params`, which binds the request
 * as the producer hashes it, its method alone.
 */

import type { DetachedProof } from '../src/index.js';
import type { BindingKit } from './delegation-binding-kit.js';
import type { ConformanceVector, SignedProofInput } from './types.js';

/** What a vector alters of the chain-binding proof, and why that must fail. */
interface Alteration {
  name: string;
  description: string;
  reason: string;
  input: SignedProofInput;
}

/** The vectors of the chain-binding proof as received, from its vector `bound`. */
export async function tamperedVectors<P extends { did: string }>(
  kit: BindingKit<P>,
  bound: ConformanceVector,
): Promise<ConformanceVector[]> {
  const input = bound.input as SignedProofInput;
  const proof = input.proof as DetachedProof;
  const { meta } = proof;
  const [header, payload, signature] = proof.jws.split('.') as [string, string, string];
  const withJws = (jws: string): SignedProofInput => ({ ...input, proof: { ...proof, jws } });
  const withSignature = (written: string): SignedProofInput => withJws(`${header}.${payload}.${written}`);
  const withMeta = (members: Partial<DetachedProof['meta']>): SignedProofInput => ({
    ...input,
    proof: { ...proof, meta: { ...meta, ...members } },
  });
  const signedUnder = async (
    members: Partial<DetachedProof['meta']>,
    signedHeader: Record<string, unknown>,
  ): Promise<SignedProofInput> => ({
    ...input,
    proof: await kit.mint.signedUnder({ ...meta, ...members }, signedHeader),
  });

  const base64Signature = Buffer.from(signature, 'base64url').toString('base64');
  if (!/[+/]/.test(base64Signature) || !base64Signature.endsWith('=')) {
    throw new Error('expected a signature that base64 writes with another character and padding');
  }

  const alterations: Alteration[] = [
    {
      name: 'proof-signature-stray-character',
      description: 'The chain-binding proof with a character outside base64url (*) in its JWS signature segment',
      reason: 'A JWS segment is base64url: a segment with any other character is none, so the JWS does not verify',
      input: withSignature(`${signature.slice(0, 10)}*${signature.slice(10)}`),
    },
    {
      name: 'proof-signature-stray-characters',
      description: 'The chain-binding proof with four characters outside base64url (*!*!) in its JWS signature segment',
      reason:
        'A decoder that passes over characters outside its alphabet reads the signature bytes from this segment, and must not: it is no JWS segment',
      input: withSignature(`${signature.slice(0, 10)}*!*!${signature.slice(10)}`),
    },
    {
      name: 'proof-signature-base64',
      description:
        'The chain-binding proof with its JWS signature segment written in the base64 alphabet, padded (+ and / for - and _)',
      reason:
        'A decoder of both alphabets reads the same bytes from this segment, but + and / are not base64url, so it is no JWS segment and the JWS does not verify',
      input: withSignature(base64Signature),
    },
    {
      name: 'proof-signature-white-space',
      description: 'The chain-binding proof with a line break in its JWS signature segment',
      reason:
        'A JWS segment holds no white space (RFC 7515 §2): a decoder that passes over it reads the signature bytes from this segment, and must not, so the JWS does not verify',
      input: withSignature(`${signature.slice(0, 43)}\n${signature.slice(43)}`),
    },
    {
      name: 'proof-signature-padded',
      description: 'The chain-binding proof with its JWS signature segment padded with = to complete its last group',
      reason:
        'A JWS segment carries no padding (RFC 7515 §2): a decoder that reads padding reads the signature bytes from this segment, and must not, so the JWS does not verify',
      input: withSignature(`${signature}==`),
    },
    {
      name: 'proof-fourth-segment',
      description: 'The chain-binding proof with a fourth segment appended to its JWS',
      reason: 'A compact JWS is three segments: a verifier that reads the first three of four verifies a JWS that is none',
      input: withJws(`${proof.jws}.x`),
    },
    {
      name: 'proof-header-non-ascii',
      description: 'The chain-binding proof with a character outside ASCII (é) in its JWS header segment',
      reason: 'A JWS segment is base64url, and a character outside ASCII is not, so the JWS does not verify',
      input: withJws(`${header}é.${payload}.${signature}`),
    },
    {
      name: 'proof-request-hash-altered',
      description: 'The chain-binding proof with meta.requestHash altered after signing',
      reason:
        'Every claim of meta is held to the payload the signature covers, rebuilt from it: the altered requestHash breaks the signature',
      input: withMeta({ requestHash: `sha256:${'0'.repeat(64)}` }),
    },
    {
      name: 'proof-nonce-altered',
      description: 'The chain-binding proof with meta.nonce altered after signing',
      reason:
        'The nonce is a claim the signature covers like the others: a verifier that compares only the delegation claims with the payload passes it',
      input: withMeta({ nonce: 'nonce-other' }),
    },
    {
      name: 'proof-session-altered',
      description: 'The chain-binding proof with meta.sessionId altered after signing',
      reason:
        'The session is a claim the signature covers like the others: a verifier that compares only the delegation claims with the payload passes it',
      input: withMeta({ sessionId: 'sess_other' }),
    },
    {
      name: 'proof-request-substituted',
      description: 'The chain-binding proof verified against the chain it binds and another call than the one it proves',
      reason:
        'A proof binds the request it answers: held against another call, its requestHash mismatches, however well its chain matches',
      input: {
        ...input,
        expected: {
          ...input.expected!,
          request: { method: 'tools/call', params: { name: 'records.delete', arguments: { recordId: 'r-1' } } },
        },
      },
    },
    {
      name: 'proof-header-algorithm',
      description: 'The chain-binding proof signed again with the server key, under a JWS header that names HS256',
      reason:
        'A proof is an EdDSA JWS: a verifier refuses one whose header names another algorithm, though its signature verifies under the key',
      input: await signedUnder({}, { alg: 'HS256', kid: meta.kid }),
    },
    {
      name: 'proof-header-key',
      description:
        'The chain-binding proof signed again with the server key, under a JWS header that names another key of its DID',
      reason:
        'The header must name the key meta.kid names: a verifier refuses a proof whose header names another, though its signature verifies under the key',
      input: await signedUnder({}, { alg: 'EdDSA', kid: `${meta.did}#another-key` }),
    },
    {
      name: 'proof-signer-of-another-did',
      description:
        "The chain-binding proof signed again with the server key, over a meta whose did is the delegating user's",
      reason:
        'meta.kid names a key of the server DID, not of meta.did: a verifier refuses it, or one DID could sign proofs as any other',
      input: await signedUnder({ did: kit.user.did }, { alg: 'EdDSA', kid: meta.kid }),
    },
  ];

  const bareRequest = { method: 'tools/call' };
  const { delegationRef, delegationChainDigest } = meta;
  const bareProof = await kit.mint.proof(bareRequest, kit.response, { delegationRef, delegationChainDigest });

  return [
    ...alterations.map(({ name, ...vector }) => ({
      id: `signed-proof/delegation-${name}`,
      category: 'signed-proof' as const,
      expected: 'fail' as const,
      ...vector,
    })),
    {
      id: 'signed-proof/delegation-proof-request-without-params',
      category: 'signed-proof',
      description: 'Chain-binding proof of a tools/call request that has no params, verified against that request',
      expected: 'pass',
      reason:
        'A request is hashed as JCS({method, params}) with params left out where the request has none, so the proof binds the method alone',
      input: { ...input, proof: bareProof, expected: { ...input.expected!, request: bareRequest } },
    },
  ];
}
