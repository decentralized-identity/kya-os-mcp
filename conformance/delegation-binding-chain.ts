/**
 * The chain a proof binds, and the credential it names (SPEC.md §7.8).
 *
 * user → orchestrator → worker → sub-agent, each hop signed by its issuer:
 * two credential objects and a VC-JWT leaf, so both signed forms are covered.
 * The proofs here bind that chain, allowed or refused, or bind nothing, or
 * name a credential other than the leaf. They are held against the chain,
 * against another copy of it, and against chains a digest must tell apart
 * from it. One more names a credential whose id is too long to record.
 */

import type { DetachedProof } from '../src/index.js';
import { isDigest } from '../src/delegation/digest-form.js';
import type { BindingKit } from './delegation-binding-kit.js';
import { orderTwoForgeryHolds } from './small-order.js';
import type { ConformanceVector } from './types.js';

/** The vectors of a chain bound whole, and of the credential a proof names. */
export async function chainVectors<P extends { did: string }>(kit: BindingKit<P>): Promise<ConformanceVector[]> {
  const { mint, user, orchestrator, worker, request, response } = kit;
  const chainRoot = await mint.credential({
    issuer: user,
    subjectDid: orchestrator.did,
    id: 'del-user-orchestrator',
    scopes: ['records:read', 'records:list'],
  });
  const middleHop = {
    issuer: orchestrator,
    subjectDid: worker.did,
    id: 'del-orchestrator-worker',
    parentId: 'del-user-orchestrator',
  };
  const chainMiddle = await mint.credential({ ...middleHop, scopes: ['records:read'] });
  // The leaf is minted until its JWS signature has a character base64 writes
  // another way (`-` or `_`), which the no-signed-form vector below needs.
  let chainLeafJwt: string;
  do {
    const subAgent = await mint.party();
    const leafCredential = await mint.credential({
      issuer: worker,
      subjectDid: subAgent.did,
      id: 'del-worker-subagent',
      parentId: 'del-orchestrator-worker',
      scopes: ['records:read'],
    });
    chainLeafJwt = await mint.vcJwt(worker, leafCredential);
  } while (!/[-_]/.test(jwsSignature(chainLeafJwt)));
  const boundChain = [chainRoot, chainMiddle, chainLeafJwt];
  // The middle hop signed again under the same id, for more than it gave:
  // every id and parent link in the chain is unchanged.
  const reissuedMiddle = await mint.credential({ ...middleHop, scopes: ['records:read', 'records:delete'] });
  const widenedChain = [chainRoot, reissuedMiddle, chainLeafJwt];
  // The bound chain as another party might hold it. Nothing an issuer signed
  // differs. The root has proof metadata outside the §6.2 signature edited,
  // and its signature padded. The middle credential's signature is broken
  // across two lines with a spare bit set. The leaf's JWS signature has a
  // spare bit set and is padded, which is as far as a JWS segment may differ.
  const middleSignature = withSpareBitSet(String(chainMiddle.proof?.proofValue));
  const reserializedChain = [
    {
      ...chainRoot,
      proof: {
        ...chainRoot.proof,
        created: '2031-01-01T00:00:00.000Z',
        note: 'added by a holder',
        proofValue: `${String(chainRoot.proof?.proofValue)}==`,
      },
    },
    {
      ...chainMiddle,
      proof: {
        ...chainMiddle.proof,
        proofValue: `${middleSignature.slice(0, 43)}\n${middleSignature.slice(43)}`,
      },
    },
    `${withSpareBitSet(chainLeafJwt)}==`,
  ];
  // The bound chain with the leaf's JWS signature in the base64 alphabet. A
  // decoder that reads both alphabets gets the same bytes from it, but it is
  // not base64url, so it is not a JWS and the credential has no signed form.
  const [leafHeader, leafPayload] = chainLeafJwt.split('.');
  const base64SignedLeaf = `${leafHeader}.${leafPayload}.${jwsSignature(chainLeafJwt)
    .replaceAll('-', '+')
    .replaceAll('_', '/')}`;
  const noSignedFormChain = [chainRoot, chainMiddle, base64SignedLeaf];
  const leafRef = await kit.reference(chainLeafJwt);

  // The proof is minted until its JWS signature, too, has a character base64
  // writes another way, which the vector of it written so needs
  // (`./delegation-binding-tampered.ts`), and until a signature forged under
  // the key of order two holds over what it signs, which the proof cases
  // need (`./small-order.ts`).
  const boundDigest = await kit.chainDigest(boundChain);
  let chainBoundProof: DetachedProof;
  do {
    chainBoundProof = await kit.allowed({ delegationRef: leafRef, delegationChainDigest: boundDigest });
  } while (!/[-_]/.test(jwsSignature(chainBoundProof.jws)) || !orderTwoForgeryHolds(chainBoundProof.jws));

  // A refusal binds no response, and still binds the chain it refused.
  const chainRefusedProof = await kit.refused(
    'Delegation del-orchestrator-worker widens scopes beyond parent del-user-orchestrator: records:delete',
    { delegationRef: leafRef, delegationChainDigest: await kit.chainDigest(widenedChain) },
  );

  // Negative: the digest stripped after signing leaves a proof that names the
  // credential and binds nothing; the signature no longer covers its payload.
  const digestStrippedMeta = { ...chainBoundProof.meta };
  delete (digestStrippedMeta as Record<string, unknown>)['delegationChainDigest'];
  const digestStrippedProof: DetachedProof = { jws: chainBoundProof.jws, meta: digestStrippedMeta };

  // Negative: an authentic proof that only names the credential.
  const chainNamedProof = await kit.allowed({ delegationRef: leafRef });

  // Negative: an authentic proof that binds the chain and names another of
  // its credentials, the root, as the one the call presented.
  const chainMisnamedProof = await kit.allowed({
    delegationRef: await kit.reference(chainRoot),
    delegationChainDigest: await kit.chainDigest(boundChain),
  });

  // A credential whose id is too long to record: it is referred to by the
  // digest of the id.
  const longIdCredential = await kit.credential(`del-${'long-'.repeat(60)}id`);
  const longIdRef = await kit.reference(longIdCredential);
  if (!isDigest(longIdRef) || String(longIdCredential.id).length <= 256) {
    throw new Error('expected an id long enough to be referred to by its digest');
  }
  const longIdProof = await kit.boundAlone(longIdCredential);

  return [
    {
      id: 'signed-proof/delegation-chain-binding',
      category: 'signed-proof',
      description:
        'Proof whose delegationChainDigest binds a three-credential chain (two credential objects and a VC-JWT leaf), verified against that chain',
      expected: 'pass',
      reason:
        'The chain digest recomputed over the supplied credentials, root first, equals the signed delegationChainDigest (SPEC §7.8)',
      input: kit.inputOf(chainBoundProof, { request, response, delegationChain: boundChain }),
    },
    {
      id: 'signed-proof/delegation-chain-reserialized',
      category: 'signed-proof',
      description:
        'The same proof verified against another copy of the same chain: proof metadata outside the credential signature edited, and the three signatures written with padding, a line break, and spare bits set',
      expected: 'pass',
      reason:
        'A credential is digested by what its issuer signed and the signature bytes, so a copy that differs in nothing signed has the same digest',
      input: kit.inputOf(chainBoundProof, { request, response, delegationChain: reserializedChain }),
    },
    {
      id: 'signed-proof/delegation-chain-refused',
      category: 'signed-proof',
      description:
        'Denial proof (no responseHash) whose delegationChainDigest binds the chain the server refused, verified against that chain as a refusal (expected.outcome: denied)',
      expected: 'pass',
      reason:
        'A refusal binds no response and still binds what was presented, so a verifier that asks for a refusal can hold it against the refused chain',
      input: kit.inputOf(chainRefusedProof, { request, delegationChain: widenedChain, outcome: 'denied' }),
    },
    {
      id: 'signed-proof/delegation-chain-refused-outcome-unstated',
      category: 'signed-proof',
      description:
        'The same denial proof verified against the chain it refused, by a verifier that supplies the chain and states no outcome',
      expected: 'fail',
      reason:
        'A chain supplied without an outcome asks whether the server accepted it. The proof records a refusal, so a matching digest must not pass: it shows what was presented, not what was allowed',
      input: kit.inputOf(chainRefusedProof, { request, delegationChain: widenedChain }),
    },
    {
      id: 'signed-proof/delegation-chain-substituted',
      category: 'signed-proof',
      description:
        'Chain-binding proof verified against a chain whose middle credential was re-issued under the same id with a wider scope',
      expected: 'fail',
      reason:
        'Every id and parent link matches, so delegationRef cannot tell the chains apart; the recomputed chain digest must mismatch the signed one',
      input: kit.inputOf(chainBoundProof, { request, response, delegationChain: widenedChain }),
    },
    {
      id: 'signed-proof/delegation-chain-digest-stripped',
      category: 'signed-proof',
      description: 'Chain-binding proof whose signature-covered delegationChainDigest was stripped after signing',
      expected: 'fail',
      reason:
        'delegationChainDigest is a covered claim: without it the reconstructed payload no longer matches the signature',
      input: kit.inputOf(digestStrippedProof, { request, response }),
    },
    {
      id: 'signed-proof/delegation-chain-unbound',
      category: 'signed-proof',
      description:
        'Authentic proof that names its credential by delegationRef and carries no delegationChainDigest, verified against a chain',
      expected: 'fail',
      reason:
        'A verifier that is given a chain must not accept a proof that binds none: an equal delegationRef is not evidence of which chain was evaluated',
      input: kit.inputOf(chainNamedProof, { request, response, delegationChain: boundChain }),
    },
    {
      id: 'signed-proof/delegation-chain-no-signed-form',
      category: 'signed-proof',
      description:
        'Chain-binding proof verified against the bound chain with the VC-JWT leaf signature rewritten in the base64 alphabet (+ and / for - and _)',
      expected: 'fail',
      reason:
        'A JWS segment is base64url. A compact JWS whose signature is not has no signed form, so the chain has no digest and no proof binds it, though a decoder of both alphabets reads the same bytes',
      input: kit.inputOf(chainBoundProof, { request, response, delegationChain: noSignedFormChain }),
    },
    {
      id: 'signed-proof/delegation-ref-substituted',
      category: 'signed-proof',
      description:
        'Authentic proof whose delegationChainDigest binds the chain and whose delegationRef names the chain root, verified against that chain',
      expected: 'fail',
      reason:
        'A proof that binds a chain names its last credential: delegationRef must be the reference derived from the presented (leaf) credential',
      input: kit.inputOf(chainMisnamedProof, { request, response, delegationChain: boundChain }),
    },
    {
      id: 'signed-proof/delegation-ref-digest-form',
      category: 'signed-proof',
      description:
        'Proof binding a single credential whose id is longer than 256 UTF-16 code units, with delegationRef the SHA-256 of the id',
      expected: 'pass',
      reason:
        'An id too long to record is referred to by sha256 of its UTF-8 bytes, and a verifier derives the same reference from the credential',
      input: kit.inputOf(longIdProof, { request, response, delegationChain: [longIdCredential] }),
    },
  ];
}

/** The signature segment of a compact JWS. */
function jwsSignature(jws: string): string {
  return jws.slice(jws.lastIndexOf('.') + 1);
}

const BASE64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/**
 * The same signature as another string. A 64-byte Ed25519 signature is 86
 * base64url characters, and the last one carries four bits no decoder reads;
 * setting the lowest of them changes the text and not the bytes. Works on a
 * `proofValue` and on a compact JWS, whose last segment is its signature.
 */
function withSpareBitSet(encoded: string): string {
  const last = BASE64URL_ALPHABET.indexOf(encoded.charAt(encoded.length - 1));
  if (last < 0 || (last & 1) === 1) {
    throw new Error('expected a canonical base64url signature');
  }
  return encoded.slice(0, -1) + BASE64URL_ALPHABET.charAt(last | 1);
}
