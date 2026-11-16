/**
 * The nesting bound (SPEC.md §7.8): a credential's arrays and objects nest at
 * most 64 deep.
 *
 * Credentials at the bound and one level past it, in both forms. What is past
 * it must come out the same from every implementation, however deep the one
 * reading it could recurse.
 */

import {
  delegationRefOf,
  digestDelegationChain,
  MAX_CREDENTIAL_NESTING_DEPTH,
  type DelegationCredential,
} from '../src/index.js';
import { jsonTextNestsDeeperThan, nestsDeeperThan } from '../src/utils/plain-data.js';
import { lenientDigest, payloadText, type BindingKit } from './delegation-binding-kit.js';
import type { ConformanceVector } from './types.js';

const BOUND = MAX_CREDENTIAL_NESTING_DEPTH;

/** A string inside `levels` arrays, one in the next. */
function nestedArrays(levels: number): unknown {
  let value: unknown = 'leaf';
  for (let level = 0; level < levels; level += 1) value = [value];
  return value;
}

/** Whether a value nests exactly `levels` deep, by how `deeperThan` counts. */
function nestsExactly(deeperThan: (limit: number) => boolean, levels: number): boolean {
  return deeperThan(levels - 1) && !deeperThan(levels);
}

/** The vectors of credentials nested as deep as a credential may, and one level deeper. */
export async function nestingVectors<P extends { did: string }>(kit: BindingKit<P>): Promise<ConformanceVector[]> {
  const { mint, user, request, response } = kit;

  // A credential object is level 1, its credentialSubject 2, the delegation 3
  // and the delegation's metadata 4: the arrays in it are the rest.
  const credentialNestedTo = (levels: number): Promise<DelegationCredential> =>
    kit.credential(`del-nested-${levels}-deep`, { metadata: { nested: nestedArrays(levels - 4) } });
  const atBoundCredential = await credentialNestedTo(BOUND);
  const pastBoundCredential = await credentialNestedTo(BOUND + 1);
  if (
    BOUND !== 64 ||
    !nestsExactly((limit) => nestsDeeperThan(atBoundCredential, limit), BOUND) ||
    !nestsExactly((limit) => nestsDeeperThan(pastBoundCredential, limit), BOUND + 1)
  ) {
    throw new Error('expected credential objects nested 64 and 65 levels deep');
  }
  const atBoundProof = await kit.boundAlone(atBoundCredential);

  // The digest an implementation that counts no nesting takes is the
  // package's own for a credential within the bound.
  const [atBoundDigest] = (await digestDelegationChain([atBoundCredential], mint.hash)).credentials;
  if ((await lenientDigest(atBoundCredential, mint.hash)) !== atBoundDigest) {
    throw new Error('expected the digest taken by hand to be the digest of a credential within the bound');
  }
  // An authentic proof from a server that did not count: it carries the digest
  // such a server takes of the credential nested past the bound.
  const pastBoundProof = await kit.lenientProof(pastBoundCredential);

  // The payload of a VC-JWT is level 1, its `vc` 2, the credentialSubject 3,
  // the delegation 4 and the delegation's metadata 5.
  const jwtNestedTo = async (levels: number): Promise<string> =>
    mint.vcJwt(
      user,
      await kit.credential(`del-jwt-nested-${levels}-deep`, { metadata: { nested: nestedArrays(levels - 5) } }),
    );
  const atBoundJwt = await jwtNestedTo(BOUND);
  const pastBoundJwt = await jwtNestedTo(BOUND + 1);
  if (
    !nestsExactly((limit) => jsonTextNestsDeeperThan(payloadText(atBoundJwt), limit), BOUND) ||
    !nestsExactly((limit) => jsonTextNestsDeeperThan(payloadText(pastBoundJwt), limit), BOUND + 1)
  ) {
    throw new Error('expected VC-JWT payloads nested 64 and 65 levels deep');
  }
  const atBoundJwtProof = await kit.boundAlone(atBoundJwt);
  // A payload nested past the bound is not read as JSON, so the VC-JWT shows
  // no id and does not verify. The server refuses it and names no credential.
  // The digest is of its segments as received, which nothing had to read.
  if ((await delegationRefOf(pastBoundJwt, mint.hash)) !== undefined) {
    throw new Error('expected a VC-JWT that shows no id');
  }
  const pastBoundJwtProof = await kit.refused('Invalid VC-JWT format', {
    delegationChainDigest: await kit.chainDigest([pastBoundJwt]),
  });

  return [
    {
      id: 'signed-proof/delegation-chain-nested-at-bound',
      category: 'signed-proof',
      description:
        'Proof binding a single credential object whose arrays and objects nest 64 levels deep, as deep as a credential may nest',
      expected: 'pass',
      reason:
        'A credential object nested 64 levels deep has a signed form, so its digest is taken and the proof binds it: an implementation must read that deep, whatever its bound or its stack',
      input: kit.inputOf(atBoundProof, { request, response, delegationChain: [atBoundCredential] }),
    },
    {
      id: 'signed-proof/delegation-chain-nested-past-bound',
      category: 'signed-proof',
      description:
        'Authentic proof carrying the chain digest an implementation that counts no nesting takes of a credential object nested 65 levels deep, verified against that credential',
      expected: 'fail',
      reason:
        'A credential object nested more than 64 levels deep has no signed form, so the chain has no digest and no proof binds it, however deep the implementation reading it could go',
      input: kit.inputOf(pastBoundProof, { request, response, delegationChain: [pastBoundCredential] }),
    },
    {
      id: 'signed-proof/delegation-ref-jwt-nested-at-bound',
      category: 'signed-proof',
      description:
        'Proof binding a single VC-JWT whose payload nests 64 levels deep, with delegationRef the id that payload shows',
      expected: 'pass',
      reason:
        'A VC-JWT payload nested 64 levels deep is read as JSON, so the credential shows its id and a proof that binds it names it',
      input: kit.inputOf(atBoundJwtProof, { request, response, delegationChain: [atBoundJwt] }),
    },
    {
      id: 'signed-proof/delegation-ref-jwt-nested-past-bound',
      category: 'signed-proof',
      description:
        'Denial proof binding a single VC-JWT whose payload nests 65 levels deep and naming no credential, verified against that VC-JWT as a refusal (expected.outcome: denied)',
      expected: 'pass',
      reason:
        'A VC-JWT payload nested more than 64 levels deep is not read as JSON, so the credential shows no id and a proof that binds it carries no delegationRef. It still has a digest, taken over its segments as received',
      input: kit.inputOf(pastBoundJwtProof, { request, delegationChain: [pastBoundJwt], outcome: 'denied' }),
    },
  ];
}
