/**
 * The vectors of a base profile re-delegation's commitment to its parent (SPEC.md §6.2, suite
 * 1.13.0): `delegation-chain/parent-digest-*`.
 *
 * A credential names its parent by `parentId`, and an id is a name. A re-delegation MAY also state
 * `parentCredentialDigest`, the §7.8 digest of its parent credential, which commits it to that one
 * credential: a verifier refuses it under any other, a parent issued again under the same id
 * included. A credential with no parent states none. Each vector turns on that member alone: every
 * chain is otherwise one a verifier accepts.
 */

import { delegationCredentialDigest } from '../src/index.js';
import { AGENT, SERVER_DID, SUB_AGENT, USER, credential, crypto, didDocumentOf } from './request-binding-kit.js';
import type { ConformanceVector, DelegationChainInput, VectorFile } from './types.js';
import { SUITE_VERSION } from './vector-files.js';

export async function parentCommitmentVectorFile(): Promise<VectorFile> {
  const didDocuments = Object.fromEntries([USER, AGENT, SUB_AGENT].map((party) => [party.did, didDocumentOf(party)]));
  const parentOf = (scopes: string[]) => credential({ issuer: USER, subjectDid: AGENT.did, id: 'del-user-agent', scopes });
  const parent = await parentOf(['records:read', 'records:write']);
  // The parent issued again under the same id, still wide enough for the child.
  const reissuedParent = await parentOf(['records:read', 'records:write', 'records:delete']);
  const child = (stated: { parentCredentialDigest?: unknown }) =>
    credential({ issuer: AGENT, subjectDid: SUB_AGENT.did, id: 'del-agent-sub-agent', parentId: 'del-user-agent', scopes: ['records:read'], ...stated });
  const parentDigest = await delegationCredentialDigest(parent, (bytes) => crypto.hash(bytes));
  const committed = await child({ parentCredentialDigest: parentDigest });
  const root = await credential({ issuer: USER, subjectDid: AGENT.did, id: 'del-user-agent-root', scopes: ['records:read'], parentCredentialDigest: parentDigest });

  const vector = (
    name: string,
    expected: 'pass' | 'fail',
    description: string,
    reason: string,
    input: Omit<DelegationChainInput, 'serverDid' | 'didDocuments'>,
  ): ConformanceVector => ({
    id: `delegation-chain/parent-digest-${name}`,
    category: 'delegation-chain',
    description,
    expected,
    reason,
    input: { ...input, serverDid: SERVER_DID, didDocuments },
  });

  const vectors: ConformanceVector[] = [
    vector('committed', 'pass',
      `A re-delegation that states the §7.8 digest of its parent credential, ${parentDigest}, under that parent`,
      'The digest stated is that of the parent the chain resolves to, so the commitment holds',
      { leaf: committed, ancestors: [parent] }),
    vector('reissued-parent', 'fail',
      'The same re-delegation under a parent its issuer issued again under the same id, with wider scopes',
      'The child committed to one parent credential; another under the same id has another digest, so the chain is refused although every id and issuer links',
      { leaf: committed, ancestors: [reissuedParent] }),
    vector('absent', 'pass',
      'A re-delegation that states no parentCredentialDigest, under its parent',
      'The member is optional in this version of the suite: a credential that states none is held to its parentId and its issuer alone',
      { leaf: await child({}), ancestors: [parent] }),
    vector('null', 'fail',
      'A re-delegation that states parentCredentialDigest as null, under its parent',
      'A credential states the member when it holds it, whatever its value, and null is not the digest of its parent',
      { leaf: await child({ parentCredentialDigest: null }), ancestors: [parent] }),
    vector('on-root', 'fail',
      'A delegation with no parentId that states a parentCredentialDigest',
      'A credential with no parent has no parent credential to commit to, so it states none',
      { leaf: root }),
  ];
  return { version: SUITE_VERSION, category: 'delegation-chain', vectors };
}
