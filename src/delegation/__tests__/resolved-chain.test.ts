/**
 * The values a resolver returns for a chain, read as the chain walk reads
 * them: the resolver's own copy of the leaf is told by the delegation id it
 * shows, read as the reference of SPEC.md §7.8 reads that id.
 */
import { describe, expect, it } from 'vitest';
import type { DelegationCredential } from '../../types/protocol.js';
import { resolvedAncestors } from '../resolved-chain.js';

const LEAF_ID = 'del-leaf';

/** A value shaped as a delegation credential, whose delegation is `delegation`. */
const credential = (delegation: object): DelegationCredential =>
  ({ credentialSubject: { id: 'did:web:agent.example', delegation } }) as unknown as DelegationCredential;

/** A delegation whose id is `id`, and has constraints, as the walk requires. */
const delegation = (id: string): object => ({ id, constraints: {} });

describe('resolvedAncestors', () => {
  it("sets aside the resolver's copy of the leaf, last, and refuses one ahead of the last", () => {
    const root = credential(delegation('del-root'));
    expect(resolvedAncestors([root, credential(delegation(LEAF_ID))], LEAF_ID, {})).toEqual({ ancestors: [root] });
    expect(resolvedAncestors([credential(delegation(LEAF_ID)), root], LEAF_ID, {})).toEqual({
      valid: false,
      reason: `Resolved delegation chain for ${LEAF_ID} must end with the leaf credential`,
      code: 'chain_invalid',
      transient: false,
    });
  });

  it.each([
    ['behind an accessor', () => Object.defineProperty({ constraints: {} }, 'id', { get: () => LEAF_ID, enumerable: true })],
    ['inherited', () => Object.assign(Object.create({ id: LEAF_ID }) as object, { constraints: {} })],
    ['not enumerable', () => Object.defineProperty({ constraints: {} }, 'id', { value: LEAF_ID })],
  ])('takes a delegation id %s for none, as the reference does, so the value is no copy of the leaf', (_name, build) => {
    const ancestor = credential(build());
    const root = credential(delegation('del-root'));
    expect(resolvedAncestors([ancestor, root], LEAF_ID, {})).toEqual({ ancestors: [ancestor, root] });
  });
});
