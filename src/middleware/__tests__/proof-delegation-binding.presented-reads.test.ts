/**
 * How often the gate reads what a caller presents (SPEC.md §7.8): once, in
 * one walk, before anything else does, and a bounded number of times in all
 * before any signature is checked. A credential refused for how deep it
 * nests is described from that one walk, and read no more.
 */
import { afterEach, describe, it, expect, vi } from 'vitest';
import { arrays } from '../../__tests__/utils/nesting.js';
import type { DelegationCredential } from '../../types/protocol.js';
import { readOnce } from '../with-kya-os.delegation-check.js';
import { makeServer } from './helpers/delegation-gate-server.js';
import { ARGS, CONSENT, TOOL, released } from './helpers/delegated-call.js';
import { threeHops } from './helpers/delegation-chains.js';
import { delegationEvidence, refusal } from './helpers/server-answers.js';

/** A gate with an audit trail, which digests what it refuses, and a chain of three to present to it. */
async function gate() {
  const { kyaos, server, ancestors, recorded } = await makeServer();
  const chain = await threeHops(server.did);
  ancestors.push(chain.root, chain.middle);
  const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));
  return { present: (presented: unknown) => handler({ ...ARGS, _kyaos_delegation: presented }), recorded, ...chain };
}

describe('the reads the gate makes of a presented credential', () => {
  // An array this long is the only one of its length in the call, so the
  // descriptors read of it, and of every copy of it, can be told apart.
  const LENGTH = 4099;

  /** The descriptors of an array of LENGTH elements read while `presenting` runs. */
  async function elementReads(presenting: () => Promise<unknown>): Promise<number> {
    const read = vi.spyOn(Object, 'getOwnPropertyDescriptor');
    try {
      await presenting();
      return read.mock.calls.filter(([target]) => Array.isArray(target) && target.length === LENGTH).length;
    } finally {
      read.mockRestore();
    }
  }

  it.each([
    // Refused on its basic checks: the walk, and the digest of what was
    // refused, which counts how deep the copy nests now and then reads it.
    ['one with no type', (leaf: DelegationCredential) => ({ ...leaf, type: [] }), 3],
    // Refused on its signature: the walk, the verification cache's key, and
    // what the signature covers and the digest of what was refused, each
    // of which counts how deep the copy nests now and then reads it.
    ['one its issuer did not sign so', (leaf: DelegationCredential) => leaf, 6],
  ])('reads each element of a large array a bounded number of times: %s', async (_name, edit, times) => {
    const { present, leaf } = await gate();
    const long = Array.from({ length: LENGTH }, (_, index) => index);

    const reads = await elementReads(async () => {
      expect((await present({ ...edit(leaf), long })).isError).toBe(true);
    });
    expect(reads).toBe(times * LENGTH);
  });

  it('describes a credential refused as nesting too deep from the walk that refused it, and reads it no more', async () => {
    const { present, recorded, leaf } = await gate();
    // 63 arrays in a member of the proof, which no signature covers, make it 65 levels deep.
    const deep = { ...leaf, id: 'urn:uuid:read-by-the-walk', proof: { ...leaf.proof!, note: arrays(63) } };
    const shallow = { ...leaf, id: 'urn:uuid:read-after-the-walk' };
    /** A credential that answers as `deep` for its first `first` reads, and as `shallow` after. */
    const changing = (first: number) => {
      let reads = 0;
      const answering = () => (reads++ < first ? deep : shallow);
      const value = new Proxy(deep, {
        ownKeys: () => Reflect.ownKeys(answering()),
        getOwnPropertyDescriptor: (_target, key) => Reflect.getOwnPropertyDescriptor(answering(), key),
      });
      return { value, reads: () => reads };
    };
    // How many reads the walk makes of such a credential.
    const twin = changing(Number.POSITIVE_INFINITY);
    expect(readOnce(twin.value)).toMatchObject({ unread: 'nests more than 64 levels deep' });

    const presented = changing(twin.reads());
    expect(refusal(await present(presented.value)).reason).toBe(
      'Malformed delegation credential: it nests more than 64 levels deep',
    );
    expect(presented.reads()).toBe(twin.reads());
    // Named by the id the walk read, and not digested: it has no signed form.
    const rejected = recorded.find((event) => event.eventType === 'delegation.rejected')!;
    expect(delegationEvidence(rejected)).toEqual({ delegationRef: 'urn:uuid:read-by-the-walk' });
  });

  it('names a credential refused as nesting too deep, and showing no id of its own, by the id of its delegation the walk read', async () => {
    const { present, recorded, leaf } = await gate();
    const { id: _id, ...noId } = leaf;
    const subject = leaf.credentialSubject;
    // The leaf with no id of its own, and 65 levels deep by a member of its proof.
    const deep = {
      ...noId,
      credentialSubject: { ...subject, delegation: { ...subject.delegation, id: 'del-read-by-the-walk' } },
      proof: { ...leaf.proof!, note: arrays(63) },
    };

    expect(refusal(await present(deep)).reason).toBe('Malformed delegation credential: it nests more than 64 levels deep');
    const rejected = recorded.find((event) => event.eventType === 'delegation.rejected')!;
    expect(delegationEvidence(rejected)).toEqual({ delegationRef: 'del-read-by-the-walk' });
  });
});

describe('a copy of a presented credential that is changed after the gate made it', () => {
  // The chain resolver is the application's, and is handed the copy the gate
  // reads from then on. What it nests in that copy is counted when the copy
  // is next read, so a credential nested deeper than SPEC.md 7.8 allows is
  // refused by the bound at any depth, never canonicalized and never digested.
  it.each([65, 100, 5_000, 200_000])('refuses by the nesting bound one nested %d levels deep since', async (levels) => {
    const { kyaos, server, ancestors, recorded } = await makeServer({
      resolveDelegationChain: async (presented) => {
        Object.assign(presented, { note: arrays(levels - 1) });
        return [...ancestors];
      },
    });
    const { root, middle, leaf } = await threeHops(server.did);
    ancestors.push(root, middle);
    const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));

    const result = await handler({ ...ARGS, _kyaos_delegation: leaf });

    expect(refusal(result).reason).toBe(
      `Delegation ${leaf.credentialSubject.delegation.id} invalid: ` +
        'Unreadable credential content: A credential object nests at most 64 levels deep',
    );
    // It has no signed form, so it is named by its id and has no digest.
    const rejected = recorded.find((event) => event.eventType === 'delegation.rejected')!;
    expect(delegationEvidence(rejected)).toEqual({ delegationRef: leaf.id });
    // The credential the caller presented is as it was.
    expect(leaf).not.toHaveProperty('note');
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});
