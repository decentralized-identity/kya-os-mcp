/**
 * The verdict on a delegation credential (SPEC.md §7.8) is the same on every
 * server: with or without an audit trail, a value that is no plain data, or
 * nests too deep, is refused, and plain data is read as the credential its
 * issuer signed. A credential presented must also encode whole, its proof
 * included, since the gate hands it on (./with-kya-os.delegation-encoding.ts).
 */
import { afterEach, describe, it, expect, vi } from 'vitest';
import { arrays } from '../../__tests__/utils/nesting.js';
import type { DelegationCredential } from '../../types/protocol.js';
import { UNENCODABLE_DELEGATION_REASON } from '../with-kya-os.delegation-encoding.js';
import { CONFIGURATIONS, makeServer } from './helpers/delegation-gate-server.js';
import { ARGS, CONSENT, TOOL, released } from './helpers/delegated-call.js';
import { delegate, party } from './helpers/delegating-party.js';
import { threeHops } from './helpers/delegation-chains.js';
import { proofOf } from './helpers/received-proof.js';
import { refusal } from './helpers/server-answers.js';

describe('the verdict on a credential, whatever the server records', () => {
  // The verdict on a delegation is an authorization decision. Turning on an
  // audit trail must not change it: so each value below is presented to a
  // server in every configuration, as the credential a caller presents and as
  // an ancestor a resolver returns.

  /** A server that records what `configuration` says, and a chain of three to present to it. */
  async function serving({ audit }: { audit: boolean }) {
    const { kyaos, server, ancestors } = await makeServer({}, { audit });
    const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));
    return {
      server,
      /** The answer to `leaf` presented under the ancestors `resolved`. */
      present: (resolved: readonly unknown[], leaf: unknown) => {
        ancestors.splice(0, ancestors.length, ...(resolved as DelegationCredential[]));
        return handler({ ...ARGS, _kyaos_delegation: leaf });
      },
    };
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- a credential edited out of its type
  type Edited = Record<string, any>;
  const copyOf = (credential: DelegationCredential): Edited => structuredClone(credential);
  const withProofMember = (credential: DelegationCredential, member: unknown): Edited => {
    const copy = copyOf(credential);
    copy.proof.note = member;
    return copy;
  };
  class Held {
    constructor(from: object) {
      Object.assign(this, from);
    }
  }
  class Scopes extends Array<string> {}
  const frozen = <T>(value: T): T => {
    if (typeof value === 'object' && value !== null) {
      Object.freeze(value);
      Object.values(value).forEach(frozen);
    }
    return value;
  };
  /** Values that are not plain data: a copy would make something else of each, or cannot be taken. */
  const notPlainData: Array<[string, (credential: DelegationCredential) => unknown]> = [
    ['is a Proxy', (c) => new Proxy(copyOf(c), {})],
    ['holds a Proxy', (c) => ({ ...copyOf(c), credentialSubject: new Proxy(copyOf(c).credentialSubject, {}) })],
    ['holds a Proxy for its proof', (c) => ({ ...copyOf(c), proof: new Proxy(copyOf(c).proof, {}) })],
    ['answers for its id through a getter', (c) => {
      const { id, ...rest } = copyOf(c);
      return Object.defineProperty(rest, 'id', { enumerable: true, get: () => id });
    }],
    ['answers for its proof through a getter', (c) => {
      const { proof, ...rest } = copyOf(c);
      return Object.defineProperty(rest, 'proof', { enumerable: true, get: () => proof });
    }],
    ['holds a getter in its proof', (c) => {
      const copy = copyOf(c);
      Object.defineProperty(copy.proof, 'note', { enumerable: true, get: () => 'mine' });
      return copy;
    }],
    ['is a class instance', (c) => new Held(copyOf(c))],
    ['holds a class instance among what its issuer signed', (c) => {
      const copy = copyOf(c);
      copy.credentialSubject.delegation.constraints = new Held(copy.credentialSubject.delegation.constraints);
      return copy;
    }],
    ['holds a class instance in its proof', (c) => withProofMember(c, new Held({ kept: 'by a store' }))],
    // A copy leaves out an element that is not enumerable, and JSON has it.
    ['holds an element that is not enumerable among what its issuer signed', (c) => {
      const copy = copyOf(c);
      const { scopes } = copy.credentialSubject.delegation.constraints;
      Object.defineProperty(scopes, 0, { value: scopes[0], enumerable: false });
      return copy;
    }],
    ['holds a Map in its proof', (c) => withProofMember(c, new Map([['kept', 'by a store']]))],
    ['has a symbol-keyed member', (c) => ({ ...copyOf(c), [Symbol('tag')]: 1 })],
    ['holds a symbol-keyed member among what its issuer signed', (c) => {
      const copy = copyOf(c);
      copy.credentialSubject.delegation[Symbol('tag')] = 1;
      return copy;
    }],
    ['holds a symbol-keyed member in its proof', (c) => withProofMember(c, { [Symbol('tag')]: 1 })],
    ['holds a function among what its issuer signed', (c) => ({ ...copyOf(c), refresh: () => c })],
    ['holds a function in its proof', (c) => withProofMember(c, () => c)],
    ['holds a symbol in its proof', (c) => withProofMember(c, Symbol('tag'))],
  ];

  /** Values that are plain data, each the credential its issuer signed with nothing signed changed. */
  const plainData: Array<[string, (credential: DelegationCredential) => unknown]> = [
    ['is frozen', (c) => frozen(copyOf(c))],
    ['has no prototype', (c) => Object.assign(Object.create(null), copyOf(c))],
    ['holds an object with no prototype among what its issuer signed', (c) => {
      const copy = copyOf(c);
      copy.credentialSubject.delegation.constraints = Object.assign(
        Object.create(null),
        copy.credentialSubject.delegation.constraints,
      );
      return copy;
    }],
    ['holds an array of a subclass of Array', (c) => {
      const copy = copyOf(c);
      copy.credentialSubject.delegation.constraints.scopes = Scopes.from(
        copy.credentialSubject.delegation.constraints.scopes,
      );
      return copy;
    }],
    ['holds an array with a named member', (c) => {
      const copy = copyOf(c);
      copy.credentialSubject.delegation.constraints.scopes.kept = 'by a store';
      return copy;
    }],
    ['has a getter that is not enumerable', (c) =>
      Object.defineProperty(copyOf(c), 'kept', { enumerable: false, get: () => 'by a store' })],
    [`nests ${64} levels deep in its proof`, (c) => withProofMember(c, arrays(62))],
  ];

  /** Plain data in a proof, which no signature covers, that has no RFC 8785 form. */
  const unencodableInProof: Array<[string, (credential: DelegationCredential) => unknown]> = [
    ['holds undefined in its proof', (c) => withProofMember(c, undefined)],
    ['holds a bigint in its proof', (c) => withProofMember(c, 1n)],
    ['holds a Date in its proof', (c) => withProofMember(c, new Date(0))],
    // eslint-disable-next-line no-sparse-arrays -- a hole is the case
    ['holds an array with a hole in its proof', (c) => withProofMember(c, [1, , 3])],
  ];

  /** Plain data that nests deeper than a credential may (SPEC §7.8): it has no signed form. */
  const tooDeep: Array<[string, (credential: DelegationCredential) => unknown]> = [
    ['nests 65 levels deep in its proof', (c) => withProofMember(c, arrays(63))],
    ['nests 65 levels deep in a member its issuer did not sign', (c) => ({ ...copyOf(c), note: arrays(64) })],
    ['nests deeper than any call stack', (c) => withProofMember(c, arrays(200_000))],
    ['holds itself', (c) => {
      const copy = copyOf(c);
      copy.proof.self = copy.proof;
      return copy;
    }],
  ];

  describe.each(CONFIGURATIONS)('with %s', (_name, configuration) => {
    it.each(notPlainData)('refuses a value that %s, presented or resolved', async (_what, edit) => {
      const { server, present } = await serving(configuration);
      const { root, middle, leaf } = await threeHops(server.did);

      expect(refusal(await present([root, middle], edit(leaf)))).toEqual({
        error: 'delegation_invalid',
        reason: 'Malformed delegation credential: it is not plain data',
      });
      expect(refusal(await present([root, edit(middle)], leaf))).toEqual({
        error: 'delegation_invalid',
        reason: `Resolved delegation chain for ${leaf.credentialSubject.delegation.id} holds a value that could not be copied`,
      });
    });

    it.each(tooDeep)('refuses a value that %s, presented or resolved', async (_what, edit) => {
      const { server, present } = await serving(configuration);
      const { root, middle, leaf } = await threeHops(server.did);

      expect(refusal(await present([root, middle], edit(leaf)))).toEqual({
        error: 'delegation_invalid',
        reason: 'Malformed delegation credential: it nests more than 64 levels deep',
      });
      expect(refusal(await present([root, edit(middle)], leaf))).toEqual({
        error: 'delegation_invalid',
        reason: `Resolved delegation chain for ${leaf.credentialSubject.delegation.id} holds a value that could not be copied`,
      });
    });

    it.each(plainData)('allows a credential that %s, presented or resolved', async (_what, edit) => {
      const { server, present } = await serving(configuration);
      const { root, middle, leaf } = await threeHops(server.did);

      for (const result of [
        await present([root, middle], edit(leaf)),
        await present([root, edit(middle)], leaf),
      ]) {
        expect(result.isError).toBeUndefined();
        // The server signs no chain digest, whatever the copies are.
        expect(proofOf(result)!.meta.delegationChainDigest).toBeUndefined();
      }
    });

    it.each(unencodableInProof)('refuses a credential that %s presented, as one it cannot encode, and allows it resolved', async (_what, edit) => {
      const { server, present } = await serving(configuration);
      const { root, middle, leaf } = await threeHops(server.did);

      expect(refusal(await present([root, middle], edit(leaf)))).toEqual({
        error: 'delegation_invalid',
        reason: UNENCODABLE_DELEGATION_REASON,
      });
      const resolved = await present([root, edit(middle)], leaf);
      expect(resolved.isError).toBeUndefined();
      expect(proofOf(resolved)!.meta.delegationChainDigest).toBeUndefined();
    });

    it.each([
      [
        'undefined',
        (c: DelegationCredential) => ({ ...copyOf(c), note: undefined }),
        "Unreadable credential content: What a credential's signature covers has no canonical JSON form: Cannot canonicalize undefined at $.note",
      ],
      [
        'a Date',
        (c: DelegationCredential) => ({ ...copyOf(c), issuanceDate: new Date(c.issuanceDate) }),
        'Schema validation failed: Missing issuanceDate',
      ],
    ])('refuses a credential that holds %s among what its issuer signed, for that', async (_what, edit, said) => {
      const { server, present } = await serving(configuration);
      const { root, middle, leaf } = await threeHops(server.did);

      // Plain data, so it is read. What it holds has no JSON form, and no
      // signature covers it.
      expect(refusal(await present([root, middle], edit(leaf))).reason).toBe(
        `Delegation ${leaf.credentialSubject.delegation.id} invalid: ${said}`,
      );
      expect(refusal(await present([root, edit(middle)], leaf)).reason).toBe(
        `Delegation ${middle.credentialSubject.delegation.id} invalid: ${said}`,
      );
    });

    it('allows a credential whose issuer signed 64 levels of nesting, and refuses one whose issuer signed 65', async () => {
      const { server, present } = await serving(configuration);
      const [user, agent] = await Promise.all([party(), party()]);
      // credential, credentialSubject, delegation and metadata are four
      // levels, and the arrays under metadata are the rest.
      const issue = (levels: number) =>
        delegate(user, agent.did, { audience: server.did, metadata: { nested: arrays(levels - 4) } });
      const [atBound, pastBound] = await Promise.all([issue(64), issue(65)]);

      const allowed = await present([], atBound);
      expect(allowed.isError).toBeUndefined();
      expect(proofOf(allowed)!.meta.delegationChainDigest).toBeUndefined();

      expect(refusal(await present([], pastBound))).toEqual({
        error: 'delegation_invalid',
        reason: 'Malformed delegation credential: it nests more than 64 levels deep',
      });
    });

    it('runs no getter of a value it refuses', async () => {
      const { server, present } = await serving(configuration);
      const { root, middle, leaf } = await threeHops(server.did);
      let reads = 0;
      const guarded = (credential: DelegationCredential) => {
        const { issuer, ...rest } = copyOf(credential);
        return Object.defineProperty(rest, 'issuer', {
          enumerable: true,
          get: () => {
            reads += 1;
            return issuer;
          },
        });
      };

      expect((await present([root, middle], guarded(leaf))).isError).toBe(true);
      expect((await present([root, guarded(middle)], leaf)).isError).toBe(true);
      expect(reads).toBe(0);
    });
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});
