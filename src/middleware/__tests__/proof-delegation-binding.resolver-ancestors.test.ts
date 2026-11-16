/**
 * The audit trail records the chain the gate examined by the digest of each
 * credential (SPEC.md §7.8). These tests hold the gate to the ancestors a
 * resolver returns: each is copied as plain data as soon as it is returned,
 * and what is verified and recorded is that one reading.
 */
import { afterEach, describe, it, expect, vi } from 'vitest';
import type { KyaOsCallContext } from '../with-kya-os.js';
import { isCredentialDigestInput } from '../../__tests__/utils/digests.js';
import { digestDelegationChain } from '../../delegation/chain-digest.js';
import type { DelegationCredential } from '../../types/protocol.js';
import { CONFIGURATIONS, crypto, hash, makeServer } from './helpers/delegation-gate-server.js';
import { ARGS, CONSENT, SCOPE, TOOL, released } from './helpers/delegated-call.js';
import { threeHops } from './helpers/delegation-chains.js';
import { proofOf, verifyReceived } from './helpers/received-proof.js';
import { delegationClaims, delegationEvidence, recordedReferences, refusal } from './helpers/server-answers.js';

describe('a refused call', () => {
  describe('the ancestors a resolver returns', () => {
    // Each value a resolver returns is copied as plain data as soon as it is
    // returned, root first, and one that cannot be copied refuses the chain
    // before any of it is verified. A Proxy cannot be, and nothing short of
    // the copy can tell that it is one.
    const uncopyable = (credential: DelegationCredential) => new Proxy(credential, {});
    /** The copies the gate took of `values`, each of which it was handed by identity. */
    const copiesOf = (clone: { mock: { calls: unknown[][] } }, values: readonly unknown[]) =>
      clone.mock.calls.map(([value]) => value).filter((value) => values.includes(value));

    it('are not copied when there are more of them than the server agreed to evaluate', async () => {
      const clone = vi.spyOn(globalThis, 'structuredClone');
      const present = async (maxChainLength: number) => {
        const { kyaos, server, ancestors } = await makeServer({ maxChainLength });
        const { root, middle, leaf } = await threeHops(server.did);
        ancestors.push(uncopyable(root), uncopyable(middle));
        const resolved = [...ancestors];
        const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));
        return { result: await handler({ ...ARGS, _kyaos_delegation: leaf }), leaf, resolved };
      };

      // Within the limit, each is copied, root first, and the root cannot be.
      const within = await present(2);
      expect(refusal(within.result).reason).toBe(
        `Resolved delegation chain for ${within.leaf.credentialSubject.delegation.id} holds a value that could not be copied`,
      );
      expect(copiesOf(clone, within.resolved)).toEqual([within.resolved[0]]);
      expect(delegationClaims(within.result)).toEqual({});

      // More values than the limit are more credentials than it, whatever the
      // last of them is: refused by length, before any is copied.
      const beyond = await present(1);
      expect(refusal(beyond.result).reason).toBe('Delegation chain of at least 2 credentials exceeds the maximum of 1');
      expect(copiesOf(clone, beyond.resolved)).toEqual([]);
    });

    it('are all copied before any is verified, and a chain refused at its root is recorded as far as it was examined', async () => {
      const clone = vi.spyOn(globalThis, 'structuredClone');
      const { kyaos, server, ancestors, recorded } = await makeServer();
      const { root, middle, leaf } = await threeHops(server.did);
      // The root's signature does not verify, so the walk stops there, after
      // the credential after it was copied and before it was examined.
      const forged = {
        ...root,
        proof: { ...root.proof!, proofValue: String(root.proof!.proofValue).split('').reverse().join('') },
      } as DelegationCredential;
      ancestors.push(forged, middle);
      const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));

      const result = await handler({ ...ARGS, _kyaos_delegation: leaf });

      expect(refusal(result).error).toBe('delegation_invalid');
      expect(refusal(result).reason).toContain(`Delegation ${forged.credentialSubject.delegation.id} invalid`);
      expect(copiesOf(clone, [forged, middle])).toEqual([forged, middle]);
      // The audit trail lists the ancestors the walk examined, then the
      // credential presented.
      const examined = await digestDelegationChain([forged, leaf], hash);
      expect(proofOf(result)!.meta.outcome).toBe('denied');
      expect(delegationClaims(result)).toEqual({});
      const rejected = recorded.find((event) => event.eventType === 'delegation.rejected')!;
      expect(rejected.authorization!.delegationChainDigests).toEqual(examined.credentials);
      const verified = await verifyReceived(result, {
        signer: server.did,
        toolName: TOOL,
        params: ARGS,
        binds: 'nothing',
        outcome: 'denied',
      });
      expect(verified).toEqual({ valid: true });
    });

    it('are read as plain data when a resolver returns the leaf with them: that is still a chain within the limit', async () => {
      const { kyaos, server, ancestors, recorded } = await makeServer({ maxChainLength: 3 });
      const { root, middle, leaf } = await threeHops(server.did);
      // Three values are then a chain of three, and are read like any other:
      // the one after the root cannot be copied.
      ancestors.push(root, uncopyable(middle), leaf);
      const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));

      const result = await handler({ ...ARGS, _kyaos_delegation: leaf });

      expect(refusal(result).reason).toBe(
        `Resolved delegation chain for ${leaf.credentialSubject.delegation.id} holds a value that could not be copied`,
      );
      expect(proofOf(result)!.meta.outcome).toBe('denied');
      expect(delegationClaims(result)).toEqual({});
      expect(recordedReferences(recorded, 'delegation.rejected')).toEqual([leaf.id]);
    });

    it.each([
      [
        'an instance of a class, as an ancestor',
        (root: DelegationCredential, middle: DelegationCredential) => [root, Object.assign(new (class Credential {})(), middle)],
      ],
      [
        'an instance of a class, as its copy of the leaf',
        (root: DelegationCredential, middle: DelegationCredential, leaf: DelegationCredential) => [
          root,
          middle,
          Object.assign(new (class Credential {})(), leaf),
        ],
      ],
      [
        'a value whose getter would answer as the leaf when first read, and as the credential it was copied from after',
        (root: DelegationCredential, middle: DelegationCredential, leaf: DelegationCredential) => {
          let reads = 0;
          const claiming = { ...middle };
          Object.defineProperty(claiming, 'credentialSubject', {
            enumerable: true,
            get: () => (reads++ === 0 ? leaf.credentialSubject : middle.credentialSubject),
          });
          return [root, claiming];
        },
      ],
    ])('refuse the chain unread when one is %s, and the audit trail lists no chain', async (_name, resolve) => {
      const { kyaos, server, ancestors, recorded } = await makeServer();
      const { root, middle, leaf } = await threeHops(server.did);
      const resolved = resolve(root, middle, leaf) as DelegationCredential[];
      ancestors.push(...resolved);
      const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));

      const result = await handler({ ...ARGS, _kyaos_delegation: leaf });

      expect(refusal(result)).toEqual({
        error: 'delegation_invalid',
        reason: `Resolved delegation chain for ${leaf.credentialSubject.delegation.id} holds a value that could not be copied`,
      });
      // The root was copied and never examined, and the value after it was
      // not read at all: a digest of the root and the leaf would claim a
      // chain the server was not shown.
      expect(proofOf(result)!.meta.outcome).toBe('denied');
      expect(delegationClaims(result)).toEqual({});
      const rejected = recorded.find((event) => event.eventType === 'delegation.rejected')!;
      expect(delegationEvidence(rejected)).toEqual({
        delegationRef: leaf.id,
        delegationCredentialDigest: (await digestDelegationChain([leaf], hash)).credentials[0],
      });
      const verified = await verifyReceived(result, {
        signer: server.did,
        toolName: TOOL,
        params: ARGS,
        binds: 'nothing',
        outcome: 'denied',
      });
      expect(verified).toEqual({ valid: true });
    });

    it('set aside a copy of the leaf unchecked, whatever else it holds, as long as it can be read', async () => {
      const { kyaos, server, ancestors, recorded } = await makeServer();
      const { root, middle, leaf, chain } = await threeHops(server.did);
      // Plain data that names the leaf and is no credential: it is the
      // resolver's copy of the leaf, and the leaf presented is what is checked.
      ancestors.push(root, middle, { credentialSubject: { delegation: { id: leaf.credentialSubject.delegation.id } } } as never);
      const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));

      const result = await handler({ ...ARGS, _kyaos_delegation: leaf });

      expect(result.isError).toBeUndefined();
      const digests = await digestDelegationChain(chain, hash);
      const verifiedEvent = recorded.find((event) => event.eventType === 'delegation.verified')!;
      expect(verifiedEvent.authorization!.delegationChainDigests).toEqual(digests.credentials);
    });

    it.each(CONFIGURATIONS)('are copied with %s: what is verified is one reading, whatever is recorded', async (_name, { audit }) => {
      const clone = vi.spyOn(globalThis, 'structuredClone');
      const { kyaos, server, ancestors } = await makeServer({}, { audit });
      const { root, middle, leaf, chain } = await threeHops(server.did);
      ancestors.push(root, middle);
      const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));

      const result = await handler({ ...ARGS, _kyaos_delegation: leaf });

      expect(result.isError).toBeUndefined();
      expect(copiesOf(clone, chain)).toEqual([leaf, root, middle]);
    });

    it.each(CONFIGURATIONS)(
      'are what the call is decided on with %s, and so is the credential presented: one made to claim more once it is verified is granted no more',
      async (_name, { audit }) => {
        let whileDeciding = (): void => {};
        const { kyaos, server, ancestors, recorded } = await makeServer(
          {
            // Asked about each credential once every signature has been checked.
            revocationChecker: {
              isRevoked: async () => {
                whileDeciding();
                return { revoked: false };
              },
            },
          },
          { audit },
        );
        const { root, middle, leaf } = await threeHops(server.did);
        ancestors.push(root, middle);
        // The chain grants no scope to delete. The object the caller presented
        // is then made to claim one, which nobody signed.
        const claimed = [SCOPE, 'records:delete'];
        whileDeciding = () => {
          leaf.credentialSubject.delegation.constraints.scopes = claimed;
        };
        const handler = kyaos.wrapWithDelegation(
          'records.delete',
          { ...CONSENT, scopeId: 'records:delete' },
          kyaos.wrapWithProof('records.delete', released),
        );

        const result = await handler({ ...ARGS, _kyaos_delegation: leaf });

        // Refused as the credential that was verified is. A chain that verified
        // and was not acted on is recorded as in 1.22.0, by the refusal alone.
        expect(leaf.credentialSubject.delegation.constraints.scopes).toBe(claimed);
        expect(refusal(result).error).toBe('insufficient_scope');
        expect(proofOf(result)!.meta.outcome).toBe('denied');
        expect(delegationClaims(result)).toEqual({});
        expect(recorded.filter((event) => event.eventType === 'authorization.denied').map(delegationEvidence)).toEqual(
          audit ? [{}] : [],
        );
      },
    );

    it.each(CONFIGURATIONS)(
      'are what the call is decided on with %s: one that is revoked stays so, whatever the value it came as is changed to',
      async (_name, { audit }) => {
        const asked: string[] = [];
        let revoked = '';
        let whileDeciding = (): void => {};
        const { kyaos, server, ancestors, recorded } = await makeServer(
          {
            revocationChecker: {
              isRevoked: async (delegationId) => {
                asked.push(delegationId);
                whileDeciding();
                return { revoked: delegationId === revoked };
              },
            },
          },
          { audit },
        );
        const { root, middle, leaf } = await threeHops(server.did);
        ancestors.push(root, middle);
        const asResolved = structuredClone(middle);
        revoked = middle.credentialSubject.delegation.id;
        // The resolver's own object is changed while the chain is checked, and
        // then goes by an id nobody revoked.
        whileDeciding = () => {
          middle.credentialSubject.delegation.id = 'urn:uuid:never-revoked';
        };
        const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));

        const result = await handler({ ...ARGS, _kyaos_delegation: leaf });

        // The checker is asked about the credential the walk verified.
        expect(middle.credentialSubject.delegation.id).toBe('urn:uuid:never-revoked');
        expect(asked).toEqual([root.credentialSubject.delegation.id, revoked]);
        expect(refusal(result)).toEqual({
          error: 'delegation_invalid',
          reason: `Delegation "${leaf.credentialSubject.delegation.id}" is revoked via ancestor "${revoked}"`,
        });
        const read = await digestDelegationChain([root, asResolved, leaf], hash);
        expect(proofOf(result)!.meta.outcome).toBe('denied');
        expect(delegationClaims(result)).toEqual({});
        expect(recorded.filter((event) => event.eventType === 'delegation.rejected').map(delegationEvidence)).toEqual(
          audit
            ? [{
              delegationRef: leaf.id,
              delegationCredentialDigest: read.credentials.at(-1),
              delegationChainDigests: read.credentials,
            }]
            : [],
        );
      },
    );

    it('are not digested, and nothing but the presented credential is, when no chain is recorded: no audit trail', async () => {
      const { kyaos, server, ancestors } = await makeServer({}, { audit: false });
      const { root, middle, leaf } = await threeHops(server.did);
      ancestors.push(root, middle);
      const contexts: Array<KyaOsCallContext | undefined> = [];
      const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, async (args, _sessionId, context) => {
        contexts.push(context);
        return released(args);
      }));
      const hashing = vi.spyOn(crypto, 'hash');
      const credentialDigests = () => hashing.mock.calls.filter(([bytes]) => isCredentialDigestInput(bytes)).length;

      const result = await handler({ ...ARGS, _kyaos_delegation: leaf });

      // Allowed, as on earlier releases.
      expect(result.isError).toBeUndefined();
      // The handler is still told which credential the call presented.
      expect(contexts[0]!.authorization).toMatchObject({
        delegationRef: leaf.id,
        delegationCredentialDigest: (await digestDelegationChain([leaf], hash)).credentials[0],
      });
      expect(delegationClaims(result)).toEqual({});
      expect(credentialDigests()).toBe(1 + 1); // the gate's, and this test's own

      // A refusal has no use for a digest there, and takes none.
      hashing.mockClear();
      const tampered = structuredClone(leaf);
      tampered.credentialSubject.delegation.constraints.scopes = [SCOPE, 'records:delete'];
      const refused = await handler({ ...ARGS, _kyaos_delegation: tampered });
      expect(refused.isError).toBe(true);
      expect(credentialDigests()).toBe(0);
      expect(proofOf(refused)!.meta.outcome).toBe('denied');
      expect(delegationClaims(refused)).toEqual({});
    });
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});
