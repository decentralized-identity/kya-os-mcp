/**
 * The chain walk names a hop whose status it refuses by the status list and the index the hop
 * states. Whoever issued the hop wrote both, and the reason is shown to people, written to logs and
 * signed into response proofs, so it quotes each as a JSON string of at most its first 64 characters
 * and names a value that is not a string by its type, never converting it. `verifyRequestDelegation` parses every hop
 * before it checks a status, so on that path only a string reaches the reason.
 */

import { describe, it, expect } from 'vitest';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import { evaluateDelegationChain, revocationEntriesOf, type DelegationChain } from '../delegation.js';
import { createDelegationProofVerifier } from '../delegation-proof.js';
import { toDelegationChainMeta, verifyRequestDelegation } from '../request-delegation.js';
import { createRevocationChecker, evaluateRevocationChain } from '../revocation.js';
import { createStatusListProofVerifier } from '../status-list-proof.js';
import { NOW_MS, parties, RESOURCE, serve, signEddsaJcs2022, statusList, twoHopChain, type ChainParties } from './signed-chain-helpers.js';

const didResolver = createDidKeyResolver();
const now = () => NOW_MS;

const LONG = { statusListCredential: `https://acme.example/status/${'u'.repeat(100_000)}`, statusListIndex: '7'.repeat(100_000) };
const LONG_NAMED = `list "${LONG.statusListCredential.slice(0, 64)}"..., index "${'7'.repeat(64)}"...`;
const NAMED = JSON.parse('{"toString":"3"}') as string;
const OBJECTS = { statusListCredential: NAMED, statusListIndex: NAMED };
const OBJECTS_NAMED = 'list of type object, index of type object';

/** The words a refusal names its hop by: the list and the index. */
const hopNamed = (reasons: readonly string[]): string | undefined =>
  /^revocation: hop 0 \((.*)\) is revoked or unresolvable/s.exec(reasons[0] ?? '')?.[1];

/** The number a refusal names its hop by. */
const hopNumber = (reasons: readonly string[]): string | undefined => /^revocation: hop (\S+) /.exec(reasons[0] ?? '')?.[1];

/** The shipped checker, verifying list proofs, with the root's list served at its status URL. */
const checkerFor = (p: ChainParties) =>
  createRevocationChecker({ fetch: serve(statusList(p.acme)), now, verifyStatusList: createStatusListProofVerifier({ didResolver }) });

/** The two-hop chain, its root restating its status entry with `status` and signed again by the root. */
function restatedChain(p: ChainParties, status: Record<string, unknown>): DelegationChain {
  const [root, leaf] = twoHopChain(p);
  const credentialStatus = { ...root.credentialStatus, ...status };
  const { proof: _proof, ...unsigned } = { ...root, credentialStatus } as Record<string, unknown>;
  return [signEddsaJcs2022(unsigned, p.acme) as unknown as typeof root, leaf];
}

describe('how the chain walk names a hop it refuses', () => {
  it('evaluateRevocationChain quotes the list and the index, whatever their form', async () => {
    const p = parties();
    for (const [entry, named] of [[LONG, LONG_NAMED], [OBJECTS, OBJECTS_NAMED]] as const) {
      const result = await evaluateRevocationChain([{ entry, credentialIssuer: p.acme.did }], checkerFor(p));
      expect(result).toMatchObject({ ok: false, fresh: false });
      expect(hopNamed(result.reasons)).toBe(named);
    }
  });

  it('evaluateDelegationChain, which checks no hop proof, quotes them the same way', async () => {
    const p = parties();
    for (const [status, named] of [[LONG, LONG_NAMED], [OBJECTS, OBJECTS_NAMED]] as const) {
      const chain = restatedChain(p, status);
      const result = await evaluateDelegationChain(chain, checkerFor(p), { resource: RESOURCE, now, resourceOwner: p.acme.did });
      expect(result.ok).toBe(false);
      expect(hopNamed(result.reasons)).toBe(named);
    }
  });

  it('verifyRequestDelegation quotes a long list and index, and refuses ones that are not strings before any status check', async () => {
    const p = parties();
    const request = (chain: DelegationChain) =>
      verifyRequestDelegation(
        { meta: toDelegationChainMeta(chain), proofDid: p.subAgent.did, action: 'orders.place' },
        {
          resource: RESOURCE,
          verifyHopProof: createDelegationProofVerifier({ didResolver }),
          checkRevocation: checkerFor(p),
          now,
          trustedRootIssuers: [p.acme.did],
        },
      );

    const long = await request(restatedChain(p, LONG));
    expect(long).toMatchObject({ ok: false, code: 'delegation_revoked' });
    expect(hopNamed(long.ok ? [] : long.reasons)).toBe(LONG_NAMED);

    const objects = await request(restatedChain(p, OBJECTS));
    expect(objects).toMatchObject({
      ok: false,
      code: 'delegation_invalid',
      reasons: [expect.stringMatching(/^hop 0: not a DelegationCredential at credentialStatus\.statusList(Index|Credential): /)],
    });
  });

  // A hop is named by its position in the chain, counting from the root as 0, whichever hops before
  // it carry a status entry.
  it('names a hop by its position in the chain, when only a later hop carries a status entry', async () => {
    const p = parties();
    const [root, signedLeaf] = twoHopChain(p);
    const { proof: _proof, ...unsignedRoot } = root as Record<string, unknown>;
    const { credentialStatus: _status, ...statusless } = unsignedRoot;
    const chain: DelegationChain = [signEddsaJcs2022(statusless, p.acme) as unknown as typeof root, signedLeaf];
    expect(revocationEntriesOf(chain)).toEqual([expect.objectContaining({ credentialIssuer: p.agent.did, position: 1 })]);

    const checker = createRevocationChecker({ fetch: serve(statusList(p.agent, [7])), now, verifyStatusList: createStatusListProofVerifier({ didResolver }) });
    const walked = await evaluateDelegationChain(chain, checker, { resource: RESOURCE, now, resourceOwner: p.acme.did });
    expect(walked.ok).toBe(false);
    expect(hopNumber(walked.reasons)).toBe('1');
    const requested = await verifyRequestDelegation(
      { meta: toDelegationChainMeta(chain), proofDid: p.subAgent.did, action: 'orders.place' },
      { resource: RESOURCE, verifyHopProof: createDelegationProofVerifier({ didResolver }), checkRevocation: checker, now, trustedRootIssuers: [p.acme.did] },
    );
    expect(requested).toMatchObject({ ok: false, code: 'delegation_revoked' });
    expect(hopNumber(requested.ok ? [] : requested.reasons)).toBe('1');
  });

  it('names a hop by its place among the entries when its position is not a non-negative whole number', async () => {
    const p = parties();
    for (const [position, named] of [[3, '3'], [-1, '0'], [1.5, '0'], [Number.NaN, '0'], [2 ** 53, '0']] as const) {
      const result = await evaluateRevocationChain([{ entry: OBJECTS, credentialIssuer: p.acme.did, position }], checkerFor(p));
      expect(hopNumber(result.reasons), `position ${position}`).toBe(named);
    }
  });

  it('names a hop by its position, the root 0 included, wherever it stands among the entries', async () => {
    const p = parties();
    const clear = { entry: { statusListCredential: 'https://acme.example/status/clear', statusListIndex: '1' }, credentialIssuer: p.acme.did };
    const check = async (entry: unknown) => ({ revoked: entry === OBJECTS, fresh: true });
    for (const position of [0, 1, 4]) {
      const result = await evaluateRevocationChain([clear, clear, { entry: OBJECTS, credentialIssuer: p.acme.did, position }], check);
      expect(hopNumber(result.reasons), `position ${position}`).toBe(String(position));
    }
  });
});
