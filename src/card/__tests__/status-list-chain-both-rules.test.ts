/**
 * A delegation chain's status lists are read only when both rules hold: the list's issuer is one the
 * checker accepts for the hop (`acceptStatusList`), and the list's proof verifies with a key that
 * issuer's DID document lists under `assertionMethod` (SPEC.md §6.2). Each path that reads a chain's
 * lists is run: `evaluateDelegationChain`, `verifyRequestDelegation` and `requireDelegation`.
 *
 * Acme (pinned) grants the agent, the agent the sub-agent, the sub-agent the worker. The first two
 * hops are on their issuers' own lists. The third, which the sub-agent issued, is on a list Mallory
 * signs; she signs no hop, so her DID document decides only whether her list's proof verifies. Every
 * list states its URL as its `id` and has every bit clear, so a list that is read reports its hop
 * active.
 */
import { describe, it } from 'vitest';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import type { DIDResolver } from '../../delegation/vc-verifier.types.js';
import { cast, expectAccepted, expectRevokedAt, listOf, servedBy, threeHopChain } from './status-list-paths.js';

const c = cast();
const chain = threeHopChain(c, [c.acme, c.agent, c.mallory]);
const lists = servedBy(listOf(c.acme), listOf(c.agent), listOf(c.mallory));
/** The verifier accepts Mallory's lists for the sub-agent's credentials. */
const malloryForSubAgent = { [c.subAgent.did]: [c.mallory.did] };

const didKeys = createDidKeyResolver();
/** Each did:key's own document, but Mallory's lists her key only under `authentication`. */
const malloryAuthenticationOnly: DIDResolver = {
  resolve: async (did) => {
    const document = await didKeys.resolve(did);
    return did === c.mallory.did && document ? { ...document, assertionMethod: [] } : document;
  },
};

describe("a chain's status lists are held to a trusted issuer and to that issuer's assertionMethod key", () => {
  it('refuses a list of an issuer trusted for the hop, signed with a key it lists only under authentication', async () => {
    await expectRevokedAt(2, chain, lists, { statusListIssuers: malloryForSubAgent, didResolver: malloryAuthenticationOnly });
  });

  it('refuses a list signed with an assertionMethod key of an issuer not trusted for the hop', async () => {
    await expectRevokedAt(2, chain, lists, {});
  });

  it('reads a list of an issuer trusted for the hop, signed with the key it lists under assertionMethod', async () => {
    await expectAccepted(chain, lists, { statusListIssuers: malloryForSubAgent });
  });
});
