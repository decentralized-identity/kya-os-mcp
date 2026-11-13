/**
 * A hop may name its issuer as a DID string or as an object whose `id` is that DID. The chain walk
 * reads either the same way, for the link from a hop to its parent's delegate and for the root a
 * verifier pins, so a chain is accepted or refused whichever form its hops use.
 */

import { describe, it, expect } from 'vitest';
import { evaluateDelegationChain, issuerDid, type DelegationChain } from '../delegation.js';
import { issuerOf } from '../../utils/guards.js';
import { NOW_MS, parties, RESOURCE, twoHopChain } from './signed-chain-helpers.js';

const now = () => NOW_MS;
const clear = async () => ({ revoked: false, fresh: true });

describe('a hop that names its issuer as an { id } object', () => {
  it('is read as the DID it names, as a bare string is, by issuerDid and issuerOf alike', () => {
    const p = parties();
    for (const hop of twoHopChain(p)) {
      const did = hop.issuer as string;
      for (const issuer of [did, { id: did }, { id: did, name: 'Acme' }]) {
        expect(issuerDid({ ...hop, issuer } as typeof hop)).toBe(did);
        expect(issuerOf(issuer)).toBe(did);
      }
    }
  });

  it('links to its parent and to the pinned root as the same hop with a string issuer does', async () => {
    const p = parties();
    const asString = twoHopChain(p);
    const asObject = asString.map((hop) => ({ ...hop, issuer: { id: hop.issuer as string } })) as unknown as DelegationChain;
    for (const chain of [asString, asObject]) {
      expect(await evaluateDelegationChain(chain, clear, { resource: RESOURCE, now, resourceOwner: p.acme.did })).toMatchObject({ ok: true });
      const otherOwner = await evaluateDelegationChain(chain, clear, { resource: RESOURCE, now, resourceOwner: p.agent.did });
      expect(otherOwner.ok).toBe(false);
    }
  });
});
