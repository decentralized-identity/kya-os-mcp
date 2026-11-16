/**
 * A hop may name its issuer as a DID string or as an object whose `id` is that DID. The chain walk
 * names each hop's issuer, and the root a verifier pins with the status-list URL its own hop names,
 * to the revocation checker, which holds the hop's status list to the keeper of its URL. It names the same DIDs whichever form the hops use, so a chain is not
 * refused, nor a list accepted, for the way an issuer is written.
 */

import { describe, it, expect } from 'vitest';
import { evaluateDelegationChain, revocationEntriesOf, type DelegationChain } from '../delegation.js';
import type { StatusCheckContext } from '../revocation.js';
import { now, parties, RESOURCE, STATUS_URL, twoHopChain } from './signed-chain-helpers.js';

/** `chain` with every hop's issuer written as an object, with a member beside its `id`. */
const withObjectIssuers = (chain: DelegationChain): DelegationChain =>
  chain.map((hop) => ({ ...hop, issuer: { id: hop.issuer as string, name: 'Acme' } })) as unknown as DelegationChain;

describe('a hop that names its issuer as an { id } object', () => {
  it('is paired with the DID it names, and with the pinned root, as the same hop with a string issuer is', () => {
    const p = parties();
    const asString = twoHopChain(p);
    for (const chain of [asString, withObjectIssuers(asString)]) {
      expect(revocationEntriesOf(chain, p.acme.did)).toMatchObject([
        { credentialIssuer: p.acme.did, trustedRootIssuer: p.acme.did, position: 0 },
        { credentialIssuer: p.agent.did, trustedRootIssuer: p.acme.did, position: 1 },
      ]);
      // A root the chain does not start at is not named, in either form.
      expect(revocationEntriesOf(chain, p.agent.did).every((entry) => !('trustedRootIssuer' in entry))).toBe(true);
    }
  });

  it('has its issuer and the pinned root named to the revocation checker by the chain walk', async () => {
    const p = parties();
    const asString = twoHopChain(p);
    for (const chain of [asString, withObjectIssuers(asString)]) {
      const named: (StatusCheckContext | undefined)[] = [];
      const check = async (_entry: unknown, context?: StatusCheckContext) => {
        named.push(context);
        return { revoked: false, fresh: true };
      };
      const result = await evaluateDelegationChain(chain, check, { resource: RESOURCE, now, resourceOwner: p.acme.did });
      expect(result).toMatchObject({ ok: true });
      expect(named).toEqual([
        { credentialIssuer: p.acme.did, trustedRootIssuer: p.acme.did, trustedRootStatusList: STATUS_URL },
        { credentialIssuer: p.agent.did, trustedRootIssuer: p.acme.did, trustedRootStatusList: STATUS_URL },
      ]);
    }
  });
});
