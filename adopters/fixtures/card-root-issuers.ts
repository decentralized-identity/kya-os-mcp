/**
 * An adopter verifies the delegation chain a request carries with the Entity Card guard,
 * `requireDelegation` from `@kya-os/mcp/card`, and learns when it builds the guard whose authority
 * it must name. With neither `trustedRootIssuers` nor `resourceOwner` set the guard would accept a
 * chain rooted anywhere, so outside development building it throws, naming every fix;
 * `development: true` and `allowAnyRootIssuer: true` build it with one warning. Every party is a
 * did:key and no hop carries a status entry, so nothing is read over a network, and the warnings
 * are read where an adopter sees them, on the console.
 */
import assert from 'node:assert/strict';
import { createDidKeyResolver } from '@kya-os/mcp';
import {
  createDelegationProofVerifier,
  requireDelegation,
  toDelegationChainMeta,
  type DelegationGuard,
  type VerifyRequestDelegationDeps,
} from '@kya-os/mcp/card';
import { runCases } from './shared/cases.js';
import { signCardHop } from './shared/credentials.js';
import { didKeyParty, type Party } from './shared/keys.js';
import { buildInProduction, isProductionChild, reportProductionBuild } from './shared/production.js';

/** The verifier's own DID: the resource every chain is for. */
const RESOURCE = 'did:web:orders.example';
const ACTION = 'orders.place';

/** The guard's options beside the shipped hop-proof verifier, pinning nothing unless `options` does. */
const guardWith = (options: Partial<VerifyRequestDelegationDeps> = {}): DelegationGuard =>
  requireDelegation({
    resource: RESOURCE,
    verifyHopProof: createDelegationProofVerifier({ didResolver: createDidKeyResolver() }),
    // No hop carries a status entry, so the guard never asks.
    checkRevocation: async () => ({ revoked: false, fresh: true }),
    ...options,
  });

/** Run `work`, and return what it returned with the console warnings about trust roots it caused. */
async function watchingWarnings<T>(work: () => Promise<T>): Promise<{ value: T; warnings: string[] }> {
  const warnings: string[] = [];
  const original = console.warn;
  console.warn = (...args: unknown[]) => {
    const text = args.map(String).join(' ');
    if (text.includes('trustedRootIssuers')) warnings.push(text);
  };
  try {
    return { value: await work(), warnings };
  } finally {
    console.warn = original;
  }
}

/** Whether a guard built with `options` lets `agent` act on each chain `issuers` sign to it, with the warnings on the way. */
function verdictsOf(options: Partial<VerifyRequestDelegationDeps>, issuers: readonly Party[], agent: Party) {
  return watchingWarnings(async () => {
    const guard = guardWith(options);
    const verdicts: boolean[] = [];
    for (const issuer of issuers) verdicts.push(await lets(guard, issuer, agent));
    return verdicts;
  });
}

/** Whether `guard` lets `agent` place an order on the one-hop chain `issuer` signs to it. */
async function lets(guard: DelegationGuard, issuer: Party, agent: Party): Promise<boolean> {
  const root = await signCardHop(issuer, {
    id: `urn:example:${issuer === agent ? 'self' : 'owner'}`,
    invoker: agent.did,
    invocationTarget: RESOURCE,
    parentCapability: RESOURCE,
    allowedAction: [ACTION],
  });
  const verdict = await guard({ meta: toDelegationChainMeta([root]), proofDid: agent.did, action: ACTION });
  return verdict.ok;
}

if (isProductionChild()) {
  await reportProductionBuild(() => guardWith());
} else {
  const owner = await didKeyParty();
  const agent = await didKeyParty();

  await runCases('card-root-issuers', 'requireDelegation needs trustedRootIssuers or resourceOwner outside development, every fix is named, and each opt-out warns once', [
    {
      name: 'under NODE_ENV=production, building a guard with nothing pinned throws, naming trustedRootIssuers, resourceOwner, development: true and allowAnyRootIssuer',
      run: () => {
        const build = buildInProduction(import.meta.url);
        assert.equal(build.threw, true, 'the guard was built with no root pinned in production');
        for (const fix of ['trustedRootIssuers', 'resourceOwner', 'development: true', 'allowAnyRootIssuer: true']) {
          assert.ok(build.message.includes(fix), `the error does not name ${fix}: ${build.message}`);
        }
      },
    },
    {
      name: 'development: true builds the guard, accepts a self-issued chain and warns once',
      run: async () => {
        const { value, warnings } = await verdictsOf({ development: true }, [agent, agent], agent);
        assert.deepEqual(value, [true, true], 'a self-issued chain was refused in development');
        assert.equal(warnings.length, 1, warnings.join('\n'));
      },
    },
    {
      name: 'allowAnyRootIssuer: true builds the guard, accepts a self-issued chain and warns once',
      run: async () => {
        const { value, warnings } = await verdictsOf({ allowAnyRootIssuer: true }, [agent, agent], agent);
        assert.deepEqual(value, [true, true], 'a self-issued chain was refused with allowAnyRootIssuer: true');
        assert.equal(warnings.length, 1, warnings.join('\n'));
        assert.match(warnings[0] ?? '', /allowAnyRootIssuer is true/);
      },
    },
    {
      name: 'trustedRootIssuers set builds silently, accepts a chain from a listed root and refuses a self-issued one',
      run: async () => {
        const { value, warnings } = await verdictsOf({ trustedRootIssuers: [owner.did] }, [owner, agent], agent);
        assert.deepEqual(value, [true, false], 'the listed root was refused, or a self-issued chain accepted');
        assert.deepEqual(warnings, []);
      },
    },
    {
      name: 'allowAnyRootIssuer: true beside resourceOwner is refused when the guard is built',
      run: () => {
        assert.throws(() => guardWith({ allowAnyRootIssuer: true, resourceOwner: owner.did }), TypeError);
      },
    },
  ]);
}
