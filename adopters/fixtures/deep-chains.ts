/**
 * An adopter gates a tool on the chain a request carries, with `requireDelegation` from
 * `@kya-os/mcp/card`, and sets no limit on how far authority is delegated: a chain 25 hops deep is
 * accepted as one of 2 is, and `maxChainLength` is the adopter's to set. What a long chain can make
 * the guard do is held without a count. A delegate that adds hops naming other parties' hosts has
 * one of those hosts asked, not each, since nothing a hop names is read before the hops above it
 * verify and the first failure ends the check. And status answers that are each slow end the check
 * at `totalTimeoutMs`, as `deadline_exceeded`, with nothing more asked.
 */
import assert from 'node:assert/strict';
import { createDidKeyResolver } from '@kya-os/mcp';
import {
  createDelegationProofVerifier,
  createRevocationChecker,
  createStatusListProofVerifier,
  requireDelegation,
  toDelegationChainMeta,
  type DelegationCredential,
  type VerifyRequestDelegationDeps,
} from '@kya-os/mcp/card';
import { runCases } from './shared/cases.js';
import { revocationEntry, signCardHop } from './shared/credentials.js';
import { didKeyParty, type Party } from './shared/keys.js';
import { signedStatusList } from './shared/lists.js';
import { MemoryWeb } from './shared/web.js';

const RESOURCE = 'did:web:orders.example';
const ACTION = 'orders.place';
const DEEP = 25;
const OWNER_LIST = 'https://owner.example/status/1';
const didResolver = createDidKeyResolver();

/** `count` parties, the first the resource's owner and each delegating to the next. */
const lineOf = async (count: number): Promise<Party[]> => Promise.all(Array.from({ length: count }, () => didKeyParty()));

/** The chain over `line`, root first, each hop with a status entry at `listOf(k)` when given. */
async function chainOver(line: readonly Party[], listOf?: (hop: number) => string): Promise<DelegationCredential[]> {
  const hops: DelegationCredential[] = [];
  for (const [k, issuer] of line.slice(0, -1).entries()) {
    hops.push(
      await signCardHop(issuer, {
        id: `urn:example:hop-${k}`,
        invoker: line[k + 1]!.did,
        invocationTarget: RESOURCE,
        parentCapability: k === 0 ? RESOURCE : `urn:example:hop-${k - 1}`,
        allowedAction: [ACTION],
        ...(listOf === undefined ? {} : { credentialStatus: revocationEntry(listOf(k), k) }),
      }),
    );
  }
  return hops;
}

/** The guard's verdict on `chain`, presented by the last of `line`, under the owner's root and `options`. */
function verdictOn(chain: DelegationCredential[], line: readonly Party[], options: Partial<VerifyRequestDelegationDeps> = {}) {
  return requireDelegation({
    resource: RESOURCE,
    trustedRootIssuers: [line[0]!.did],
    verifyHopProof: createDelegationProofVerifier({ didResolver }),
    checkRevocation: async () => ({ revoked: false, fresh: true }),
    ...options,
  })({ meta: toDelegationChainMeta(chain), proofDid: line[line.length - 1]!.did, action: ACTION });
}

const line = await lineOf(DEEP + 1);
const chain = await chainOver(line);

await runCases('deep-chains', 'requireDelegation accepts a chain of any length, asks one outside host of a long hostile chain, and ends a slow check at totalTimeoutMs', [
  {
    name: 'control: a chain of 2 hops is accepted',
    run: async () => {
      const verdict = await verdictOn(chain.slice(0, 2), line.slice(0, 3));
      assert.equal(verdict.ok, true, JSON.stringify(verdict));
    },
  },
  {
    name: `a chain of ${DEEP} hops is accepted with no option set`,
    run: async () => {
      const verdict = await verdictOn(chain, line);
      assert.equal(verdict.ok, true, JSON.stringify(verdict));
      assert.equal(verdict.ok && verdict.depth, DEEP);
    },
  },
  {
    name: 'maxChainLength is the adopter\'s to set: 10 refuses the same chain, saying so',
    run: async () => {
      const verdict = await verdictOn(chain, line, { maxChainLength: 10 });
      assert.equal(verdict.ok, false);
      assert.equal(!verdict.ok && verdict.refusalCode, 'chain_invalid');
      assert.match(JSON.stringify(verdict), /carried delegation chain of 25 credentials exceeds the limit of 10/);
    },
  },
  {
    name: 'a delegate whose hops name 24 other hosts has one of them asked',
    run: async () => {
      const outside = (k: number) => `https://outside-${k}.example/status/1`;
      const listed = await chainOver(line, (k) => (k === 0 ? OWNER_LIST : outside(k)));
      const web = new MemoryWeb();
      web.serve(OWNER_LIST, await signedStatusList(line[0]!, OWNER_LIST));
      const asked: string[] = [];
      const fetch = web.safeFetch();
      const original = console.warn;
      console.warn = () => undefined;
      try {
        const verdict = await verdictOn(listed, line, {
          checkRevocation: createRevocationChecker({
            fetch: async (url) => {
              asked.push(url);
              return fetch(url);
            },
            verifyStatusList: createStatusListProofVerifier({ didResolver }),
          }),
        });
        assert.equal(verdict.ok, false);
        assert.equal(!verdict.ok && verdict.refusalCode, 'status_unavailable');
      } finally {
        console.warn = original;
      }
      assert.deepEqual(asked, [OWNER_LIST, outside(1)]);
    },
  },
  {
    name: 'status answers of 20 ms each end the check at a totalTimeoutMs of 100, and pass under the default',
    run: async () => {
      const listed = await chainOver(line, (k) => `https://owner.example/status/${k}`);
      let asked = 0;
      const checkRevocation = () => {
        asked += 1;
        return new Promise<{ revoked: false; fresh: true }>((resolve) => setTimeout(() => resolve({ revoked: false, fresh: true }), 20));
      };
      const refused = await verdictOn(listed, line, { checkRevocation, totalTimeoutMs: 100 });
      assert.equal(refused.ok, false);
      assert.equal(!refused.ok && refused.refusalCode, 'deadline_exceeded');
      assert.equal(!refused.ok && refused.transient, true);
      assert.match(JSON.stringify(refused), /the delegation check did not finish within 100 ms/);
      const askedBeforeRefusal = asked;
      assert.ok(askedBeforeRefusal < DEEP, `every status was asked for: ${askedBeforeRefusal}`);
      await new Promise((resolve) => setTimeout(resolve, 100));
      assert.equal(asked, askedBeforeRefusal, 'a status was asked for after the check was refused');
      const passed = await verdictOn(listed, line, { checkRevocation });
      assert.equal(passed.ok, true, JSON.stringify(passed));
    },
  },
]);
