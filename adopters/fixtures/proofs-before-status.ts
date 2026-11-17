/** An installed-package adopter checks every hop proof before any status read. */
import assert from 'node:assert/strict';
import { createDidKeyResolver } from '@kya-os/mcp';
import {
  createDelegationProofVerifier,
  createRevocationChecker,
  createStatusListProofVerifier,
  evaluateDelegationChain,
  type DelegationChainContext,
} from '@kya-os/mcp/card';
import { runCases } from './shared/cases.js';
import { revocationEntry, signCardHop } from './shared/credentials.js';
import { didKeyParty } from './shared/keys.js';
import { signedStatusList } from './shared/lists.js';
import { MemoryWeb } from './shared/web.js';

const RESOURCE = 'did:web:orders.example';
const STATUS_URL = 'https://issuer.example/status';
const owner = await didKeyParty();
const agent = await didKeyParty();
const worker = await didKeyParty();
const root = await signCardHop(owner, {
  id: 'urn:example:root', invoker: agent.did, invocationTarget: RESOURCE,
  parentCapability: RESOURCE, allowedAction: ['orders.place', 'orders.read'],
  credentialStatus: revocationEntry(STATUS_URL, 3),
});
const leaf = await signCardHop(agent, {
  id: 'urn:example:leaf', invoker: worker.did, invocationTarget: RESOURCE,
  parentCapability: root.credentialSubject.id, allowedAction: ['orders.place', 'orders.read'],
  credentialStatus: revocationEntry(STATUS_URL, 7),
});
const didResolver = createDidKeyResolver();
const ctx: DelegationChainContext = {
  resource: RESOURCE,
  resourceOwner: owner.did,
  verifyHopProof: createDelegationProofVerifier({ didResolver }),
};
const web = new MemoryWeb();
web.serve(STATUS_URL, await signedStatusList(owner, STATUS_URL));

/** Status wiring with counters around both the checker and the underlying fetch. */
function observedStatus() {
  const checked: string[] = [];
  const fetched: string[] = [];
  const fetch = web.safeFetch();
  const check = createRevocationChecker({
    fetch: async (url) => { fetched.push(url); return fetch(url); },
    verifyStatusList: createStatusListProofVerifier({ didResolver }),
  });
  return {
    checked,
    fetched,
    check: async (...args: Parameters<typeof check>) => {
      checked.push(args[0]?.statusListIndex ?? 'missing');
      return check(...args);
    },
  };
}

await runCases('proofs-before-status', 'evaluateDelegationChain proves every hop before status through the installed public API', [
  {
    name: 'control: a signed chain uses the pinned root list for both hops',
    run: async () => {
      const status = observedStatus();
      const result = await evaluateDelegationChain([root, leaf], status.check, ctx);
      assert.equal(result.ok, true, result.reasons.join('; '));
      assert.equal(result.fresh, true);
      assert.deepEqual(status.checked, ['3', '7']);
      assert.ok(status.fetched.length > 0);
    },
  },
  {
    name: 'a hop narrowed after signing is refused before the checker or fetch runs',
    run: async () => {
      const status = observedStatus();
      const edited = { ...leaf, credentialSubject: { ...leaf.credentialSubject, allowedAction: ['orders.place'] } };
      const result = await evaluateDelegationChain([root, edited], status.check, ctx);
      assert.equal(result.ok, false);
      assert.equal(result.code, 'invalid_proof');
      assert.equal(result.fresh, false);
      assert.deepEqual(result.reasons, ['hop 1: proof did not verify']);
      assert.deepEqual(status.checked, []);
      assert.deepEqual(status.fetched, []);
    },
  },
]);
