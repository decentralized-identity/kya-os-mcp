/**
 * An adopter's issuer publishes its revocation list with a validity window, as W3C Bitstring Status
 * List v1.0 lets it, and republishes the list before the window ends. An earlier version, signed
 * before a delegation was revoked, still verifies, so whoever controls what the list's URL returns
 * can serve it in place of the current one. Past its own `validUntil` it says nothing about now, so
 * the Entity Card guard, `requireDelegation`, and `verifyCard` refuse it, as a status that could not
 * be read, `status_unavailable`, which is transient: the issuer republishes and the next call passes.
 * A list not yet valid is refused the same way, and a list that states no window is read as before.
 *
 * Every list is signed `eddsa-jcs-2022` and checked by `createStatusListProofVerifier`, so the only
 * thing wrong with the refused ones is their window.
 */
import assert from 'node:assert/strict';
import { createDidWebResolver } from '@kya-os/mcp';
import {
  createDelegationProofVerifier,
  createRevocationChecker,
  createStatusListProofVerifier,
  requireDelegation,
  toDelegationChainMeta,
  verifyCard,
  type DelegationGateResult,
  type EntityCard,
} from '@kya-os/mcp/card';
import { runCases } from './shared/cases.js';
import { revocationEntry, signCardHop } from './shared/credentials.js';
import { didDocumentOf, didKeyParty, didWebParty } from './shared/keys.js';
import { signedStatusList, type ListWindow } from './shared/lists.js';
import { MemoryWeb } from './shared/web.js';

/** The verifier's own DID: the resource the chain is for. */
const RESOURCE = 'did:web:orders.example';
const ACTION = 'orders.place';
const LIST_URL = 'https://issuer.example/lists/1';
const CARD_LIST_URL = 'https://agent.example/lists/cards';
const INDEX = 3;

const HOUR = 60 * 60 * 1000;
const at = (offsetMs: number): string => new Date(Date.now() + offsetMs).toISOString();
/** A window that ended an hour ago, the version an issuer replaced. */
const ENDED: ListWindow = { validFrom: at(-48 * HOUR), validUntil: at(-HOUR) };
/** A window that is open now. */
const OPEN: ListWindow = { validFrom: at(-HOUR), validUntil: at(24 * HOUR) };
/** A window that opens tomorrow. */
const NOT_YET: ListWindow = { validFrom: at(24 * HOUR), validUntil: at(48 * HOUR) };

const issuer = await didWebParty('did:web:issuer.example');
const entity = await didWebParty('did:web:agent.example');
const agent = await didKeyParty();
const web = new MemoryWeb();
web.serveDidDocument(didDocumentOf(issuer));
web.serveDidDocument(didDocumentOf(entity));
const didResolver = createDidWebResolver(web.fetchProvider());
const checkRevocation = createRevocationChecker({
  fetch: web.safeFetch(),
  verifyStatusList: createStatusListProofVerifier({ didResolver }),
});

const hop = await signCardHop(issuer, {
  id: 'urn:example:issuer-to-agent',
  invoker: agent.did,
  invocationTarget: RESOURCE,
  parentCapability: RESOURCE,
  allowedAction: [ACTION],
  credentialStatus: revocationEntry(LIST_URL, INDEX),
});

const guard = requireDelegation({
  resource: RESOURCE,
  trustedRootIssuers: [issuer.did],
  verifyHopProof: createDelegationProofVerifier({ didResolver }),
  checkRevocation,
});

/** The guard's verdict on the agent's call while the issuer's URL serves a clear list stating `window`. */
async function gateWith(window?: ListWindow): Promise<DelegationGateResult> {
  web.serve(LIST_URL, await signedStatusList(issuer, LIST_URL, [], window));
  return guard({ meta: toDelegationChainMeta([hop]), proofDid: agent.did, action: ACTION });
}

const card: EntityCard = {
  id: entity.did,
  entityType: 'agent',
  name: 'Orders Agent',
  kid: entity.kid,
  capabilities: ['handshake'],
  revocation: { statusListCredential: CARD_LIST_URL, statusListIndex: String(INDEX) },
};

/** `verifyCard` on the Card while its URL serves a clear list the Entity signed, stating `window`. */
async function cardWith(window?: ListWindow) {
  web.serve(CARD_LIST_URL, await signedStatusList(entity, CARD_LIST_URL, [], window));
  return verifyCard(card, { statusListChecker: checkRevocation });
}

/** Fail with the guard's reasons unless it let the call through. */
function assertLetThrough(result: DelegationGateResult): void {
  assert.ok(result.ok, result.ok ? '' : `refused as ${result.refusalCode}: ${result.error.reasons.join('; ')}`);
}

/** Fail unless the guard refused the call as a status it could not read, transiently, saying `words`. */
function assertUnavailable(result: DelegationGateResult, words: string): void {
  assert.equal(result.ok, false, 'the call was let through');
  if (result.ok) return;
  assert.equal(result.status, 403);
  assert.equal(result.refusalCode, 'status_unavailable', result.error.reasons.join('; '));
  assert.equal(result.transient, true);
  const reasons = result.error.reasons.join('; ');
  assert.ok(reasons.includes(words), `the reason does not say ${words}: ${reasons}`);
}

await runCases('expired-status-list', 'a signed list outside its validity window is refused as status_unavailable by requireDelegation and verifyCard, and a list in its window or stating none is read', [
  {
    name: 'control: a clear list in its window lets the call through, fresh',
    run: async () => {
      const result = await gateWith(OPEN);
      assertLetThrough(result);
      assert.equal(result.ok && result.fresh, true);
    },
  },
  {
    name: 'control: a clear list that states no validUntil lets the call through, as before',
    run: async () => assertLetThrough(await gateWith()),
  },
  {
    name: 'requireDelegation refuses a clear list past its validUntil, saying when it expired',
    run: async () => assertUnavailable(await gateWith(ENDED), `expired at "${ENDED.validUntil}"`),
  },
  {
    name: 'requireDelegation refuses a clear list before its validFrom, saying when it becomes valid',
    run: async () => assertUnavailable(await gateWith(NOT_YET), `not valid until "${NOT_YET.validFrom}"`),
  },
  {
    name: 'control: verifyCard reads a clear list in its window and the Card is ok',
    run: async () => {
      const result = await cardWith(OPEN);
      assert.equal(result.ok, true, JSON.stringify(result.revocation));
      assert.deepEqual(result.revocation, { revoked: false, fresh: true });
    },
  },
  {
    name: 'verifyCard refuses a Card whose clear list is past its validUntil, as status_unavailable',
    run: async () => {
      const result = await cardWith(ENDED);
      assert.equal(result.ok, false, 'the Card verified');
      assert.equal(result.code, 'status_unavailable');
      assert.equal(result.transient, true);
      assert.equal(result.revocation?.revoked, true);
      const reason = result.revocation?.reason ?? '';
      assert.ok(reason.includes(`expired at "${ENDED.validUntil}"`), `the reason does not say when the list expired: ${reason}`);
    },
  },
]);
