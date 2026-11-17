/**
 * An adopter verifies an Entity Card that declares a revocation entry, the Card's kill switch. Its
 * Entity has revoked the Card: the list at the entry's URL, signed by the Entity, has the Card's bit
 * set. A host that gives `verifyCard` a `statusListChecker` sees the Card revoked. A host that
 * leaves the checker out cannot tell, so `verifyCard` refuses the Card as `configuration_error`,
 * as it refuses an accountability or attestation that no verifier checks, rather than letting the
 * revoked Card through. A Card that declares no revocation entry needs no checker.
 */
import assert from 'node:assert/strict';
import { createDidWebResolver } from '@kya-os/mcp';
import {
  createRevocationChecker,
  createStatusListProofVerifier,
  verifyCard,
  type EntityCard,
} from '@kya-os/mcp/card';
import { runCases } from './shared/cases.js';
import { didDocumentOf, didWebParty } from './shared/keys.js';
import { signedStatusList } from './shared/lists.js';
import { MemoryWeb } from './shared/web.js';

const CARD_LIST_URL = 'https://agent.example/lists/cards';
const INDEX = 3;

const entity = await didWebParty('did:web:agent.example');
const web = new MemoryWeb();
web.serveDidDocument(didDocumentOf(entity));
web.serve(CARD_LIST_URL, await signedStatusList(entity, CARD_LIST_URL, [INDEX]));
const statusListChecker = createRevocationChecker({
  fetch: web.safeFetch(),
  verifyStatusList: createStatusListProofVerifier({ didResolver: createDidWebResolver(web.fetchProvider()) }),
});

const card: EntityCard = {
  id: entity.did,
  entityType: 'agent',
  name: 'Orders Agent',
  kid: entity.kid,
  capabilities: ['handshake'],
  revocation: { statusListCredential: CARD_LIST_URL, statusListIndex: String(INDEX) },
};
const { revocation: _entry, ...undeclared } = card;

await runCases('card-revocation-checker', 'verifyCard refuses a Card that declares a revocation entry when no statusListChecker is supplied, as configuration_error, and needs none for a Card that declares no entry', [
  {
    name: 'control: with a statusListChecker, the revoked Card is refused as delegation_revoked',
    run: async () => {
      const result = await verifyCard(card, { statusListChecker });
      assert.equal(result.ok, false, 'the revoked Card verified');
      assert.equal(result.code, 'delegation_revoked');
      assert.equal(result.revocation?.revoked, true);
    },
  },
  {
    name: 'without a statusListChecker, the revoked Card is refused as configuration_error, not let through',
    run: async () => {
      const result = await verifyCard(card, {});
      assert.equal(result.ok, false, 'the revoked Card verified with no statusListChecker');
      assert.equal(result.code, 'configuration_error');
      assert.equal(result.transient, false);
      assert.equal(result.conformanceLevel, 'L1');
      assert.equal(result.revocation?.revoked, true);
      assert.equal(result.revocation?.fresh, false);
      const reason = result.revocation?.reason ?? '';
      assert.ok(reason.includes('statusListChecker'), `the reason does not name the missing checker: ${reason}`);
    },
  },
  {
    name: 'a Card that declares no revocation entry verifies without a statusListChecker, as before',
    run: async () => {
      const result = await verifyCard(undeclared, {});
      assert.equal(result.ok, true, `refused as ${result.code}`);
      assert.equal(result.revocation, undefined);
    },
  },
]);
