/**
 * An adopter's issuer, `did:web:issuer.example`, signs its delegations with its own key and its
 * status lists with a separate identity, `did:web:issuer.example:status`, as a deployment that keeps
 * the list-signing key apart does. A verifier holds a list to the one keeper of its URL, so it
 * refuses that list until it is told, in `statusListIssuers`, that the status identity keeps it.
 * The refusal has to say so, printing the list's own URL to bind, never its origin, which would
 * hand the status identity every list there. An operator who means the whole origin binds it as
 * SPEC.md §6.6 reads one, `https://issuer.example`; written with a `/` after it, the origin would
 * bind only itself, as an exact URL, so the configuration is refused when it is given, naming the
 * form to write.
 *
 * The chain is verified as the Entity Card gate verifies a request, `verifyRequestDelegation`, with
 * `createRevocationChecker` as its revocation check, so the checker's reason reaches the adopter.
 */
import assert from 'node:assert/strict';
import { createDidWebResolver, type StatusListIssuers } from '@kya-os/mcp';
import {
  createDelegationProofVerifier,
  createRevocationChecker,
  createStatusListProofVerifier,
  toDelegationChainMeta,
  verifyRequestDelegation,
  type RequestDelegationResult,
} from '@kya-os/mcp/card';
import { runCases } from './shared/cases.js';
import { revocationEntry, signCardHop } from './shared/credentials.js';
import { didDocumentOf, didKeyParty, didWebParty } from './shared/keys.js';
import { signedStatusList } from './shared/lists.js';
import { MemoryWeb } from './shared/web.js';

/** The verifier's own DID: the resource the chain is for. */
const RESOURCE = 'did:web:api.example';
const LIST_URL = 'https://issuer.example/lists/1';
const ACTION = 'notes.read';

const issuer = await didWebParty('did:web:issuer.example');
const statusSigner = await didWebParty('did:web:issuer.example:status');
const agent = await didKeyParty();
const web = new MemoryWeb();
web.serveDidDocument(didDocumentOf(issuer));
web.serveDidDocument(didDocumentOf(statusSigner));
web.serve(LIST_URL, await signedStatusList(statusSigner, LIST_URL));
const didResolver = createDidWebResolver(web.fetchProvider());

const hop = await signCardHop(issuer, {
  id: 'urn:example:issuer-to-agent',
  invoker: agent.did,
  invocationTarget: RESOURCE,
  parentCapability: RESOURCE,
  allowedAction: [ACTION],
  credentialStatus: revocationEntry(LIST_URL, 3),
});

/** Verify the agent's one-hop chain under a revocation checker given `statusListIssuers`, or none. */
function verifyChain(statusListIssuers?: StatusListIssuers): Promise<RequestDelegationResult> {
  return verifyRequestDelegation(
    { meta: toDelegationChainMeta([hop]), proofDid: agent.did, action: ACTION },
    {
      resource: RESOURCE,
      trustedRootIssuers: [issuer.did],
      verifyHopProof: createDelegationProofVerifier({ didResolver }),
      checkRevocation: createRevocationChecker({
        fetch: web.safeFetch(),
        verifyStatusList: createStatusListProofVerifier({ didResolver }),
        ...(statusListIssuers !== undefined ? { statusListIssuers } : {}),
      }),
    },
  );
}

/** Fail with the verifier's reasons unless it accepted the chain. */
function assertAccepted(result: RequestDelegationResult): void {
  assert.ok(result.ok, result.ok ? '' : `refused as ${result.code}: ${result.reasons.join('; ')}`);
}

await runCases('separate-status-signer', 'a list signed by a separate status DID is refused with a statusListIssuers hint, and accepted once it is configured', [
  {
    name: 'with no statusListIssuers, the credential is refused and the reason names statusListIssuers',
    run: async () => {
      const result = await verifyChain();
      assert.equal(result.ok, false, 'the chain was accepted');
      if (result.ok) return;
      assert.equal(result.code, 'delegation_revoked');
      const reasons = result.reasons.join('; ');
      assert.ok(reasons.includes('statusListIssuers'), `the reason does not name statusListIssuers: ${reasons}`);
      const hint = `{ "${statusSigner.did}": ["${LIST_URL}"] }`;
      assert.ok(reasons.includes(hint), `the reason does not give the configuration ${hint}: ${reasons}`);
    },
  },
  {
    name: "with statusListIssuers binding the list's URL, the form the refusal prints, to the status DID, it is accepted",
    run: async () => assertAccepted(await verifyChain({ [statusSigner.did]: [LIST_URL] })),
  },
  {
    name: 'with statusListIssuers binding the origin https://issuer.example to the status DID, it is accepted',
    run: async () => assertAccepted(await verifyChain({ [statusSigner.did]: ['https://issuer.example'] })),
  },
  {
    name: 'with the origin written https://issuer.example/, the configuration throws, naming https://issuer.example',
    run: () => {
      assert.throws(
        () => verifyChain({ [statusSigner.did]: ['https://issuer.example/'] }),
        (error: unknown) => {
          assert.ok(error instanceof TypeError, `it threw ${String(error)}, not a TypeError`);
          assert.ok(error.message.includes('write it as "https://issuer.example"'), `the error does not name the origin to write: ${error.message}`);
          return true;
        },
      );
    },
  },
]);
