/**
 * An adopter's issuer, `did:web:issuer.example`, signs its delegations with its own key and its
 * status lists with a separate identity, `did:web:issuer.example:status`, as a deployment that keeps
 * the list-signing key apart does. A verifier holds a list to the one keeper of its URL, so it
 * refuses that list until it is told, in `statusListIssuers`, that the status identity keeps it.
 * The operator's log has to say so, printing the list's own URL to bind, never its origin, which
 * would hand the status identity every list there. The refusal itself, which reaches whoever
 * presented the chain, says only that the list could not be read or checked, since the rule that
 * refused it quoted the list before its proof was checked. An operator who means the whole origin
 * binds it as SPEC.md §6.6 reads one, `https://issuer.example`; written with a `/` after it, the
 * origin would bind only itself, as an exact URL, so the configuration is refused when it is given,
 * naming the form to write.
 *
 * The chain is verified as the Entity Card gate verifies a request, `verifyRequestDelegation`, with
 * `createRevocationChecker` as its revocation check, and the library's default logger writes the
 * operator's lines to the console as warnings.
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

/** What `work` comes to, and the lines it writes to the console as warnings, where the operator reads them. */
async function withWarnings<T>(work: () => Promise<T>): Promise<{ value: T; warnings: string }> {
  const lines: string[] = [];
  const original = console.warn;
  console.warn = (...args: unknown[]) => void lines.push(args.map(String).join(' '));
  try {
    return { value: await work(), warnings: lines.join('\n') };
  } finally {
    console.warn = original;
  }
}

/** Fail with the verifier's reasons unless it accepted the chain. */
function assertAccepted(result: RequestDelegationResult): void {
  assert.ok(result.ok, result.ok ? '' : `refused as ${result.code}: ${result.reasons.join('; ')}`);
}

await runCases('separate-status-signer', "a list signed by a separate status DID is refused with a statusListIssuers hint in the operator's log, and accepted once it is configured", [
  {
    name: "with no statusListIssuers, the credential is refused, the operator's log names statusListIssuers, and the reason does not",
    run: async () => {
      const { value: result, warnings } = await withWarnings(() => verifyChain());
      assert.equal(result.ok, false, 'the chain was accepted');
      if (result.ok) return;
      assert.equal(result.code, 'delegation_revoked');
      const reasons = result.reasons.join('; ');
      assert.ok(reasons.endsWith(`the status list at "${LIST_URL}" could not be read or checked`), `the reason says more than that the list could not be read: ${reasons}`);
      assert.ok(!reasons.includes('statusListIssuers'), `the reason names statusListIssuers: ${reasons}`);
      const hint = `in statusListIssuers: { "${statusSigner.did}": ["${LIST_URL}"] }`;
      assert.ok(warnings.includes(hint), `the operator's log does not give the configuration ${hint}: ${warnings}`);
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
