/**
 * An adopter reads status lists with the library's `createRevocationChecker` and gives the verifier
 * its own `StatusListResolver` around it. The resolver asks the checker about the status entry it
 * was given and nothing else, which its type allows, and keeps a list it could not read apart from
 * a revoked credential by throwing a `RefusalError` with the checker's code, whose words the
 * verifier's reason carries. Any other error a resolver throws may be its transport's, so the
 * verifier logs its words and its reason says only that the list could not be read or checked.
 *
 * The issuer is a did:key that signs its own credentials and its own status list, the simplest
 * deployment there is, so the only thing between the adopter and a verified credential is the
 * wrapper.
 *
 * Each refusal carries a `code` the adopter can branch on and whether it is `transient`: a revoked
 * credential is `delegation_revoked` and stays refused, and a resolver that never answers is
 * `deadline_exceeded`, which a later call may get past.
 */
import assert from 'node:assert/strict';
import { DelegationCredentialVerifier, RefusalError, createDidKeyResolver, type StatusListResolver } from '@kya-os/mcp';
import { createRevocationChecker, createStatusListProofVerifier } from '@kya-os/mcp/card';
import { runCases } from './shared/cases.js';
import { ed25519SignatureVerifier, issueDelegation, revocationEntry } from './shared/credentials.js';
import { didKeyParty } from './shared/keys.js';
import { signedStatusList } from './shared/lists.js';
import { MemoryWeb } from './shared/web.js';

const LIST_URL = 'https://status.example/lists/1';
const LIVE_INDEX = 41;
const REVOKED_INDEX = 42;

const issuer = await didKeyParty();
const agent = await didKeyParty();
const didResolver = createDidKeyResolver();
const web = new MemoryWeb();
web.serve(LIST_URL, await signedStatusList(issuer, LIST_URL, [REVOKED_INDEX]));

const check = createRevocationChecker({
  fetch: web.safeFetch(),
  verifyStatusList: createStatusListProofVerifier({ didResolver }),
});

/** The adopter's resolver: the library's checker, asked about the entry alone. */
const statusListResolver: StatusListResolver = {
  async checkStatus(status) {
    const verdict = await check(status);
    if (verdict.revoked && !verdict.fresh) {
      throw new RefusalError(verdict.code ?? 'status_unavailable', `the status list could not be read: ${verdict.reason ?? 'no reason given'}`);
    }
    return verdict.revoked;
  },
};

const verifier = new DelegationCredentialVerifier({ didResolver, signatureVerifier: ed25519SignatureVerifier, statusListResolver });
const live = await issueDelegation(issuer, {
  id: 'live',
  subjectDid: agent.did,
  scopes: ['notes:read'],
  credentialStatus: revocationEntry(LIST_URL, LIVE_INDEX),
});
const revoked = await issueDelegation(issuer, {
  id: 'revoked',
  subjectDid: agent.did,
  scopes: ['notes:read'],
  credentialStatus: revocationEntry(LIST_URL, REVOKED_INDEX),
});

await runCases('wrapped-status-checker', 'a resolver that wraps createRevocationChecker passes a live credential, refuses a revoked one as delegation_revoked, and a stalled one as deadline_exceeded', [
  {
    name: "control: the checker, told the credential's issuer, reads the live entry as clear",
    run: async () => {
      const verdict = await check(revocationEntry(LIST_URL, LIVE_INDEX), { credentialIssuer: issuer.did });
      assert.deepEqual(verdict, { revoked: false, fresh: true });
    },
  },
  {
    name: 'an unrevoked credential verifies',
    run: async () => {
      const result = await verifier.verifyDelegationCredential(live);
      assert.equal(result.valid, true, result.reason ?? 'no reason given');
    },
  },
  {
    name: 'a revoked credential is refused as revoked',
    run: async () => {
      const result = await verifier.verifyDelegationCredential(revoked);
      assert.equal(result.valid, false, 'the revoked credential verified');
      assert.equal(result.statusOutcome, 'revoked', result.reason ?? 'no reason given');
      assert.equal(result.code, 'delegation_revoked', result.reason ?? 'no reason given');
      assert.equal(result.transient, false, 'a revoked credential was refused as transient');
    },
  },
  {
    name: 'a resolver that never answers is refused as deadline_exceeded, transient',
    run: async () => {
      const stalled = new DelegationCredentialVerifier({
        didResolver,
        signatureVerifier: ed25519SignatureVerifier,
        statusListResolver: { checkStatus: () => new Promise<boolean>(() => undefined) },
        dependencyTimeoutMs: 100,
      });
      const result = await stalled.verifyDelegationCredential(live);
      assert.equal(result.valid, false, 'the credential verified without a status');
      assert.equal(result.code, 'deadline_exceeded', result.reason ?? 'no reason given');
      assert.equal(result.transient, true, 'a deadline was refused as lasting');
    },
  },
]);
