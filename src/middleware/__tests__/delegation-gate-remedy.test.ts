/**
 * The `statusListIssuers` configuration a keeper refusal ends with, as the delegation gate passes it
 * on. The keeper rule quotes the list before its proof is checked, so the checker logs its words,
 * the configuration whole among them, for the operator to copy, and its reason says only that the
 * list could not be read or checked. The gate's log line starts with the chain walk's words and the
 * verifier's, then the words of the adopter's resolver, then that reason. The client's reason
 * carries no part of the configuration.
 */

import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { logger } from '../../logging/index.js';
import { RefusalError, type CredentialStatus, type StatusListResolver } from '../../index.js';
import { createRevocationChecker, createStatusListProofVerifier, type BitstringStatusListEntry } from '../../card/index.js';
import { documentsOf, servingFromMemory, signedStatusList, webParty, type WebParty } from '../../__tests__/utils/adopter-issuers.js';
import { delegationRecord, signedCredential } from '../../__tests__/utils/delegation-credentials.js';
import { makeServer } from './helpers/delegation-gate-server.js';
import { ARGS, CONSENT, SCOPE, TOOL, released } from './helpers/delegated-call.js';

afterEach(() => {
  vi.restoreAllMocks();
});

const TENANT = 'did:web:identity.platform.example.com:tenants:northwind';
const LIST_URL = 'https://identity.platform.example.com/tenants/northwind/status/revocation/1';
const CONFIGURATION = `{ "${TENANT}:status": ["${LIST_URL}"] }`;
const LOG_OPENING = `[kya-os] Delegation verification failed for "${TOOL}": `;

let issuer: WebParty;
let signer: WebParty;
let statusListResolver: StatusListResolver;
beforeAll(async () => {
  [issuer, signer] = await Promise.all([webParty(TENANT), webParty(`${TENANT}:status`)]);
  const checker = createRevocationChecker({
    fetch: servingFromMemory({ [LIST_URL]: await signedStatusList(signer, LIST_URL) }),
    verifyStatusList: createStatusListProofVerifier({ didResolver: documentsOf(issuer, signer) }),
  });
  // The adopter fixture's resolver: the checker, asked about the entry alone.
  statusListResolver = {
    async checkStatus(status) {
      const verdict = await checker(status as unknown as BitstringStatusListEntry);
      if (verdict.revoked && !verdict.fresh) throw new RefusalError(verdict.code ?? 'status_unavailable', `the status list could not be read: ${verdict.reason ?? 'no reason given'}`);
      return verdict.revoked;
    },
  };
});

describe("a delegation refused on a tenant's status list another DID signed", () => {
  it("logs the statusListIssuers configuration whole, and tells the client no part of it", async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const { kyaos } = await makeServer({ didResolver: documentsOf(issuer), statusListResolver });
    const credentialStatus: CredentialStatus = {
      id: `${LIST_URL}#3`,
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: '3',
      statusListCredential: LIST_URL,
    };
    const record = delegationRecord(issuer.did, {
      id: `delegation-${'d'.repeat(48)}`,
      constraints: { scopes: [SCOPE], notAfter: Math.floor(Date.now() / 1000) + 3600 },
    });
    const credential = await signedCredential(issuer.key, { record, credentialStatus });

    const result = await kyaos.wrapWithDelegation(TOOL, CONSENT, released)({ ...ARGS, _kyaos_delegation: credential });

    const lines = warn.mock.calls.map(([line]) => String(line));
    const checker = lines.find((line) => line.startsWith('[revocation] the status list at "') && line.includes(' could not be read or checked: revocation: '));
    expect(checker?.endsWith(`in statusListIssuers: ${CONFIGURATION}`)).toBe(true);
    const gate = lines.find((line) => line.startsWith(LOG_OPENING));
    expect(gate).toMatch(/^\[kya-os\] Delegation verification failed for "[^"]+": Delegation delegation-d+ invalid: Status check error: /);
    const body = JSON.parse((result.content[0] as { text: string }).text) as { reason: string };
    expect(body.reason.length).toBeLessThanOrEqual(257);
    expect(body.reason).not.toMatch(/; if |statusListIssuers/);
  });
});
