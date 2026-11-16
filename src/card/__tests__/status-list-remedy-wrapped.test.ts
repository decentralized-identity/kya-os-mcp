/**
 * The `statusListIssuers` configuration a keeper refusal ends with, as it reaches the operator
 * through a resolver or a checker an adopter wraps around the library's checker, with words of its
 * own before the checker's reason. Tenant DIDs on a shared identity host are long, so the reason
 * nears the length a checker's reason may have. The configuration is the line an operator copies,
 * so wherever a reason is cut, it is printed whole or not at all, and a wrapper's words of up to
 * 128 code units still leave it whole. Every test uses the package's public exports.
 */

import { beforeAll, describe, expect, it } from 'vitest';
import { DelegationCredentialVerifier, type CredentialStatus, type StatusListResolver } from '../../index.js';
import {
  CHECKER_REASON_LENGTH,
  createRevocationChecker,
  createStatusListProofVerifier,
  evaluateRevocationChain,
  type BitstringRevocationChecker,
  type BitstringStatusListEntry,
  type StatusListIssuers,
} from '../index.js';
import { documentsOf, servingFromMemory, signedStatusList, webParty, type WebParty } from '../../__tests__/utils/adopter-issuers.js';
import { credentialJwt, delegationRecord, signedCredential } from '../../__tests__/utils/delegation-credentials.js';

const TENANT = 'did:web:identity.platform.example.com:tenants:northwind-traders-emea';
const LIST_URL = 'https://identity.platform.example.com/tenants/northwind-traders-emea/status/revocation/1';
const ENTRY = { statusListCredential: LIST_URL, statusListIndex: '3', statusPurpose: 'revocation' as const };
const CONFIGURATION = `{ "${TENANT}:status": ["https://identity.platform.example.com"] }`;
/** The words the adopter fixture's resolver puts before the checker's reason. */
const ADOPTER_WORDS = 'the status list could not be read: ';

let issuer: WebParty;
let signer: WebParty;
let checker: BitstringRevocationChecker;
beforeAll(async () => {
  [issuer, signer] = await Promise.all([webParty(TENANT), webParty(`${TENANT}:status`)]);
  checker = createRevocationChecker({
    fetch: servingFromMemory({ [LIST_URL]: await signedStatusList(signer, LIST_URL) }),
    verifyStatusList: createStatusListProofVerifier({ didResolver: documentsOf(issuer, signer) }),
  });
});

/** A resolver as an adopter writes one: the checker, asked about the entry alone, throwing `words` and its reason. */
function wrapping(words: string): StatusListResolver {
  return {
    async checkStatus(status) {
      const verdict = await checker(status as unknown as BitstringStatusListEntry);
      if (verdict.revoked && !verdict.fresh) throw new Error(`${words}${verdict.reason ?? 'no reason given'}`);
      return verdict.revoked;
    },
  };
}

/** The reason the delegation verifier refuses a credential of the tenant's with, through `resolver`. */
async function verifierReason(resolver: StatusListResolver): Promise<string> {
  const credentialStatus: CredentialStatus = { id: `${LIST_URL}#3`, type: 'BitstringStatusListEntry', ...ENTRY };
  const credential = await signedCredential(issuer.key, { record: delegationRecord(issuer.did), credentialStatus });
  const result = await new DelegationCredentialVerifier({ didResolver: documentsOf(issuer) }).verifyDelegationJwt(
    await credentialJwt(credential, issuer.key),
    { statusListResolver: resolver, skipCache: true },
  );
  expect(result.valid).toBe(false);
  return result.reason ?? '';
}

/** Whether `reason` holds the remedy whole, holds none of it, or holds part of it. */
function remedyIn(reason: string): 'whole' | 'none' | 'part' {
  if (reason.endsWith(`in statusListIssuers: ${CONFIGURATION}`)) return 'whole';
  return /; if |statusListIssuers|\{ "did:/.test(reason) ? 'part' : 'none';
}

describe("the statusListIssuers remedy of a tenant's list, through a wrapper", () => {
  it("is whole in the checker's own reason, which nears the length a reason may have", async () => {
    const verdict = await checker(ENTRY, { credentialIssuer: issuer.did });
    expect(remedyIn(verdict.reason!)).toBe('whole');
    expect(verdict.reason!.length).toBeGreaterThan(CHECKER_REASON_LENGTH - 64);
    expect(verdict.reason!.length).toBeLessThanOrEqual(CHECKER_REASON_LENGTH);
  });

  it("reaches the delegation verifier's reason whole through the adopter fixture's resolver, and that configuration accepts the list", async () => {
    const reason = await verifierReason(wrapping(ADOPTER_WORDS));
    expect(reason.startsWith(`Status check error: ${ADOPTER_WORDS}status list issuer `)).toBe(true);
    expect(remedyIn(reason)).toBe('whole');
    const configured = JSON.parse(CONFIGURATION) as StatusListIssuers;
    const accepting = createRevocationChecker({
      fetch: servingFromMemory({ [LIST_URL]: await signedStatusList(signer, LIST_URL) }),
      verifyStatusList: createStatusListProofVerifier({ didResolver: documentsOf(issuer, signer) }),
      statusListIssuers: configured,
    });
    expect(await accepting(ENTRY, { credentialIssuer: issuer.did })).toEqual({ revoked: false, fresh: true });
  });

  it('stays whole after a wrapper\'s words of up to 128 code units, and is never printed in part after longer ones', async () => {
    for (let length = 0; length <= 384; length += 8) {
      const reason = await verifierReason(wrapping(`${'w'.repeat(length)}: `));
      const found = remedyIn(reason);
      expect(found, `${length} code units of words: ${reason}`).not.toBe('part');
      if (length + 2 <= 128) expect(found, `${length} code units of words`).toBe('whole');
    }
  });

  it('reaches the Card revocation walk whole through a checker that wraps the library\'s', async () => {
    const wrapped: BitstringRevocationChecker = async (entry, context) => {
      const verdict = await checker(entry, context);
      return verdict.revoked && !verdict.fresh ? { ...verdict, reason: `${ADOPTER_WORDS}${verdict.reason}` } : verdict;
    };
    const walked = await evaluateRevocationChain([{ entry: ENTRY, credentialIssuer: issuer.did }], wrapped);
    expect(walked.ok).toBe(false);
    expect(remedyIn(walked.reasons[0]!)).toBe('whole');
  });
});
