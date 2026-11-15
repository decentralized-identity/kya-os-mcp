/**
 * The card's status-list reader, `createRevocationChecker` given `createStatusListProofVerifier`,
 * reads a list only when both rules hold: the list's issuer is one the checker accepts for the
 * credential (`acceptStatusList`), and the list's proof verifies with a key that issuer's DID
 * document lists under `assertionMethod` (SPEC.md §6.2). The credential's issuer, Acme, keeps
 * `#login-1` under `authentication` and `#key-1` under `assertionMethod`; a status service keeps
 * its own `#key-1` under its own `assertionMethod`. Every list states its URL as its `id` and has the
 * entry's bit clear, so a list that is read reports the credential active and live, and one that is
 * refused reports it revoked and not live.
 */
import { describe, it, expect, vi } from 'vitest';
import { createRevocationChecker, type StatusListIssuers } from '../revocation.js';
import { createStatusListProofVerifier } from '../status-list-proof.js';
import { ACME, acmeDocument, issuerDidDocument, methodOf } from '../../__tests__/utils/did-documents.js';
import { identity, NOW_MS, published, serve, STATUS_URL, statusList, type TestIdentity } from './signed-chain-helpers.js';
import type { DIDDocument } from '../../delegation/vc-verifier.types.js';

const SERVICE = 'did:web:status-service.example';
/** A fresh key of `did`, published as `#<fragment>`, as the shared DID document helpers take one. */
const webKey = (did: string, fragment: string) => published({ ...identity(), did, method: `${did}#${fragment}` });
const login = webKey(ACME, 'login-1');
const assert = webKey(ACME, 'key-1');
const service = webKey(SERVICE, 'key-1');

const documents: Record<string, DIDDocument> = {
  [ACME]: acmeDocument(login, assert),
  [SERVICE]: issuerDidDocument(methodOf(service)),
};

const READ = { revoked: false, fresh: true };
const REFUSED = { revoked: true, fresh: false, reason: expect.any(String) as string };

/** Check Acme's credential's clear entry against the list `signer` signed, recording the proof verdicts. */
async function check(signer: TestIdentity, statusListIssuers?: StatusListIssuers) {
  const verifyProof = createStatusListProofVerifier({ didResolver: { resolve: async (did) => documents[did] ?? null } });
  const verifyStatusList = vi.fn(verifyProof);
  const checker = createRevocationChecker({
    fetch: serve(statusList(signer, [])),
    now: () => NOW_MS,
    verifyStatusList,
    ...(statusListIssuers ? { statusListIssuers } : {}),
  });
  const verdict = await checker({ statusListCredential: STATUS_URL, statusListIndex: '5' }, { credentialIssuer: ACME });
  return { verdict, proofVerdicts: await Promise.all(verifyStatusList.mock.results.map((result) => result.value)) };
}

describe("the card's status-list reader holds a list to a trusted issuer and to that issuer's assertionMethod key", () => {
  it("refuses the credential issuer's list signed with a key it lists only under authentication", async () => {
    // The list's issuer is trusted, so the proof is checked, and it fails.
    expect(await check(login)).toEqual({ verdict: REFUSED, proofVerdicts: [false] });
  });

  it('refuses a list signed with an assertionMethod key of an issuer not trusted for the credential', async () => {
    // Refused before its proof is checked; binding the list's URL to that issuer reads it.
    expect(await check(service)).toEqual({ verdict: REFUSED, proofVerdicts: [] });
    expect(await check(service, { [SERVICE]: [STATUS_URL] })).toEqual({ verdict: READ, proofVerdicts: [true] });
  });

  it("reads the credential issuer's list signed with the key it lists under assertionMethod", async () => {
    expect(await check(assert)).toEqual({ verdict: READ, proofVerdicts: [true] });
  });
});
