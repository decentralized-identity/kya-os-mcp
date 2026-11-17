#!/usr/bin/env node
/**
 * Generator for the status-list validity vectors (suite ≥ 1.7.0),
 * `conformance/vectors/status-list-validity.json`: a list is read only inside the validity window it
 * states (SPEC.md §6.6), its `validFrom` and `validUntil`, or with neither its `issuanceDate` and
 * `expirationDate`. Each list is the credential issuer's own, states its URL as its `id`, has the
 * credential's bit clear and is signed by the issuer, so the window alone decides: a list past its
 * end, before its start or stating a bound that is not a date is refused, and one inside its window,
 * or stating no end, is read. A date is an RFC 3339 date-time with its zone (suite >= 1.10.0): a
 * bound with no zone, or in a form `Date.parse` reads but RFC 3339 does not write, is refused, and one
 * at an offset from UTC is read. It runs on its own, so adding a case re-signs this file and no other.
 *
 * It mints parties and signs delegations as `generate-vectors.ts` does, with fresh keys on every
 * run, so its output must never be committed over an existing suiteVersion. Every window is fixed,
 * in the past or in the year 2999, so a vector decides alike whenever it is run before then, and
 * alike with or without the clock tolerance SPEC.md §6.6 permits.
 *
 *   run:  tsx conformance/status-list-validity-vectors.ts   (npm run conformance:generate:status-validity)
 */
import { pathToFileURL } from 'node:url';
import { BitstringManager, statusListGzipCodec, type CredentialStatus } from '../src/index.js';
import { signVC } from './crypto-kit.js';
import { statusListVectorDeps } from './generate-vectors.js';
import { SUITE_VERSION, writeVectorFile } from './vector-files.js';
import type { Signer } from './status-list-binding-vectors.js';
import type { StatusListVectorDeps } from './status-list-vectors.js';
import type { ConformanceVector, VectorFile } from './types.js';

const PAST = '2026-02-01T00:00:00.000Z';
const LONG_AGO = '2026-01-01T00:00:00.000Z';
const FAR_AHEAD = '2999-01-01T00:00:00.000Z';

/** One case: the vector's name, its outcome, why, the list's form and the window it states. */
type WindowCase = readonly [name: string, expected: 'pass' | 'fail', reason: string, form: 'bitstring' | 'statuslist2021', window: Record<string, unknown>];

const CASES: readonly WindowCase[] = [
  ['in-window-list', 'pass', 'A clear list inside the window it states is read', 'bitstring', { validFrom: LONG_AGO, validUntil: FAR_AHEAD }],
  ['in-window-list-2021', 'pass', 'A clear StatusList2021 list inside its issuanceDate and expirationDate is read', 'statuslist2021', { issuanceDate: LONG_AGO, expirationDate: FAR_AHEAD }],
  ['expired-list', 'fail', "A clear list past its validUntil says nothing of now: it may be an earlier version, signed before the credential was revoked", 'bitstring', { validFrom: LONG_AGO, validUntil: PAST }],
  ['expired-list-2021', 'fail', 'A clear StatusList2021 list past its expirationDate is refused as a list past its validUntil is', 'statuslist2021', { issuanceDate: LONG_AGO, expirationDate: PAST }],
  ['not-yet-valid-list', 'fail', 'A clear list before its validFrom does not yet speak for the credential', 'bitstring', { validFrom: FAR_AHEAD }],
  ['not-yet-valid-list-2021', 'fail', 'A clear StatusList2021 list before its issuanceDate is refused as a list before its validFrom is', 'statuslist2021', { issuanceDate: FAR_AHEAD }],
  ['undated-end-list', 'fail', 'A clear list whose validUntil is not a date has a window no verifier can read, so it is refused', 'bitstring', { validFrom: LONG_AGO, validUntil: 'not a date' }],
  ['current-member-decides', 'fail', 'A list that states both validUntil and expirationDate is read by its validUntil, here past, whatever its expirationDate', 'bitstring', { validFrom: LONG_AGO, validUntil: PAST, expirationDate: FAR_AHEAD }],
  ['zoneless-start-list', 'fail', 'A list whose validFrom states no time zone names no single instant, since each verifier would read it in its own zone, so it is refused', 'bitstring', { validFrom: '2026-01-01T00:00:00', validUntil: FAR_AHEAD }],
  ['zoneless-end-list-2021', 'fail', 'A StatusList2021 list whose expirationDate states no time zone is refused, though VC 1.1 lets a dateTime leave its zone out', 'statuslist2021', { issuanceDate: LONG_AGO, expirationDate: '2999-01-01T00:00:00' }],
  ['http-date-end-list', 'fail', 'A list whose validUntil is an HTTP date, which is not an RFC 3339 date-time, is refused', 'bitstring', { validFrom: LONG_AGO, validUntil: 'Tue, 01 Jan 2999 00:00:00 GMT' }],
  ['offset-window-list', 'pass', 'A clear list whose bounds are RFC 3339 date-times at offsets from UTC, one with nine digits of a second, is read', 'bitstring', { validFrom: '2026-01-01T05:30:00.123456789+05:30', validUntil: '2998-12-31T18:00:00-06:00' }],
];

export async function statusListValidityVectors<P extends Signer>(deps: StatusListVectorDeps<P>): Promise<VectorFile> {
  const [issuer, holder] = await Promise.all([deps.mintParty(), deps.mintParty()]);
  if (!issuer || !holder) throw new Error('missing signing parties');
  const didDocuments = { [issuer.did]: deps.didDocumentFor(issuer) };
  const encodedList = await new BitstringManager(131072, statusListGzipCodec, statusListGzipCodec).encode();

  /** The issuer's clear list at `url` in `form`, stating `window`, signed by the issuer. */
  async function list(url: string, form: WindowCase[3], window: Record<string, unknown>) {
    const unsigned = form === 'bitstring'
      ? {
          '@context': ['https://www.w3.org/ns/credentials/v2'], id: url,
          type: ['VerifiableCredential', 'BitstringStatusListCredential'], issuer: issuer.did, ...window,
          credentialSubject: { id: `${url}#list`, type: 'BitstringStatusList', statusPurpose: 'revocation', encodedList },
        }
      : {
          '@context': ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/vc/status-list/2021/v1'], id: url,
          type: ['VerifiableCredential', 'StatusList2021Credential'], issuer: issuer.did, ...window,
          credentialSubject: { id: `${url}#list`, type: 'StatusList2021', statusPurpose: 'revocation', encodedList },
        };
    return { ...unsigned, proof: await signVC(deps.crypto, unsigned, issuer.privateKey, issuer.kid) };
  }

  const vectors: ConformanceVector[] = [];
  for (const [name, expected, reason, form, window] of CASES) {
    const url = `https://status.example.com/validity/${name}`;
    const entry: CredentialStatus = {
      id: `${url}#7`, type: form === 'bitstring' ? 'BitstringStatusListEntry' : 'StatusList2021Entry',
      statusPurpose: 'revocation', statusListIndex: '7', statusListCredential: url,
    };
    vectors.push({
      id: `status-list/${name}`, category: 'status-list', description: reason, reason, expected,
      input: {
        credential: await deps.signDelegation(issuer, holder.did, `validity-${name}`, entry),
        statusLists: { [url]: await list(url, form, window) },
        didDocuments, serverDid: deps.serverDid,
      },
    });
  }
  return { version: SUITE_VERSION, category: 'status-list', vectors };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  statusListValidityVectors(statusListVectorDeps)
    .then((file) => writeVectorFile(file, 'status-list-validity.json'))
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
}
