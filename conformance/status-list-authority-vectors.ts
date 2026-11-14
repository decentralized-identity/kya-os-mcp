#!/usr/bin/env node
/**
 * Generator for the status-list authority vectors (suite ≥ 1.4.0),
 * `conformance/vectors/status-list-authority.json`: lists signed by an issuer other than the
 * credential's, read only when the verifier accepts that issuer for the credential; the credential's
 * own issuer's list without an `id`, read only when no other issuer is accepted; and entries whose
 * `statusListIndex` is a string of decimal digits or not. It runs on its own, so adding a case
 * re-signs this file and no other.
 *
 * It mints parties and signs delegations as `generate-vectors.ts` does, with fresh keys on every
 * run, so its output must never be committed over an existing suiteVersion.
 *
 *   run:  tsx conformance/status-list-authority-vectors.ts   (npm run conformance:generate:status-authority)
 */
import { pathToFileURL } from 'node:url';
import { BitstringManager, statusListGzipCodec, type CredentialStatus } from '../src/index.js';
import { signVC } from './crypto-kit.js';
import { statusListVectorDeps } from './generate-vectors.js';
import { SUITE_VERSION, writeVectorFile } from './vector-files.js';
import type { Signer } from './status-list-binding-vectors.js';
import type { StatusListVectorDeps } from './status-list-vectors.js';
import type { ConformanceVector, StatusListInput, VectorFile } from './types.js';

export async function statusListAuthorityVectors<P extends Signer>(deps: StatusListVectorDeps<P>): Promise<VectorFile> {
  const [issuer, root, service, holder] = await Promise.all(Array.from({ length: 4 }, () => deps.mintParty()));
  if (!issuer || !root || !service || !holder) throw new Error('missing signing parties');
  const url = 'https://status.example.com/authority?version=1';
  const didDocuments = Object.fromEntries([issuer, root, service].map((p) => [p.did, deps.didDocumentFor(p)]));
  const bits = new BitstringManager(131072, statusListGzipCodec, statusListGzipCodec);
  const encodedList = await bits.encode();
  const entry: CredentialStatus = {
    type: 'BitstringStatusListEntry', id: `${url}#7`, statusPurpose: 'revocation',
    statusListIndex: '7', statusListCredential: url,
  };
  const credential = await deps.signDelegation(issuer, holder.did, 'authority-active', entry);
  async function list(signer: P, statesId = true) {
    const unsigned = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      ...(statesId ? { id: url } : {}),
      type: ['VerifiableCredential', 'BitstringStatusListCredential'],
      issuer: signer.did, validFrom: '2026-01-01T00:00:00.000Z',
      credentialSubject: { id: `${url}#list`, type: 'BitstringStatusList', statusPurpose: 'revocation', encodedList },
    };
    return { ...unsigned, proof: await signVC(deps.crypto, unsigned, signer.privateKey, signer.kid) };
  }
  function vector(name: string, expected: 'pass' | 'fail', reason: string, input: StatusListInput): ConformanceVector {
    return { id: `status-list/${name}`, category: 'status-list', description: reason, reason, expected, input };
  }
  const common = { credential, didDocuments, serverDid: deps.serverDid };
  const rootInput = { ...common, trustedRootIssuer: root.did, statusLists: { [url]: await list(root) } };
  const configuredInput = { ...common, statusListIssuers: { [issuer.did]: [service.did] }, statusLists: { [url]: await list(service) } };
  const vectors: ConformanceVector[] = [
    vector('pinned-root-list', 'pass', 'An authorized per-credential root signs an exactly identified clear list', rootInput),
    vector('configured-service-list', 'pass', 'A service configured for this credential issuer signs an exactly identified clear list', configuredInput),
    vector('unconfigured-service-list', 'fail', 'The same service has no authority without a mapping for this issuer', { ...configuredInput, statusListIssuers: {} }),
    vector('wrong-direction-service-map', 'fail', 'Mapping the service to the issuer does not authorize the service for the issuer', {
      ...configuredInput, statusListIssuers: { [service.did]: [issuer.did] },
    }),
    vector('owner-root-alias-no-id', 'pass', 'A signer identical to the credential issuer retains the own-issuer id exemption even when also named as root', {
      ...common, trustedRootIssuer: issuer.did, statusLists: { [url]: await list(issuer, false) },
    }),
    vector('owner-no-id-at-pinned-root-url', 'fail', "With another root pinned, the credential issuer's list without an id cannot stand in for the root's list at the root's URL", {
      ...rootInput, statusLists: { [url]: await list(issuer, false) },
    }),
  ];
  const ownList = await list(issuer);
  // An issuer signs whatever JSON it writes, so a signed index may be a number, though CredentialStatus types it as a string.
  const indexes: ReadonlyArray<readonly [string, unknown]> = [['suffix', '7junk'], ['fraction', '7.5'], ['space', ' 7'], ['number', 7]];
  for (const [name, index] of indexes) {
    vectors.push(vector(`index-${name}`, 'fail', 'A signed entry must name a whole decimal index without coercion or truncation', {
      ...common,
      credential: await deps.signDelegation(issuer, holder.did, `authority-index-${name}`, { ...entry, statusListIndex: index as string }),
      statusLists: { [url]: ownList },
    }));
  }
  // More digits than Python's int() takes from a string by default (4,300), all but the last a zero.
  vectors.push(vector('index-leading-zeros', 'pass', 'A decimal index may open with zeros, however many, and names the bit its value names', {
    ...common,
    credential: await deps.signDelegation(issuer, holder.did, 'authority-index-leading-zeros', { ...entry, statusListIndex: `${'0'.repeat(4300)}7` }),
    statusLists: { [url]: ownList },
  }));
  return { version: SUITE_VERSION, category: 'status-list', vectors };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  statusListAuthorityVectors(statusListVectorDeps)
    .then((file) => writeVectorFile(file, 'status-list-authority.json'))
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
}
