#!/usr/bin/env node
/**
 * Generator for the status-list authority vectors (suite ≥ 1.4.0),
 * `conformance/vectors/status-list-authority.json`: lists read only from the one keeper of the URL
 * a credential's entry names, which is the issuer the verifier binds the URL or its origin to, else
 * the pinned root when its own credential names the URL, else the credential's issuer; the
 * credential's own issuer's list without an `id`, read only when nobody else keeps a URL; entries whose
 * `statusListIndex` is a string of decimal digits or not; entries that state a `statusSize`,
 * read only when it is 1; and, from suite 1.12.0, how a list is written and how many entries it
 * holds (SPEC.md §6.6 and §6.7): a list in a 1.x legacy encoding, an index past 131,071 on a longer
 * list and a list of 16 entries, each read, and an index past a list's end, refused. It runs on its
 * own, so adding a case re-signs this file and no other.
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
  const [issuer, root, service, holder, delegate] = await Promise.all(Array.from({ length: 5 }, () => deps.mintParty()));
  if (!issuer || !root || !service || !holder || !delegate) throw new Error('missing signing parties');
  const url = 'https://status.example.com/authority?version=1';
  const didDocuments = Object.fromEntries([issuer, root, service, delegate].map((p) => [p.did, deps.didDocumentFor(p)]));
  const bits = new BitstringManager(131072, statusListGzipCodec, statusListGzipCodec);
  const encodedList = await bits.encode();
  const entry: CredentialStatus = {
    type: 'BitstringStatusListEntry', id: `${url}#7`, statusPurpose: 'revocation',
    statusListIndex: '7', statusListCredential: url,
  };
  const credential = await deps.signDelegation(issuer, holder.did, 'authority-active', entry);
  async function list(signer: P, statesId = true, encoded = encodedList) {
    const unsigned = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      ...(statesId ? { id: url } : {}),
      type: ['VerifiableCredential', 'BitstringStatusListCredential'],
      issuer: signer.did, validFrom: '2026-01-01T00:00:00.000Z',
      credentialSubject: { id: `${url}#list`, type: 'BitstringStatusList', statusPurpose: 'revocation', encodedList: encoded },
    };
    return { ...unsigned, proof: await signVC(deps.crypto, unsigned, signer.privateKey, signer.kid) };
  }
  function vector(name: string, expected: 'pass' | 'fail', reason: string, input: StatusListInput): ConformanceVector {
    return { id: `status-list/${name}`, category: 'status-list', description: reason, reason, expected, input };
  }
  const common = { credential, didDocuments, serverDid: deps.serverDid };
  /** Another list URL, which the root's own credential names where it does not name `url`. */
  const elsewhere = 'https://status.example.com/authority-root-own';
  const origin = 'https://status.example.com';
  const rootInput = { ...common, trustedRootIssuer: root.did, trustedRootStatusList: url, statusLists: { [url]: await list(root) } };
  const configuredInput = { ...common, statusListIssuers: { [service.did]: [url] }, statusLists: { [url]: await list(service) } };
  const vectors: ConformanceVector[] = [
    vector('pinned-root-list', 'pass', "The pinned root keeps the URL its own credential names, so its exactly identified clear list there is read for a credential that names it too", rootInput),
    vector('root-list-at-issuer-url', 'fail', "The pinned root's own credential names another URL, so this one is the credential issuer's and the root's list there is refused", {
      ...rootInput, trustedRootStatusList: elsewhere,
    }),
    vector('configured-service-list', 'pass', 'A service the verifier binds the exact list URL to signs an exactly identified clear list', configuredInput),
    vector('configured-origin-list', 'pass', "A service the verifier binds the list URL's https origin to signs an exactly identified clear list", {
      ...configuredInput, statusListIssuers: { [service.did]: [origin] },
    }),
    vector('lookalike-origin-list', 'fail', 'An origin binding is matched on the bytes as written, so an origin that is only a prefix of the host binds nothing here', {
      ...configuredInput, statusListIssuers: { [service.did]: [origin.slice(0, -'.com'.length)] },
    }),
    vector('unconfigured-service-list', 'fail', 'The same service keeps no URL when the verifier binds none to it', { ...configuredInput, statusListIssuers: {} }),
    vector('service-list-at-unbound-url', 'fail', 'A service the verifier binds another URL to keeps that URL alone, so its list is refused here', {
      ...configuredInput, statusListIssuers: { [service.did]: [elsewhere] },
    }),
    vector('issuer-list-at-bound-url', 'fail', "At a URL the verifier binds to a service, the credential's own issuer's list is refused as any other is", {
      ...configuredInput, statusLists: { [url]: await list(issuer) },
    }),
    vector('configured-over-root-list', 'fail', "Where the verifier binds a URL to a service and the pinned root's credential names it too, the binding decides and the root's list is refused", {
      ...rootInput, statusListIssuers: { [service.did]: [url] },
    }),
    vector('owner-root-alias-no-id', 'pass', 'A signer identical to the credential issuer retains the own-issuer id exemption even when also named as root', {
      ...common, trustedRootIssuer: issuer.did, statusLists: { [url]: await list(issuer, false) },
    }),
    vector('pinned-root-own-no-id', 'pass', "A pinned root is the issuer of its own credential, so its list without an id is read for that credential at the URL the credential names", {
      ...common, trustedRootIssuer: issuer.did, trustedRootStatusList: url, statusLists: { [url]: await list(issuer, false) },
    }),
    vector('pinned-root-no-id-for-delegate', 'fail', "The same list is refused for a delegate's credential whose entry names that URL: the root keeps it, and only a credential's own issuer may leave out an id", {
      ...common,
      credential: await deps.signDelegation(delegate, holder.did, 'authority-delegate', entry),
      trustedRootIssuer: issuer.did, trustedRootStatusList: url, statusLists: { [url]: await list(issuer, false) },
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
  // Entry 7 of two bits keeps its value at bits 14 and 15, which this list sets; bit 7, which it
  // leaves clear, is entry 3's. A reader of one bit per entry would pass the entry on bit 7.
  bits.setBit(14, true);
  bits.setBit(15, true);
  const valueSetList = await list(issuer, true, await bits.encode());
  const statusMessage = ['valid', 'revoked', 'revoked', 'revoked'].map((message, value) => ({ status: `0x${value}`, message }));
  const sizes: ReadonlyArray<readonly [string, 'pass' | 'fail', string, Record<string, unknown>, typeof ownList]> = [
    ['two-bits', 'fail', "An entry of two bits is not read from the bit at its index, which is another entry's", { statusSize: 2, statusMessage }, valueSetList],
    ['zero', 'fail', 'A signed entry must state a statusSize that is an integer greater than zero, or none', { statusSize: 0 }, ownList],
    ['one', 'pass', 'An entry that states a statusSize of 1, the size of an entry that states none, is read from the bit at its index', { statusSize: 1 }, valueSetList],
  ];
  for (const [name, expected, reason, members, served] of sizes) {
    vectors.push(vector(`status-size-${name}`, expected, reason, {
      ...common,
      credential: await deps.signDelegation(issuer, holder.did, `authority-status-size-${name}`, { ...entry, ...members }),
      statusLists: { [url]: served },
    }));
  }
  /**
   * How a list is written and how many entries it holds (SPEC.md §6.6 and §6.7, suite >= 1.12.0).
   * Each list is the credential issuer's own, states its URL as its `id` and verifies, so only its
   * encoding, its length or the entry's index decides.
   */
  const encodingAndLengthVectors = async (): Promise<ConformanceVector[]> => {
    const encodedOf = (size: number, set: number[] = []) =>
      BitstringManager.fromSetBits(size, set, statusListGzipCodec, statusListGzipCodec).encode();
    // The clear list of 262,144 entries is the one whose GZIP, in the base64 alphabet, has a `+`, a `/` and padding.
    const legacy = Buffer.from((await encodedOf(262144)).slice(1), 'base64url').toString('base64');
    if (!/[+/]/.test(legacy) || !legacy.endsWith('=')) {
      throw new Error('the legacy encodedList has no character of the base64 alphabet alone, or no padding');
    }
    const unsigned2021 = {
      '@context': ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/vc/status-list/2021/v1'],
      id: url, type: ['VerifiableCredential', 'StatusList2021Credential'], issuer: issuer.did,
      issuanceDate: '2026-01-01T00:00:00.000Z',
      credentialSubject: { id: `${url}#list`, type: 'StatusList2021', statusPurpose: 'revocation', encodedList: legacy },
    };
    const legacyList = { ...unsigned2021, proof: await signVC(deps.crypto, unsigned2021, issuer.privateKey, issuer.kid) };
    const at = (name: string, index: number) => deps.signDelegation(issuer, holder.did, `authority-${name}`, {
      ...entry, id: `${url}#${index}`, statusListIndex: String(index),
    });
    return [
      vector('legacy-encoding-2021', 'pass', 'A StatusList2021 list whose encodedList is base64 in the base64 alphabet, padded, with no multibase prefix, as Status List v2021 lets a publisher write it, is read during 1.x', {
        ...common,
        credential: await deps.signDelegation(issuer, holder.did, 'authority-legacy-encoding-2021', { ...entry, type: 'StatusList2021Entry' }),
        statusLists: { [url]: legacyList },
      }),
      // Bit 0 is set, so a reader that takes the index modulo 131,072 reads the credential as revoked.
      vector('index-past-minimum', 'pass', 'An index past 131,071 names an entry of a list of 262,144 entries, and its clear bit is read', {
        ...common, credential: await at('index-past-minimum', 131072), statusLists: { [url]: await list(issuer, true, await encodedOf(262144, [0])) },
      }),
      vector('index-past-end', 'fail', 'The same index on a list of 131,072 entries names no entry the list has, so the credential is refused', {
        ...common, credential: await at('index-past-end', 131072), statusLists: { [url]: ownList },
      }),
      vector('short-list', 'pass', 'During 1.x a reader does not refuse a list of fewer than 131,072 entries: this one has 16, and the bit at index 7 is clear', {
        ...common, statusLists: { [url]: await list(issuer, true, await encodedOf(16)) },
      }),
    ];
  };
  vectors.push(...(await encodingAndLengthVectors()));
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
