/**
 * Issuers set up the way adopters set them up, over the package's public exports: a did:web party
 * whose DID document `buildDidWebDocument` builds and whose status lists `signStatusListCredential`
 * signs, a resolver that answers those documents, and a SafeFetch that serves those lists from
 * memory. Delegation credentials are signed with the party's `key` through the shared helpers.
 */

import { gzipSync } from 'node:zlib';
import { buildDidWebDocument, type AgentIdentity, type DIDDocument, type DIDResolver } from '../../index.js';
import { ed25519SignerFromJwk, signStatusListCredential, type ProofSigner, type SafeFetch } from '../../card/index.js';
import { keyOf } from './delegation-credentials.js';

/** A did:web party: its DID, its Ed25519 key `<did>#key-1`, its DID document, and a signer for its lists. */
export interface WebParty {
  readonly did: string;
  readonly key: AgentIdentity;
  readonly document: DIDDocument;
  readonly signer: ProofSigner;
}

/** A fresh did:web party for `did`. */
export async function webParty(did: string): Promise<WebParty> {
  const key = await keyOf(did, 'key-1');
  const base64url = (base64: string): string => Buffer.from(base64, 'base64').toString('base64url');
  const signer = await ed25519SignerFromJwk({
    did,
    kid: key.kid,
    privateJwk: { kty: 'OKP', crv: 'Ed25519', x: base64url(key.publicKey), d: base64url(key.privateKey) },
  });
  return { did, key, document: buildDidWebDocument(key), signer };
}

/** A DID resolver that answers each party's document, and nothing for any other DID. */
export function documentsOf(...parties: readonly WebParty[]): DIDResolver {
  return { resolve: async (did) => parties.find((party) => party.did === did)?.document ?? null };
}

/**
 * A Bitstring Status List for revocation at `url`, issued and signed by `signer`, stating `url` as
 * its `id`, with each index in `revoked` set: 16 KiB, most significant bit first, gzip-compressed.
 */
export function signedStatusList(
  signer: WebParty,
  url: string,
  revoked: readonly number[] = [],
): Promise<Record<string, unknown>> {
  const bits = new Uint8Array(16 * 1024);
  for (const index of revoked) bits[index >>> 3] = (bits[index >>> 3] ?? 0) | (0x80 >> (index & 7));
  return signStatusListCredential(
    {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: url,
      type: ['VerifiableCredential', 'BitstringStatusListCredential'],
      issuer: signer.did,
      validFrom: '2026-01-01T00:00:00Z',
      credentialSubject: {
        id: `${url}#list`,
        type: 'BitstringStatusList',
        statusPurpose: 'revocation',
        encodedList: `u${gzipSync(bits).toString('base64url')}`,
      },
    },
    signer.signer,
  );
}

/** A SafeFetch that answers each body at its URL, and 404 for any other URL. */
export function servingFromMemory(bodies: Readonly<Record<string, unknown>>): SafeFetch {
  return async (url) => {
    const served = Object.prototype.hasOwnProperty.call(bodies, url);
    const body = served ? bodies[url] : undefined;
    return { ok: served, status: served ? 200 : 404, json: async () => body };
  };
}
