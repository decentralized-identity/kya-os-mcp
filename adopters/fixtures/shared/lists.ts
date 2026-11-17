/**
 * Status lists as a publisher writes them: a W3C Bitstring Status List of 131,072 entries, encoded by
 * the library's `BitstringManager` and signed `eddsa-jcs-2022` by `signStatusListCredential`, so
 * `createStatusListProofVerifier` can check it.
 */
import { BitstringManager } from '@kya-os/mcp';
import { DELEGATION_CONTEXT_V2, signStatusListCredential } from '@kya-os/mcp/card';
import type { Party } from './keys.js';

/** Entries per list: 16 KiB of bits, the smallest list W3C Bitstring Status List v1.0 allows. */
export const LIST_ENTRIES = 16 * 1024 * 8;

/** The validity window a list states: its `validFrom` and its `validUntil`, each when it states one. */
export interface ListWindow {
  validFrom?: string;
  validUntil?: string;
}

/**
 * The revocation list at `url`, signed by `signer`, with the bits at `revoked` set, stating `window`:
 * by default, valid from a minute before it is made, with no end.
 */
export async function signedStatusList(
  signer: Party,
  url: string,
  revoked: readonly number[] = [],
  window: ListWindow = { validFrom: new Date(Date.now() - 60 * 1000).toISOString() },
): Promise<Record<string, unknown>> {
  const bits = new BitstringManager(LIST_ENTRIES);
  for (const index of revoked) bits.setBit(index, true);
  return signStatusListCredential(
    {
      '@context': [DELEGATION_CONTEXT_V2],
      id: url,
      type: ['VerifiableCredential', 'BitstringStatusListCredential'],
      issuer: signer.did,
      ...window,
      credentialSubject: {
        id: `${url}#list`,
        type: 'BitstringStatusList',
        statusPurpose: 'revocation',
        encodedList: await bits.encode(),
      },
    },
    signer.signer,
  );
}
