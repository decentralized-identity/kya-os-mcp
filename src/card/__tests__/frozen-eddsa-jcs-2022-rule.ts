/**
 * The check 1.25.0 made of an `eddsa-jcs-2022` proof once it held the issuer's key, copied from
 * `src/card/data-integrity.ts` at that release (the end of `verifyEddsaJcs2022`, `hashData`,
 * `contexts` and `startsWith`) with only the signature decoded here, so a test can show which proofs
 * a 1.25.0 verifier accepts. 1.20.0 to 1.24.0 build the same proof configuration and document
 * (`src/card/status-list-proof.ts` before 1.22.0). It is frozen: never change it to match the
 * library.
 */

import { base58Decode } from '../../utils/base58.js';
import { canonicalizeJson, canonicalizeJsonBytes } from '../../utils/canonical-json.js';
import { ed25519VerifyRaw, sha256, type RawSigningJwk } from '../proof/canonical.js';

/** Whether a verifier of 1.25.0 accepts `document`'s proof under `jwk`. */
export async function verifiesAs1250(document: Record<string, unknown>, jwk: RawSigningJwk): Promise<boolean> {
  const proof = document.proof as Record<string, unknown>;
  const signature = base58Decode(String(proof.proofValue).slice(1));

  const unsecured: Record<string, unknown> = { ...document };
  delete unsecured.proof;
  const options: Record<string, unknown> = { ...proof };
  delete options.proofValue;
  if (options['@context'] !== undefined) {
    // The proof may name its own @context only as a prefix of the document's.
    if (!startsWith(contexts(document['@context']), contexts(options['@context']))) return false;
    unsecured['@context'] = options['@context'];
  }
  if (unsecured['@context'] !== undefined) options['@context'] = unsecured['@context'];

  return ed25519VerifyRaw(jwk, signature, await hashData(options, unsecured));
}

/** The cryptosuite's hash data: SHA-256 of the canonical proof options, then of the canonical document. */
async function hashData(options: Record<string, unknown>, unsecured: Record<string, unknown>): Promise<Uint8Array> {
  const proofHash = await sha256(canonicalizeJsonBytes(options));
  const documentHash = await sha256(canonicalizeJsonBytes(unsecured));
  const data = new Uint8Array(proofHash.length + documentHash.length);
  data.set(proofHash, 0);
  data.set(documentHash, proofHash.length);
  return data;
}

function contexts(value: unknown): unknown[] {
  return Array.isArray(value) ? value : value === undefined ? [] : [value];
}

function startsWith(whole: unknown[], prefix: unknown[]): boolean {
  return prefix.length <= whole.length && prefix.every((entry, i) => canonicalizeJson(entry) === canonicalizeJson(whole[i]));
}
