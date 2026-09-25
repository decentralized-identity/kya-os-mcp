/**
 * The Responsible Party's revocation list: a W3C StatusList2021 credential,
 * signed with the RP's did:web key, hosted by the RP's own hub.
 *
 * Every mutation (revoke / restore) re-signs the whole list and appends a
 * version to var/rp/status-list-history/. The hub serves the latest version
 * at STATUS_LIST_URL with `Cache-Control: no-store`; the merchant fetches and
 * verifies it on every call. Where you HOST the list is policy (your domain, a
 * registry, a ledger — the REVOKED demo anchored the same signed document on
 * cheqd); the protocol only needs a URL and a signature.
 */
import path from 'node:path';
import fs from 'node:fs';
import {
  BitstringManager,
  base64urlDecodeToBytes,
  canonicalizeJSON,
  type StatusList2021Credential,
  type VCSigningFunction,
} from '@kya-os/mcp';
import {
  VAR_DIR,
  cryptoProvider,
  gzipCompressor,
  gzipDecompressor,
  readJson,
  writeJson,
  type KeyedIdentity,
} from '../lib/wiring.js';

export const STATUS_LIST_SIZE = 131072; // W3C minimum-recommended herd size

export const RP_DIR = path.join(VAR_DIR, 'rp');
export const STATUS_LIST_FILE = path.join(RP_DIR, 'status-list.json');
export const STATUS_LIST_HISTORY_DIR = path.join(RP_DIR, 'status-list-history');
export const STATUS_LIST_META_FILE = path.join(RP_DIR, 'status-list-meta.json');

export interface StatusListMeta {
  version: number;
  updatedAt: string;
  lastAction?: { action: 'revoke' | 'restore'; index: number; at: string };
}

export async function buildInitialStatusList(options: {
  identity: KeyedIdentity;
  signingFunction: VCSigningFunction;
  url: string;
  purpose?: 'revocation' | 'suspension';
  size?: number;
}): Promise<StatusList2021Credential> {
  const { identity, signingFunction, url } = options;
  const purpose = options.purpose ?? 'revocation';
  const manager = new BitstringManager(options.size ?? STATUS_LIST_SIZE, gzipCompressor, gzipDecompressor);
  const encodedList = await manager.encode();
  const unsigned = {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      'https://w3id.org/vc/status-list/2021/v1',
    ] as (string | Record<string, unknown>)[],
    id: url,
    type: ['VerifiableCredential', 'StatusList2021Credential'],
    issuer: identity.did,
    issuanceDate: new Date().toISOString(),
    credentialSubject: {
      id: `${url}#list`,
      type: 'StatusList2021' as const,
      statusPurpose: purpose,
      encodedList,
    },
  };
  const proof = await signingFunction(canonicalizeJSON(unsigned), identity.did, identity.kid);
  return { ...unsigned, proof: proof as Record<string, unknown> };
}

/** Flip one bit and re-sign — the entire content of a revocation. */
export async function resignWithBit(options: {
  credential: StatusList2021Credential;
  index: number;
  revoked: boolean;
  identity: KeyedIdentity;
  signingFunction: VCSigningFunction;
}): Promise<StatusList2021Credential> {
  const { credential, index, revoked, identity, signingFunction } = options;
  const bits = await BitstringManager.decode(credential.credentialSubject.encodedList, gzipCompressor, gzipDecompressor);
  bits.setBit(index, revoked);
  const encodedList = await bits.encode();
  const unsigned: Record<string, unknown> = {
    ...credential,
    issuanceDate: new Date().toISOString(),
    credentialSubject: { ...credential.credentialSubject, encodedList },
  };
  delete unsigned['proof'];
  const proof = await signingFunction(canonicalizeJSON(unsigned), identity.did, identity.kid);
  return { ...(unsigned as unknown as StatusList2021Credential), proof: proof as Record<string, unknown> };
}

export async function readBit(credential: StatusList2021Credential, index: number): Promise<boolean> {
  const bits = await BitstringManager.decode(credential.credentialSubject.encodedList, gzipCompressor, gzipDecompressor);
  return bits.getBit(index);
}

// ---------------------------------------------------------------------------
// Persistence (the hub's storage)
// ---------------------------------------------------------------------------

export function loadStatusList(): StatusList2021Credential | null {
  return readJson<StatusList2021Credential>(STATUS_LIST_FILE);
}

export function loadStatusListMeta(): StatusListMeta {
  return readJson<StatusListMeta>(STATUS_LIST_META_FILE) ?? { version: 0, updatedAt: '' };
}

/** Persist a new version: latest pointer + append-only history entry. */
export function saveStatusListVersion(
  credential: StatusList2021Credential,
  action?: StatusListMeta['lastAction'],
): StatusListMeta {
  const meta = loadStatusListMeta();
  const next: StatusListMeta = {
    version: meta.version + 1,
    updatedAt: new Date().toISOString(),
    ...(action ? { lastAction: action } : {}),
  };
  fs.mkdirSync(STATUS_LIST_HISTORY_DIR, { recursive: true });
  writeJson(path.join(STATUS_LIST_HISTORY_DIR, `v${String(next.version).padStart(4, '0')}.json`), credential);
  writeJson(STATUS_LIST_FILE, credential);
  writeJson(STATUS_LIST_META_FILE, next);
  return next;
}

export async function ensureStatusList(options: {
  identity: KeyedIdentity;
  signingFunction: VCSigningFunction;
  url: string;
}): Promise<StatusList2021Credential> {
  for (;;) {
    const existing = loadStatusList();
    const snapshot = JSON.stringify(existing);
    const existingIssuer = existing ? (typeof existing.issuer === 'string' ? existing.issuer : existing.issuer.id) : null;
    let currentSignature = false;
    if (existing && existing.id === options.url && existingIssuer === options.identity.did) {
      const { proof, ...unsigned } = existing;
      const value = proof as Record<string, unknown> | undefined;
      if (value?.['verificationMethod'] === options.identity.kid && typeof value['proofValue'] === 'string') {
        try {
          currentSignature = await cryptoProvider.verify(new TextEncoder().encode(canonicalizeJSON(unsigned)),
            base64urlDecodeToBytes(value['proofValue']), options.identity.publicKeyBase64);
        } catch { /* A retained list signed by the previous key needs re-signing. */ }
      }
    }
    if (currentSignature) {
      if (JSON.stringify(loadStatusList()) !== snapshot) continue;
      return existing!;
    }
    let fresh: StatusList2021Credential;
    if (existing) {
      // Key or URL changes must never restore previously revoked authority.
      // Validate the retained bitstring and re-sign it without changing a bit.
      await BitstringManager.decode(existing.credentialSubject.encodedList, gzipCompressor, gzipDecompressor);
      const { proof: _oldProof, ...unsigned } = existing;
      const updated = { ...unsigned, id: options.url, issuer: options.identity.did, issuanceDate: new Date().toISOString(),
        credentialSubject: { ...unsigned.credentialSubject, id: `${options.url}#list` } };
      const proof = await options.signingFunction(canonicalizeJSON(updated), options.identity.did, options.identity.kid);
      fresh = { ...updated, proof: proof as Record<string, unknown> };
    } else fresh = await buildInitialStatusList(options);
    // Signing yields. If revocation published meanwhile, retry from that
    // newer list instead of overwriting its bits with this older snapshot.
    if (JSON.stringify(loadStatusList()) !== snapshot) continue;
    saveStatusListVersion(fresh, loadStatusListMeta().lastAction);
    return fresh;
  }
}
