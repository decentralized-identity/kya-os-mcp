/**
 * Tiny JSON persistence for the Responsible Party's registered FIDO2
 * authenticators (any number: a security key, a conference badge, a platform
 * passkey) + the hardware-attested revocation records. Anchored to the
 * example's .data/ (gitignored).
 */
import fs from 'node:fs';
import path from 'node:path';
import { writeJsonAtomic } from '../../lib/atomic-json.js';
import { DATA_DIR } from '../../lib/wiring.js';

const AUTHENTICATORS_FILE = path.join(DATA_DIR, 'authenticators.json');
const RECORDS_DIR = path.join(DATA_DIR, 'revocation-records');

export interface StoredAuthenticator {
  id: string; // base64url credential id
  publicKey: string; // base64url COSE public key
  counter: number;
  transports?: string[];
  aaguid?: string;
  label: string; // "DEF CON badge", "YubiKey", "Touch ID"…
  registeredAt: string;
  /** Opaque RP account reference, set only after authenticated registration. */
  accountId?: string;
}

export function listAuthenticators(): StoredAuthenticator[] {
  let raw: string;
  try {
    raw = fs.readFileSync(AUTHENTICATORS_FILE, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw new Error('Registered authenticator store cannot be read.');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    throw new Error('Registered authenticator store is malformed.');
  }
  if (
    !Array.isArray(parsed) ||
    parsed.some(
      (value) =>
        !value ||
        typeof value !== 'object' ||
        typeof value.id !== 'string' ||
        !value.id ||
        typeof value.publicKey !== 'string' ||
        !value.publicKey ||
        !Number.isInteger(value.counter) ||
        value.counter < 0 ||
        typeof value.label !== 'string' ||
        typeof value.registeredAt !== 'string' ||
        (value.accountId !== undefined &&
          (typeof value.accountId !== 'string' || !value.accountId)),
    )
  ) {
    throw new Error(
      'Authenticator store is invalid. Issuance requires repair of the registered-key store.',
    );
  }
  return parsed as StoredAuthenticator[];
}

export function hasAuthenticator(): boolean {
  return listAuthenticators().length > 0;
}

export function findAuthenticator(id: string): StoredAuthenticator | undefined {
  return listAuthenticators().find((a) => a.id === id);
}

function persist(list: StoredAuthenticator[]): void {
  writeJsonAtomic(AUTHENTICATORS_FILE, list);
}

export function saveAuthenticator(cred: StoredAuthenticator): void {
  const list = listAuthenticators().filter((a) => a.id !== cred.id);
  list.push(cred);
  persist(list);
}

export function removeAuthenticator(id: string): void {
  persist(listAuthenticators().filter((a) => a.id !== id));
}

export function updateCounter(id: string, counter: number): void {
  const list = listAuthenticators();
  const cred = list.find((a) => a.id === id);
  if (!cred) return;
  cred.counter = counter;
  persist(list);
}

/** The audit artifact shown on screen and kept next to the status-list version. */
export function writeRevocationRecord(record: Record<string, unknown>): string {
  fs.mkdirSync(RECORDS_DIR, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const file = path.join(RECORDS_DIR, `revocation-${stamp}.json`);
  fs.writeFileSync(file, JSON.stringify(record, null, 2));
  return file;
}
