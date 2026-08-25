/**
 * Tiny JSON persistence for the ONE registered badge credential + the
 * hardware-attested revocation records. Single operator; no DB needed.
 * Anchored to the repo's .data/ (via DATA_DIR), gitignored.
 */
import fs from 'node:fs';
import path from 'node:path';
import { DATA_DIR } from '../lib/wiring.js';

const CRED_FILE = path.join(DATA_DIR, 'badge-credential.json');
const RECORDS_DIR = path.join(DATA_DIR, 'revocation-records');

export interface StoredBadgeCredential {
  id: string;          // base64url credential id
  publicKey: string;   // base64url COSE public key
  counter: number;
  transports?: string[];
  aaguid?: string;
  registeredAt: string;
}

export function hasBadgeCredential(): boolean {
  return fs.existsSync(CRED_FILE);
}

export function loadBadgeCredential(): StoredBadgeCredential | null {
  if (!fs.existsSync(CRED_FILE)) return null;
  return JSON.parse(fs.readFileSync(CRED_FILE, 'utf8')) as StoredBadgeCredential;
}

export function saveBadgeCredential(cred: StoredBadgeCredential): void {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(CRED_FILE, JSON.stringify(cred, null, 2), { mode: 0o600 });
}

export function updateCounter(counter: number): void {
  const cred = loadBadgeCredential();
  if (!cred) return;
  cred.counter = counter;
  fs.writeFileSync(CRED_FILE, JSON.stringify(cred, null, 2), { mode: 0o600 });
}

/** The audit artifact shown on screen and kept next to the DLR reference. */
export function writeRevocationRecord(record: Record<string, unknown>): string {
  fs.mkdirSync(RECORDS_DIR, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const file = path.join(RECORDS_DIR, `revocation-${stamp}.json`);
  fs.writeFileSync(file, JSON.stringify(record, null, 2));
  return file;
}
