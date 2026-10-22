/**
 * Shared wiring for the agentic-commerce example.
 *
 * Everything here composes PUBLIC exports of the published @kya-os/mcp — no
 * forks, no vendored modules. Three parties with separate identities and state:
 *
 *   Responsible Party (RP)  did:web   issues the delegation, hosts the revocation list
 *   Merchant edge           did:key   verifies every call, signs every receipt
 *   Shopping agent          did:key   holds its own key; the LLM never sees it
 *
 * Paths anchor to the EXAMPLE root (resolved from this module), never
 * process.cwd(): the Claude Desktop gateway is spawned with an arbitrary cwd.
 */
import { config as loadDotenv } from 'dotenv';
import { timingSafeEqual } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { gzip, gunzip } from 'node:zlib';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import {
  NodeCryptoProvider,
  base64urlEncodeFromBytes,
  type VCSigningFunction,
} from '@kya-os/mcp';

export const EXAMPLE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
loadDotenv({ path: process.env['DEMO_ENV_FILE'] ?? [path.join(EXAMPLE_ROOT, '.env.local'), path.join(EXAMPLE_ROOT, '.env')], quiet: true });

export const VAR_DIR = process.env['DEMO_VAR_DIR'] ?? path.join(EXAMPLE_ROOT, 'var');
export const DATA_DIR = process.env['DEMO_DATA_DIR'] ?? path.join(EXAMPLE_ROOT, '.data');
export const WEB_DIR = path.join(EXAMPLE_ROOT, 'web');

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

export function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required — run \`npm run setup\` (it writes .env.local)`);
  return value;
}

export function env(name: string, fallback: string): string {
  const v = process.env[name];
  return v === undefined || v === '' ? fallback : v;
}

export function flag(name: string): boolean {
  return process.env[name] === '1' || process.env[name] === 'true';
}

export const MERCHANT_PORT = Number(env('MERCHANT_PORT', '4949'));
export const RP_PORT = Number(env('RP_PORT', '4950'));
export const merchantOrigin = (): string => env('MERCHANT_ORIGIN', `http://localhost:${MERCHANT_PORT}`);
export const rpOrigin = (): string => env('RP_ORIGIN', `http://localhost:${RP_PORT}`);

/** The Responsible Party's DID. Default resolves to the hub on this laptop. */
export const RP_DID = env('RP_DID', `did:web:localhost%3A${RP_PORT}`);
/** Where the RP publishes the revocation list. Any URL; the signature is what is trusted. */
export const STATUS_LIST_URL = env('STATUS_LIST_URL', `${rpOrigin()}/status-list`);
export const RP_DID_MIRROR_URL = env('RP_DID_MIRROR_URL', `${rpOrigin()}/.well-known/did.json`);

// --- Hosting -----------------------------------------------------------------
/** Shared secret the agent gateway requires once it is reachable off this laptop. */
export const GATEWAY_TOKEN = env('GATEWAY_TOKEN', '');
/** Shared secret guarding the presenter's destructive console controls. */
export const ADMIN_TOKEN = env('ADMIN_TOKEN', '');
/**
 * Constant-time check for that secret. An unset token means a laptop rehearsal,
 * where the loopback binding is already the boundary, so the guard stays open.
 */
export function adminTokenOk(presented: string | undefined): boolean {
  if (!ADMIN_TOKEN) return true;
  const a = Buffer.from(presented ?? '');
  const b = Buffer.from(ADMIN_TOKEN);
  return a.length === b.length && timingSafeEqual(a, b);
}
/** The hostnames a public deployment answers on, taken from its configured origin. */
export function publicHosts(origin: string): string[] {
  const url = new URL(origin);
  return url.port ? [url.host] : [url.host, `${url.hostname}:443`, `${url.hostname}:80`];
}

export const SCOPE_PRODUCT_CLASS = env('SCOPE_PRODUCT_CLASS', 'https://id.gs1.org/01/09506000134352');
export const SPEND_CAP = env('SPEND_CAP', '50.00');
export const SPEND_CURRENCY = env('SPEND_CURRENCY', 'CHF');
export const VALID_HOURS = Number(env('VALID_HOURS', '48'));

// ---------------------------------------------------------------------------
// GZIP codec (W3C StatusList2021 encodedList)
// ---------------------------------------------------------------------------

const gzipAsync = promisify(gzip);
const gunzipAsync = promisify(gunzip);

export const gzipCompressor = {
  compress: async (data: Uint8Array): Promise<Uint8Array> => new Uint8Array(await gzipAsync(data)),
};
export const gzipDecompressor = {
  decompress: async (data: Uint8Array): Promise<Uint8Array> => new Uint8Array(await gunzipAsync(data)),
};

// ---------------------------------------------------------------------------
// Crypto + identities
// ---------------------------------------------------------------------------

export const cryptoProvider = new NodeCryptoProvider();

export interface KeyedIdentity {
  did: string;
  kid: string;
  privateKeyBase64: string;
  publicKeyBase64: string;
}

export function loadRpIdentity(): KeyedIdentity {
  return {
    did: RP_DID,
    kid: requiredEnv('RP_KID'),
    privateKeyBase64: requiredEnv('RP_PRIVATE_KEY_BASE64'),
    publicKeyBase64: requiredEnv('RP_PUBLIC_KEY_BASE64'),
  };
}

export function loadMerchantIdentity(): KeyedIdentity {
  const did = requiredEnv('MERCHANT_DID');
  return {
    did,
    kid: `${did}#${did.replace('did:key:', '')}`,
    privateKeyBase64: requiredEnv('MERCHANT_PRIVATE_KEY_BASE64'),
    publicKeyBase64: requiredEnv('MERCHANT_PUBLIC_KEY_BASE64'),
  };
}

export function loadAgentIdentity(): KeyedIdentity {
  const did = requiredEnv('AGENT_DID');
  return {
    did,
    kid: `${did}#${did.replace('did:key:', '')}`,
    privateKeyBase64: requiredEnv('AGENT_ED25519_PRIVATE_KEY_BASE64'),
    publicKeyBase64: requiredEnv('AGENT_ED25519_PUBLIC_KEY_BASE64'),
  };
}

/** Ed25519Signature2020 signing function over the canonicalized VC (JCS). */
export function makeVcSigningFunction(privateKeyBase64: string): VCSigningFunction {
  return async (canonicalVC, _issuerDid, kid) => {
    const sig = await cryptoProvider.sign(new TextEncoder().encode(canonicalVC), privateKeyBase64);
    return {
      type: 'Ed25519Signature2020',
      created: new Date().toISOString(),
      verificationMethod: kid,
      proofPurpose: 'assertionMethod',
      proofValue: base64urlEncodeFromBytes(sig),
    };
  };
}

// ---------------------------------------------------------------------------
// Tiny JSON persistence under var/
// ---------------------------------------------------------------------------

export function readJson<T>(file: string): T | null {
  if (!fs.existsSync(file)) return null;
  return JSON.parse(fs.readFileSync(file, 'utf8')) as T;
}

export function writeJson(file: string, value: unknown, mode?: number): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(value, null, 2), mode ? { mode } : undefined);
}
