/**
 * Shared wiring for the REVOKED example (DEF CON 34 Cryptocurrency Village).
 *
 * Everything here composes PUBLIC exports of the published @kya-os/mcp@1.14.0
 * — no forks, no vendored modules. What the hackathon repo had to vendor
 * (the on-chain status-list resolver, the DLR publisher, the JWK-synthesizing
 * DID-resolver workaround) has since shipped upstream.
 */
import { config as loadDotenv } from 'dotenv';
import { gzip, gunzip } from 'node:zlib';
import { promisify } from 'node:util';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  NodeCryptoProvider,
  RuntimeFetchProvider,
  base64urlEncodeFromBytes,
  type VCSigningFunction,
} from '@kya-os/mcp';
import {
  CheqdDidRegistrarClient,
  cheqdResolver,
  createLocalEd25519CheqdRegistrarSigner,
  buildCheqdDlrReference,
} from '@kya-os/mcp/cheqd';

/**
 * Example root, resolved from this module (src/lib/wiring.ts) — NOT
 * process.cwd(). The gateway is spawned by Claude Desktop with an arbitrary
 * working directory, so `.env.local`, `var/`, and `.data/` must anchor here
 * to be found.
 */
export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
export const VAR_DIR = path.join(REPO_ROOT, 'var');
export const DATA_DIR = path.join(REPO_ROOT, '.data');
export const SAMPLES_DIR = path.join(REPO_ROOT, 'samples');

loadDotenv({ path: [path.join(REPO_ROOT, '.env.local'), path.join(REPO_ROOT, '.env')], quiet: true });

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

export function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required (set it in .env.local)`);
  return value;
}

export function env(name: string, fallback: string): string {
  return process.env[name] ?? fallback;
}

export const REGISTRAR_URL = env('CHEQD_REGISTRAR_URL', 'https://did-registrar-staging.cheqd.net/1.0');
export const RESOLVER_URL = env('CHEQD_RESOLVER_URL', 'https://resolver.cheqd.net');
export const STATUSLIST_NAME = env('STATUSLIST_NAME', 'kya-statuslist-demo');
export const STATUSLIST_RESOURCE_TYPE = 'StatusListCredential';

/**
 * The PUBLIC issuer DID the DEF CON 34 demo anchored on cheqd testnet. Baked
 * in so `verify:once` runs Tier-0 (zero env, zero secrets): the DID document
 * and the status list both still resolve from the chain. Set CHEQD_DID to
 * verify against your own issuer instead.
 */
export const DEMO_ISSUER_DID = 'did:cheqd:testnet:17bc59fe-2e93-4e01-8613-c7c4560adcf2';

// ---------------------------------------------------------------------------
// GZIP compressor/decompressor (W3C StatusList2021 encodedList codec)
// ---------------------------------------------------------------------------

const gzipAsync = promisify(gzip);
const gunzipAsync = promisify(gunzip);

export const gzipCompressor = {
  compress: async (data: Uint8Array): Promise<Uint8Array> =>
    new Uint8Array(await gzipAsync(data)),
};

export const gzipDecompressor = {
  decompress: async (data: Uint8Array): Promise<Uint8Array> =>
    new Uint8Array(await gunzipAsync(data)),
};

// ---------------------------------------------------------------------------
// Providers
// ---------------------------------------------------------------------------

export const cryptoProvider = new NodeCryptoProvider();

export function makeFetchProvider(): RuntimeFetchProvider {
  return new RuntimeFetchProvider({
    didResolvers: {
      cheqd: cheqdResolver({ resolverUrl: RESOLVER_URL }),
    },
  });
}

// ---------------------------------------------------------------------------
// Issuer identity (the Responsible Party — signs delegations + status lists)
// ---------------------------------------------------------------------------

export interface IssuerIdentity {
  did: string;
  kid: string;
  privateKeyBase64: string;
}

export function loadIssuerIdentity(): IssuerIdentity {
  return {
    did: requiredEnv('CHEQD_DID'),
    kid: requiredEnv('CHEQD_KID'),
    privateKeyBase64: requiredEnv('CHEQD_PRIVATE_KEY_BASE64'),
  };
}

/** Ed25519Signature2020 signing function over the canonicalized VC. */
export function makeVcSigningFunction(privateKeyBase64: string): VCSigningFunction {
  return async (canonicalVC, _issuerDid, kid) => {
    const sig = await cryptoProvider.sign(
      new TextEncoder().encode(canonicalVC),
      privateKeyBase64,
    );
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
// Registrar (client-managed-secret flow against cheqd staging)
// ---------------------------------------------------------------------------

export function makeRegistrar(fetchProvider: RuntimeFetchProvider) {
  return new CheqdDidRegistrarClient({
    registrarUrl: REGISTRAR_URL,
    fetchProvider,
  });
}

export function makeRegistrarSigner(identity: IssuerIdentity) {
  return createLocalEd25519CheqdRegistrarSigner({
    cryptoProvider,
    privateKey: identity.privateKeyBase64,
    verificationMethodId: identity.kid,
    signatureEncoding: 'base64url',
  });
}

// ---------------------------------------------------------------------------
// URLs
// ---------------------------------------------------------------------------

/**
 * The VERSION-INDEPENDENT resolver URL for the status list (§4.2 of the spec):
 * name/type query form, which the cheqd resolver resolves to the LATEST
 * resource version. Revocation = publish a new version; every verifier holding
 * an old credential automatically reads the new list.
 */
export function statusListUrl(issuerDid: string): string {
  return buildCheqdDlrReference({
    did: issuerDid,
    resolverUrl: RESOLVER_URL,
    resourceName: STATUSLIST_NAME,
    resourceType: STATUSLIST_RESOURCE_TYPE,
  }).url;
}

export function explorerTxUrl(txHash: string): string {
  const template = env('EXPLORER_TX_URL', 'https://testnet-explorer.cheqd.io/transactions/{hash}');
  return template.replace('{hash}', txHash);
}
