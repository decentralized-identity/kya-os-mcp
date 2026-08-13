#!/usr/bin/env npx tsx
/**
 * Create the issuer's did:cheqd:testnet DID via the cheqd staging registrar
 * (client-managed-secret flow — the Ed25519 key never leaves this machine).
 *
 * The DID document comes from the registrar's own /did-document helper, so the
 * shape is exactly what the registrar's create flow expects (verified against
 * its OpenAPI spec: params verificationMethod / methodSpecificIdAlgo / network
 * / publicKeyHex; the response's didDoc includes the top-level controller
 * array the create validation requires).
 *
 * Writes CHEQD_DID / CHEQD_KID / CHEQD_PRIVATE_KEY_BASE64 to .env.local.
 * Idempotent: refuses to overwrite an existing identity unless --force.
 */
import type { DIDDocument } from '@kya-os/mcp';
import {
  cryptoProvider,
  makeFetchProvider,
  makeRegistrar,
  REGISTRAR_URL,
} from '../src/lib/wiring.js';
import { createLocalEd25519CheqdRegistrarSigner } from '@kya-os/mcp/cheqd';
import { readEnvLocal, writeEnvLocal } from './lib/env-local.js';

async function main() {
  const existing = readEnvLocal();
  if (existing['CHEQD_DID'] && !process.argv.includes('--force')) {
    console.log(`CHEQD_DID already set (${existing['CHEQD_DID']}). Use --force to replace.`);
    return;
  }

  const keyPair = await cryptoProvider.generateKeyPair();
  const publicKeyHex = Buffer.from(keyPair.publicKey, 'base64').toString('hex');

  const fetchProvider = makeFetchProvider();

  const helperUrl = `${REGISTRAR_URL}/did-document` +
    `?verificationMethod=Ed25519VerificationKey2020` +
    `&methodSpecificIdAlgo=uuid&network=testnet&publicKeyHex=${publicKeyHex}`;
  const helperResponse = await fetchProvider.fetch(helperUrl, {
    method: 'GET',
    headers: { Accept: 'application/json' },
  });
  if (!helperResponse.ok) {
    throw new Error(`did-document helper failed: HTTP ${helperResponse.status}`);
  }
  const helper = (await helperResponse.json()) as {
    didDoc: DIDDocument & { controller?: string[] };
    key: { kid: string; publicKeyHex: string };
  };
  const didDocument = helper.didDoc;
  const did = didDocument.id;
  const kid = helper.key.kid ?? `${did}#key-1`;
  console.log(`Registrar-generated DID document for ${did}`);

  const registrar = makeRegistrar(fetchProvider);
  const signer = createLocalEd25519CheqdRegistrarSigner({
    cryptoProvider,
    privateKey: keyPair.privateKey,
    verificationMethodId: kid,
    signatureEncoding: 'base64url',
  });

  console.log('Submitting create (client-managed-secret signing flow)…');
  const result = await registrar.createDid({
    didDocument,
    signer,
    verificationMethodId: kid,
    options: { network: 'testnet' },
  });

  if (!result.success) {
    console.error(`Create failed at stage "${result.stage}": ${result.reason ?? 'unknown'}`);
    console.error(JSON.stringify(result.response ?? {}, null, 2).slice(0, 3000));
    process.exit(1);
  }

  console.log('Registrar reports finished. Confirming resolution…');
  const resolved = await fetchProvider.resolveDID(did);
  if (!resolved) {
    console.error('DID created but did not resolve yet — retry resolution in a few seconds.');
  } else {
    console.log(`Resolved ${did} ✓`);
  }

  writeEnvLocal(
    {
      CHEQD_DID: did,
      CHEQD_KID: kid,
      CHEQD_PRIVATE_KEY_BASE64: keyPair.privateKey,
      CHEQD_PUBLIC_KEY_BASE64: keyPair.publicKey,
    },
    { overwrite: process.argv.includes('--force') },
  );
  console.log('Identity written to .env.local (0600).');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
