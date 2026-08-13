#!/usr/bin/env npx tsx
/**
 * THE KILL SWITCH. Flip one bit on-chain:
 *
 *   fetch latest list → set bit → re-sign → publish as a NEW DLR version
 *   (same name/type) → poll the version-independent URL until every verifier
 *   on earth reads the revocation.
 *
 * Exit code 0 only when the new version is VISIBLE — the demo UI shells this
 * (or calls revokeIndex()) and streams the phases.
 *
 * Usage: npm run revoke [-- --index 94] [--restore]
 */
import {
  loadIssuerIdentity,
  makeFetchProvider,
  makeRegistrar,
  makeRegistrarSigner,
  makeVcSigningFunction,
  statusListUrl,
  env,
} from './lib/wiring.js';
import {
  fetchLatestStatusList,
  resignWithBit,
  publishStatusListVersion,
  waitForStatusListVisible,
  findStringByKey,
} from './statuslist-ops.js';
import { BitstringManager } from '@kya-os/mcp';
import { gzipCompressor, gzipDecompressor } from './lib/wiring.js';

export interface RevokePhase {
  phase: 'fetch' | 'sign' | 'submit' | 'propagate';
  detail: string;
  elapsedMs: number;
}

export async function revokeIndex(
  index: number,
  options?: { restore?: boolean; onPhase?: (p: RevokePhase) => void },
): Promise<{ resourceId: string | undefined; txHash: string | undefined; visibleMs: number; totalMs: number }> {
  const revoked = !options?.restore;
  const identity = loadIssuerIdentity();
  const fetchProvider = makeFetchProvider();
  const registrar = makeRegistrar(fetchProvider);
  const signer = makeRegistrarSigner(identity);
  const signingFunction = makeVcSigningFunction(identity.privateKeyBase64);
  const url = statusListUrl(identity.did);
  const started = Date.now();
  const emit = (phase: RevokePhase['phase'], detail: string) =>
    options?.onPhase?.({ phase, detail, elapsedMs: Date.now() - started });

  emit('fetch', 'reading the latest status list from the cheqd resolver');
  const current = await fetchLatestStatusList(fetchProvider, url, { bust: true });

  emit('sign', `setting bit ${index} → ${revoked ? '1 (REVOKED)' : '0 (restored)'} and re-signing`);
  const updated = await resignWithBit({ credential: current, index, revoked, identity, signingFunction });

  emit('submit', 'publishing new resource version to cheqd testnet (Cosmos)');
  const version = `${revoked ? 'revoke' : 'restore'}-${index}-${new Date().toISOString().replace(/[:.]/g, '-')}`;
  const published = await publishStatusListVersion({ registrar, signer, identity, credential: updated, version });
  const txHash = findStringByKey(published.response, 'transactionHash') ??
    findStringByKey(published.response, 'txHash');

  emit('propagate', 'waiting for the resolver to serve the new version');
  const visible = await waitForStatusListVisible({
    fetchProvider,
    url,
    predicate: (vc) => vc.credentialSubject.encodedList === updated.credentialSubject.encodedList,
  });

  const bits = await BitstringManager.decode(
    visible.credential.credentialSubject.encodedList, gzipCompressor, gzipDecompressor,
  );
  if (bits.getBit(index) !== revoked) {
    throw new Error(`Visible list disagrees: bit ${index} is not ${revoked ? 'set' : 'clear'}`);
  }

  return {
    resourceId: published.resourceId,
    txHash,
    visibleMs: visible.elapsedMs,
    totalMs: Date.now() - started,
  };
}

async function main() {
  const indexArg = process.argv.indexOf('--index');
  const index = Number(indexArg > -1 ? process.argv[indexArg + 1]! : env('STATUSLIST_INDEX', '94'));
  const restore = process.argv.includes('--restore');

  const result = await revokeIndex(index, {
    restore,
    onPhase: (p) => console.log(`[${String(p.elapsedMs).padStart(6)}ms] ${p.phase}: ${p.detail}`),
  });

  console.log('\n================ REVOCATION ANCHORED ================');
  console.log(JSON.stringify({ index, ...result }, null, 2));
  console.log(restore
    ? '\nBit cleared. (Demo reset — in production, un-revocation is a new consent ceremony.)'
    : '\nThe issuer cannot quietly undo this — versions are append-only and every verifier reads the same chain.');
}

const isMain = process.argv[1]?.endsWith('revoke.ts');
if (isMain) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
