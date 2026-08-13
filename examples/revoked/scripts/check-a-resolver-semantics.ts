#!/usr/bin/env npx tsx
/**
 * WP0 assumption check A — the one external assumption the design leans on:
 *
 *   cheqd DLR "updates" are new resource versions under the same
 *   resourceName/resourceType, and the resolver's name/type QUERY form
 *   returns the LATEST version.
 *
 * Publishes a throwaway status list (v1, all clear), confirms the query
 * returns it, publishes v2 (bit 94 set), confirms the query now returns v2,
 * and measures write→visible latency. Exits non-zero if latest-version
 * semantics do not hold.
 *
 * Uses the REAL operator ops (statuslist-ops.ts) — green here means the
 * publish/revoke path works end to end.
 */
import { BitstringManager } from '@kya-os/mcp';
import { buildCheqdDlrReference } from '@kya-os/mcp/cheqd';
import {
  loadIssuerIdentity,
  makeFetchProvider,
  makeRegistrar,
  makeRegistrarSigner,
  makeVcSigningFunction,
  gzipCompressor,
  gzipDecompressor,
  RESOLVER_URL,
  STATUSLIST_RESOURCE_TYPE,
} from '../src/lib/wiring.js';
import {
  buildInitialStatusListCredential,
  resignWithBit,
  fetchLatestStatusList,
  publishStatusListVersion,
  waitForStatusListVisible,
} from '../src/statuslist-ops.js';

const CHECK_INDEX = 94;

async function main() {
  const identity = loadIssuerIdentity();
  const fetchProvider = makeFetchProvider();
  const registrar = makeRegistrar(fetchProvider);
  const signer = makeRegistrarSigner(identity);
  const signingFunction = makeVcSigningFunction(identity.privateKeyBase64);

  const name = `kya-check-a-${Date.now()}`;
  const url = buildCheqdDlrReference({
    did: identity.did,
    resolverUrl: RESOLVER_URL,
    resourceName: name,
    resourceType: STATUSLIST_RESOURCE_TYPE,
  }).url;

  console.log(`Check A against: ${url}\n`);

  // ---- v1: all-clear list --------------------------------------------------
  const v1 = await buildInitialStatusListCredential({ identity, signingFunction, url });
  console.log('Publishing v1 (all bits clear)…');
  let t = Date.now();
  const pub1 = await publishStatusListVersion({
    registrar, signer, identity, credential: v1, version: `v1-${t}`, name,
  });
  console.log(`  v1 published, resourceId=${pub1.resourceId ?? '?'} (${Date.now() - t}ms)`);

  console.log('Waiting for v1 via name/type query…');
  t = Date.now();
  const seen1 = await waitForStatusListVisible({
    fetchProvider,
    url,
    predicate: (vc) => vc.credentialSubject.encodedList === v1.credentialSubject.encodedList,
  });
  console.log(`  v1 visible in ${seen1.elapsedMs}ms ✓`);

  // ---- v2: bit set — same name/type, new version --------------------------
  const v2 = await resignWithBit({
    credential: v1, index: CHECK_INDEX, revoked: true, identity, signingFunction,
  });
  console.log(`Publishing v2 (bit ${CHECK_INDEX} SET) under the SAME name/type…`);
  t = Date.now();
  const pub2 = await publishStatusListVersion({
    registrar, signer, identity, credential: v2, version: `v2-${t}`, name,
  });
  console.log(`  v2 published, resourceId=${pub2.resourceId ?? '?'} (${Date.now() - t}ms)`);

  console.log('Waiting for the query to switch to v2 (LATEST-version semantics)…');
  const seen2 = await waitForStatusListVisible({
    fetchProvider,
    url,
    predicate: (vc) => vc.credentialSubject.encodedList === v2.credentialSubject.encodedList,
  });
  console.log(`  v2 visible in ${seen2.elapsedMs}ms ✓`);

  const bits = await BitstringManager.decode(
    seen2.credential.credentialSubject.encodedList, gzipCompressor, gzipDecompressor,
  );
  if (!bits.getBit(CHECK_INDEX)) {
    throw new Error('Latest list fetched but bit is NOT set — check failed');
  }

  // ---- caching behavior ----------------------------------------------------
  console.log('\nCache probe: plain fetch (no bust param)…');
  const plain = await fetchLatestStatusList(fetchProvider, url);
  const plainIsV2 = plain.credentialSubject.encodedList === v2.credentialSubject.encodedList;
  console.log(`  plain query returns ${plainIsV2 ? 'v2 (no aggressive caching observed)' : 'v1 — RESOLVER CACHES; demo must cache-bust'}`);

  console.log('\n================ CHECK A RESULT ================');
  console.log(JSON.stringify({
    latestVersionSemantics: true,
    v1VisibleMs: seen1.elapsedMs,
    v2VisibleMs: seen2.elapsedMs,
    resolverCachesPlainQuery: !plainIsV2,
    v1ResourceId: pub1.resourceId,
    v2ResourceId: pub2.resourceId,
    url,
  }, null, 2));
  console.log('PASS — the design assumption holds.');
}

main().catch((err) => {
  console.error('\nCHECK A FAILED:', err);
  console.error('\nFallback (§WP0 gate): front the list with a thin 302 redirect to the latest resourceId.');
  process.exit(1);
});
