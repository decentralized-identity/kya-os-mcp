#!/usr/bin/env npx tsx
/**
 * Publish the demo status list (v1, all bits clear) as a cheqd DLR under the
 * version-independent name/type handle. Idempotent: refuses to publish if the
 * handle already resolves, unless --force (which publishes a fresh ALL-CLEAR
 * version — the demo-reset path).
 */
import {
  loadIssuerIdentity,
  makeFetchProvider,
  makeRegistrar,
  makeRegistrarSigner,
  makeVcSigningFunction,
  statusListUrl,
} from './lib/wiring.js';
import {
  buildInitialStatusListCredential,
  fetchLatestStatusList,
  publishStatusListVersion,
  waitForStatusListVisible,
} from './statuslist-ops.js';

async function main() {
  const identity = loadIssuerIdentity();
  const fetchProvider = makeFetchProvider();
  const registrar = makeRegistrar(fetchProvider);
  const signer = makeRegistrarSigner(identity);
  const signingFunction = makeVcSigningFunction(identity.privateKeyBase64);
  const url = statusListUrl(identity.did);
  const force = process.argv.includes('--force');

  const existing = await fetchLatestStatusList(fetchProvider, url, { bust: true }).catch(() => null);
  if (existing && !force) {
    console.log(`Status list already published at:\n  ${url}\nUse --force to publish a fresh all-clear version.`);
    return;
  }

  const credential = await buildInitialStatusListCredential({ identity, signingFunction, url });
  const version = `v-${new Date().toISOString().replace(/[:.]/g, '-')}`;

  console.log(`Publishing status list (all clear) as ${version}…`);
  const started = Date.now();
  const published = await publishStatusListVersion({ registrar, signer, identity, credential, version });
  const visible = await waitForStatusListVisible({
    fetchProvider,
    url,
    predicate: (vc) => vc.credentialSubject.encodedList === credential.credentialSubject.encodedList,
  });

  console.log(JSON.stringify({
    url,
    resourceId: published.resourceId,
    contentHash: published.contentHash,
    publishMs: Date.now() - started - visible.elapsedMs,
    visibleMs: visible.elapsedMs,
  }, null, 2));
  console.log('\nThis URL goes into every delegation credentialStatus. Verifiers worldwide read the chain, not our server.');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
