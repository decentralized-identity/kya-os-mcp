#!/usr/bin/env npx tsx
/**
 * One-shot verification — the judge artifact.
 *
 * Runs the SHIPPED DelegationCredentialVerifier (nothing mocked) against a
 * delegation credential, with issuer identity AND revocation status both
 * resolved from cheqd testnet. Prints the verdict JSON; exit 0 iff valid.
 *
 * Tier-0 DevX: needs ZERO configuration and ZERO secrets. With no env and no
 * flags it verifies the bundled credential (samples/delegation-777.json) — a
 * genuinely REVOKED, long-lived delegation — against the PUBLIC issuer DID +
 * on-chain status list anchored on cheqd testnet. The full pipeline runs
 * live: issuer signature against the on-chain DID document, status-list
 * signature, purpose parity, and the revocation bit. Expected verdict:
 * CREDENTIAL_REVOKED — which is the point, so it exits 0. Env (CHEQD_DID,
 * STATUSLIST_INDEX, …) and flags override when present.
 *
 * samples/delegation-94.json is also bundled: the actual DEF CON 34 stage
 * credential (48-hour expiry, long past). The shipped verifier denies it at
 * the basic stage, fail-closed, before any network — try
 * `npm run verify:once -- --index 94` to see expiry beat revocation to the
 * refusal. On any pre-network denial this script additionally reads the
 * status bit from the on-chain DLR so the run still proves the chain.
 *
 * Usage: npm run verify:once [-- --index 777 | --file var/delegation-N.json]
 */
import fs from 'node:fs';
import path from 'node:path';
import type { DelegationCredential } from '@kya-os/mcp';
import { buildOnChainVerifier } from './lib/verifier.js';
import { env, statusListUrl, DEMO_ISSUER_DID, SAMPLES_DIR, VAR_DIR } from './lib/wiring.js';

function pickCredentialFile(index: string): { file: string; source: 'flag' | 'var' | 'sample' } {
  const fileArg = process.argv.indexOf('--file');
  if (fileArg > -1) return { file: process.argv[fileArg + 1]!, source: 'flag' };

  const varFile = path.join(VAR_DIR, `delegation-${index}.json`);
  if (fs.existsSync(varFile)) return { file: varFile, source: 'var' };

  const sampleFile = path.join(SAMPLES_DIR, `delegation-${index}.json`);
  if (fs.existsSync(sampleFile)) return { file: sampleFile, source: 'sample' };

  throw new Error(
    `No credential at ${varFile} or ${sampleFile} — run: npm run issue:delegation -- --index ${index}`,
  );
}

async function main() {
  const indexArg = process.argv.indexOf('--index');
  const index = indexArg > -1 ? process.argv[indexArg + 1]! : env('STATUSLIST_INDEX', '777');
  const { file, source } = pickCredentialFile(index);
  const vc = JSON.parse(fs.readFileSync(file, 'utf-8')) as DelegationCredential;

  // Zero secrets needed: verification only requires the PUBLIC issuer DID.
  // Everything else (DID document, status list) is read from the chain.
  const issuerDid = env('CHEQD_DID', DEMO_ISSUER_DID);
  const { verifier, statusListResolver } = buildOnChainVerifier({ issuerDid });

  const started = Date.now();
  const result = await verifier.verifyDelegationCredential(vc, { skipCache: true });
  const elapsedMs = Date.now() - started;

  const verdict = result.valid
    ? 'AUTHORIZED'
    : result.statusOutcome === 'revoked'
      ? 'CREDENTIAL_REVOKED'
      : `DENIED (${result.statusOutcome ?? result.stage})`;

  // A basic-stage denial (e.g. the bundled sample has expired) never reached
  // the network. Read the on-chain status bit anyway — same shipped resolver
  // the gate uses — so the run always proves the chain, never fakes it.
  let onChainStatus: Record<string, unknown> | undefined;
  if (!result.valid && result.stage === 'basic' && vc.credentialStatus) {
    const readStarted = Date.now();
    try {
      const revoked = await statusListResolver.checkStatus(vc.credentialStatus);
      onChainStatus = {
        note: 'supplementary read — the verifier denied at the basic stage (pre-network)',
        listUrl: vc.credentialStatus.statusListCredential,
        index: vc.credentialStatus.statusListIndex,
        revoked,
        elapsedMs: Date.now() - readStarted,
      };
    } catch (err) {
      onChainStatus = {
        note: 'supplementary read FAILED — status list or issuer DID unreachable/unverifiable',
        listUrl: vc.credentialStatus.statusListCredential,
        index: vc.credentialStatus.statusListIndex,
        error: err instanceof Error ? err.message : String(err),
        elapsedMs: Date.now() - readStarted,
      };
    }
  }

  console.log(JSON.stringify({
    verdict,
    valid: result.valid,
    reason: result.reason,
    statusOutcome: result.statusOutcome,
    checks: result.checks,
    stage: result.stage,
    elapsedMs,
    expectedIssuerDid: issuerDid,
    statusListUrl: statusListUrl(issuerDid),
    credential: {
      file,
      source,
      issuer: typeof vc.issuer === 'string' ? vc.issuer : vc.issuer.id,
      subject: vc.credentialSubject?.id,
      statusListIndex: vc.credentialStatus?.statusListIndex,
      statusListCredential: vc.credentialStatus?.statusListCredential,
    },
    ...(onChainStatus ? { onChainStatus } : {}),
  }, null, 2));

  // A demonstrated revocation is this artifact's SUCCESS: the whole pipeline
  // ran live and the chain refused the credential. Anything else invalid
  // (expiry, bad signature, unreachable list) exits 1.
  process.exit(result.valid || result.statusOutcome === 'revoked' ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(2);
});
