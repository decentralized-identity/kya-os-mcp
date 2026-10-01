#!/usr/bin/env npx tsx
/** Model-independent stage path. The human still approves in the real consent UI. */
import { spawnSync } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import path from 'node:path';
import { browseCatalog, discover, runAgentOrder } from '../src/agent/agent.js';
import { responseBody } from '../src/agent/authorization.js';
import { EXAMPLE_ROOT, VAR_DIR, merchantOrigin, rpOrigin } from '../src/lib/wiring.js';

const PRODUCT = 'https://id.gs1.org/01/09506000134352';
const ORDER = { product: PRODUCT, quantity: 2 };
const operatorWaitMs = Number(process.env['DEMO_APPROVAL_TIMEOUT_SECONDS'] ?? 600) * 1000;
if (!Number.isFinite(operatorWaitMs) || operatorWaitMs <= 0) throw new Error('DEMO_APPROVAL_TIMEOUT_SECONDS must be positive');

async function request(url: string, data?: object): Promise<Record<string, any>> {
  const response = await fetch(url, {
    method: data ? 'POST' : 'GET',
    ...(data ? { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) } : {}),
    signal: AbortSignal.timeout(15_000),
  });
  const body = await response.json() as Record<string, any>;
  if (!response.ok || body['error']) throw new Error(`${url}: ${body['message'] ?? body['error'] ?? response.status}`);
  return body;
}

async function order(label: string, options = ORDER): Promise<Record<string, any>> {
  const outcome = await runAgentOrder(options);
  const body = responseBody(outcome.result);
  console.log(`\n${label}`);
  console.log(JSON.stringify(body, null, 2));
  return body;
}

async function waitForHuman(challenge: Record<string, any>): Promise<void> {
  const deadline = Math.min(Date.now() + operatorWaitMs, Number(challenge['expiresAt']) * 1000);
  if (!Number.isFinite(deadline)) throw new Error('Challenge expiry is missing');
  const statusUrl = new URL('/consent/status', challenge['authorizationUrl'] as string);
  statusUrl.searchParams.set('resume_token', challenge['resumeToken'] as string);
  console.log(`\nOpen this URL on the projector and click Approve grant:\n${challenge['authorizationUrl']}`);
  console.log('Waiting for the human. The scripted agent does not approve its own grant.');
  let nextReminder = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const status = await request(statusUrl.href);
    if (status['state'] === 'denied') throw new Error('Human denied the grant. No order placed. Run npm run demo:scripted to request a new decision.');
    if (status['state'] === 'approved') {
      const grant = await request(`${rpOrigin()}/api/rp/delegation`);
      if (!grant['credential']) throw new Error('Approval did not persist the agent credential');
      return;
    }
    if (status['state'] === 'expired' || status['state'] === 'consumed') throw new Error(`Consent request ${status['state']}; request a new grant`);
    if (Date.now() >= nextReminder) {
      console.log('Still waiting for Approve grant in the consent tab.');
      nextReminder = Date.now() + 30_000;
    }
    await delay(500);
  }
  throw new Error('Consent request timed out without approval. No order placed.');
}

function verifyLedger(file: string, expectedValid: boolean): void {
  const result = spawnSync(process.env['PYTHON'] ?? 'python3', [
    path.join(EXAMPLE_ROOT, 'scripts/verify-ledger.py'),
    path.join(VAR_DIR, 'audit', file), '--keys', path.join(VAR_DIR, 'audit/keys.json'), '--quiet',
  ], { cwd: EXAMPLE_ROOT, encoding: 'utf8' });
  if (result.error) throw result.error;
  process.stdout.write(result.stdout);
  process.stderr.write(result.stderr);
  // Exit 1 is the verifier's deliberate rejection. A crash is not a tamper pass.
  const expectedCode = expectedValid ? 0 : 1;
  if (result.status !== expectedCode) throw new Error(`${file}: expected verifier exit ${expectedCode}, got ${result.status}`);
  const report = JSON.parse(result.stdout) as { verdict?: string; checks?: number; failed?: number };
  if (report.verdict !== (expectedValid ? 'valid' : 'invalid') || !(Number(report.checks) > 0)
      || (!expectedValid && !(Number(report.failed) > 0))) {
    throw new Error(`${file}: verifier did not produce the expected integrity report`);
  }
}

async function main(): Promise<void> {
  console.log('Human consent → scoped grant → order → revoke → denied → verified evidence');
  console.log(`Project: ${merchantOrigin()}/  (press P for presenter mode)`);
  const decision = await discover();
  if (!decision.accepted) throw new Error(`Merchant discovery refused: ${decision.reasons.join('; ')}`);
  await browseCatalog();
  // Every rehearsal starts with no active grant; only the human can issue one.
  await request(`${merchantOrigin()}/api/act/reset`, {});
  const challenge = await order('1. Request 2 × risotto, CHF 39.80, before human approval');
  if (challenge['error'] !== 'needs_authorization') throw new Error('Fresh agent did not receive needs_authorization');
  await waitForHuman(challenge);
  const allowed = await order('2. Human approved. Retry the exact same order');
  if (allowed['ok'] !== true) throw new Error('Approved order was not allowed');
  const receipt = await request(`${merchantOrigin()}/api/act/verify-receipt`, {});
  if (receipt['ok'] !== true) throw new Error('Independent Python receipt verification failed');
  console.log('\n3. Receipt independently verified. Revoke the grant on the RP status list.');
  await delay(1800);
  await request(`${rpOrigin()}/api/rp/revoke`, {});
  const denied = await order('4. Retry with the same credential and holder key after revocation');
  if (!denied['error'] || !/revoked/i.test(JSON.stringify(denied))) throw new Error('Revoked order was not explicitly denied');
  await delay(1800);
  await request(`${merchantOrigin()}/api/act/export`, {});
  console.log('\n5. Honest Merkle bundle must verify. The tampered bundle must fail.');
  verifyLedger('bundle.json', true);
  verifyLedger('bundle.tampered.json', false);
  console.log(`\nDONE: human grant, allowed order, revoked denial, honest ledger verified, tampering rejected.\nEvidence: ${path.join(VAR_DIR, 'audit/bundle.json')}\nPress E on the projector to show the exported evidence.`);
}

main().catch((error: unknown) => {
  console.error(`\nScripted demo stopped: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
});
