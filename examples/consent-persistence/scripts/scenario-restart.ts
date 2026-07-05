#!/usr/bin/env npx tsx
/**
 * Scenario: restart survival via holder-of-key (no re-paste after a restart).
 *
 * Approve a checkout on an instance (binds an agent-anchored grant to the file
 * store), then simulate a restart by building a brand-new instance with EMPTY
 * in-process memory that reads the same file store. The agent presents a fresh
 * `_kyaos_proof` and the retry succeeds from the file store — proving consent
 * survives a restart, with no re-paste and no shared session.
 *
 * Headless and deterministic. Exits 0 on success, 1 on failure.
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createInstance, loadIdentity, mintCheckoutProof, SCOPE } from '../src/instance.js';
import { FileGrantStore } from '../src/file-grant-store.js';
import { approve } from '../src/approve.js';
import { describeProof } from '../src/explain-proof.js';

type Result = { content: Array<{ text: string }>; isError?: boolean };
const text = (r: Result): string => r.content[0]?.text ?? '';
const isChallenge = (r: Result): boolean => text(r).includes('Authorization required');
const isConfirmed = (r: Result): boolean => !r.isError && text(r).includes('Order confirmed');

let failed = false;
function check(label: string, ok: boolean): void {
  process.stdout.write(`     ${ok ? '✓' : '✗ FAIL —'} ${label}\n`);
  if (!ok) failed = true;
}
function step(title: string): void {
  process.stdout.write(`\n── ${title}\n`);
}
function say(line: string): void {
  process.stdout.write(`     ${line}\n`);
}

async function main(): Promise<void> {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'kya-consent-restart-'));
  const identity = await loadIdentity();
  const consentUrl = 'http://consent.local/consent';
  const grantsFile = path.join(dataDir, 'grants.json');
  const shortDid = `${identity.did.slice(0, 24)}…`;
  const grantsOnDisk = (): number => {
    try {
      const g = JSON.parse(fs.readFileSync(grantsFile, 'utf-8'));
      return Array.isArray(g) ? g.length : 0;
    } catch {
      return 0;
    }
  };
  const firstLine = (r: Result): string => text(r).split('\n')[0] ?? '';

  process.stdout.write(
    '\n═══ Scenario: consent survives a server RESTART (holder-of-key) ═══\n\n' +
      'An approved authorization normally lives in server MEMORY, so a restart loses it — and\n' +
      'the naive workaround is to re-send ("re-paste") the whole delegation credential on every\n' +
      "call. Here the grant is anchored to the AGENT'S KEY and persisted to disk, so after a\n" +
      'restart the agent just RE-PROVES possession with a fresh signed proof: no second human\n' +
      'approval, no credential re-paste.\n\n' +
      `File-backed grant store: ${grantsFile}\n`,
  );

  const instance1 = createInstance({ label: '1', identity, grantStore: new FileGrantStore(grantsFile), consentUrl });

  step('1. Agent calls checkout — before any grant exists');
  say(`grants persisted on disk right now: ${grantsOnDisk()}`);
  const proof1 = await mintCheckoutProof(identity, { item: 'laptop' });
  const first = await instance1.checkout({ item: 'laptop', _kyaos_proof: proof1 });
  say(`server replied: "${firstLine(first)}"`);
  check('challenged instead of silently allowing (needs_authorization)', isChallenge(first));

  step('2. Human approves the checkout — once');
  await approve({ identity, grantStore: new FileGrantStore(grantsFile), agentDid: identity.did, scopes: [SCOPE] });
  say(`an agent-anchored grant (scope "${SCOPE}") was written to the file store, keyed to ${shortDid}`);
  check(`grant is now persisted on disk (${grantsOnDisk()} on file)`, grantsOnDisk() >= 1);

  step('3. RESTART — a brand-new instance with EMPTY memory, same file');
  const instance2 = createInstance({ label: '2 (restarted)', identity, grantStore: new FileGrantStore(grantsFile), consentUrl });
  say('instance #2 boots with a cold in-memory cache — only the file survived the restart');

  step('4. Agent retries with a FRESH proof — no re-paste');
  say('the agent mints a NEW _kyaos_proof (proving it still holds the key) and retries the SAME call.');
  const proof2 = await mintCheckoutProof(identity, { item: 'laptop' });
  say('');
  describeProof(proof2, 'checkout {item:"laptop"}').forEach(say);
  say('');
  const retry = await instance2.checkout({ item: 'laptop', _kyaos_proof: proof2 });
  say('server resolved the grant FROM THE FILE — not from memory, not from a re-pasted credential');
  say(`server replied: "${firstLine(retry)}"`);
  check('authorized after the restart, straight from the persisted grant', isConfirmed(retry));

  fs.rmSync(dataDir, { recursive: true, force: true });
  process.stdout.write(
    failed
      ? '\n✗ SCENARIO FAILED\n'
      : '\n✓ SCENARIO PASSED — the grant outlived the restart.\n' +
          '  The human approved ONCE and the agent never re-pasted the credential; the retry\n' +
          '  succeeded because authorization rode on the holder-of-key proof + the file store.\n',
  );
  process.exit(failed ? 1 : 0);
}

main().catch((err) => {
  process.stderr.write(`Error: ${err}\n`);
  process.exit(1);
});
