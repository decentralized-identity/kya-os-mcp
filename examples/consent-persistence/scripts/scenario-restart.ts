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

type Result = { content: Array<{ text: string }>; isError?: boolean };
const text = (r: Result): string => r.content[0]?.text ?? '';
const isChallenge = (r: Result): boolean => text(r).includes('Authorization required');
const isConfirmed = (r: Result): boolean => !r.isError && text(r).includes('Order confirmed');

let failed = false;
function check(label: string, ok: boolean): void {
  process.stdout.write(`${ok ? 'PASS' : 'FAIL'}  ${label}\n`);
  if (!ok) failed = true;
}

async function main(): Promise<void> {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'kya-consent-restart-'));
  const identity = await loadIdentity();
  const consentUrl = 'http://consent.local/consent';
  const grantsFile = path.join(dataDir, 'grants.json');

  // ── Process 1 ───────────────────────────────────────────────────────────
  const instance1 = createInstance({
    label: '1',
    identity,
    grantStore: new FileGrantStore(grantsFile),
    consentUrl,
  });

  const proof1 = await mintCheckoutProof(identity, { item: 'laptop' });
  const first = await instance1.checkout({ item: 'laptop', _kyaos_proof: proof1 });
  check('process 1: first call (proof, no grant) returns needs_authorization', isChallenge(first));

  await approve({ identity, grantStore: new FileGrantStore(grantsFile), agentDid: identity.did, scopes: [SCOPE] });

  // ── Restart: a brand-new instance with EMPTY memory, same file store ──────
  const instance2 = createInstance({
    label: '2 (restarted)',
    identity,
    grantStore: new FileGrantStore(grantsFile),
    consentUrl,
  });

  const proof2 = await mintCheckoutProof(identity, { item: 'laptop' });
  const retry = await instance2.checkout({ item: 'laptop', _kyaos_proof: proof2 });
  check('process 2 (restarted): retry resolves the grant from the file store (NO re-paste)', isConfirmed(retry));

  fs.rmSync(dataDir, { recursive: true, force: true });
  process.stdout.write(
    failed ? '\nSCENARIO FAILED\n' : '\nSCENARIO PASSED — consent survives a restart (holder-of-key) with no re-paste\n',
  );
  process.exit(failed ? 1 : 0);
}

main().catch((err) => {
  process.stderr.write(`Error: ${err}\n`);
  process.exit(1);
});
