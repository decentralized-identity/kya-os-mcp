#!/usr/bin/env npx tsx
/**
 * Scenario: cross-instance consent persistence via holder-of-key (no re-paste,
 * no shared session).
 *
 * The agent presents a per-request `_kyaos_proof` in the checkout args. Call
 * protected `checkout` on instance A → needs_authorization. Approve (binds an
 * agent-anchored grant to the shared, file-backed store). Retry on a SEPARATE
 * instance B with a fresh proof → it succeeds with NO re-paste and NO shared
 * session, because B re-proves possession of the agent's key and resolves the
 * grant via getByAgent. Also proves the OAuth half: a PKCE pending flow
 * initiated on A is atomically consumed on B via the shared PendingFlowStore.
 *
 * Headless and deterministic. Exits 0 on success, 1 on failure.
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { GenericOidcAdapter } from '@kya-os/mcp/authz';
import { createInstance, loadIdentity, mintCheckoutProof, SCOPE } from '../src/instance.js';
import { FileGrantStore } from '../src/file-grant-store.js';
import { FilePendingFlowStore } from '../src/file-pending-flow-store.js';
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
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'kya-consent-xinst-'));
  const identity = await loadIdentity();
  const consentUrl = 'http://consent.local/consent';
  const shortDid = `${identity.did.slice(0, 24)}…`;
  const firstLine = (r: Result): string => text(r).split('\n')[0] ?? '';

  process.stdout.write(
    '\n═══ Scenario: consent survives ACROSS INSTANCES (holder-of-key) ═══\n\n' +
      'Two separate server instances (A and B) share ONE file-backed grant store but NO session\n' +
      'or in-memory state — like two pods behind a load balancer. An approval on A must be\n' +
      'honored on B without the human re-approving and without the agent re-sending ("re-pasting")\n' +
      "the credential. It works because the grant is anchored to the AGENT'S KEY: B trusts a call\n" +
      'that RE-PROVES possession with a fresh signed proof.\n\n' +
      `Shared grant store: ${path.join(dataDir, 'grants.json')}\n`,
  );

  // Two INDEPENDENT store objects over the SAME files: two instances, one durable backing.
  const grantA = new FileGrantStore(path.join(dataDir, 'grants.json'));
  const grantB = new FileGrantStore(path.join(dataDir, 'grants.json'));
  const instanceA = createInstance({ label: 'A', identity, grantStore: grantA, consentUrl });
  const instanceB = createInstance({ label: 'B', identity, grantStore: grantB, consentUrl });

  step('1. Agent calls checkout on instance A — with a proof, but no grant yet');
  const proof1 = await mintCheckoutProof(identity, { item: 'laptop' });
  const first = await instanceA.checkout({ item: 'laptop', _kyaos_proof: proof1 });
  say(`instance A replied: "${firstLine(first)}"`);
  check('A challenges instead of silently allowing (needs_authorization)', isChallenge(first));

  step('2. Human approves on A — once');
  await approve({ identity, grantStore: grantA, agentDid: identity.did, scopes: [SCOPE] });
  say(`an agent-anchored grant (scope "${SCOPE}") was written to the SHARED file, keyed to ${shortDid}`);

  step('3. Agent retries on a DIFFERENT instance B — fresh proof, no re-paste, no session');
  say('instance B has its own memory and never saw the approval; it only shares the file store');
  const proof2 = await mintCheckoutProof(identity, { item: 'laptop' });
  say('');
  describeProof(proof2, 'checkout {item:"laptop"}').forEach(say);
  say('');
  const retry = await instanceB.checkout({ item: 'laptop', _kyaos_proof: proof2 });
  say(`instance B replied: "${firstLine(retry)}"`);
  check('B resolves the grant from the shared file via holder-of-key (no re-paste, no session)', isConfirmed(retry));

  step('4. Confused-deputy guard — a call WITHOUT a proof must not inherit the grant');
  const noProof = await instanceB.checkout({ item: 'laptop' });
  say(`instance B replied: "${firstLine(noProof)}"`);
  check('an unsigned call is NOT auto-authorized (grant is bound to the agent key, not the tool)', isChallenge(noProof));

  step('5. OAuth half — a PKCE login started on A finishes on B (shared pending-flow store)');
  // A PKCE pending flow initiated on A is consumed on B via the shared store.
  const oidcConfig = {
    type: 'oauth' as const,
    issuer: 'https://idp.local',
    authorizationEndpoint: 'https://idp.local/authorize',
    tokenEndpoint: 'https://idp.local/token',
    clientId: 'agent-client',
    scopes: ['openid', 'vault:read'],
  };
  const protection = {
    toolName: 'vault.read',
    requirement: { type: 'oauth' as const, provider: 'generic-oidc', requiredScopes: ['vault:read'] },
  };
  const oidcA = new GenericOidcAdapter({
    ...oidcConfig,
    pendingFlowStore: new FilePendingFlowStore(path.join(dataDir, 'pending-flows.json')),
  });
  const challenge = await oidcA.initiateFlow({
    protection,
    agentDid: identity.did,
    redirectUri: 'https://app.local/cb',
    state: 'state-xyz',
  });
  const fakeToken = async (): Promise<Response> =>
    new Response(JSON.stringify({ access_token: 'at', token_type: 'Bearer', scope: 'vault:read' }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  const oidcB = new GenericOidcAdapter({
    ...oidcConfig,
    fetchImpl: fakeToken,
    pendingFlowStore: new FilePendingFlowStore(path.join(dataDir, 'pending-flows.json')),
  });
  const verified = await oidcB.verifyAuthorization(challenge.resumeToken, { code: 'code-1', state: 'state-xyz' });
  say('the PKCE flow started on A is consumed exactly once on B (one-time-use across instances)');
  check('OAuth: PKCE flow initiated on A completes on B', verified.valid === true);

  fs.rmSync(dataDir, { recursive: true, force: true });
  process.stdout.write(
    failed
      ? '\n✗ SCENARIO FAILED\n'
      : '\n✓ SCENARIO PASSED — one approval on A was honored on B.\n' +
          '  No human re-approval, no credential re-paste, no shared session: authorization rode\n' +
          '  on the holder-of-key proof plus the shared grant / pending-flow store.\n',
  );
  process.exit(failed ? 1 : 0);
}

main().catch((err) => {
  process.stderr.write(`Error: ${err}\n`);
  process.exit(1);
});
