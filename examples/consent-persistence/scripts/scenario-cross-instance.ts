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
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'kya-consent-xinst-'));
  const identity = await loadIdentity();
  const consentUrl = 'http://consent.local/consent';

  // Two INDEPENDENT store objects over the SAME files: two instances, one durable backing.
  const grantA = new FileGrantStore(path.join(dataDir, 'grants.json'));
  const grantB = new FileGrantStore(path.join(dataDir, 'grants.json'));
  const instanceA = createInstance({ label: 'A', identity, grantStore: grantA, consentUrl });
  const instanceB = createInstance({ label: 'B', identity, grantStore: grantB, consentUrl });

  // 1. Call protected checkout on A with a holder-of-key proof but NO grant → challenge.
  const proof1 = await mintCheckoutProof(identity, { item: 'laptop' });
  const first = await instanceA.checkout({ item: 'laptop', _kyaos_proof: proof1 });
  check('instance A: first call (proof, no grant) returns needs_authorization', isChallenge(first));

  // 2. Approve → agent-anchored grant written to the shared durable store.
  await approve({ identity, grantStore: grantA, agentDid: identity.did, scopes: [SCOPE] });

  // 3. Retry on instance B (separate memory) with a FRESH proof, no session → success.
  const proof2 = await mintCheckoutProof(identity, { item: 'laptop' });
  const retry = await instanceB.checkout({ item: 'laptop', _kyaos_proof: proof2 });
  check('instance B: retry resolves the grant via holder-of-key (NO re-paste, NO session)', isConfirmed(retry));

  // 4. Confused-deputy guard: a call with NO proof can't resolve the agent grant.
  const noProof = await instanceB.checkout({ item: 'laptop' });
  check('instance B: a call without a holder-of-key proof is NOT auto-authorized', isChallenge(noProof));

  // 5. OAuth half: a PKCE pending flow initiated on A is consumed on B via the shared store.
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
  check('OAuth: PKCE pending flow initiated on A is consumed + completes on B', verified.valid === true);

  fs.rmSync(dataDir, { recursive: true, force: true });
  process.stdout.write(
    failed
      ? '\nSCENARIO FAILED\n'
      : '\nSCENARIO PASSED — consent survives cross-instance (holder-of-key) with no re-paste\n',
  );
  process.exit(failed ? 1 : 0);
}

main().catch((err) => {
  process.stderr.write(`Error: ${err}\n`);
  process.exit(1);
});
