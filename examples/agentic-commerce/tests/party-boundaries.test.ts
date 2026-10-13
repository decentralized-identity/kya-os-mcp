import { afterAll, beforeAll, expect, it, vi } from 'vitest';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { NodeCryptoProvider, generateDidKeyFromBase64 } from '@kya-os/mcp';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'commerce-parties-'));
const root = fileURLToPath(new URL('..', import.meta.url));
const children: ChildProcess[] = [];
let signMessage: typeof import('../src/lib/consent-protocol.js')['signMessage'];
let agentIdentity: import('../src/lib/wiring.js').KeyedIdentity, merchantIdentity: import('../src/lib/wiring.js').KeyedIdentity;
let agent: typeof import('../src/agent/agent.js');
let merchantOrigin: string, rpOrigin: string;
let output = '';
let rpEnv: NodeJS.ProcessEnv;
function launch(role: string, env: NodeJS.ProcessEnv) {
  const child = spawn(process.execPath, [path.join(root, 'node_modules/tsx/dist/cli.mjs'), path.join(root, `src/${role}/server.ts`)], { env, cwd: tmp, stdio: ['ignore', 'pipe', 'pipe'] });
  child.stdout?.on('data', chunk => { output += chunk; });
  child.stderr?.on('data', chunk => { output += chunk; });
  children.push(child);
  return child;
}
async function port() {
  const server = http.createServer();
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const value = (server.address() as { port: number }).port;
  await new Promise<void>(resolve => server.close(() => resolve()));
  return value;
}
async function ready(url: string) {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    try { if ((await fetch(url)).ok) return; } catch {}
    await new Promise(resolve => setTimeout(resolve, 30));
  }
  throw new Error(`Party failed to start: ${output}`);
}
beforeAll(async () => {
  const crypto = new NodeCryptoProvider();
  const [rpKey, merchantKey, agentKey] = await Promise.all(Array.from({ length: 3 }, () => crypto.generateKeyPair()));
  const rpPort = await port(), merchantPort = await port();
  rpOrigin = `http://127.0.0.1:${rpPort}`; merchantOrigin = `http://127.0.0.1:${merchantPort}`;
  const publicConfig = {
    DEMO_ENV_FILE: path.join(tmp, 'no-shared-env'),
    RP_PORT: String(rpPort), MERCHANT_PORT: String(merchantPort), RP_ORIGIN: rpOrigin, MERCHANT_ORIGIN: merchantOrigin,
    RP_DID: `did:web:localhost%3A${rpPort}`, RP_KID: `did:web:localhost%3A${rpPort}#key-1`,
    MERCHANT_DID: generateDidKeyFromBase64(merchantKey!.publicKey), AGENT_DID: generateDidKeyFromBase64(agentKey!.publicKey),
    STATUS_LIST_URL: `${rpOrigin}/status-list`, RP_DID_MIRROR_URL: `${rpOrigin}/.well-known/did.json`,
    GOOGLE_CLIENT_ID: '', KEY_SETUP: '0', KEY_WEBAUTHN: '0', CONSENT_WEBAUTHN: '0', OFFLINE: '0', AUDIT_WITNESS: '0',
  };
  for (const [key, value] of Object.entries({ ...publicConfig,
    DEMO_VAR_DIR: path.join(tmp, 'agent'), DEMO_DATA_DIR: path.join(tmp, 'agent-data'),
    AGENT_ED25519_PRIVATE_KEY_BASE64: agentKey!.privateKey, AGENT_ED25519_PUBLIC_KEY_BASE64: agentKey!.publicKey,
  })) vi.stubEnv(key, value);
  // Only public trust configuration crosses these process boundaries. Each
  // process receives its own private key and a different filesystem root.
  for (const [role, keys] of [['rp', rpKey!], ['merchant', merchantKey!]] as const) {
    const env: NodeJS.ProcessEnv = { PATH: process.env.PATH, ...publicConfig,
      DEMO_VAR_DIR: path.join(tmp, role), DEMO_DATA_DIR: path.join(tmp, `${role}-data`),
      [`${role.toUpperCase()}_PRIVATE_KEY_BASE64`]: keys.privateKey,
      [`${role.toUpperCase()}_PUBLIC_KEY_BASE64`]: keys.publicKey,
    };
    if (role === 'rp') rpEnv = env;
    launch(role, env);
  }
  await Promise.all([ready(`${rpOrigin}/`), ready(`${merchantOrigin}/api/state`)]);
  agent = await import('../src/agent/agent.js');
  ({ signMessage } = await import('../src/lib/consent-protocol.js'));
  const identity = (key: typeof agentKey, did: string) => ({ did, kid: `${did}#${did.slice(8)}`, publicKeyBase64: key!.publicKey, privateKeyBase64: key!.privateKey });
  agentIdentity = identity(agentKey, publicConfig.AGENT_DID);
  merchantIdentity = identity(merchantKey, publicConfig.MERCHANT_DID);
}, 20_000);
afterAll(async () => {
  await Promise.all(children.map(child => new Promise<void>(resolve => { if (child.exitCode !== null || child.signalCode !== null) return resolve(); child.once('exit', () => resolve()); child.kill('SIGTERM'); })));
  fs.rmSync(tmp, { recursive: true, force: true }); vi.unstubAllEnvs();
});

const post = (path: string, body: unknown) => fetch(`${rpOrigin}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
it('authenticates both callers at the RP and rejects replay over real HTTP', async () => {
  const order = { product: 'risotto', quantity: 2 };
  const agentRequest = { ...order, _kyaos_proof: (await signMessage('place_order', order, agentIdentity, merchantIdentity.did)).proof };
  const body = { bindings: { agentDid: agentIdentity.did, audience: merchantIdentity.did, ...order,
    productClass: 'https://id.gs1.org/01/09506000134352', cap: '50.00', currency: 'CHF', validHours: 48 }, agentRequest };
  expect((await post('/consent/requests', { body })).status).toBe(400);
  expect((await post('/consent/requests', await signMessage('consent.create', body, agentIdentity, process.env.RP_DID!))).status).toBe(400);
  const message = await signMessage('consent.create', body, merchantIdentity, process.env.RP_DID!);
  const created = await post('/consent/requests', message);
  expect(created.status).toBe(200);
  const reply = await created.json();
  expect((await post('/consent/requests', message)).status).toBe(400);
  // A fresh merchant envelope cannot launder a replayed agent proof.
  expect((await post('/consent/requests', await signMessage('consent.create', body, merchantIdentity, process.env.RP_DID!))).status).toBe(400);
  const pickup = { resumeToken: reply.body.challenge.resumeToken, audience: merchantIdentity.did };
  expect((await post('/consent/pickup', { body: pickup })).status).toBe(400);
  expect((await post('/consent/pickup', await signMessage('consent.pickup', pickup, merchantIdentity, process.env.RP_DID!))).status).toBe(400);
  const signedPickup = await signMessage('consent.pickup', pickup, agentIdentity, process.env.RP_DID!);
  expect((await post('/consent/pickup', signedPickup)).status).toBe(200);
  expect((await post('/consent/pickup', signedPickup)).status).toBe(400);
});

it('carries consent and credential delivery over HTTP with separate RP, merchant and agent storage', async () => {
  const challenged = await agent.runAgentOrder({ product: 'risotto', quantity: 2 });
  const challenge = JSON.parse(challenged.result.content![0]!.text!);
  expect(challenge.error).toBe('needs_authorization');
  const page = await fetch(challenge.authorizationUrl);
  expect(page.status, 'RP must know the consent request without opening a merchant file').toBe(200);
  const decision = await fetch(`${rpOrigin}/consent/approve`, { method: 'POST', body: new URLSearchParams({
    tool: 'place_order', agent_did: process.env.AGENT_DID!, session_id: challenge.resumeToken,
    scopes: JSON.stringify(challenge.scopes), selected_scopes: JSON.stringify(challenge.scopes),
  }) });
  expect(decision.ok, await decision.text()).toBe(true);
  const agentFile = path.join(tmp, 'agent', 'agent', 'state.json');
  expect(JSON.parse(fs.readFileSync(agentFile, 'utf8')).credential, 'RP approval must not write the agent store').toBeUndefined();
  const approved = await agent.runAgentOrder({ product: 'risotto', quantity: 1 });
  expect(approved.result.isError, JSON.stringify(approved.result)).toBeFalsy();
  const receipt = JSON.parse(approved.result.content![0]!.text!);
  expect(receipt.orderId).toMatch(/^ORD-/);
  expect(receipt.consent.consentRef).toMatch(/^sha256:/);
  const issued = JSON.parse(fs.readFileSync(agentFile, 'utf8')).credential;
  expect(issued.credentialSubject.delegation.metadata.consent).toMatchObject({ consentRef: receipt.consent.consentRef, authentication: 'rp-local-approval', agentDid: process.env.AGENT_DID, audience: process.env.MERCHANT_DID });
  const altered = structuredClone(issued);
  altered.credentialSubject.delegation.metadata.consent.consentRef = 'sha256:' + '0'.repeat(64);
  expect((await agent.runAgentOrder({ product: 'risotto', credential: altered })).result.isError).toBe(true);
  // Lost delivery responses are recoverable with a fresh bound pickup proof.
  const pickupBody = { resumeToken: challenge.resumeToken, audience: process.env.MERCHANT_DID };
  const recovered = await post('/consent/pickup', await signMessage('consent.pickup', pickupBody, agentIdentity, process.env.RP_DID!));
  expect((await recovered.json()).body.credential).toEqual(issued);
  expect((await post('/consent/pickup', await signMessage('consent.pickup', { ...pickupBody, audience: agentIdentity.did }, agentIdentity, process.env.RP_DID!))).status).toBe(400);
  const rpLedger = await (await fetch(`${rpOrigin}/api/rp/audit/ledger`)).json();
  const merchantLedger = await (await fetch(`${merchantOrigin}/api/audit/ledger`)).json();
  expect(rpLedger.recorder.did).toBe(process.env.RP_DID);
  expect(merchantLedger.recorder.did).toBe(process.env.MERCHANT_DID);
  expect(rpLedger.entries.map((e: { eventType: string }) => e.eventType)).toContain('consent.approved');
  expect(merchantLedger.entries.map((e: { eventType: string }) => e.eventType)).not.toContain('consent.approved');
  expect(merchantLedger.entries.map((e: { correlationId: string }) => e.correlationId)).toContain(receipt.consent.consentRef);
  // The merchant cannot consult the RP's private consent state on a retry.
  const rpFlows = path.join(tmp, 'rp', 'rp', 'consent', 'flows.json');
  const saved = fs.readFileSync(rpFlows);
  try {
    fs.writeFileSync(rpFlows, 'intentionally unreadable private RP state');
    const retry = await agent.runAgentOrder({ product: 'risotto', quantity: 2 });
    expect(JSON.parse(retry.result.content![0]!.text!).orderId).toMatch(/^ORD-/);
  } finally { fs.writeFileSync(rpFlows, saved); }
  const revoked = await fetch(`${rpOrigin}/api/rp/revoke`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
  expect(revoked.ok).toBe(true);
  const refused = await agent.runAgentOrder({ product: 'risotto', quantity: 1 });
  expect(refused.result.isError).toBe(true);
  expect(refused.result.content![0]!.text).toMatch(/revoked/i);
  const finalRp = await (await fetch(`${rpOrigin}/api/rp/audit/ledger`)).json();
  expect(finalRp.entries.find((e: { eventType: string }) => e.eventType === 'delegation.revoked').correlationId).toBe(receipt.consent.consentRef);
  const exported = await (await post('/api/rp/audit/export', {})).json();
  for (const dimension of ['cryptographicIntegrity', 'chainIntegrity', 'checkpointIntegrity']) expect(exported.reports.honest[dimension].verdict).toBe('valid');
  for (const [file, exit] of [[exported.files.bundle, 0], [exported.files.tampered, 1]] as const) {
    const sdk = spawnSync(process.execPath, [path.join(root, 'node_modules/@kya-os/mcp/dist/audit/cli.js'), 'verify', file, '--policy', exported.files.policy, '--keys', exported.files.keys], { encoding: 'utf8' });
    expect(sdk.status, sdk.stdout + sdk.stderr).toBe(exit);
    const python = spawnSync('python3', [path.join(root, 'scripts/verify-ledger.py'), file, '--keys', exported.files.keys, '--quiet'], { encoding: 'utf8' });
    expect(python.status, python.stdout + python.stderr).toBe(exit);
  }
}, 20_000);

it('replays the RP-owned consent history in a distinct epoch after restarting only the RP', async () => {
  const previous = await (await fetch(`${rpOrigin}/api/rp/audit/ledger`)).json();
  const oldRp = children[0]!;
  await new Promise<void>(resolve => { oldRp.once('exit', () => resolve()); oldRp.kill('SIGTERM'); });
  launch('rp', rpEnv);
  await ready(`${rpOrigin}/`);
  const current = await (await fetch(`${rpOrigin}/api/rp/audit/ledger`)).json();
  expect(current.ledger.ledgerId).toBe(previous.ledger.ledgerId);
  expect(current.ledger.ledgerEpochId).not.toBe(previous.ledger.ledgerEpochId);
  const events = (report: typeof current) => report.entries.slice(1).map((entry: { eventType: string; correlationId: string }) => [entry.eventType, entry.correlationId]);
  expect(events(current)).toEqual(events(previous));
  expect(current.chainIntact).toBe(true);
  expect((await agent.runAgentOrder({ product: 'risotto' })).result.content![0]!.text).toMatch(/revoked/i);
}, 20_000);

async function freshChallenge() {
  (await import('../src/agent/store.js')).clearAgentState();
  const result = await agent.runAgentOrder({ product: 'risotto', quantity: 2 });
  const challenge = JSON.parse(result.result.content![0]!.text!) as import('../src/lib/consent-contract.js').ConsentChallenge;
  expect(challenge.error).toBe('needs_authorization');
  return challenge;
}
async function decide(challenge: import('../src/lib/consent-contract.js').ConsentChallenge, decision: 'approve' | 'deny') {
  return fetch(`${rpOrigin}/consent/${decision}`, { method: 'POST', body: new URLSearchParams({
    tool: 'place_order', agent_did: agentIdentity.did, session_id: challenge.resumeToken,
    scopes: JSON.stringify(challenge.scopes), selected_scopes: JSON.stringify(challenge.scopes),
  }) });
}
function expireChallenge(token: string) {
  // Age only this fixture's decision deadline. Real HTTP, proofs, credential
  // validity, and the independently running RP/merchant clocks stay unchanged.
  const file = path.join(tmp, 'rp', 'rp', 'consent', 'flows.json');
  const data = JSON.parse(fs.readFileSync(file, 'utf8'));
  data.flows[token].challenge.expiresAt = Math.floor(Date.now() / 1000) - 1;
  fs.writeFileSync(file, JSON.stringify(data));
}
async function pickup(token: string, audience = merchantIdentity.did) {
  return post('/consent/pickup', await signMessage('consent.pickup', {
    resumeToken: token, audience,
  }, agentIdentity, process.env.RP_DID!));
}

it('delivers an approved grant after the decision deadline and recovers that same grant after a lost pickup response', async () => {
  const challenge = await freshChallenge();
  expect((await decide(challenge, 'approve')).ok).toBe(true);
  const issued = (await (await fetch(`${rpOrigin}/api/rp/delegation`)).json()).credential;
  expireChallenge(challenge.resumeToken);

  // The first delivery response is lost before the agent persists it.
  const first = await pickup(challenge.resumeToken);
  expect(first.status).toBe(200);
  expect((await first.json()).body).toEqual({ requestNonce: expect.any(String), state: 'approved', credential: issued });
  expect((await pickup(challenge.resumeToken, agentIdentity.did)).status).toBe(400);

  const recovered = await agent.runAgentOrder({ product: 'risotto', quantity: 1 });
  expect(recovered.result.isError, JSON.stringify(recovered.result)).toBeFalsy();
  expect(recovered.presented.credentialId).toBe(issued.id);
  expect((await import('../src/agent/store.js')).readAgentState().credential).toEqual(issued);
  expect((await decide(challenge, 'approve')).ok).toBe(false);
  const ledger = await (await fetch(`${rpOrigin}/api/rp/audit/ledger`)).json();
  const consentRef = issued.credentialSubject.delegation.metadata.consent.consentRef;
  expect(ledger.entries.filter((e: { eventType: string; correlationId: string }) => e.eventType === 'delegation.issued' && e.correlationId === consentRef)).toHaveLength(1);
});

it.each(['pending', 'denied'] as const)('preserves %s decision semantics after the deadline without delivering authority', async (state) => {
  const challenge = await freshChallenge();
  if (state === 'denied') expect((await decide(challenge, 'deny')).ok).toBe(true);
  expireChallenge(challenge.resumeToken);
  const response = await pickup(challenge.resumeToken);
  expect(response.status).toBe(200);
  expect((await response.json()).body).toEqual({ requestNonce: expect.any(String), state: state === 'pending' ? 'expired' : 'denied' });
  expect((await decide(challenge, 'approve')).ok).toBe(false);
});

it('keeps a picked-up grant usable for later orders after the first merchant response is lost', async () => {
  const challenge = await freshChallenge();
  expect((await decide(challenge, 'approve')).ok).toBe(true);
  const ordersBefore = (await (await fetch(`${merchantOrigin}/api/state`)).json()).orders;
  const realFetch = globalThis.fetch;
  const requests: Record<string, unknown>[] = [];
  let loseResponse = true;
  const intercepted = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const response = await realFetch(input, init);
    if (String(input) === `${merchantOrigin}/mcp` && typeof init?.body === 'string') {
      const request = JSON.parse(init.body);
      if (request.method === 'tools/call' && request.params.name === 'place_order') {
        requests.push(request.params.arguments);
        if (loseResponse) {
          loseResponse = false;
          const reply = await response.clone().json();
          expect(JSON.parse(reply.result.content[0].text).orderId).toMatch(/^ORD-/);
          throw new TypeError('Simulated lost merchant response after acceptance');
        }
      }
    }
    return response;
  });
  try {
    await expect(agent.runAgentOrder({ product: 'risotto', quantity: 2 })).rejects.toThrow(/Simulated lost merchant response/);
    expect((await (await realFetch(`${merchantOrigin}/api/state`)).json()).orders).toBe(ordersBefore + 1);
    // This is a separate, explicit order. No automatic purchase retry occurs.
    const later = await agent.runAgentOrder({ product: 'risotto-lot', quantity: 1 });
    expect(later.result.isError, JSON.stringify(later.result)).toBeFalsy();
    expect(JSON.parse(later.result.content![0]!.text!).orderId).toMatch(/^ORD-/);
    expect(requests).toHaveLength(2);
    for (const request of requests) expect(request).not.toHaveProperty('resumeToken');
    expect(fs.existsSync(path.join(tmp, 'merchant', 'merchant', 'consent-use.json'))).toBe(false);
  } finally { intercepted.mockRestore(); }
});
