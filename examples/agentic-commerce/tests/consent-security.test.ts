/** Adversarial requests cross the real MCP transport and shipped merchant gate. */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { NodeCryptoProvider, generateDidKeyFromBase64, generateRequestProof } from '@kya-os/mcp';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const crypto = new NodeCryptoProvider();
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'consent-security-'));
const rpPort = 17500 + Math.floor(Math.random() * 1000);
const merchantPort = rpPort + 1;
let rp: ReturnType<typeof import('../src/rp/server.js')['startRpServer']>;
let merchant: Awaited<ReturnType<typeof import('../src/merchant/server.js')['startMerchantServer']>>;
let agent: typeof import('../src/agent/agent.js');
let issue: typeof import('../src/rp/issue.js');
let store: InstanceType<typeof import('../src/rp/consent-store.js')['ConsentFlowStore']>;
let agentDid: string;
let merchantDid: string;
let originalToken: string;
const scope = 'https://id.gs1.org/01/09506000134352';
async function observeVerdict<T>(action: () => Promise<T>) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);
  try {
    const stream = await fetch(`http://127.0.0.1:${merchantPort}/api/events`, { signal: controller.signal });
    const reader = stream.body!.getReader();
    await reader.read(); // Subscription is established before the real MCP call.
    const result = await action();
    let buffer = '';
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) throw new Error('Merchant event stream ended without a verdict');
      buffer += new TextDecoder().decode(chunk.value);
      for (;;) {
        const end = buffer.indexOf('\n\n');
        if (end < 0) break;
        const message = buffer.slice(0, end); buffer = buffer.slice(end + 2);
        const data = message.split('\n').find(line => line.startsWith('data:'));
        if (data) {
          const event = JSON.parse(data.slice(5));
          if (event.type === 'verdict') return { result, checks: event.checks as Record<string, string> };
        }
      }
    }
  } finally { clearTimeout(timeout); controller.abort(); }
}
const order = async (options: Partial<Parameters<typeof agent.runAgentOrder>[0]> = {}) => {
  const { result: outcome, checks } = await observeVerdict(() => agent.runAgentOrder({ product: 'risotto', quantity: 2, ...options }));
  return { result: outcome.result, body: JSON.parse(outcome.result.content![0]!.text!) as Record<string, unknown>, checks };
};

beforeAll(async () => {
  const [rpKeys, merchantKeys, agentKeys] = await Promise.all([crypto.generateKeyPair(), crypto.generateKeyPair(), crypto.generateKeyPair()]);
  merchantDid = generateDidKeyFromBase64(merchantKeys.publicKey);
  agentDid = generateDidKeyFromBase64(agentKeys.publicKey);
  Object.assign(process.env, {
    DEMO_VAR_DIR: path.join(tmp, 'var'), DEMO_DATA_DIR: path.join(tmp, 'data'),
    RP_PORT: String(rpPort), MERCHANT_PORT: String(merchantPort),
    RP_ORIGIN: `http://127.0.0.1:${rpPort}`, MERCHANT_ORIGIN: `http://127.0.0.1:${merchantPort}`,
    RP_DID: `did:web:localhost%3A${rpPort}`, RP_KID: `did:web:localhost%3A${rpPort}#key-1`,
    RP_PRIVATE_KEY_BASE64: rpKeys.privateKey, RP_PUBLIC_KEY_BASE64: rpKeys.publicKey,
    MERCHANT_DID: merchantDid, MERCHANT_PRIVATE_KEY_BASE64: merchantKeys.privateKey, MERCHANT_PUBLIC_KEY_BASE64: merchantKeys.publicKey,
    AGENT_DID: agentDid, AGENT_ED25519_PRIVATE_KEY_BASE64: agentKeys.privateKey, AGENT_ED25519_PUBLIC_KEY_BASE64: agentKeys.publicKey,
    KEY_WEBAUTHN: '0', CONSENT_WEBAUTHN: '0', KEY_SETUP: '0', OFFLINE: '0',
  });
  const rpMod = await import('../src/rp/server.js');
  const merchantMod = await import('../src/merchant/server.js');
  const { ConsentFlowStore } = await import('../src/rp/consent-store.js');
  const { ensureStatusList } = await import('../src/rp/statuslist.js');
  const { loadRpIdentity, makeVcSigningFunction, STATUS_LIST_URL } = await import('../src/lib/wiring.js');
  agent = await import('../src/agent/agent.js');
  issue = await import('../src/rp/issue.js');
  store = new ConsentFlowStore();
  const identity = loadRpIdentity();
  rpMod.ensureDidDocument(identity);
  await ensureStatusList({ identity, signingFunction: makeVcSigningFunction(identity.privateKeyBase64), url: STATUS_LIST_URL });
  rp = rpMod.startRpServer(rpPort);
  merchant = await merchantMod.startMerchantServer({ port: merchantPort, witness: false, auditDir: path.join(tmp, 'audit') });
});

afterAll(async () => {
  if (merchant) await new Promise<void>((resolve) => merchant.httpServer.close(() => resolve()));
  if (rp) await new Promise<void>((resolve) => rp.server.close(() => resolve()));
  fs.rmSync(tmp, { recursive: true, force: true });
});

const fields = (token: string) => ({ tool: 'place_order', scopes: JSON.stringify([scope]), selected_scopes: JSON.stringify([scope]), agent_did: agentDid, session_id: token });

async function rawOrder(args: Record<string, unknown>) {
  const client = new Client({ name: 'adversarial-agent', version: '1.0' });
  await client.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${merchantPort}/mcp`)));
  try {
    const { result, checks } = await observeVerdict(() => client.callTool({ name: 'place_order', arguments: args }));
    return { result, body: JSON.parse((result.content as Array<{ text: string }>)[0]!.text), checks };
  } finally { await client.close(); }
}
const flowCount = () => {
  const file = path.join(store.dir, 'flows.json');
  return fs.existsSync(file) ? Object.keys(JSON.parse(fs.readFileSync(file, 'utf8')).flows).length : 0;
};
const requestedCount = async () => {
  const report = await (await fetch(`http://127.0.0.1:${merchantPort}/api/audit/ledger`)).json();
  return report.entries.filter((entry: { eventType: string }) => entry.eventType === 'consent.requested').length;
};
async function requestProof(args: Record<string, unknown>, audience = merchantDid) {
  const { loadAgentIdentity } = await import('../src/lib/wiring.js');
  const identity = loadAgentIdentity();
  return generateRequestProof({ identity: { did: identity.did, kid: identity.kid, privateKey: identity.privateKeyBase64, publicKey: identity.publicKeyBase64 }, crypto, toolName: 'place_order', args, audience });
}

describe('consent cannot be bypassed by cached authority or a valid credential alone', () => {
  it('refuses a missing initial proof over real MCP without creating a consent flow or consent-requested audit record', async () => {
    const before = { flows: flowCount(), requested: await requestedCount() };
    const { result, body, checks } = await rawOrder({ product: 'risotto', quantity: 2 });
    expect(result.isError).toBe(true);
    expect(body.error).toBe('holder_binding_failed');
    expect(body.authorizationUrl).toBeUndefined();
    expect(flowCount()).toBe(before.flows);
    expect(await requestedCount()).toBe(before.requested);
    expect(checks).toMatchObject({ signature: 'skip', revocation: 'skip', holder: 'fail', consent: 'skip' });
  });

  it('refuses wrong-audience and request-tampered initial proofs without a flow', async () => {
    const args = { product: 'risotto', quantity: 2 };
    const before = flowCount();
    for (const invalid of [
      { ...args, _kyaos_proof: await requestProof(args, 'did:key:wrong-merchant') },
      { ...args, quantity: 9, _kyaos_proof: await requestProof(args) },
    ]) {
      const { body, checks } = await rawOrder(invalid);
      expect(body.error).toBe('holder_binding_failed');
      expect(body.authorizationUrl).toBeUndefined();
      expect(checks).toMatchObject({ signature: 'skip', holder: 'fail', consent: 'skip' });
    }
    expect(flowCount()).toBe(before);
  });

  it('accepts a fresh proof once and refuses its replay without a second flow', async () => {
    const args: Record<string, unknown> = { product: 'risotto', quantity: 2 };
    args['_kyaos_proof'] = await requestProof(args);
    const requestsBefore = await requestedCount();
    const first = await rawOrder(args);
    expect(first.body.error).toBe('needs_authorization');
    expect(first.result._meta?.['org.kya-os/response-proof']).toBeTruthy();
    expect(first.checks).toMatchObject({ signature: 'skip', holder: 'pass', consent: 'pending', receipt: 'skip' });
    expect(await requestedCount()).toBe(requestsBefore + 1);
    const before = { flows: flowCount(), requested: await requestedCount() };
    const replay = await rawOrder(args);
    expect(replay.body.error).toBe('holder_binding_failed');
    expect(flowCount()).toBe(before.flows);
    expect(await requestedCount()).toBe(before.requested);
  });
  it('gets a genuine signed challenge with no covering grant', async () => {
    const { body } = await order();
    expect(body.error).toBe('needs_authorization');
    originalToken = String(body.resumeToken);
    expect(store.get(originalToken)?.bindings).toMatchObject({ agentDid, audience: merchantDid, product: 'risotto', quantity: 2 });
  });

  it('reports an unreadable consent store at the consent gate without claiming a credential signature failed', async () => {
    const file = path.join(store.dir, 'flows.json');
    const saved = fs.readFileSync(file);
    try {
      fs.writeFileSync(file, '{');
      const args: Record<string, unknown> = { product: 'risotto', quantity: 2 };
      args['_kyaos_proof'] = await requestProof(args);
      const { body, checks } = await rawOrder(args);
      expect(body.error).toBe('CONSENT_PROTOCOL_UNAVAILABLE');
      expect(body.authorizationUrl).toBeUndefined();
      expect(checks).toMatchObject({ signature: 'skip', revocation: 'skip', holder: 'pass', consent: 'fail' });
    } finally { fs.writeFileSync(file, saved); }
  });

  it('rejects a directly minted valid RP credential lacking a human approval record', async () => {
    const vc = await issue.issueDelegation({ index: 95, agentDid, audience: merchantDid });
    const { result, body, checks } = await order({ credential: vc });
    expect(result.isError).toBe(true);
    expect(body.error).toBe('CONSENT_REQUIRED');
    expect(body.reason).toMatch(/missing signed human consent/i);
    expect(checks).toMatchObject({ signature: 'pass', revocation: 'pass', holder: 'pass', consent: 'fail', product: 'skip', cap: 'skip' });
  });

  it('does not let the SDK grant cache replace consent after the rejected VC', async () => {
    expect((await order({ credential: null })).body.error).toBe('needs_authorization');
  });

  it('keeps the delivered grant usable when scope or cap rejects an order', async () => {
    const approval = await fetch(`http://127.0.0.1:${rpPort}/consent/approve`, { method: 'POST', body: new URLSearchParams(fields(originalToken)) });
    expect(approval.ok, await approval.text()).toBe(true);
    for (const [product, quantity, code] of [['olive-oil', 1, 'PRODUCT_OUT_OF_SCOPE'], ['risotto', 5, 'SPEND_CAP_EXCEEDED']] as const) {
      const { result, body } = await order({ product, quantity });
      expect(result.isError).toBe(true);
      expect(body.error).toBe(code);
      expect(store.get(originalToken)?.state).toBe('consumed'); // RP delivery is separate from order acceptance.
    }
  });

  it('allows fresh in-scope orders even when an older caller repeatedly sends its obsolete first-use token', async () => {
    expect((await order({ quantity: 1 })).body.orderId).toMatch(/^ORD-/);
    expect(store.get(originalToken)?.state).toBe('consumed');
    const credential = (await import('../src/agent/store.js')).readAgentState().credential;
    for (const token of [originalToken, originalToken, 'unrelated-legacy-token']) {
      const args: Record<string, unknown> = { product: 'risotto', quantity: 2, _kyaos_delegation: credential, resumeToken: token };
      args['_kyaos_proof'] = await requestProof(args);
      const accepted = await rawOrder(args);
      expect(accepted.result.isError, JSON.stringify(accepted.body)).toBeFalsy();
      expect(accepted.body.orderId).toMatch(/^ORD-/);
      expect(accepted.checks).toMatchObject({ signature: 'pass', revocation: 'pass', holder: 'pass', consent: 'pass' });
    }
    expect(fs.existsSync(path.join(tmp, 'var', 'merchant', 'consent-use.json'))).toBe(false);
  });

  it('still rejects an exact request-proof replay before placing a second order', async () => {
    const credential = (await import('../src/agent/store.js')).readAgentState().credential;
    const args: Record<string, unknown> = { product: 'risotto', quantity: 1, _kyaos_delegation: credential };
    args['_kyaos_proof'] = await requestProof(args);
    expect((await rawOrder(args)).body.orderId).toMatch(/^ORD-/);
    const before = await (await fetch(`http://127.0.0.1:${merchantPort}/api/state`)).json();
    const replay = await rawOrder(args);
    expect(replay.result.isError).toBe(true);
    expect(replay.body.error).toBe('holder_binding_failed');
    expect(replay.checks).toMatchObject({ signature: 'pass', revocation: 'pass', holder: 'fail', consent: 'skip' });
    expect((await (await fetch(`http://127.0.0.1:${merchantPort}/api/state`)).json()).orders).toBe(before.orders);
    expect((await order()).body.orderId).toMatch(/^ORD-/);
  });

  it.each(['agent', 'rp'] as const)('rejects a different %s-issued credential reusing an approved credential id with wider scope and cap', async (signer) => {
    const legitimate = issue.activeCredential();
    const keys = await crypto.generateKeyPair();
    const did = generateDidKeyFromBase64(keys.publicKey);
    const { loadRpIdentity, makeVcSigningFunction } = await import('../src/lib/wiring.js');
    const identity = signer === 'rp' ? loadRpIdentity() : { did, kid: `${did}#${did.slice(8)}`, privateKeyBase64: keys.privateKey, publicKeyBase64: keys.publicKey };
    const counterfeit = await issue.issueDelegation({ index: 95, agentDid, audience: merchantDid, identity, cap: '999.00', productClass: 'https://id.gs1.org/01/09506000134369' });
    counterfeit.id = legitimate.id;
    counterfeit.credentialSubject.delegation.metadata = legitimate.credentialSubject.delegation.metadata;
    const { canonicalizeJSON } = await import('@kya-os/mcp');
    const { proof: ignored, ...unsigned } = counterfeit;
    counterfeit.proof = await makeVcSigningFunction(identity.privateKeyBase64)(canonicalizeJSON(unsigned), identity.did, identity.kid);
    const { result, body } = await order({ product: 'olive-oil', quantity: 1, credential: counterfeit });
    expect(result.isError).toBe(true);
    expect(body.error).toBe('CONSENT_BINDING_MISMATCH');
    expect(body.reason).toMatch(/signed consent attestation/i);
  });

  it('starts a fresh consent challenge when the active credential is removed after success', async () => {
    const { clearAgentState } = await import('../src/agent/store.js');
    clearAgentState();
    expect((await order()).body.error).toBe('needs_authorization');
  });

  it.each(['approved', 'unknown'] as const)('never treats an %s resume token as authority without a credential', async (kind) => {
    const before = await (await fetch(`http://127.0.0.1:${merchantPort}/api/state`)).json();
    const args: Record<string, unknown> = { product: 'risotto', quantity: 1,
      resumeToken: kind === 'approved' ? originalToken : 'unknown-token-that-is-not-issued-to-anyone' };
    args['_kyaos_proof'] = await requestProof(args);
    const { body, checks } = await rawOrder(args);
    expect(body.error).toBe('needs_authorization');
    expect(checks).toMatchObject({ holder: 'pass', consent: 'pending', receipt: 'skip' });
    expect((await (await fetch(`http://127.0.0.1:${merchantPort}/api/state`)).json()).orders).toBe(before.orders);
  });
});
