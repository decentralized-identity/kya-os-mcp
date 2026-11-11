import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { NodeCryptoProvider, generateDidKeyFromBase64 } from '@kya-os/mcp';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'payment-protocol-e2e-'));
const crypto = new NodeCryptoProvider();
const rpPort = 31000 + Math.floor(Math.random() * 1000), merchantPort = rpPort + 1;
const origin = `http://localhost:${merchantPort}`;
let rp: ReturnType<typeof import('../src/rp/server.js')['startRpServer']>;
let merchant: Awaited<ReturnType<typeof import('../src/merchant/server.js')['startMerchantServer']>>;
let paymentRuntime: NonNullable<typeof merchant.commerce>;
let commerce: typeof import('../src/agent/commerce.js');
let merchantDid: string;
const responseBody = (result: { content?: Array<{ text?: string }> }) => JSON.parse(result.content?.[0]?.text ?? '{}');

beforeAll(async () => {
  const [r, m, a] = await Promise.all([crypto.generateKeyPair(), crypto.generateKeyPair(), crypto.generateKeyPair()]);
  merchantDid = generateDidKeyFromBase64(m.publicKey);
  Object.assign(process.env, {
    DEMO_VAR_DIR: path.join(tmp, 'var'), DEMO_DATA_DIR: path.join(tmp, 'data'), GOOGLE_CLIENT_ID: '',
    RP_PORT: String(rpPort), MERCHANT_PORT: String(merchantPort), MERCHANT_ORIGIN: origin,
    RP_ORIGIN: `http://localhost:${rpPort}`, RP_DID: `did:web:localhost%3A${rpPort}`, RP_KID: `did:web:localhost%3A${rpPort}#key-1`,
    STATUS_LIST_URL: `http://localhost:${rpPort}/status-list`, RP_DID_MIRROR_URL: `http://localhost:${rpPort}/.well-known/did.json`,
    RP_PRIVATE_KEY_BASE64: r.privateKey, RP_PUBLIC_KEY_BASE64: r.publicKey,
    MERCHANT_DID: merchantDid, MERCHANT_PRIVATE_KEY_BASE64: m.privateKey, MERCHANT_PUBLIC_KEY_BASE64: m.publicKey,
    AGENT_DID: generateDidKeyFromBase64(a.publicKey), AGENT_ED25519_PRIVATE_KEY_BASE64: a.privateKey, AGENT_ED25519_PUBLIC_KEY_BASE64: a.publicKey,
    KEY_WEBAUTHN: '0', CONSENT_WEBAUTHN: '0', KEY_SETUP: '0', OFFLINE: '0', COMMERCE_PAYMENTS: '1', PAYMENT_MODE: 'sandbox',
    X402_PAY_TO: '0x000000000000000000000000000000000000dEaD', X402_ATOMIC_UNITS_PER_CHF_CENT: '10000',
  });
  const rpModule = await import('../src/rp/server.js');
  const wiring = await import('../src/lib/wiring.js');
  expect(wiring.VAR_DIR).toBe(path.join(tmp, 'var'));
  expect(wiring.DATA_DIR).toBe(path.join(tmp, 'data'));
  expect(wiring.RP_DID).toBe(`did:web:localhost%3A${rpPort}`);
  const { ensureStatusList } = await import('../src/rp/statuslist.js');
  const identity = wiring.loadRpIdentity();
  rpModule.ensureDidDocument(identity);
  await ensureStatusList({ identity, signingFunction: wiring.makeVcSigningFunction(identity.privateKeyBase64), url: wiring.STATUS_LIST_URL });
  rp = rpModule.startRpServer(rpPort);
  merchant = await (await import('../src/merchant/server.js')).startMerchantServer({ port: merchantPort, origin, witness: true, auditDir: path.join(tmp, 'audit') });
  if (!merchant.commerce) throw new Error('Payment fixture requires the explicit commerce opt-in');
  paymentRuntime = merchant.commerce;
  commerce = await import('../src/agent/commerce.js');
});
afterAll(async () => {
  if (merchant) await new Promise<void>(resolve => merchant.httpServer.close(() => resolve()));
  if (rp) await new Promise<void>(resolve => rp.server.close(() => resolve()));
  fs.rmSync(tmp, { recursive: true, force: true });
});
async function run(paymentProtocol: 'x402' | 'ucp', paymentMethod: 'x402' | 'sandbox-token' = 'x402', product = 'risotto', quantity = 2, checkoutId?: string) {
  const result = await commerce.runAgentCommerce({ product, quantity, paymentProtocol, paymentMethod, checkoutId, serverUrl: `${origin}/mcp`, audience: merchantDid });
  return { result, body: responseBody(result.result) };
}
async function approveGrant(body: Record<string, unknown>) {
  const response = await fetch(new URL('/consent/approve', String(body['authorizationUrl'])), { method: 'POST', body: new URLSearchParams({
    tool: 'place_order', scopes: JSON.stringify(body['scopes']), selected_scopes: JSON.stringify(body['scopes']),
    agent_did: process.env['AGENT_DID']!, session_id: String(body['resumeToken']),
  }) });
  expect(response.ok, await response.text()).toBe(true);
}
async function confirmCheckout(url: string) {
  expect(new URL(url).origin).toBe(origin);
  const html = await (await fetch(url)).text();
  expect(html).toContain('Confirm the exact purchase');
  const digest = /name="terms_digest" value="([^"]+)"/.exec(html)![1]!;
  const id = new URL(url).pathname.split('/').at(-1)!;
  const response = await fetch(`${origin}/checkout/${id}/confirm`, { method: 'POST', headers: { Origin: origin }, body: new URLSearchParams({
    token: new URL(url).searchParams.get('token')!, terms_digest: digest, confirm: 'yes',
  }) });
  expect(response.ok, await response.text()).toBe(true);
}

describe('real RP, merchant, SDK payment and UCP wire flow', () => {
  it('advertises real protocol endpoints and requires human delegation before x402 signing or settlement', async () => {
    const discovery = await (await fetch(`${origin}/.well-known/mcp`)).json();
    expect(discovery.commerce).toMatchObject({ catalog: '/api/catalog', currency: 'CHF', x402: { version: 2, mode: 'sandbox' } });
    const profile = await (await fetch(`${origin}/.well-known/ucp`)).json();
    expect(profile.ucp.version).toBe('2026-08-25');
    expect(profile.ucp.services['dev.ucp.shopping'][0].endpoint).toBe(`${origin}/ucp`);
    const settle = vi.spyOn(paymentRuntime.rail, 'settle');
    const challenge = await run('x402');
    expect(challenge.body.error).toBe('needs_authorization');
    expect(settle).not.toHaveBeenCalled();
    await approveGrant(challenge.body);
  });

  it('completes genuine SDK-signed x402 over Streamable HTTP with a signed merchant receipt and one simulated settlement', async () => {
    const settle = vi.spyOn(paymentRuntime.rail, 'settle'); settle.mockClear();
    const completed = await run('x402');
    expect(completed.body, JSON.stringify(completed.body)).toMatchObject({ ok: true, payment: { status: 'simulated', rail: 'x402' } });
    expect(completed.body.orderId).toMatch(/^ORD-/);
    expect(completed.result.result._meta?.['org.kya-os/response-proof']).toBeTruthy();
    expect(completed.result.result._meta?.['x402/payment-response']).toMatchObject({ success: true, transaction: '' });
    expect(settle).toHaveBeenCalledTimes(1);
  });

  for (const rail of ['x402', 'sandbox-token'] as const) it(`UCP ${rail}: human reviews exact checkout, agent retries, same KYA verifier gates completion`, async () => {
    const first = await run('ucp', rail, 'risotto', 2);
    const url = String(first.body.continue_url ?? first.body.continueUrl ?? first.body.authorizationUrl ?? '');
    expect(url, JSON.stringify(first.body)).toContain('/checkout/');
    const id = String(first.body.checkoutId);
    const record = paymentRuntime.coordinator.get(id);
    expect(record?.state).toBe('open');
    await confirmCheckout(url);
    const second = await run('ucp', rail, 'risotto', 2, id);
    expect(second.body, JSON.stringify(second.body)).toMatchObject({ ok: true, payment: { status: 'simulated', rail } });
    expect(paymentRuntime.coordinator.get(id)?.state).toBe('settled');
  });

  it('wrong product and over-cap requests cannot reach either payment provider', async () => {
    const settle = vi.spyOn(paymentRuntime.rail, 'settle'); settle.mockClear();
    expect((await run('x402', 'x402', 'olive-oil', 1)).body.error).toBe('PRODUCT_OUT_OF_SCOPE');
    expect((await run('x402', 'x402', 'risotto', 5)).body.error).toBe('SPEND_CAP_EXCEEDED');
    expect(settle).not.toHaveBeenCalled();
  });

  it('a UCP checkout sent to the MCP order endpoint cannot silently become an unpaid order', async () => {
    const before = await (await fetch(`${origin}/api/state`)).json();
    const { runAgentOrder } = await import('../src/agent/agent.js');
    const result = await runAgentOrder({ product: 'risotto', quantity: 2,
      serverUrl: `${origin}/mcp`, audience: merchantDid,
      checkout: { id: 'wrong-transport', protocol: 'ucp', termsDigest: 'sha256:wrong-transport' },
    });
    expect(responseBody(result.result).error).toBe('CHECKOUT_PROTOCOL_UNSUPPORTED');
    const after = await (await fetch(`${origin}/api/state`)).json();
    expect(after.orders).toBe(before.orders);
  });

  it.each([
    { payment_protocol: 'x402' }, { payment_method: 'sandbox-token' }, { checkout_id: 'wrong-transport' },
  ])('a correctly holder-bound gateway argument cannot become an unpaid raw MCP order: %j', async extra => {
    const before = await (await fetch(`${origin}/api/state`)).json();
    const flowFile = path.join(tmp, 'var', 'rp', 'consent', 'flows.json');
    const flows = fs.readFileSync(flowFile, 'utf8');
    const { prepareAgentOrder } = await import('../src/agent/agent.js');
    const { generateRequestProof } = await import('@kya-os/mcp');
    const prepared = await prepareAgentOrder({ product: 'risotto', quantity: 2, audience: merchantDid });
    const args: Record<string, unknown> = { ...prepared.args, ...extra };
    args['_kyaos_proof'] = await generateRequestProof({ toolName: 'place_order', args, audience: merchantDid, crypto,
      identity: { did: prepared.identity.did, kid: prepared.identity.kid, privateKey: prepared.identity.privateKeyBase64, publicKey: prepared.identity.publicKeyBase64 },
    });
    const client = new Client({ name: 'transport-mismatch-check', version: '1.0' });
    try {
      await client.connect(new StreamableHTTPClientTransport(new URL(`${origin}/mcp`)));
      const result = await client.callTool({ name: 'place_order', arguments: args });
      expect(result.isError).toBe(true);
      expect(JSON.parse((result['content'] as Array<{ text: string }>)[0]!.text)).toMatchObject({ error: 'CHECKOUT_PROTOCOL_UNSUPPORTED' });
    } finally { await client.close(); }
    expect((await (await fetch(`${origin}/api/state`)).json()).orders).toBe(before.orders);
    expect(fs.readFileSync(flowFile, 'utf8')).toBe(flows);
  });

  it('the same signed credential is refused on x402 after RP revocation, before any new payment', async () => {
    const response = await fetch(`http://localhost:${rpPort}/api/rp/revoke`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    expect(response.ok).toBe(true);
    const settle = vi.spyOn(paymentRuntime.rail, 'settle'); settle.mockClear();
    const denied = await run('x402', 'x402', 'risotto', 2);
    expect(denied.body.error).toBe('delegation_invalid');
    expect(String(denied.body.reason)).toMatch(/revoked/i);
    expect(settle).not.toHaveBeenCalled();
  });

  it('payment evidence is committed to the existing signed audit without exposing payment credentials', async () => {
    const report = await (await fetch(`${origin}/api/act/audit`, { method: 'POST' })).json();
    expect(report.chainIntact).toBe(true);
    expect(report.allIncluded).toBe(true);
    const journal = paymentRuntime.coordinator.journal.read();
    expect(Object.values(journal.records).filter(record => record.state === 'settled')).toHaveLength(3);
    const serialized = JSON.stringify(report);
    expect(serialized).not.toContain('sandbox_');
    expect(serialized).not.toContain('TransferWithAuthorization');
  });
});
