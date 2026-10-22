import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { NodeCryptoProvider, generateDidKeyFromBase64 } from '@kya-os/mcp';

const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'payment-opt-in-'));
let merchant: Awaited<ReturnType<typeof import('../src/merchant/server.js')['createMerchant']>>;
let origin: string;

beforeAll(async () => {
  const crypto = new NodeCryptoProvider();
  const [rp, shop, agent] = await Promise.all([crypto.generateKeyPair(), crypto.generateKeyPair(), crypto.generateKeyPair()]);
  const rpDid = generateDidKeyFromBase64(rp.publicKey);
  for (const [key, value] of Object.entries({
    DEMO_ENV_FILE: '/dev/null', DEMO_VAR_DIR: path.join(directory, 'var'), DEMO_DATA_DIR: path.join(directory, 'data'),
    RP_DID: rpDid, RP_KID: `${rpDid}#${rpDid.slice(8)}`, RP_ORIGIN: 'http://127.0.0.1:1',
    RP_PRIVATE_KEY_BASE64: rp.privateKey, RP_PUBLIC_KEY_BASE64: rp.publicKey,
    MERCHANT_DID: generateDidKeyFromBase64(shop.publicKey), MERCHANT_PRIVATE_KEY_BASE64: shop.privateKey, MERCHANT_PUBLIC_KEY_BASE64: shop.publicKey,
    AGENT_DID: generateDidKeyFromBase64(agent.publicKey), AGENT_ED25519_PRIVATE_KEY_BASE64: agent.privateKey, AGENT_ED25519_PUBLIC_KEY_BASE64: agent.publicKey,
    KEY_WEBAUTHN: '0', CONSENT_WEBAUTHN: '0', KEY_SETUP: '0', OFFLINE: '0', GOOGLE_CLIENT_ID: '',
    // Optional payment configuration must not break the legacy presentation.
    PAYMENT_MODE: 'invalid-disabled-mode', X402_PAY_TO: 'invalid-disabled-recipient',
    X402_ATOMIC_UNITS_PER_CHF_CENT: 'invalid-disabled-rate', UCP_PLATFORM_PROFILES: 'invalid-disabled-profile',
  })) vi.stubEnv(key, value);
  vi.stubEnv('COMMERCE_PAYMENTS', undefined);
  const server = await import('../src/merchant/server.js');
  merchant = await server.createMerchant(server.merchantConfigFromEnv({ port: 0, witness: false, auditDir: path.join(directory, 'audit') }));
  await new Promise<void>(resolve => merchant.httpServer.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${(merchant.httpServer.address() as { port: number }).port}`;
});
afterAll(async () => {
  if (merchant?.httpServer.listening) await new Promise<void>(resolve => merchant.httpServer.close(() => resolve()));
  fs.rmSync(directory, { recursive: true, force: true });
  vi.unstubAllEnvs();
});
async function call(args: Record<string, unknown>, payment?: Record<string, unknown>) {
  const client = new Client({ name: 'legacy-default-check', version: '1.0' });
  try {
    await client.connect(new StreamableHTTPClientTransport(new URL(`${origin}/mcp`)));
    return await client.callTool({ name: 'place_order', arguments: args, ...(payment ? { _meta: { 'x402/payment': payment } } : {}) });
  } finally { await client.close(); }
}
const body = (result: Awaited<ReturnType<typeof call>>) => JSON.parse((result['content'] as Array<{ text: string }>)[0]!.text);

describe('payment additions require explicit operator opt-in', () => {
  it('starts with invalid unused payment settings and preserves legacy discovery and storage', async () => {
    expect(merchant.commerce).toBeNull();
    const discovery = await (await fetch(`${origin}/.well-known/mcp`)).json();
    expect(discovery.commerce).toMatchObject({ catalog: '/api/catalog', currency: 'CHF' });
    expect(discovery.commerce).not.toHaveProperty('x402');
    expect(discovery.commerce).not.toHaveProperty('ucp');
    expect(await (await fetch(`${origin}/api/state`)).json()).toMatchObject({ commerce: { enabled: false }, orders: 0 });
    expect(fs.existsSync(path.join(directory, 'var', 'merchant', 'commerce.json'))).toBe(false);
    expect(fs.existsSync(path.join(directory, 'var', 'agent', 'commerce.json'))).toBe(false);
    expect(fs.existsSync(path.join(directory, 'var', 'agent', 'payment-wallet.json'))).toBe(false);
  });

  it.each(['/.well-known/ucp', '/agent/.well-known/ucp', '/payments/checkouts/fixture'])('does not expose optional route %s', async route => {
    expect((await fetch(`${origin}${route}`)).status).toBe(404);
  });

  it.each(['x402', 'ucp'])('explicit %s requests fail without falling back to an unpaid order', async protocol => {
    const result = await call({ product: 'risotto', quantity: 2, checkout: { id: 'fixture', protocol } });
    expect(result.isError).toBe(true);
    expect(body(result)).toMatchObject({ error: 'PAYMENTS_DISABLED' });
    expect((await (await fetch(`${origin}/api/state`)).json()).orders).toBe(0);
  });

  it.each([
    { payment_protocol: 'x402' }, { payment_protocol: 'ucp' }, { payment_protocol: 'order-only' },
    { payment_method: 'sandbox-token' }, { checkout_id: 'existing-checkout' },
  ])('rejects explicit gateway payment arguments at the raw merchant endpoint: %j', async extra => {
    const result = await call({ product: 'risotto', quantity: 2, ...extra });
    expect(body(result)).toMatchObject({ error: 'PAYMENTS_DISABLED' });
    expect((await (await fetch(`${origin}/api/state`)).json()).orders).toBe(0);
    expect(fs.existsSync(path.join(directory, 'var', 'rp', 'consent', 'flows.json'))).toBe(false);
    expect(fs.existsSync(path.join(directory, 'var', 'merchant', 'commerce.json'))).toBe(false);
  });

  it('refuses a payment meta argument while keeping ordinary merchant calls holder-bound', async () => {
    expect(body(await call({ product: 'risotto', quantity: 2 }, { x402Version: 2 }))).toMatchObject({ error: 'PAYMENTS_DISABLED' });
    expect(body(await call({ product: 'risotto', quantity: 2 }))).toMatchObject({ error: 'holder_binding_failed' });
  });
});
