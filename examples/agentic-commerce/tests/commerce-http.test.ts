import { afterEach, describe, expect, it, vi } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { NodeCryptoProvider, generateDidKeyFromBase64 } from '@kya-os/mcp';
import type { PaymentRequired } from '@x402/core/types';
import { mountCommerce } from '../src/commerce/mount.js';
import { createX402Payment } from '../src/payments/x402-client.js';
import { ConsentProtocol, signMessage, type SignedMessage } from '../src/lib/consent-protocol.js';
import type { KeyedIdentity } from '../src/lib/wiring.js';
import type { OrderExecution } from '../src/merchant/server.js';

const directories: string[] = [];
const servers: ReturnType<typeof serve>[] = [];
const paymentKey = `0x${'1'.repeat(64)}` as const;
const productUri = 'https://id.gs1.org/01/09506000134352';
const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64');
afterEach(async () => {
  await Promise.all(servers.splice(0).map(server => new Promise<void>(resolve => server.close(() => resolve()))));
  directories.splice(0).forEach(directory => fs.rmSync(directory, { recursive: true, force: true }));
  vi.restoreAllMocks(); vi.unstubAllEnvs();
});
async function identity(): Promise<KeyedIdentity> {
  const key = await new NodeCryptoProvider().generateKeyPair();
  const did = generateDidKeyFromBase64(key.publicKey);
  return { did, kid: `${did}#${did.slice(8)}`, privateKeyBase64: key.privateKey, publicKeyBase64: key.publicKey };
}
async function fixture() {
  vi.stubEnv('PAYMENT_MODE', 'sandbox'); vi.stubEnv('X402_PAY_TO', undefined); vi.stubEnv('UCP_PLATFORM_PROFILES', '');
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'commerce-http-')); directories.push(directory);
  const [owner, merchant] = await Promise.all([identity(), identity()]);
  const app = new Hono();
  const server = serve({ fetch: app.fetch, port: 0, hostname: '127.0.0.1' }); servers.push(server);
  if (!server.listening) await once(server, 'listening');
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Missing server port');
  const origin = `http://127.0.0.1:${address.port}`;
  let revoked = false;
  const proofs = new ConsentProtocol();
  // The RP/status-list integration is covered by payment-e2e. This fixture
  // exercises the HTTP adapters with real holder proofs and a controlled gate.
  const authorize = vi.fn(async (args: Record<string, unknown>, execute?: OrderExecution) => {
    const clean = Object.fromEntries(Object.entries(args).filter(([name]) => !name.startsWith('_kyaos')));
    await proofs.verify('place_order', { body: clean, proof: args['_kyaos_proof'] } as SignedMessage, owner.did, merchant.did);
    if (revoked) return { isError: true, content: [{ type: 'text', text: JSON.stringify({ error: 'delegation_invalid', reason: 'Grant revoked' }) }] };
    const result = await execute!({ vc: { credentialSubject: { id: owner.did } } as never,
      outcome: { ok: true, quantity: 2, total: 'CHF 39.80', currency: 'CHF', item: { uri: productUri, unitPrice: '19.90' } } as never,
      evidence: { merchant: { did: merchant.did }, order: { quantity: 2, total: 'CHF 39.80' } },
    });
    return { content: [{ type: 'text', text: JSON.stringify(result.body) }] };
  });
  const onPayment = vi.fn(async (_event: Record<string, unknown>) => {});
  const mounted = mountCommerce(app, { origin, merchantDid: merchant.did, file: path.join(directory, 'commerce.json'), authorize,
    beforeSettlement: async () => { if (revoked) throw new Error('Grant revoked'); }, onPayment, broadcast() {},
    signStatus: (body, audience) => signMessage('payment.status.result', body, merchant, audience),
  });
  async function orderArgs(clean: Record<string, unknown>) {
    return { ...clean, _kyaos_proof: (await signMessage('place_order', clean, owner, merchant.did)).proof };
  }
  async function status(id: string, actor = owner) {
    const message = await signMessage('payment.status', { id }, actor, merchant.did);
    const response = await fetch(`${origin}/payments/checkouts/${id}`, { headers: { 'X-KYA-Request': encode(message) } });
    return { response, message };
  }
  async function ucp(operation: 'create' | 'complete', body: Record<string, unknown>, id?: string, order?: Record<string, unknown>) {
    body = JSON.parse(JSON.stringify(body)) as Record<string, unknown>;
    const key = randomUUID();
    const proof = await signMessage(`ucp.${operation}`, { id: id ?? null, body, idempotencyKey: key, profile: mounted.profileUrl }, owner, merchant.did);
    return fetch(`${origin}/ucp/checkout-sessions${id ? `/${id}/complete` : ''}`, { method: 'POST',
      headers: { 'Content-Type': 'application/json', 'UCP-Agent': `profile="${mounted.profileUrl}"`, 'Request-Id': randomUUID(), 'Idempotency-Key': key,
        'X-KYA-Request': encode(proof), ...(order ? { 'X-KYA-Order': encode({ args: order }) } : {}) }, body: JSON.stringify(body),
    });
  }
  async function prepareUcp() {
    const response = await ucp('create', { line_items: [{ item: { id: productUri }, quantity: 2 }], kya: { rail: 'x402' } });
    expect(response.status).toBe(201);
    const checkout = await response.json();
    const page = await (await fetch(checkout.continue_url)).text();
    const digest = /name="terms_digest" value="([^"]+)"/.exec(page)?.[1];
    expect(digest).toBeTruthy();
    const review = new URL(checkout.continue_url);
    const confirmation = await fetch(`${origin}/checkout/${checkout.id}/confirm`, { method: 'POST', headers: { Origin: origin },
      body: new URLSearchParams({ token: review.searchParams.get('token')!, terms_digest: digest!, confirm: 'yes' }),
    });
    expect(confirmation.status).toBe(200);
    const record = mounted.coordinator.get(checkout.id)!;
    const payload = await createX402Payment(record.quote.paymentRequired, { privateKey: paymentKey, payTo: mounted.rail.payTo, maxAtomicAmount: record.quote.requirements.amount });
    const body = { payment: { instruments: [{ id: 'pi-demo', handler_id: 'kya_x402', type: 'x402', credential: { type: 'x402', payload } }] } };
    const clean = { product: record.product, quantity: record.quantity, checkout: { id: record.id, protocol: 'ucp', termsDigest: record.termsDigest } };
    return { record, body, clean };
  }
  return { ...mounted, origin, owner, merchant, authorize, onPayment, orderArgs, status, ucp, prepareUcp, revoke: () => { revoked = true; } };
}

describe('raw HTTP commerce and authenticated resource recovery', () => {
  it('carries standard x402 v2 HTTP 402, PAYMENT-REQUIRED, PAYMENT-SIGNATURE and PAYMENT-RESPONSE headers', async () => {
    const f = await fixture();
    const settle = vi.spyOn(f.rail, 'settle');
    const clean = { product: 'risotto', quantity: 2, checkout: { id: 'http-intent', protocol: 'x402' } };
    const quote = await fetch(`${f.origin}/payments/x402`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(await f.orderArgs(clean)) });
    expect(quote.status).toBe(402);
    expect(quote.headers.get('cache-control')).toBe('no-store');
    const required = JSON.parse(Buffer.from(quote.headers.get('PAYMENT-REQUIRED')!, 'base64').toString()) as PaymentRequired;
    expect(required).toEqual(await quote.json());
    expect(required).toMatchObject({ x402Version: 2, resource: { url: `${f.origin}/payments/checkouts/http-intent` }, accepts: [{ network: 'eip155:84532', scheme: 'exact', amount: '39800000' }] });
    expect(settle).not.toHaveBeenCalled();
    const record = f.coordinator.get('http-intent')!;
    const payload = await createX402Payment(required, { privateKey: paymentKey, payTo: f.rail.payTo, maxAtomicAmount: record.quote.requirements.amount });
    const paid = await fetch(`${f.origin}/payments/x402`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'PAYMENT-SIGNATURE': encode(payload) },
      body: JSON.stringify(await f.orderArgs({ ...clean, checkout: { ...clean.checkout, termsDigest: record.termsDigest } })),
    });
    expect(paid.status).toBe(200);
    const body = await paid.json();
    const response = JSON.parse(Buffer.from(paid.headers.get('PAYMENT-RESPONSE')!, 'base64').toString());
    expect(response).toEqual(body.payment.response);
    expect(response).toMatchObject({ success: true, network: 'eip155:84532', transaction: '' });
    expect(body).toMatchObject({ ok: true, payment: { status: 'simulated', simulated: true } });
    expect(settle).toHaveBeenCalledOnce();

    f.revoke(); // Reading an old receipt must survive loss of current authority.
    f.authorize.mockClear(); settle.mockClear(); f.onPayment.mockClear();
    const recovered = await f.status(record.id);
    expect(recovered.response.status).toBe(200);
    const signed = await recovered.response.json() as SignedMessage;
    const verified = await new ConsentProtocol().verify('payment.status.result', signed, f.merchant.did, f.owner.did);
    expect(verified).toMatchObject({ id: record.id, state: 'settled', protocol: 'x402', termsDigest: record.termsDigest, requestNonce: recovered.message.proof.meta.nonce, result: { orderId: body.orderId } });
    for (const privateField of ['reviewToken', 'tokenHash', 'paymentIdentity', '_kyaos_delegation', '_kyaos_proof']) expect(JSON.stringify(signed)).not.toContain(privateField);
    expect(f.authorize).not.toHaveBeenCalled(); expect(settle).not.toHaveBeenCalled(); expect(f.onPayment).not.toHaveBeenCalled();
  });

  it('requires exact fresh owner proofs for the quoted resource and does not expose another holder’s state', async () => {
    const f = await fixture();
    const record = await f.coordinator.prepare({ id: 'private-checkout', owner: f.owner.did, protocol: 'x402', product: 'risotto', quantity: 2, rail: 'x402' });
    expect((await fetch(record.quote.paymentRequired.resource!.url)).status).toBe(401);
    expect((await f.status(record.id, await identity())).response.status).toBe(404);
    const first = await f.status(record.id);
    expect(first.response.status).toBe(200);
    expect((await first.response.json()).body).toMatchObject({ state: 'open' });
    expect((await fetch(record.quote.paymentRequired.resource!.url, { headers: { 'X-KYA-Request': encode(first.message) } })).status).toBe(401);
    const substitution = await signMessage('payment.status', { id: 'different-checkout' }, f.owner, f.merchant.did);
    expect((await fetch(record.quote.paymentRequired.resource!.url, { headers: { 'X-KYA-Request': encode(substitution) } })).status).toBe(401);
    expect(f.authorize).not.toHaveBeenCalled(); expect(f.onPayment).not.toHaveBeenCalled();
  });

  it('recovers a failed completion audit through authenticated HTTP status after revocation without another payment', async () => {
    const f = await fixture();
    const record = await f.coordinator.prepare({ id: 'audit-recovery', owner: f.owner.did, protocol: 'x402', product: 'risotto', quantity: 2, rail: 'x402' });
    f.onPayment.mockImplementation(async event => { if (event['phase'] === 'completed') throw new Error('Audit temporarily unavailable'); });
    const payload = await createX402Payment(record.quote.paymentRequired, { privateKey: paymentKey, payTo: f.rail.payTo, maxAtomicAmount: record.quote.requirements.amount });
    const completed = await fetch(`${f.origin}/payments/x402`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'PAYMENT-SIGNATURE': encode(payload) },
      body: JSON.stringify(await f.orderArgs({ product: record.product, quantity: record.quantity, checkout: { id: record.id, protocol: record.protocol, termsDigest: record.termsDigest } })),
    });
    expect(completed.status).toBe(200);
    const original = await completed.json();
    expect(original).toMatchObject({ ok: true, orderId: 'ORD-audit-recovery', payment: { status: 'simulated' } });
    const evidence = f.coordinator.get(record.id)?.completionEvidence;
    expect(evidence?.event).toMatchObject({ phase: 'completed', checkoutId: record.id, orderId: original.orderId });
    expect(evidence?.deliveredAt).toBeUndefined();

    f.revoke(); f.authorize.mockClear(); f.onPayment.mockClear(); f.onPayment.mockResolvedValue(undefined);
    const settle = vi.spyOn(f.rail, 'settle');
    const recovered = await f.status(record.id);
    expect(recovered.response.status).toBe(200);
    const signed = await recovered.response.json() as SignedMessage;
    expect(await new ConsentProtocol().verify('payment.status.result', signed, f.merchant.did, f.owner.did)).toMatchObject({
      state: 'settled', requestNonce: recovered.message.proof.meta.nonce, result: { orderId: original.orderId },
    });
    expect(f.onPayment).toHaveBeenCalledExactlyOnceWith(evidence!.event);
    expect(f.coordinator.get(record.id)?.completionEvidence?.deliveredAt).toEqual(expect.any(String));
    expect((await f.status(record.id)).response.status).toBe(200);
    expect(f.onPayment).toHaveBeenCalledOnce();
    expect(f.authorize).not.toHaveBeenCalled(); expect(settle).not.toHaveBeenCalled();
    expect(Object.keys(f.coordinator.journal.read().payments)).toHaveLength(1);
  });

  it('reports an unresolved durable outcome without resubmitting or exposing payment credentials', async () => {
    const f = await fixture();
    const record = await f.coordinator.prepare({ id: 'unresolved-checkout', owner: f.owner.did, protocol: 'x402', product: 'risotto', quantity: 2, rail: 'x402' });
    await f.coordinator.journal.exclusive(() => {
      const state = f.coordinator.journal.read();
      state.records[record.id]!.state = 'settling'; state.records[record.id]!.paymentIdentity = 'sensitive-nonce';
      f.coordinator.journal.write(state);
    });
    const settle = vi.spyOn(f.rail, 'settle');
    const response = await f.status(record.id);
    const signed = await response.response.json() as SignedMessage;
    expect(await new ConsentProtocol().verify('payment.status.result', signed, f.merchant.did, f.owner.did)).toEqual({
      id: record.id, state: 'settling', protocol: 'x402', termsDigest: record.termsDigest, requestNonce: response.message.proof.meta.nonce,
    });
    expect(f.authorize).not.toHaveBeenCalled(); expect(settle).not.toHaveBeenCalled();
  });

  it('refuses UCP completion after exact human confirmation when the grant is revoked, with zero effects', async () => {
    const f = await fixture();
    const { record, body, clean } = await f.prepareUcp();
    expect(f.coordinator.get(record.id)?.confirmedDigest).toBe(record.termsDigest);
    const settle = vi.spyOn(f.rail, 'settle');
    f.revoke();
    const response = await f.ucp('complete', body, record.id, await f.orderArgs(clean));
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ status: 'incomplete', messages: [{ code: 'delegation_invalid' }] });
    expect(f.authorize).toHaveBeenCalledOnce(); expect(settle).not.toHaveBeenCalled(); expect(f.onPayment).not.toHaveBeenCalled();
    expect(f.coordinator.get(record.id)).toMatchObject({ state: 'open' });
    expect(f.coordinator.get(record.id)?.result).toBeUndefined();
    expect(f.coordinator.journal.read().payments).toEqual({});
  });

  it('resolves the completed UCP order permalink to a protected receipt without another confirmation form', async () => {
    const f = await fixture();
    const { record, body, clean } = await f.prepareUcp();
    const completed = await f.ucp('complete', body, record.id, await f.orderArgs(clean));
    expect(completed.status).toBe(200);
    const checkout = await completed.json();
    expect(checkout.status).toBe('completed');
    const response = await fetch(checkout.order.permalink_url);
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    const html = await response.text();
    expect(html).toContain('Order recorded');
    expect(html).toContain(checkout.order.id);
    expect(html).not.toContain('<form');
    expect(html).not.toContain('Confirm the exact purchase');
    const untrusted = new URL(checkout.order.permalink_url); untrusted.searchParams.set('token', 'wrong');
    expect((await fetch(untrusted)).status).toBe(404);
  });
});
