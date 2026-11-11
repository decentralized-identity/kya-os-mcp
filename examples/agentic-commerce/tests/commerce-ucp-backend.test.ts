import { afterEach, describe, expect, it, vi } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { NodeCryptoProvider, generateDidKeyFromBase64 } from '@kya-os/mcp';
import { createUcpBackend } from '../src/commerce/backend.js';
import { PaymentCoordinator } from '../src/commerce/payments.js';
import { CommerceJournal } from '../src/commerce/journal.js';
import { X402Rail } from '../src/payments/x402.js';
import { signMessage } from '../src/lib/consent-protocol.js';
import { Hono } from 'hono';
import { mountUcpRoutes, ucpPlatformProfile } from '../src/commerce/ucp.js';
import type { KeyedIdentity } from '../src/lib/wiring.js';
import type { UcpBackend } from '../src/commerce/ucp.js';

const directories: string[] = [];
const merchantDid = 'did:key:merchant-fixture';
const origin = 'https://merchant.example';
const profile = 'https://platform.example/.well-known/ucp';
const uri = 'https://id.gs1.org/01/09506000134352';
const createBody = { line_items: [{ item: { id: uri }, quantity: 2 }], kya: { rail: 'sandbox-token' } };
afterEach(() => { vi.restoreAllMocks(); directories.splice(0).forEach(dir => fs.rmSync(dir, { recursive: true, force: true })); });

async function identity(): Promise<KeyedIdentity> {
  const keys = await new NodeCryptoProvider().generateKeyPair();
  const did = generateDidKeyFromBase64(keys.publicKey);
  return { did, kid: `${did}#${did.slice(8)}`, privateKeyBase64: keys.privateKey, publicKeyBase64: keys.publicKey };
}
async function fixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ucp-backend-')); directories.push(dir);
  const owner = await identity();
  const rail = new X402Rail({ mode: 'sandbox' });
  const journal = new CommerceJournal(path.join(dir, 'journal.json'));
  const authorize = vi.fn(async () => ({ content: [{ type: 'text', text: JSON.stringify({ error: 'needs_authorization', authorizationUrl: 'https://rp.example/consent?resume_token=fixture' }) }] }));
  const coordinator = new PaymentCoordinator({ journal, rail, authorize, origin });
  const backend = createUcpBackend({ coordinator, merchantDid, origin });
  return { owner, coordinator, journal, backend, authorize, rail };
}

async function request(owner: KeyedIdentity, operation: 'create' | 'get' | 'update' | 'complete' | 'cancel', body: Record<string, unknown> = {}, id?: string, key = 'operation-1') {
  const idempotencyKey = operation === 'get' ? undefined : key;
  const proof = await signMessage(`ucp.${operation}`, { id: id ?? null, body, idempotencyKey: idempotencyKey ?? null, profile }, owner, merchantDid);
  return { operation, id, body, rawBody: JSON.stringify(body), requestId: 'request-1', idempotencyKey,
    headers: { 'x-kya-request': Buffer.from(JSON.stringify(proof)).toString('base64') } as Record<string, string>,
    platform: { url: profile, handlers: ['x402', 'sandbox-token'] },
  } as Parameters<UcpBackend['execute']>[0];
}

describe('authenticated UCP backend and durable request identity', () => {
  it('returns a valid review escalation through the actual UCP HTTP adapter', async () => {
    const { backend, owner } = await fixture();
    const app = new Hono();
    mountUcpRoutes(app, { backend, origin, platformProfiles: [profile], fetch: async () => Response.json(ucpPlatformProfile('https://platform.example')) });
    const signed = await request(owner, 'create', createBody);
    const response = await app.request('/ucp/checkout-sessions', { method: 'POST',
      headers: { ...signed.headers, 'UCP-Agent': `profile="${profile}"`, 'Request-Id': 'request-1', 'Idempotency-Key': 'operation-1', 'Content-Type': 'application/json' },
      body: JSON.stringify(createBody),
    });
    expect(response.status, await response.clone().text()).toBe(201);
    expect(await response.json()).toMatchObject({ status: 'requires_escalation', messages: [{ type: 'error', severity: 'requires_buyer_review' }] });
  });

  it('requires a fresh exact holder proof before creating any checkout', async () => {
    const { backend, owner, journal } = await fixture();
    const signed = await request(owner, 'create', createBody);
    signed.body = { ...createBody, line_items: [{ item: { id: uri }, quantity: 1 }] };
    expect(await backend.execute(signed)).toMatchObject({ status: 401 });
    expect(Object.keys(journal.read().records)).toHaveLength(0);
  });

  it('rejects proof replay even when the response is cached', async () => {
    const { backend, owner } = await fixture();
    const signed = await request(owner, 'create', createBody);
    expect(await backend.execute(signed)).toHaveProperty('checkout');
    expect(await backend.execute(signed)).toMatchObject({ status: 401 });
  });

  it('deduplicates concurrent authenticated creates and retains the response across restart', async () => {
    const { backend, owner, coordinator, rail } = await fixture();
    const settle = vi.spyOn(rail, 'settle');
    const results = await Promise.all([backend.execute(await request(owner, 'create', createBody)), backend.execute(await request(owner, 'create', createBody))]);
    expect(results[0]).toEqual(results[1]);
    expect(results[0]).toMatchObject({ checkout: { currency: 'CHF', lineItems: [{ quantity: 2 }] } });
    expect(settle).not.toHaveBeenCalled();
    const restarted = createUcpBackend({ coordinator, merchantDid, origin });
    expect(await restarted.execute(await request(owner, 'create', createBody))).toEqual(results[0]);
  });

  it('rejects changed content under an existing idempotency key', async () => {
    const { backend, owner } = await fixture();
    await backend.execute(await request(owner, 'create', createBody));
    const changed = { ...createBody, line_items: [{ item: { id: uri }, quantity: 1 }] };
    expect(await backend.execute(await request(owner, 'create', changed))).toMatchObject({ status: 409, error: { code: 'IDEMPOTENCY_CONFLICT' } });
  });

  it('does not disclose another holder’s checkout', async () => {
    const { backend, owner } = await fixture();
    const result = await backend.execute(await request(owner, 'create', createBody));
    if (!('checkout' in result)) throw new Error('Expected created checkout');
    expect(await backend.execute(await request(await identity(), 'get', {}, result.checkout.id))).toMatchObject({ status: 403 });
  });

  it('cancels only reversible checkouts and never changes an unresolved payment to canceled', async () => {
    const { backend, owner, journal, coordinator } = await fixture();
    const created = await backend.execute(await request(owner, 'create', createBody));
    if (!('checkout' in created)) throw new Error('Expected created checkout');
    const id = created.checkout.id;
    await journal.exclusive(() => {
      const stored = journal.read(); stored.records[id]!.state = 'settling'; journal.write(stored);
    });
    expect(await backend.execute(await request(owner, 'cancel', {}, id, 'cancel-pending'))).toMatchObject({ status: 409 });
    expect(coordinator.get(id)?.state).toBe('settling');
    expect(await backend.execute(await request(owner, 'get', {}, id))).toMatchObject({ checkout: { status: 'complete_in_progress' } });
  });

  it.each([
    { shipping_address: { country: 'CH' } }, { billing_address: {} }, { currency: 'USD' },
    { totals: [{ type: 'total', amount: 1 }] }, { taxes: 0 },
    { line_items: [{ item: { id: uri, price: 1 }, quantity: 2 }] },
  ])('rejects unsupported or substituted final terms before preparation (%j)', async extra => {
    const { backend, owner, journal } = await fixture();
    expect(await backend.execute(await request(owner, 'create', { ...createBody, ...extra }))).toMatchObject({ status: 400 });
    expect(Object.keys(journal.read().records)).toHaveLength(0);
  });

  it('updates exact terms, invalidates human confirmation, and protects the review capability', async () => {
    const { backend, owner, coordinator } = await fixture();
    const created = await backend.execute(await request(owner, 'create', createBody));
    if (!('checkout' in created)) throw new Error('Expected created checkout');
    const record = coordinator.get(created.checkout.id)!;
    expect(await backend.getReview({ id: record.id, token: 'wrong-token', headers: {} })).toBeNull();
    const review = await backend.getReview({ id: record.id, token: record.reviewToken, headers: {} });
    expect(review?.checkout.lineItems[0]?.quantity).toBe(2);
    expect(JSON.stringify(review)).not.toContain(owner.did);
    expect(await backend.confirmReview({ id: record.id, token: record.reviewToken, headers: {}, termsDigest: record.termsDigest, origin })).toMatchObject({ ok: true });
    const changed = { ...createBody, line_items: [{ item: { id: uri }, quantity: 1 }] };
    const updated = await backend.execute(await request(owner, 'update', changed, record.id, 'update-1'));
    expect(updated).toMatchObject({ checkout: { lineItems: [{ quantity: 1 }] } });
    expect(coordinator.get(record.id)?.confirmedDigest).toBeUndefined();
    expect(await backend.confirmReview({ id: record.id, token: record.reviewToken, headers: {}, termsDigest: record.termsDigest, origin })).toMatchObject({ ok: false });
  });

  it('completion binds the order intent and returns the RP consent escalation without settling', async () => {
    const { backend, owner, coordinator, authorize, rail } = await fixture();
    const created = await backend.execute(await request(owner, 'create', createBody));
    if (!('checkout' in created)) throw new Error('Expected created checkout');
    const record = coordinator.get(created.checkout.id)!;
    const completeBody = { payment: { instruments: [{ id: 'pi-1', handler_id: 'kya_sandbox_token', type: 'sandbox-token', credential: { type: 'sandbox-token', token: 'fixture-token' } }] } };
    const args = { product: record.product, quantity: record.quantity, checkout: { id: record.id, protocol: 'ucp', termsDigest: record.termsDigest } };
    const signedOrder = await signMessage('place_order', args, owner, merchantDid);
    const completeRequest = await request(owner, 'complete', completeBody, record.id, 'complete-1');
    completeRequest.headers['x-kya-order'] = Buffer.from(JSON.stringify({ args: { ...args, _kyaos_proof: signedOrder.proof } })).toString('base64');
    const settle = vi.spyOn(rail, 'settle');
    const result = await backend.execute(completeRequest);
    expect(authorize).toHaveBeenCalledOnce();
    expect(result).toMatchObject({ checkout: { status: 'requires_escalation', continueUrl: 'https://rp.example/consent?resume_token=fixture' } });
    expect(JSON.stringify(result)).not.toContain('fixture-token');
    expect(JSON.stringify(result)).not.toContain('_kyaos_proof');
    expect(settle).not.toHaveBeenCalled();
    const substituted = await request(owner, 'complete', completeBody, record.id, 'complete-2');
    substituted.headers['x-kya-order'] = Buffer.from(JSON.stringify({ args: { ...args, quantity: 1, _kyaos_proof: signedOrder.proof } })).toString('base64');
    expect(await backend.execute(substituted)).toMatchObject({ status: 409 });
    expect(authorize).toHaveBeenCalledOnce();
  });
});
