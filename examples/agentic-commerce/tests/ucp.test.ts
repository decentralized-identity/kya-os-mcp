import { describe, expect, it, vi } from 'vitest';
import { Hono } from 'hono';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Ajv2020 } from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import {
  mountUcpRoutes,
  ucpPlatformProfile,
  ucpCheckoutResponse,
  UCP_VERSION,
  type UcpBackend,
  type UcpCheckoutView,
} from '../src/commerce/ucp.js';

const origin = 'https://merchant.example';
const profileUrl = 'https://platform.example/.well-known/ucp';
const view: UcpCheckoutView = {
  id: 'checkout_123', status: 'ready_for_complete', currency: 'CHF',
  lineItems: [{ id: 'line_1', item: { id: 'https://id.gs1.org/01/09506000134352', title: 'Risotto', price: 1990 }, quantity: 2 }],
};
function fixture() {
  const backend: UcpBackend = {
    execute: vi.fn(async () => ({ checkout: structuredClone(view) })),
    getReview: vi.fn<UcpBackend['getReview']>(async () => ({ checkout: { ...structuredClone(view), status: 'requires_escalation' }, termsDigest: 'digest_123', rail: 'x402', rateDisclosure: '39.80 CHF = 43.20 test USDC. Fixed quote; Base Sepolia test network.' })),
    confirmReview: vi.fn<UcpBackend['confirmReview']>(async () => ({ ok: true })),
  };
  const fetchProfile = vi.fn<typeof fetch>(async () => Response.json(ucpPlatformProfile('https://platform.example')));
  const app = new Hono();
  mountUcpRoutes(app, { origin, platformProfiles: [profileUrl], backend, fetch: fetchProfile });
  return { app, backend, fetchProfile };
}
function headers(extra: Record<string, string> = {}) {
  return { 'Content-Type': 'application/json', 'UCP-Agent': `profile="${profileUrl}"`, 'Request-Id': 'request_123', 'Idempotency-Key': 'operation_123', ...extra };
}
const createBody = { line_items: [{ item: { id: view.lineItems[0]!.item.id }, quantity: 2 }] };
const completeBody = { payment: { instruments: [{ id: 'pi_1', handler_id: 'kya_sandbox_token', type: 'sandbox-token', credential: { type: 'sandbox-token', token: 'secret_token' } }] } };

function officialSchemas() {
  const ajv = new Ajv2020({ strict: false, allErrors: true });
  const applyFormats = typeof addFormats === 'function' ? addFormats : addFormats.default;
  applyFormats(ajv);
  const root = fileURLToPath(new URL('./fixtures/ucp-2026-08-25', import.meta.url));
  function addDirectory(dir: string) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const name = path.join(dir, entry.name);
      if (entry.isDirectory()) addDirectory(name);
      else if (entry.name.endsWith('.json')) ajv.addSchema(JSON.parse(fs.readFileSync(name, 'utf8')));
    }
  }
  addDirectory(root);
  return ajv;
}

describe('pinned official UCP 2026-08-25 schemas', () => {
  const ajv = officialSchemas();
  it('validates the actual merchant and platform profiles', async () => {
    const { app } = fixture();
    const merchant = await (await app.request('/.well-known/ucp')).json();
    const validateMerchant = ajv.compile({ $ref: 'https://ucp.dev/schemas/profile.json#/$defs/business_schema' });
    expect(validateMerchant(merchant), JSON.stringify(validateMerchant.errors)).toBe(true);
    const validatePlatform = ajv.compile({ $ref: 'https://ucp.dev/schemas/profile.json#/$defs/platform_schema' });
    expect(validatePlatform(ucpPlatformProfile('https://platform.example')), JSON.stringify(validatePlatform.errors)).toBe(true);
  });
  it.each(['incomplete', 'requires_escalation', 'ready_for_complete', 'complete_in_progress', 'completed', 'canceled'] as const)('validates %s response against official checkout schema', (status) => {
    const checkout: UcpCheckoutView = { ...view, status, expiresAt: '2026-09-09T12:00:00Z', payment: completeBody.payment, kya: { intent: { checkoutId: view.id } } };
    if (status === 'requires_escalation') {
      checkout.continueUrl = `${origin}/checkout/${view.id}?token=public_review_link`;
      checkout.messages = [{ type: 'error', code: 'consent_required', content: 'Review this exact checkout.', severity: 'requires_buyer_review' }];
    }
    if (status === 'completed') checkout.order = { id: 'order_123', permalink_url: `${origin}/orders/order_123` };
    const response = ucpCheckoutResponse(checkout, origin);
    const validate = ajv.getSchema('https://ucp.dev/schemas/shopping/checkout.json')!;
    expect(validate(response), JSON.stringify(validate.errors)).toBe(true);
  });
  it('detects invalid representations independently of our adapter tests', () => {
    const validate = ajv.getSchema('https://ucp.dev/schemas/shopping/checkout.json')!;
    const response = ucpCheckoutResponse(view, origin);
    delete response['totals'];
    expect(validate(response)).toBe(false);
    expect(validate.errors).toEqual(expect.arrayContaining([expect.objectContaining({ keyword: 'required', params: { missingProperty: 'totals' } })]));
  });
});

describe('UCP checkout REST boundary', () => {
  it('discovers real versioned checkout, KYA extension, and truthful payment handlers', async () => {
    const { app } = fixture();
    const response = await app.request('/.well-known/ucp');
    expect(response.status).toBe(200);
    const profile = await response.json();
    expect(profile.ucp.version).toBe(UCP_VERSION);
    expect(profile.ucp.services['dev.ucp.shopping'][0].endpoint).toBe(`${origin}/ucp`);
    expect(profile.ucp.capabilities['org.kya-os.delegation'][0].extends).toBe('dev.ucp.shopping.checkout');
    expect(Object.keys(profile.ucp.payment_handlers)).toEqual(['org.kya-os.x402', 'org.kya-os.sandbox-token']);
    expect(JSON.stringify(profile)).not.toMatch(/com.google.pay|visa|mastercard|ap2/);
    for (const path of ['/ucp/handlers/x402', '/ucp/handlers/x402.json', '/ucp/handlers/sandbox-token', '/ucp/handlers/sandbox-token.json', '/ucp/delegation', '/ucp/delegation.json']) {
      expect((await app.request(path)).status).toBe(200);
    }
  });

  it.each([
    ['create', 'POST', '/ucp/checkout-sessions', createBody, undefined],
    ['get', 'GET', '/ucp/checkout-sessions/checkout_123', undefined, 'checkout_123'],
    ['update', 'PUT', '/ucp/checkout-sessions/checkout_123', createBody, 'checkout_123'],
    ['complete', 'POST', '/ucp/checkout-sessions/checkout_123/complete', completeBody, 'checkout_123'],
    ['cancel', 'POST', '/ucp/checkout-sessions/checkout_123/cancel', undefined, 'checkout_123'],
  ])('routes %s with exact raw authorization context', async (operation, method, path, body, id) => {
    const { app, backend } = fixture();
    const rawBody = body ? JSON.stringify(body) : '';
    const result = await app.request(path, { method, headers: headers({ 'X-KYA-Request': 'signed-context' }), ...(body ? { body: rawBody } : {}) });
    expect(result.status).toBe(operation === 'create' ? 201 : 200);
    expect(backend.execute).toHaveBeenCalledWith(expect.objectContaining({ operation, id, rawBody, body: body ?? {}, requestId: 'request_123', ...(operation === 'get' ? {} : { idempotencyKey: 'operation_123' }), headers: expect.objectContaining({ 'x-kya-request': 'signed-context' }), platform: expect.objectContaining({ url: profileUrl, handlers: ['x402', 'sandbox-token'] }) }));
    expect(await result.json()).toMatchObject({ id: view.id, currency: 'CHF', ucp: { version: UCP_VERSION, status: 'success' }, totals: [{ type: 'subtotal', amount: 3980 }, { type: 'total', amount: 3980 }] });
  });

  it.each([
    ['missing profile', { 'UCP-Agent': '' }, 400],
    ['malformed structured header', { 'UCP-Agent': profileUrl }, 400],
    ['duplicate profile', { 'UCP-Agent': `profile="${profileUrl}", profile="${profileUrl}"` }, 400],
    ['unknown profile', { 'UCP-Agent': 'profile="http://169.254.169.254/.well-known/ucp"' }, 403],
    ['missing request ID', { 'Request-Id': '' }, 400],
    ['missing write idempotency', { 'Idempotency-Key': '' }, 400],
    ['wrong content type', { 'Content-Type': 'text/plain' }, 415],
  ])('rejects %s before calling backend', async (_label, overrides, status) => {
    const { app, backend, fetchProfile } = fixture();
    const response = await app.request('/ucp/checkout-sessions', { method: 'POST', headers: headers(overrides), body: JSON.stringify(createBody) });
    expect(response.status).toBe(status);
    expect(backend.execute).not.toHaveBeenCalled();
    if (status === 403) expect(fetchProfile).not.toHaveBeenCalled();
  });

  it('does not follow redirects when fetching an allowlisted profile', async () => {
    const { app, backend, fetchProfile } = fixture();
    fetchProfile.mockResolvedValueOnce(new Response(null, { status: 302, headers: { Location: 'http://169.254.169.254/latest/meta-data' } }));
    const response = await app.request('/ucp/checkout-sessions', { method: 'POST', headers: headers(), body: JSON.stringify(createBody) });
    expect(response.status).toBe(424);
    expect(fetchProfile.mock.calls[0]?.[1]).toMatchObject({ redirect: 'error' });
    expect(backend.execute).not.toHaveBeenCalled();
  });

  it.each(['version', 'checkout', 'delegation', 'payment'])('rejects incompatible %s negotiation', async (kind) => {
    const { app, backend, fetchProfile } = fixture();
    const profile = ucpPlatformProfile('https://platform.example');
    if (kind === 'version') profile.ucp.version = '2026-01-11';
    if (kind === 'checkout') delete profile.ucp.capabilities['dev.ucp.shopping.checkout'];
    if (kind === 'delegation') delete profile.ucp.capabilities['org.kya-os.delegation'];
    if (kind === 'payment') profile.ucp.payment_handlers = {};
    fetchProfile.mockResolvedValueOnce(Response.json(profile));
    const response = await app.request('/ucp/checkout-sessions', { method: 'POST', headers: headers(), body: JSON.stringify(createBody) });
    expect(response.status).toBe(kind === 'version' ? 422 : 200);
    if (kind !== 'version') expect(await response.json()).toMatchObject({ ucp: { status: 'error' }, messages: [{ code: 'capabilities_incompatible' }] });
    expect(backend.execute).not.toHaveBeenCalled();
  });

  it.each(['invalid JSON', 'wrong discovery container', 'malformed instruments'])('rejects malformed platform profile: %s', async (kind) => {
    const { app, backend, fetchProfile } = fixture();
    const profile = ucpPlatformProfile('https://platform.example');
    if (kind === 'invalid JSON') fetchProfile.mockResolvedValueOnce(new Response('{', { headers: { 'Content-Type': 'application/json' } }));
    if (kind === 'wrong discovery container') fetchProfile.mockResolvedValueOnce(Response.json({ ucp: { ...profile.ucp, services: [] } }));
    if (kind === 'malformed instruments') fetchProfile.mockResolvedValueOnce(Response.json({ ucp: { ...profile.ucp, payment_handlers: { 'org.kya-os.x402': [{ version: UCP_VERSION, available_instruments: {} }] } } }));
    const response = await app.request('/ucp/checkout-sessions', { method: 'POST', headers: headers(), body: JSON.stringify(createBody) });
    expect(response.status).toBe(422);
    expect(backend.execute).not.toHaveBeenCalled();
  });

  it('intersects payment instruments instead of advertising unsupported rails', async () => {
    const { app, fetchProfile } = fixture();
    fetchProfile.mockResolvedValueOnce(Response.json(ucpPlatformProfile('https://platform.example', ['sandbox-token'])));
    const response = await app.request('/ucp/checkout-sessions', { method: 'POST', headers: headers(), body: JSON.stringify(createBody) });
    expect(Object.keys((await response.json()).ucp.payment_handlers)).toEqual(['org.kya-os.sandbox-token']);
  });

  it('rejects oversized streamed request bodies before fetching profiles or invoking effects', async () => {
    const { app, backend, fetchProfile } = fixture();
    const body = JSON.stringify({ ...createBody, kya: { padding: 'x'.repeat(128 * 1024) } });
    const response = await app.request('/ucp/checkout-sessions', { method: 'POST', headers: headers(), body });
    expect(response.status).toBe(400);
    expect(fetchProfile).not.toHaveBeenCalled();
    expect(backend.execute).not.toHaveBeenCalled();
  });

  it.each([
    ['null'], ['[]'], ['{'],
    [JSON.stringify({ line_items: 'bad' })],
    [JSON.stringify({ line_items: [{ item: { id: 'risotto' }, quantity: 1.5 }] })],
    [JSON.stringify({ line_items: [{ item: { id: 'risotto' }, quantity: 0 }] })],
    [JSON.stringify({ line_items: [{ item: { id: 123 }, quantity: 2 }] })],
  ])('rejects malformed create input %s', async (body) => {
    const { app, backend } = fixture();
    const result = await app.request('/ucp/checkout-sessions', { method: 'POST', headers: headers(), body });
    expect(result.status).toBe(400);
    expect(backend.execute).not.toHaveBeenCalled();
  });

  it('requires handler-owned payment credentials on complete and strips all credentials from responses', async () => {
    const { app, backend } = fixture();
    expect((await app.request('/ucp/checkout-sessions/checkout_123/complete', { method: 'POST', headers: headers(), body: '{}' })).status).toBe(400);
    expect(backend.execute).not.toHaveBeenCalled();
    vi.mocked(backend.execute).mockResolvedValueOnce({ checkout: { ...view, payment: completeBody.payment, kya: { intent: { checkoutId: view.id }, result: { code: 'PAYMENT_REQUIRED' } } } });
    const result = await app.request('/ucp/checkout-sessions/checkout_123/complete', { method: 'POST', headers: headers(), body: JSON.stringify(completeBody) });
    const output = await result.json();
    expect(output.payment.instruments[0]).toEqual({ id: 'pi_1', handler_id: 'kya_sandbox_token', type: 'sandbox-token' });
    expect(output.kya.intent.checkoutId).toBe(view.id);
    expect(JSON.stringify(output)).not.toContain('secret_token');
  });

  it('returns backend authority refusal without creating a completed checkout', async () => {
    const { app, backend } = fixture();
    vi.mocked(backend.execute).mockResolvedValueOnce({ error: { code: 'CREDENTIAL_REVOKED', content: 'The human revoked this grant.' }, status: 403 });
    const result = await app.request('/ucp/checkout-sessions/checkout_123/complete', { method: 'POST', headers: headers(), body: JSON.stringify(completeBody) });
    expect(result.status).toBe(403);
    expect(await result.json()).toMatchObject({ ucp: { version: UCP_VERSION, status: 'error' }, code: 'CREDENTIAL_REVOKED' });
  });
});

describe('trusted exact-checkout confirmation', () => {
  it.each(['ready_for_complete', 'complete_in_progress', 'completed', 'canceled', 'incomplete'] as const)('does not offer a second confirmation for %s', async status => {
    const { app, backend } = fixture();
    vi.mocked(backend.getReview).mockResolvedValueOnce({ checkout: { ...view, status, ...(status === 'completed' ? { order: { id: 'order_123', permalink_url: `${origin}/checkout/checkout_123?token=review_token` } } : {}) }, termsDigest: 'digest_123', rail: 'x402', rateDisclosure: 'Sandbox. No funds move.' });
    const html = await (await app.request('/checkout/checkout_123?token=review_token')).text();
    expect(html).not.toContain('<form');
    expect(html).not.toContain('Confirm the exact purchase');
    if (status === 'complete_in_progress') expect(html).toContain('Do not create another payment');
    if (status === 'completed') expect(html).toContain('order_123');
  });
  it('renders exact immutable terms, payment rate and explicit confirmation without auto-completing', async () => {
    const { app, backend } = fixture();
    const response = await app.request('/checkout/checkout_123?token=review_token');
    const html = await response.text();
    expect(response.status).toBe(200);
    expect(html).toContain('Risotto');
    expect(html).toContain('CHF 39.80');
    expect(html).toContain('43.20 test USDC');
    expect(html).toContain('name="terms_digest" value="digest_123"');
    expect(html).toContain('Confirm this checkout');
    expect(html).not.toContain('<script');
    expect(response.headers.get('Referrer-Policy')).toBe('no-referrer');
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    expect(backend.execute).not.toHaveBeenCalled();
    expect(backend.confirmReview).not.toHaveBeenCalled();
  });

  it('forwards the original digest to backend and confirms only on same-origin explicit form submission', async () => {
    const { app, backend } = fixture();
    const body = new URLSearchParams({ token: 'review_token', terms_digest: 'digest_123', confirm: 'yes' });
    const rejected = await app.request('/checkout/checkout_123/confirm', { method: 'POST', headers: { Origin: 'https://attacker.example' }, body });
    expect(rejected.status).toBe(403);
    expect(backend.confirmReview).not.toHaveBeenCalled();
    const approved = await app.request('/checkout/checkout_123/confirm', { method: 'POST', headers: { Origin: origin }, body });
    expect(approved.status).toBe(200);
    expect(backend.confirmReview).toHaveBeenCalledWith(expect.objectContaining({ id: view.id, token: 'review_token', termsDigest: 'digest_123', origin }));
    expect(await approved.text()).toContain('Your agent can now retry');
    expect(backend.execute).not.toHaveBeenCalled();
  });

  it('rejects stale terms and escapes all merchant-controlled text', async () => {
    const { app, backend } = fixture();
    vi.mocked(backend.getReview).mockResolvedValueOnce({ checkout: { ...view, lineItems: [{ ...view.lineItems[0]!, item: { ...view.lineItems[0]!.item, title: '<img src=x onerror=alert(1)>' } }] }, termsDigest: '"><script>bad</script>', rail: 'sandbox-token', rateDisclosure: '<b>unsafe</b>' });
    const review = await (await app.request('/checkout/checkout_123?token=review_token')).text();
    expect(review).not.toContain('<img');
    expect(review).not.toContain('<script');
    expect(review).toContain('&lt;img');
    vi.mocked(backend.confirmReview).mockResolvedValueOnce({ ok: false, status: 409, code: 'TERMS_CHANGED', content: 'The checkout changed. Review again.' });
    const response = await app.request('/checkout/checkout_123/confirm', { method: 'POST', headers: { Origin: origin }, body: new URLSearchParams({ token: 'review_token', terms_digest: 'old_digest', confirm: 'yes' }) });
    expect(response.status).toBe(409);
    expect(await response.text()).toContain('The checkout changed');
  });
});
