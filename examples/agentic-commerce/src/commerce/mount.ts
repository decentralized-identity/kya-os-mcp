import type { Hono } from 'hono';
import { PaymentCoordinator } from './payments.js';
import { CommerceJournal } from './journal.js';
import { X402Rail } from '../payments/x402.js';
import { createUcpBackend } from './backend.js';
import { mountUcpRoutes, ucpPlatformProfile } from './ucp.js';
import { ConsentProtocol, type SignedMessage } from '../lib/consent-protocol.js';
import { responseBody, type MerchantToolResult } from '../agent/authorization.js';

async function readPaymentBody(body: ReadableStream<Uint8Array> | null): Promise<string> {
  if (!body) return '';
  const reader = body.getReader();
  const parts: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      size += part.value.byteLength;
      if (size > 128 * 1024) { await reader.cancel(); throw new Error('request_too_large'); }
      parts.push(part.value);
    }
    return Buffer.concat(parts).toString('utf8');
  } finally { reader.releaseLock(); }
}

/** Official MCP transport wraps the already signed content without modifying
 * the content-array response hash. Payment authorizations never enter logs. */
export function x402McpResult(result: MerchantToolResult): MerchantToolResult {
  const body = responseBody(result);
  if (body['x402Version'] === 2 && Array.isArray(body['accepts'])) return { ...result, isError: true, structuredContent: body };
  const payment = body['payment'] as Record<string, unknown> | undefined;
  return { ...result, ...(body['error'] ? { isError: true } : {}),
    ...(payment?.['response'] ? { _meta: { ...result._meta, 'x402/payment-response': payment['response'] } } : {}) };
}

export function decodePaymentHeader(value: string | undefined | null): unknown {
  if (!value || value.length > 96_000 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) throw new Error('Invalid encoded payment request');
  const decoded: unknown = JSON.parse(Buffer.from(value, 'base64').toString('utf8'));
  if (!decoded || typeof decoded !== 'object' || Array.isArray(decoded)) throw new Error('Invalid encoded payment request');
  return decoded;
}

export function mountCommerce(app: Hono, options: {
  origin: string; merchantDid: string; file: string;
  authorize: ConstructorParameters<typeof PaymentCoordinator>[0]['authorize'];
  beforeSettlement: NonNullable<ConstructorParameters<typeof PaymentCoordinator>[0]['beforeSettlement']>;
  onPayment: NonNullable<ConstructorParameters<typeof PaymentCoordinator>[0]['onPayment']>;
  signResult?(args: Record<string, unknown>, body: Record<string, unknown>): Promise<MerchantToolResult>;
  signStatus(body: Record<string, unknown>, audience: string): Promise<SignedMessage>;
  broadcast(event: Record<string, unknown>): void;
}) {
  const mode = process.env['PAYMENT_MODE'] ?? 'sandbox';
  if (mode !== 'sandbox' && mode !== 'testnet') throw new Error('PAYMENT_MODE must be sandbox or testnet');
  const rail = new X402Rail({ mode, payTo: process.env['X402_PAY_TO'], atomicUnitsPerChfCent: process.env['X402_ATOMIC_UNITS_PER_CHF_CENT'] ?? '10000' });
  const coordinator = new PaymentCoordinator({ ...options, journal: new CommerceJournal(options.file), rail });
  const backend = createUcpBackend({ coordinator, merchantDid: options.merchantDid, origin: options.origin, signResult: options.signResult });
  const profileUrl = `${options.origin}/agent/.well-known/ucp`;
  app.get('/agent/.well-known/ucp', c => c.json(ucpPlatformProfile(options.origin)));
  const viewBackend = { ...backend, execute: async (...args: Parameters<typeof backend.execute>) => {
    const result = await backend.execute(...args);
    if ('checkout' in result && result.checkout.status === 'requires_escalation') {
      options.broadcast({ type: 'checkout.review', id: result.checkout.id, url: result.checkout.continueUrl,
        protocol: 'ucp', total: coordinator.get(result.checkout.id)?.amountMinor, currency: result.checkout.currency, expiresAt: result.checkout.expiresAt });
    }
    return result;
  }, confirmReview: async (...args: Parameters<typeof backend.confirmReview>) => {
    const result = await backend.confirmReview(...args);
    if (result.ok) options.broadcast({ type: 'checkout.confirmed', id: args[0].id });
    return result;
  } };
  mountUcpRoutes(app, { origin: options.origin, backend: viewBackend, platformProfiles: [profileUrl,
    ...(process.env['UCP_PLATFORM_PROFILES'] ?? '').split(',').map(url => url.trim()).filter(Boolean)] });
  const protocol = new ConsentProtocol();

  /** The quoted x402 resource is also the authenticated recovery resource.
   * Reading a previous outcome needs the holder's fresh proof, not a currently
   * active grant. It cannot prepare, authorize, or submit another payment. */
  app.get('/payments/checkouts/:id', async c => {
    c.header('Cache-Control', 'no-store');
    c.header('Referrer-Policy', 'no-referrer');
    const id = c.req.param('id');
    let message: SignedMessage;
    let owner: string;
    try {
      message = decodePaymentHeader(c.req.header('X-KYA-Request')) as SignedMessage;
      owner = message.proof?.meta?.did;
      if (typeof owner !== 'string' || !owner.startsWith('did:key:') || message.body?.['id'] !== id
        || Object.keys(message.body).length !== 1) throw new Error('Status request binding differs');
      await protocol.verify('payment.status', message, owner, options.merchantDid);
    } catch { return c.json({ error: 'HOLDER_PROOF_INVALID' }, 401); }
    try {
      const record = coordinator.get(id);
      if (!record || record.owner !== owner) return c.json({ error: 'CHECKOUT_NOT_FOUND' }, 404);
      if (record.state === 'settled' && record.completionEvidence && !record.completionEvidence.deliveredAt) {
        // Retry only retained audit evidence. The order is already committed;
        // recovery must not reauthorize or resubmit its payment.
        await coordinator.recoverCompletionEvidence(id);
      }
      const result = record.state === 'settled' && record.result ? structuredClone(record.result) : undefined;
      if (result?.['payment'] && typeof result['payment'] === 'object') {
        // The journal's transfer nonce reservation is internal recovery state.
        delete (result['payment'] as Record<string, unknown>)['paymentIdentity'];
      }
      const body = { id: record.id, state: record.state, protocol: record.protocol, termsDigest: record.termsDigest,
        requestNonce: message.proof.meta.nonce,
        ...(result ? { result } : {}),
      };
      return c.json(await options.signStatus(body, owner));
    } catch { return c.json({ error: 'COMMERCE_UNAVAILABLE', message: 'The existing checkout outcome could not be safely established. No payment was submitted.' }, 503); }
  });

  app.post('/payments/sandbox/tokenize', async c => {
    try {
      const message = decodePaymentHeader(c.req.header('X-KYA-Request')) as SignedMessage;
      const owner = message.proof?.meta?.did;
      if (typeof owner !== 'string' || typeof message.body?.['id'] !== 'string' || Object.keys(message.body).length !== 1) return c.json({ error: 'invalid_request' }, 400);
      await protocol.verify('payment.tokenize', message, owner, options.merchantDid);
      const token = await coordinator.tokenize(message.body['id'], owner);
      c.header('Cache-Control', 'no-store');
      return c.json({ token, environment: 'sandbox' });
    } catch { return c.json({ error: 'tokenization_refused' }, 403); }
  });

  /** v2 HTTP transport: canonical PaymentRequired/PaymentResponse headers.
   * KYA request arguments are JSON; the logical action remains place_order. */
  app.post('/payments/x402', async c => {
    try {
      const length = Number(c.req.header('Content-Length') ?? 0);
      if (length > 128 * 1024) return c.json({ error: 'request_too_large' }, 413);
      const raw = await readPaymentBody(c.req.raw.body);
      const args: unknown = JSON.parse(raw);
      if (!args || typeof args !== 'object' || Array.isArray(args)) return c.json({ error: 'invalid_request' }, 400);
      const payment = c.req.header('PAYMENT-SIGNATURE');
      const result = payment ? await coordinator.complete(args as Record<string, unknown>, decodePaymentHeader(payment))
        : await coordinator.requestPayment(args as Record<string, unknown>);
      const body = responseBody(result);
      c.header('Cache-Control', 'no-store');
      if (result._meta) c.header('KYA-Response', Buffer.from(JSON.stringify(result._meta)).toString('base64'));
      if (body['x402Version'] === 2) {
        c.header('PAYMENT-REQUIRED', Buffer.from(JSON.stringify(body)).toString('base64'));
        return c.json(body, 402);
      }
      const settlement = body['payment'] as Record<string, unknown> | undefined;
      if (settlement?.['response']) c.header('PAYMENT-RESPONSE', Buffer.from(JSON.stringify(settlement['response'])).toString('base64'));
      return c.json(body, body['error'] === 'SETTLEMENT_PENDING' ? 202 : body['error'] || result.isError ? 403 : 200);
    } catch (error) {
      if (error instanceof Error && error.message === 'request_too_large') return c.json({ error: 'request_too_large' }, 413);
      return c.json({ error: 'PAYMENT_REQUEST_UNRESOLVED', message: 'Inspect this checkout before resubmitting a payment.' }, 400);
    }
  });
  return { coordinator, rail, backend, profileUrl };
}
