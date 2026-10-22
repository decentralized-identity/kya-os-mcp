import type { Hono } from 'hono';

/** Pinned UCP checkout subset, including trusted human confirmation, not AP2. */
export const UCP_VERSION = '2026-08-25';
export const UCP_CHECKOUT = 'dev.ucp.shopping.checkout';
export const UCP_DELEGATION = 'org.kya-os.delegation';
export type UcpRail = 'x402' | 'sandbox-token';
export type UcpOperation = 'create' | 'get' | 'update' | 'complete' | 'cancel';
export const UCP_HANDLER_IDS: Record<UcpRail, string> = { x402: 'kya_x402', 'sandbox-token': 'kya_sandbox_token' };
type JsonObject = Record<string, unknown>;
type UcpEntity = { version: string; spec?: string; schema?: string; extends?: string; id?: string; available_instruments?: { type: string }[]; config?: JsonObject };
export interface UcpProfile {
  ucp: {
    version: string;
    services: Record<string, unknown[]>;
    capabilities: Record<string, UcpEntity[]>;
    payment_handlers: Record<string, UcpEntity[]>;
  };
}
export interface UcpMessage {
  type: 'error' | 'warning' | 'info';
  code: string;
  content: string;
  path?: string;
  severity?: 'recoverable' | 'requires_buyer_input' | 'requires_buyer_review' | 'unrecoverable';
}
export interface UcpCheckoutView {
  id: string;
  status: 'incomplete' | 'requires_escalation' | 'ready_for_complete' | 'complete_in_progress' | 'completed' | 'canceled';
  currency: string;
  lineItems: { id: string; item: { id: string; title: string; price: number }; quantity: number }[];
  messages?: UcpMessage[];
  expiresAt?: string;
  continueUrl?: string;
  order?: { id: string; permalink_url: string };
  payment?: { instruments: JsonObject[] };
  handlers?: UcpRail[];
  /** Public signed challenge/receipt and canonical intent only. Never payment credentials. */
  kya?: JsonObject;
}
export interface UcpBackendRequest {
  operation: UcpOperation;
  id?: string;
  body: JsonObject;
  rawBody: string;
  headers: Record<string, string>;
  requestId: string;
  idempotencyKey?: string;
  platform: { url: string; profile: UcpProfile; handlers: UcpRail[] };
}
export type UcpBackendResult =
  | { checkout: UcpCheckoutView; status?: 200 | 201 }
  | { error: { code: string; content: string }; status: 400 | 401 | 403 | 404 | 409 | 422 | 424 | 500 | 503 };
export interface UcpReview {
  checkout: UcpCheckoutView;
  termsDigest: string;
  rail: UcpRail;
  rateDisclosure: string;
}
export interface UcpBackend {
  /** Owns fresh holder proof, resource ownership, durable idempotency and final KYA/payment effects. */
  execute(request: UcpBackendRequest): Promise<UcpBackendResult>;
  getReview(request: { id: string; token: string; headers: Record<string, string> }): Promise<UcpReview | null>;
  /** Validates token, exact terms, expiry and revocation again. Records confirmation only. */
  confirmReview(request: { id: string; token: string; termsDigest: string; origin: string; headers: Record<string, string> }): Promise<
    { ok: true } | { ok: false; code: string; content: string; status?: number }
  >;
}
export interface UcpAdapterConfig {
  origin: string;
  backend: UcpBackend;
  /** Explicitly trusted endpoint URLs. Redirects and arbitrary caller-chosen fetches are forbidden. */
  platformProfiles: readonly string[];
  handlers?: readonly UcpRail[];
  fetch?: typeof fetch;
}

const rails: readonly UcpRail[] = ['x402', 'sandbox-token'];
const maxBodyBytes = 128 * 1024;
const dict = (value: unknown): value is JsonObject => value !== null && typeof value === 'object' && !Array.isArray(value);
const nonempty = (value: unknown): value is string => typeof value === 'string' && value.length > 0 && value.length <= 4096;
const safeInteger = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 1;
const handlerName = (rail: UcpRail) => `org.kya-os.${rail}`;
function protocolError(status: number, code: string, content: string): Response {
  return json({ ucp: { version: UCP_VERSION, status: 'error' }, code, content }, status);
}
function negotiationError(content: string): Response {
  return json({ ucp: { version: UCP_VERSION, status: 'error' }, messages: [{ type: 'error', code: 'capabilities_incompatible', severity: 'unrecoverable', content }] });
}
function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' } });
}
function capabilityDeclarations(origin: string): Record<string, UcpEntity[]> {
  return {
    [UCP_CHECKOUT]: [{ version: UCP_VERSION, spec: `https://ucp.dev/${UCP_VERSION}/specification/shopping/checkout`, schema: `https://ucp.dev/${UCP_VERSION}/schemas/shopping/checkout.json` }],
    [UCP_DELEGATION]: [{ version: UCP_VERSION, extends: UCP_CHECKOUT, spec: `${origin}/ucp/delegation`, schema: `${origin}/ucp/delegation.json` }],
  };
}
function handlerDeclarations(origin: string, enabled: readonly UcpRail[], discovery = true): Record<string, UcpEntity[]> {
  return Object.fromEntries(enabled.map((rail) => [handlerName(rail), [{
    id: UCP_HANDLER_IDS[rail], version: UCP_VERSION,
    ...(discovery ? { spec: `${origin}/ucp/handlers/${rail}`, schema: `${origin}/ucp/handlers/${rail}.json` } : {}),
    available_instruments: [{ type: rail }],
    config: rail === 'x402'
      ? { payment_protocol: 'x402', x402_version: 2, quote_source: 'checkout.kya.payment_required', credential_type: 'x402' }
      : { environment: 'sandbox', real_money: false, credential_type: 'sandbox-token' },
  }]]));
}
export function ucpPlatformProfile(origin: string, enabled: readonly UcpRail[] = rails): UcpProfile {
  return { ucp: { version: UCP_VERSION, services: {}, capabilities: capabilityDeclarations(new URL(origin).origin), payment_handlers: handlerDeclarations(new URL(origin).origin, enabled) } };
}
export function ucpBusinessProfile(config: Pick<UcpAdapterConfig, 'origin' | 'handlers'>): UcpProfile {
  const origin = new URL(config.origin).origin;
  const profile = ucpPlatformProfile(origin, config.handlers ?? rails);
  profile.ucp.services['dev.ucp.shopping'] = [{ version: UCP_VERSION, transport: 'rest', spec: `https://ucp.dev/${UCP_VERSION}/specification/overview`, schema: `https://ucp.dev/${UCP_VERSION}/services/shopping/rest.openapi.json`, endpoint: `${origin}/ucp` }];
  return profile;
}

/** Merchant prices are authoritative. The subset has no shipping, tax or discount adjustments. */
export function ucpCheckoutResponse(view: UcpCheckoutView, origin: string, enabled: readonly UcpRail[] = rails): JsonObject {
  const lineItems = view.lineItems.map((line) => {
    const amount = line.item.price * line.quantity;
    if (!Number.isSafeInteger(line.item.price) || line.item.price < 0 || !safeInteger(line.quantity) || !Number.isSafeInteger(amount)) throw new Error('Invalid authoritative checkout price');
    return { id: line.id, item: { id: line.item.id, title: line.item.title, price: line.item.price }, quantity: line.quantity, totals: [{ type: 'subtotal', amount }, { type: 'total', amount }] };
  });
  const total = lineItems.reduce((sum, line) => sum + line.totals[1]!.amount, 0);
  if (!Number.isSafeInteger(total)) throw new Error('Checkout total overflow');
  if (view.status === 'completed' && !view.order) throw new Error('Completed checkout needs order confirmation');
  if (view.status !== 'completed' && view.order) throw new Error('Uncompleted checkout cannot expose an order');
  if (view.status === 'requires_escalation' && (!view.continueUrl || !view.messages?.some((m) => m.type === 'error' && (m.severity === 'requires_buyer_input' || m.severity === 'requires_buyer_review')))) throw new Error('Escalation needs a buyer handoff');
  const selectedHandlers = enabled.filter((rail) => !view.handlers || view.handlers.includes(rail));
  return {
    ucp: { version: UCP_VERSION, status: 'success', capabilities: { [UCP_CHECKOUT]: [{ version: UCP_VERSION }], [UCP_DELEGATION]: [{ version: UCP_VERSION, extends: UCP_CHECKOUT }] }, payment_handlers: handlerDeclarations(origin, selectedHandlers, false) },
    id: view.id, status: view.status, currency: view.currency, line_items: lineItems,
    totals: [{ type: 'subtotal', amount: total }, { type: 'total', amount: total }],
    links: [{ type: 'terms_of_service', url: `${origin}/ucp/terms` }, { type: 'privacy_policy', url: `${origin}/ucp/privacy` }],
    ...(view.messages ? { messages: view.messages } : {}),
    ...(view.expiresAt ? { expires_at: view.expiresAt } : {}),
    ...(view.continueUrl ? { continue_url: view.continueUrl } : {}),
    ...(view.order ? { order: view.order } : {}),
    ...(view.payment ? { payment: { instruments: view.payment.instruments.map((instrument) => Object.fromEntries(['id', 'handler_id', 'type', 'selected', 'display'].filter((key) => instrument[key] !== undefined).map((key) => [key, instrument[key]]))) } } : {}),
    ...(view.kya ? { kya: view.kya } : {}),
  };
}

async function readBounded(body: ReadableStream<Uint8Array> | null): Promise<string> {
  if (!body) return '';
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      length += chunk.value.byteLength;
      if (length > maxBodyBytes) { await reader.cancel(); throw new Error('Body exceeds size limit'); }
      chunks.push(chunk.value);
    }
    return Buffer.concat(chunks).toString('utf8');
  } finally { reader.releaseLock(); }
}
function parseProfileUrl(header: string | null): string | null {
  // This deliberately supports the canonical one-member RFC 8941 dictionary.
  // Reject duplicate members and other ambiguous spellings rather than normalizing signed metadata.
  const match = /^profile="([^"\\\s]+)"$/.exec(header?.trim() ?? '');
  if (!match) return null;
  try { const url = new URL(match[1]!); return !url.username && !url.password && !url.hash ? url.href : null; } catch { return null; }
}
function profileShape(profile: unknown): profile is UcpProfile {
  if (!dict(profile) || !dict(profile['ucp'])) return false;
  const ucp = profile['ucp'];
  if (!nonempty(ucp['version']) || !dict(ucp['services']) || !dict(ucp['capabilities']) || !dict(ucp['payment_handlers'])) return false;
  if (!Object.values(ucp['services']).every((variants) => Array.isArray(variants) && variants.every((item) => dict(item) && nonempty(item['version']) && nonempty(item['transport'])))) return false;
  return [ucp['capabilities'], ucp['payment_handlers']].every((entries) => Object.values(entries).every((variants) => Array.isArray(variants) && variants.every((item) => {
    if (!dict(item) || !nonempty(item['version'])) return false;
    const instruments = item['available_instruments'];
    return instruments === undefined || (Array.isArray(instruments) && instruments.every((instrument) => dict(instrument) && nonempty(instrument['type'])));
  })));
}
function validateBody(operation: UcpOperation, body: JsonObject, allowedHandlers: readonly UcpRail[]): string | null {
  if (operation === 'create' || operation === 'update') {
    if (!Array.isArray(body['line_items'])) return 'line_items must be an array.';
    if (body['line_items'].length > 50) return 'This merchant supports at most 50 checkout lines.';
    for (const line of body['line_items']) {
      if (!dict(line) || !dict(line['item']) || !nonempty(line['item']['id']) || !safeInteger(line['quantity'])) return 'Each line requires an item ID and a positive safe integer quantity.';
      if (line['id'] !== undefined && !nonempty(line['id'])) return 'Line IDs must be strings.';
      const unit = line['item']['quantity_unit'];
      if (unit !== undefined && (!dict(unit) || unit['unit'] !== 'C62' || (unit['scale'] !== undefined && unit['scale'] !== 0))) return 'This merchant sells whole items only (C62, scale 0).';
    }
  }
  if (operation === 'complete' && !dict(body['payment'])) return 'Complete checkout requires payment.';
  for (const key of ['buyer', 'context', 'signals', 'attribution', 'kya']) if (body[key] !== undefined && !dict(body[key])) return `${key} must be an object.`;
  if (body['payment'] !== undefined) {
    if (!dict(body['payment']) || !Array.isArray(body['payment']['instruments'])) return 'payment.instruments must be an array.';
    if (body['payment']['instruments'].length !== 1) return 'Select exactly one payment instrument.';
    const instrument: unknown = body['payment']['instruments'][0];
    if (!dict(instrument) || !nonempty(instrument['id']) || !nonempty(instrument['handler_id']) || !nonempty(instrument['type'])) return 'Payment instrument requires id, handler_id and type.';
    const rail = allowedHandlers.find((candidate) => UCP_HANDLER_IDS[candidate] === instrument['handler_id'] && candidate === instrument['type']);
    if (!rail) return 'The selected payment handler or instrument was not negotiated.';
    if (operation === 'complete') {
      const credential = instrument['credential'];
      if (!dict(credential) || credential['type'] !== rail) return 'Payment credential type must match the negotiated handler.';
      if (rail === 'sandbox-token' && !nonempty(credential['token'])) return 'Sandbox payment requires a token.';
      if (rail === 'x402' && !dict(credential['payload'])) return 'x402 payment requires its signed payment payload.';
    }
  }
  return null;
}

const escapeHtml = (text: unknown) => String(text).replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]!);
const reviewStyles = 'html{color-scheme:light}*{box-sizing:border-box}body{margin:0;padding:32px 16px;background:#f6f7f9;color:#101827;font-family:system-ui,sans-serif;font-size:18px;line-height:1.5}main{max-width:640px;margin:0 auto;background:white;border:1px solid #dde1e6;border-radius:24px;padding:32px;box-shadow:0 18px 50px #10182712}h1{font-size:34px;line-height:1.15;margin:8px 0 24px}h2{font-size:24px}.eyebrow{text-transform:uppercase;letter-spacing:.12em;font-size:13px;font-weight:700;color:#455570}.line,.total{display:flex;justify-content:space-between;gap:16px;padding:14px 0;border-bottom:1px solid #dde1e6}.total{font-size:24px;font-weight:650}.note{padding:18px;background:#f3efe7;border-radius:14px;margin:20px 0}button{width:100%;border:0;border-radius:999px;background:#101827;color:white;font:600 18px system-ui;padding:18px;cursor:pointer}button:focus-visible{outline:3px solid #467fe0;outline-offset:4px}.detail,code{overflow-wrap:anywhere;font-size:14px}a{color:inherit}small{font-size:15px}@media(max-width:480px){main{padding:24px}h1{font-size:30px}}';
function htmlPage(title: string, body: string, status = 200): Response {
  return new Response(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escapeHtml(title)}</title><style>${reviewStyles}</style></head><body><main>${body}</main></body></html>`, { status, headers: {
    'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY',
    'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
  } });
}
function money(amount: number, currency: string): string { return `${currency} ${(amount / 100).toFixed(2)}`; }
function reviewPage(review: UcpReview, token: string, origin: string): Response {
  const view = review.checkout;
  const total = view.lineItems.reduce((sum, line) => sum + line.item.price * line.quantity, 0);
  const heading = { requires_escalation: 'Confirm the exact purchase', ready_for_complete: 'Checkout confirmed',
    completed: 'Order recorded', complete_in_progress: 'Payment outcome unresolved', canceled: 'Checkout canceled', incomplete: 'Checkout unavailable' }[view.status];
  const action = view.status === 'requires_escalation'
    ? `<p>Your confirmation applies only to these items, quantity, price and payment terms. Any change requires a new review.</p><form method="post" action="/checkout/${encodeURIComponent(view.id)}/confirm"><input type="hidden" name="token" value="${escapeHtml(token)}"><input type="hidden" name="terms_digest" value="${escapeHtml(review.termsDigest)}"><button name="confirm" value="yes" type="submit">Confirm this checkout</button></form><p><small>This records your approval. Your agent must retry, and the merchant checks your current grant before payment or placing an order.</small></p>`
    : view.status === 'completed'
      ? `<p>Your workshop order was recorded. This demonstration does not fulfill goods.</p><p class="detail">Order: ${escapeHtml(view.order?.id ?? '')}</p>`
      : view.status === 'complete_in_progress'
        ? '<p>The payment may already have been submitted. Do not create another payment. Your agent can check this checkout for its recorded outcome.</p>'
        : view.status === 'ready_for_complete'
          ? '<p>Your confirmation is recorded. Your agent can now complete this checkout; the merchant will check your current grant before payment.</p>'
          : '<p>This checkout cannot be confirmed. Ask your agent to inspect its current status.</p>';
  return htmlPage(heading, `<p class="eyebrow">Your checkout</p><h1>${heading}</h1><p class="detail">Merchant: ${escapeHtml(origin)}</p>${view.lineItems.map((line) => `<div class="line"><span><strong>${escapeHtml(line.quantity)} × ${escapeHtml(line.item.title)}</strong><br><small>${escapeHtml(money(line.item.price, view.currency))} each</small></span><strong>${escapeHtml(money(line.item.price * line.quantity, view.currency))}</strong></div>`).join('')}<div class="total"><span>Total</span><span>${escapeHtml(money(total, view.currency))}</span></div><div class="note"><strong>${review.rail === 'x402' ? 'x402 payment' : 'Sandbox token payment'}</strong><p>${escapeHtml(review.rateDisclosure)}</p></div>${action}<details><summary>Checkout details</summary><p class="detail">${escapeHtml(view.id)}</p><code>${escapeHtml(review.termsDigest)}</code></details>`);
}
function handlerSchema(origin: string, rail: UcpRail): JsonObject {
  return { $schema: 'https://json-schema.org/draft/2020-12/schema', $id: `${origin}/ucp/handlers/${rail}.json`, name: handlerName(rail), version: UCP_VERSION,
    $defs: { [handlerName(rail)]: {
      business_schema: { $ref: `https://ucp.dev/${UCP_VERSION}/schemas/payment_handler.json#/$defs/business_schema` },
      platform_schema: { $ref: `https://ucp.dev/${UCP_VERSION}/schemas/payment_handler.json#/$defs/platform_schema` },
      response_schema: { $ref: `https://ucp.dev/${UCP_VERSION}/schemas/payment_handler.json#/$defs/response_schema` },
      payment_instrument: { allOf: [{ $ref: `https://ucp.dev/${UCP_VERSION}/schemas/common/types/payment_instrument.json` }, { type: 'object', properties: { type: { const: rail }, handler_id: { const: UCP_HANDLER_IDS[rail] }, credential: { type: 'object', required: ['type', rail === 'x402' ? 'payload' : 'token'], properties: { type: { const: rail }, ...(rail === 'x402' ? { payload: { type: 'object', description: 'x402 v2 PaymentPayload, validated and settled by the advertised x402 handler.' } } : { token: { type: 'string', minLength: 1, ucp_response: 'omit' } }) }, ucp_response: 'omit' } } }] },
    } },
  };
}

/** Mounts only UCP wire semantics. Backend is the sole authority for checkout state and effects. */
export function mountUcpRoutes(app: Hono, config: UcpAdapterConfig): void {
  const origin = new URL(config.origin).origin;
  const enabled = config.handlers ?? rails;
  const allowedProfiles = new Set(config.platformProfiles.map((url) => new URL(url).href));
  const fetchProfile = config.fetch ?? fetch;
  app.get('/.well-known/ucp', () => json(ucpBusinessProfile(config)));
  for (const rail of enabled) {
    app.get(`/ucp/handlers/${rail}.json`, () => json(handlerSchema(origin, rail)));
    app.get(`/ucp/handlers/${rail}`, () => htmlPage(`${rail} payment handler`, `<h1>${rail === 'x402' ? 'x402 v2 payment handler' : 'Sandbox token payment handler'}</h1><p>${rail === 'x402' ? 'The platform uses checkout.kya.payment_required to acquire an x402 v2 signed payment payload. Submit it as payment.instruments[0].credential.payload with credential.type=x402. The merchant validates the advertised network, asset, recipient, amount and settlement result before placing an order. This workshop supports local sandbox simulation and Base Sepolia testnet settlement only. The quote identifies the active mode.' : 'This is an explicitly simulated payment rail. It does not charge a card, bank account or blockchain wallet. Submit a merchant-issued sandbox token in payment.instruments[0].credential.token with credential.type=sandbox-token. The token is scoped to this checkout and payment terms; completion verifies it after current grant authorization.'}</p><p>All instruments require the negotiated handler_id, type and opaque instrument id. The platform and merchant advertise support under <code>${handlerName(rail)}</code>. Complete checkout requires trusted human review of exact terms; this handler does not implement AP2 mandates. The checkout backend binds payment evidence to its owner, terms and idempotency key. Reuse for different terms is rejected. Responses omit credentials. Consult checkout messages for recoverable payment failures.</p>`));
  }
  app.get('/ucp/delegation.json', () => json({ $schema: 'https://json-schema.org/draft/2020-12/schema', $id: `${origin}/ucp/delegation.json`, name: UCP_DELEGATION, version: UCP_VERSION, $defs: { [UCP_CHECKOUT]: { allOf: [{ $ref: `https://ucp.dev/${UCP_VERSION}/schemas/shopping/checkout.json` }, { type: 'object', properties: { kya: { type: 'object', description: 'Public signed merchant authorization challenge or receipt, canonical proof intent, and public payment quote. Contains no private payment credential.' } } }] } } }));
  app.get('/ucp/delegation', () => htmlPage('KYA checkout authorization', '<h1>KYA checkout authorization</h1><p>This negotiated checkout extension carries public merchant-signed challenges, decision receipts, canonical holder-proof arguments, and payment quotes in the top-level kya member. It does not redefine the reserved ucp namespace or implement AP2 mandates.</p><p>The agent signs each canonical request with a fresh holder proof and carries its delegation credential in X-KYA-Request. The merchant validates holder identity, signed consent, audience, scope, expiry, revocation and amount before settlement. A reusable grant does not replace trusted human confirmation of the exact checkout terms. The merchant requires both before completing the order.</p>'));
  app.get('/ucp/terms', () => htmlPage('Workshop checkout terms', '<h1>Workshop checkout terms</h1><p>This reference merchant demonstrates delegated commerce. Catalog orders are demonstration records and are not fulfilled. Sandbox token payments move no money. The x402 sandbox or Base Sepolia testnet mode, asset, amount and conversion rate are disclosed in the exact checkout review before approval. Mainnet payments are not supported.</p>'));
  app.get('/ucp/privacy', () => htmlPage('Workshop checkout privacy', '<h1>Workshop checkout privacy</h1><p>The merchant records checkout terms, agent authorization decisions and payment outcome references for the signed demo audit. Payment credentials are not included in checkout responses or public audit records. Avoid entering real customer or payment-card data in this workshop demonstration.</p>'));

  const operations: [UcpOperation, 'get' | 'post' | 'put', string][] = [
    ['create', 'post', '/ucp/checkout-sessions'], ['get', 'get', '/ucp/checkout-sessions/:id'],
    ['update', 'put', '/ucp/checkout-sessions/:id'], ['complete', 'post', '/ucp/checkout-sessions/:id/complete'], ['cancel', 'post', '/ucp/checkout-sessions/:id/cancel'],
  ];
  for (const [operation, method, path] of operations) app[method](path, async (c) => {
    const req = c.req.raw;
    const profileUrl = parseProfileUrl(req.headers.get('UCP-Agent'));
    if (!profileUrl) return protocolError(400, 'invalid_profile_url', 'UCP-Agent must contain a single quoted profile URL.');
    if (!allowedProfiles.has(profileUrl)) return protocolError(403, 'profile_not_allowed', 'This merchant accepts only configured platform profiles.');
    const requestId = req.headers.get('Request-Id');
    const idempotencyKey = operation === 'get' ? undefined : req.headers.get('Idempotency-Key');
    if (!nonempty(requestId) || requestId.length > 256 || (operation !== 'get' && (!nonempty(idempotencyKey) || idempotencyKey.length > 256))) return protocolError(400, 'invalid_request', 'Request-Id and write-operation Idempotency-Key are required.');
    if (!['get', 'cancel'].includes(operation) && req.headers.get('Content-Type')?.split(';')[0]?.trim().toLowerCase() !== 'application/json') return protocolError(415, 'unsupported_media_type', 'Checkout requests require application/json.');
    let rawBody: string;
    let body: JsonObject;
    try { rawBody = await readBounded(req.body); const parsed: unknown = rawBody ? JSON.parse(rawBody) : {}; if (!dict(parsed)) throw new Error(); body = parsed; } catch { return protocolError(400, 'invalid_request', 'Request body must be a JSON object no larger than 128 KiB.'); }
    let response: Response;
    try {
      response = await fetchProfile(profileUrl, { headers: { Accept: 'application/json' }, redirect: 'error', signal: AbortSignal.timeout(8000) });
      if (!response.ok) return protocolError(424, 'profile_unreachable', 'The configured platform profile could not be fetched.');
    } catch { return protocolError(424, 'profile_unreachable', 'The configured platform profile could not be fetched.'); }
    let profile: UcpProfile;
    try {
      const parsed: unknown = JSON.parse(await readBounded(response.body));
      if (!profileShape(parsed)) return protocolError(422, 'profile_malformed', 'Platform profile does not match the UCP discovery contract.');
      profile = parsed;
    } catch { return protocolError(422, 'profile_malformed', 'Platform profile must contain a JSON object no larger than 128 KiB.'); }
    if (profile.ucp.version !== UCP_VERSION) return protocolError(422, 'version_unsupported', `This merchant supports UCP ${UCP_VERSION}.`);
    if (![UCP_CHECKOUT, UCP_DELEGATION].every((capability) => profile.ucp.capabilities[capability]?.some((entry) => entry.version === UCP_VERSION))) return negotiationError('Checkout requires mutually supported checkout and KYA delegation capabilities.');
    const negotiated = enabled.filter((rail) => profile.ucp.payment_handlers[handlerName(rail)]?.some((handler) => handler.version === UCP_VERSION && (!handler.available_instruments || handler.available_instruments.some((instrument) => instrument.type === rail))));
    if (!negotiated.length) return negotiationError('No mutually supported payment handler.');
    const invalid = validateBody(operation, body, negotiated);
    if (invalid) return protocolError(400, 'invalid_request', invalid);
    try {
      const result = await config.backend.execute({ operation, id: c.req.param('id'), body, rawBody, headers: Object.fromEntries(req.headers), requestId, ...(idempotencyKey ? { idempotencyKey } : {}), platform: { url: profileUrl, profile, handlers: negotiated } });
      if ('error' in result) return protocolError(result.status, result.error.code, result.error.content);
      return json(ucpCheckoutResponse(result.checkout, origin, negotiated), result.status ?? (operation === 'create' ? 201 : 200));
    } catch { return protocolError(500, 'internal_error', 'Checkout could not be processed. Retry with the same idempotency key.'); }
  });
  app.get('/checkout/:id', async (c) => {
    const token = c.req.query('token');
    if (!nonempty(token)) return htmlPage('Checkout unavailable', '<h1>Checkout unavailable</h1><p>A valid review link is required.</p>', 400);
    const review = await config.backend.getReview({ id: c.req.param('id'), token, headers: Object.fromEntries(c.req.raw.headers) });
    return review ? reviewPage(review, token, origin) : htmlPage('Checkout unavailable', '<h1>Checkout unavailable</h1><p>This review link is expired or no longer matches the checkout.</p>', 404);
  });
  app.post('/checkout/:id/confirm', async (c) => {
    if (c.req.header('Origin') !== origin) return htmlPage('Confirmation refused', '<h1>Confirmation refused</h1><p>Return to the merchant checkout review.</p>', 403);
    let form: URLSearchParams;
    try { form = new URLSearchParams(await readBounded(c.req.raw.body)); } catch { return htmlPage('Invalid confirmation', '<h1>Invalid confirmation</h1>', 400); }
    const token = form.get('token');
    const termsDigest = form.get('terms_digest');
    if (!nonempty(token) || !nonempty(termsDigest) || form.get('confirm') !== 'yes' || ['token', 'terms_digest', 'confirm'].some((key) => form.getAll(key).length !== 1)) return htmlPage('Invalid confirmation', '<h1>Invalid confirmation</h1><p>Use the confirmation button after reviewing the exact terms.</p>', 400);
    const result = await config.backend.confirmReview({ id: c.req.param('id'), token, termsDigest, origin, headers: Object.fromEntries(c.req.raw.headers) });
    return result.ok
      ? htmlPage('Checkout confirmed', '<h1>Checkout confirmed</h1><p>Your agent can now retry to finish this checkout. The merchant will check your current grant before payment and placing the order.</p><p>You can close this window.</p>')
      : htmlPage('Review required', `<h1>Review required</h1><p>${escapeHtml(result.content)}</p>`, result.status ?? 409);
  });
}
