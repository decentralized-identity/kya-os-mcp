import { ConsentProtocol, type SignedMessage } from '../lib/consent-protocol.js';
import { consentDigest, tokenReference } from '../lib/consent-evidence.js';
import { findCatalogItem, toMinor } from '../lib/product.js';
import { responseBody, type MerchantToolResult } from '../agent/authorization.js';
import { PaymentCoordinator, type CheckoutRecord, type CommerceRail } from './payments.js';
import { UCP_HANDLER_IDS, type UcpBackend, type UcpBackendRequest, type UcpBackendResult, type UcpCheckoutView, type UcpMessage } from './ucp.js';

type JsonObject = Record<string, unknown>;
type ErrorStatus = Extract<UcpBackendResult, { error: unknown }>['status'];
const object = (value: unknown): value is JsonObject => value !== null && typeof value === 'object' && !Array.isArray(value);
const queues = new Map<string, Promise<unknown>>();
const retentionMs = 24 * 60 * 60 * 1000;
class BackendError extends Error {
  constructor(readonly code: string, readonly status: ErrorStatus, message = code) { super(message); }
}
const errorResult = (error: unknown): UcpBackendResult => {
  if (error instanceof BackendError) return { error: { code: error.code, content: error.message }, status: error.status };
  const code = error instanceof Error ? error.message.split(':')[0]! : 'COMMERCE_UNAVAILABLE';
  if (code === 'CHECKOUT_NOT_FOUND') return { error: { code, content: 'Checkout not found.' }, status: 404 };
  if (['CHECKOUT_IMMUTABLE', 'CHECKOUT_CONFIRMATION_INVALID', 'CHECKOUT_BINDING_MISMATCH'].includes(code)) return { error: { code, content: 'The checkout changed or cannot be modified in its current state.' }, status: 409 };
  if (['CHECKOUT_INVALID', 'PAYMENT_RAIL_UNSUPPORTED'].includes(code)) return { error: { code, content: 'Unsupported checkout or payment terms.' }, status: 400 };
  return { error: { code: 'COMMERCE_UNAVAILABLE', content: 'Checkout state could not be safely established. Inspect this checkout before retrying.' }, status: 503 };
};
function decodeHeader(value: string | undefined): JsonObject {
  if (!value || value.length > 128 * 1024 || !/^[A-Za-z0-9+/_=-]+$/.test(value)) throw new BackendError('HOLDER_PROOF_REQUIRED', 401, 'A fresh bound holder proof is required.');
  try {
    const decoded: unknown = JSON.parse(Buffer.from(value, 'base64').toString('utf8'));
    if (object(decoded)) return decoded;
  } catch { /* The untrusted header is never returned to the caller. */ }
  throw new BackendError('HOLDER_PROOF_INVALID', 401, 'The signed request is malformed.');
}
const keysWithin = (value: JsonObject, keys: readonly string[]) => Object.keys(value).every(key => keys.includes(key));

/** Stateful checkout ownership belongs to the merchant. Consent and delegation
 * remain verified by the common KYA order gate before PaymentCoordinator acts. */
export function createUcpBackend(options: {
  coordinator: PaymentCoordinator; merchantDid: string; origin: string;
  /** Fresh proof for a historical result; never a new authorization or effect. */
  signResult?: (args: JsonObject, body: JsonObject) => Promise<MerchantToolResult>;
}): UcpBackend {
  const { coordinator } = options;
  const origin = new URL(options.origin).origin;
  const verifier = new ConsentProtocol();
  async function authenticate(request: UcpBackendRequest): Promise<string> {
    try {
      const message = decodeHeader(request.headers['x-kya-request']) as unknown as SignedMessage;
      const owner = message.proof?.meta?.did;
      if (typeof owner !== 'string' || !owner.startsWith('did:key:')) throw new Error('Unsupported holder');
      const expected = { id: request.id ?? null, body: request.body, idempotencyKey: request.idempotencyKey ?? null, profile: request.platform.url };
      if (consentDigest(message.body) !== consentDigest(expected)) throw new Error('Request binding differs');
      await verifier.verify(`ucp.${request.operation}`, message, owner, options.merchantDid);
      return owner;
    } catch { throw new BackendError('HOLDER_PROOF_INVALID', 401, 'A fresh holder proof must bind this operation, checkout, body, idempotency key, and platform.'); }
  }
  function owned(id: string | undefined, owner: string): CheckoutRecord {
    const record = id ? coordinator.get(id) : null;
    if (!record) throw new BackendError('CHECKOUT_NOT_FOUND', 404, 'Checkout not found.');
    if (record.owner !== owner) throw new BackendError('CHECKOUT_FORBIDDEN', 403, 'This checkout belongs to another holder.');
    if (record.protocol !== 'ucp') throw new BackendError('CHECKOUT_BINDING_MISMATCH', 409, 'This is not a UCP checkout.');
    return record;
  }
  function terms(request: UcpBackendRequest, previousRail?: CommerceRail): { product: string; quantity: number; rail: CommerceRail } {
    const { body } = request;
    if (!keysWithin(body, ['line_items', 'currency', 'kya']) || (body['currency'] !== undefined && body['currency'] !== 'CHF')) throw new BackendError('UNSUPPORTED_CHECKOUT_TERMS', 400, 'This checkout supports CHF catalog items only; billing, shipping, taxes, and caller-supplied totals are not supported.');
    const lines = body['line_items'];
    if (!Array.isArray(lines) || lines.length !== 1 || !object(lines[0]) || !keysWithin(lines[0], ['id', 'item', 'quantity'])) throw new BackendError('CHECKOUT_INVALID', 400, 'Provide exactly one catalog line item.');
    const line = lines[0];
    const item = line['item'];
    if (!object(item) || !keysWithin(item, ['id', 'title', 'price']) || typeof item['id'] !== 'string') throw new BackendError('CHECKOUT_INVALID', 400);
    const catalog = findCatalogItem(item['id']);
    if (!catalog || (item['price'] !== undefined && item['price'] !== Number(toMinor(catalog.unitPrice))) || (item['title'] !== undefined && item['title'] !== catalog.name)) throw new BackendError('CATALOG_TERMS_MISMATCH', 400, 'Product identity, title, and price must match the merchant catalog.');
    if (!Number.isSafeInteger(line['quantity']) || Number(line['quantity']) < 1 || Number(line['quantity']) > 999) throw new BackendError('CHECKOUT_INVALID', 400, 'Quantity must be an integer from 1 to 999.');
    const kya = body['kya'];
    if (kya !== undefined && (!object(kya) || !keysWithin(kya, ['rail']))) throw new BackendError('PAYMENT_RAIL_UNSUPPORTED', 400);
    const rail = (object(kya) ? kya['rail'] : undefined) ?? previousRail ?? request.platform.handlers[0];
    if ((rail !== 'x402' && rail !== 'sandbox-token') || !request.platform.handlers.includes(rail)) throw new BackendError('PAYMENT_RAIL_UNSUPPORTED', 400, 'Select a negotiated payment handler.');
    return { product: catalog.sku, quantity: Number(line['quantity']), rail };
  }
  function view(record: CheckoutRecord, result?: MerchantToolResult): UcpCheckoutView {
    const item = findCatalogItem(record.product);
    if (!item) throw new Error('COMMERCE_STORAGE_INVALID');
    const body = result ? responseBody(result) : record.result;
    const reviewUrl = `${origin}/checkout/${encodeURIComponent(record.id)}?token=${encodeURIComponent(record.reviewToken)}`;
    let status: UcpCheckoutView['status'] = record.state === 'settled' ? 'completed' : record.state === 'settling' ? 'complete_in_progress' : record.state === 'canceled' ? 'canceled' : record.confirmedDigest === record.termsDigest ? 'ready_for_complete' : 'requires_escalation';
    let continueUrl: string | undefined = status === 'requires_escalation' ? reviewUrl : undefined;
    if (body?.['error'] === 'needs_authorization' && typeof body['authorizationUrl'] === 'string') {
      status = 'requires_escalation'; continueUrl = body['authorizationUrl'];
    } else if (body?.['error'] === 'SETTLEMENT_PENDING') { status = 'complete_in_progress'; continueUrl = undefined; }
    else if (record.state === 'failed' || (body?.['error'] && !['PAYMENT_REQUIRED', 'CHECKOUT_CONFIRMATION_REQUIRED'].includes(String(body['error'])))) { status = 'incomplete'; continueUrl = undefined; }
    if (record.state === 'open' && Date.now() >= Date.parse(record.expiresAt)) { status = 'incomplete'; continueUrl = undefined; }
    const messages: UcpMessage[] = status === 'requires_escalation'
      ? [{ type: 'error', code: body?.['error'] === 'needs_authorization' ? 'needs_authorization' : 'CHECKOUT_CONFIRMATION_REQUIRED',
        content: body?.['error'] === 'needs_authorization' ? 'Approve the agent delegation at your authorization host, then retry this checkout.' : 'Review and confirm these exact checkout terms before the agent completes the order.',
        severity: body?.['error'] === 'needs_authorization' ? 'requires_buyer_input' : 'requires_buyer_review' }]
      : body?.['error'] ? [{ type: status === 'complete_in_progress' ? 'info' : 'error', code: String(body['error']), content: String(body['message'] ?? body['reason'] ?? 'The checkout requires another step.'), severity: 'recoverable' }] : [];
    return {
      id: record.id, status, currency: record.currency,
      lineItems: [{ id: 'line_1', item: { id: item.uri, title: item.name, price: Number(toMinor(item.unitPrice)) }, quantity: record.quantity }],
      expiresAt: record.expiresAt, ...(continueUrl ? { continueUrl } : {}), handlers: [record.rail],
      ...(record.result?.['orderId'] ? { order: { id: String(record.result['orderId']), permalink_url: `${origin}/checkout/${encodeURIComponent(record.id)}?token=${encodeURIComponent(record.reviewToken)}` } } : {}),
      ...(messages.length ? { messages } : {}),
      kya: {
        intent: { product: record.product, quantity: record.quantity, checkout: { id: record.id, protocol: record.protocol, termsDigest: record.termsDigest } },
        ...(result ? { result } : {}), payment_required: coordinator.paymentRequired(record), pricing: record.quote.pricing,
      },
    };
  }
  function completion(request: UcpBackendRequest, record: CheckoutRecord, owner: string) {
    if (!keysWithin(request.body, ['payment'])) throw new BackendError('UNSUPPORTED_CHECKOUT_TERMS', 400, 'Completion cannot change the reviewed checkout terms.');
    const payment = request.body['payment'];
    if (!object(payment) || !keysWithin(payment, ['instruments']) || !Array.isArray(payment['instruments']) || payment['instruments'].length !== 1) throw new BackendError('PAYMENT_INVALID', 400);
    const instrument = payment['instruments'][0];
    if (!object(instrument) || !keysWithin(instrument, ['id', 'handler_id', 'type', 'credential']) || instrument['handler_id'] !== UCP_HANDLER_IDS[record.rail] || instrument['type'] !== record.rail || !request.platform.handlers.includes(record.rail)) throw new BackendError('PAYMENT_RAIL_UNSUPPORTED', 400);
    const credential = instrument['credential'];
    if (!object(credential) || credential['type'] !== record.rail || !keysWithin(credential, ['type', record.rail === 'x402' ? 'payload' : 'token'])) throw new BackendError('PAYMENT_INVALID', 400);
    const payload = record.rail === 'x402' ? credential['payload'] : credential['token'];
    if (record.rail === 'x402' ? !object(payload) : typeof payload !== 'string' || !payload) throw new BackendError('PAYMENT_INVALID', 400);
    const order = decodeHeader(request.headers['x-kya-order']);
    const args = order['args'];
    if (!object(args)) throw new BackendError('CHECKOUT_BINDING_MISMATCH', 409);
    const checkout = args['checkout'];
    const proof = args['_kyaos_proof'];
    const proofOwner = object(proof) && object(proof['meta']) ? proof['meta']['did'] : undefined;
    if (args['product'] !== record.product || args['quantity'] !== record.quantity || !object(checkout)
      || checkout['id'] !== record.id || checkout['protocol'] !== 'ucp' || checkout['termsDigest'] !== record.termsDigest || proofOwner !== owner) throw new BackendError('CHECKOUT_BINDING_MISMATCH', 409, 'The delegated action must match this holder and the exact checkout terms.');
    return { args, payload };
  }
  async function recoverResult(args: JsonObject, body: JsonObject, owner: string): Promise<MerchantToolResult> {
    if (!options.signResult) throw new BackendError('RECEIPT_SIGNER_UNAVAILABLE', 503, 'The historical order is retained, but a fresh receipt proof is unavailable.');
    // The outer request proves ownership. Verify the independently bound inner
    // request too, without treating a historical read as new grant approval.
    await verifier.verify('place_order', { body: args, proof: args['_kyaos_proof'] as SignedMessage['proof'] }, owner, options.merchantDid);
    return options.signResult(args, structuredClone(body));
  }
  async function perform(request: UcpBackendRequest, owner: string, createId: string): Promise<UcpBackendResult> {
    if (request.operation === 'create') {
      const record = await coordinator.prepare({ ...terms(request), id: createId, owner, protocol: 'ucp' });
      return { checkout: view(record), status: 201 };
    }
    const record = owned(request.id, owner);
    if (request.operation === 'get') {
      if (Object.keys(request.body).length) throw new BackendError('CHECKOUT_INVALID', 400);
      return { checkout: view(record) };
    }
    if (request.operation === 'update') return { checkout: view(await coordinator.update(record.id, owner, terms(request, record.rail))) };
    if (request.operation === 'cancel') {
      if (Object.keys(request.body).length) throw new BackendError('UNSUPPORTED_CHECKOUT_TERMS', 400);
      return { checkout: view(await coordinator.cancel(record.id, owner)) };
    }
    const { args, payload } = completion(request, record, owner);
    if (record.state === 'settled' && record.result) {
      await coordinator.recoverCompletionEvidence(record.id);
      return { checkout: view(owned(record.id, owner), await recoverResult(args, record.result, owner)) };
    }
    const result = await coordinator.complete(args, payload);
    return { checkout: view(owned(record.id, owner), result) };
  }
  async function serialized<T>(action: () => Promise<T>): Promise<T> {
    const previous = queues.get(coordinator.journal.file) ?? Promise.resolve();
    const next = previous.then(action); const tail = next.catch(() => {});
    queues.set(coordinator.journal.file, tail);
    try { return await next; }
    finally { if (queues.get(coordinator.journal.file) === tail) queues.delete(coordinator.journal.file); }
  }
  return {
    async execute(request) {
      try {
        const owner = await authenticate(request);
        if (request.operation === 'get') return await perform(request, owner, '');
        if (!request.idempotencyKey || request.idempotencyKey.length > 200) throw new BackendError('IDEMPOTENCY_KEY_REQUIRED', 400);
        return await serialized(async () => {
          const key = `ucp:${consentDigest({ owner, profile: request.platform.url, key: request.idempotencyKey })}`;
          const completionArgs = request.operation === 'complete' ? completion(request, owned(request.id, owner), owner).args : undefined;
          const intent = completionArgs ? Object.fromEntries(Object.entries(completionArgs).filter(([name]) => !name.startsWith('_kyaos'))) : null;
          const digest = consentDigest({ operation: request.operation, id: request.id ?? null, body: request.body, intent });
          const cached = coordinator.journal.read().requests[key];
          if (cached && cached.digest !== digest) throw new BackendError('IDEMPOTENCY_CONFLICT', 409, 'This idempotency key was already used for different checkout content.');
          if (cached?.result) {
            const result = structuredClone(cached.result) as UcpBackendResult;
            if (completionArgs && 'checkout' in result) {
              const saved = result.checkout.kya?.['result'];
              const record = owned(request.id, owner);
              if (record.state === 'settled' && record.result) {
                await coordinator.recoverCompletionEvidence(record.id);
                return { checkout: view(owned(record.id, owner), await recoverResult(completionArgs, record.result, owner)) };
              }
              if (object(saved)) {
                const body = responseBody(saved as MerchantToolResult);
                if (body['error'] === 'needs_authorization' && Number(body['expiresAt']) <= Math.floor(Date.now() / 1000)) {
                  const refusal = { ok: false, error: 'CONSENT_EXPIRED', message: 'This authorization request expired. Begin a new completion attempt for this checkout and review any refreshed terms.' };
                  return { checkout: view(record, await recoverResult(completionArgs, refusal, owner)) };
                }
                result.checkout.kya = { ...result.checkout.kya, result: await recoverResult(completionArgs, body, owner) };
              }
            }
            return result;
          }
          await coordinator.journal.exclusive(() => {
            const state = coordinator.journal.read();
            // Other merchant processes can reserve this key after the optimistic
            // cache read above. Compare and reserve while holding the shared
            // journal lock, before any checkout or payment operation proceeds.
            const reserved = state.requests[key];
            if (reserved && reserved.digest !== digest) throw new BackendError('IDEMPOTENCY_CONFLICT', 409, 'This idempotency key was already used for different checkout content.');
            for (const [oldKey, saved] of Object.entries(state.requests)) if (saved.at < Date.now() - retentionMs) delete state.requests[oldKey];
            if (Object.keys(state.requests).length >= 10000 && !state.requests[key]) throw new Error('COMMERCE_STORAGE_FULL');
            state.requests[key] ??= { digest, result: null, at: Date.now() }; coordinator.journal.write(state);
          });
          let result: UcpBackendResult;
          try { result = await perform(request, owner, `ucp_${tokenReference(key).slice(7, 47)}`); }
          catch (error) { result = errorResult(error); }
          await coordinator.journal.exclusive(() => {
            const state = coordinator.journal.read();
            if (state.requests[key]?.digest !== digest) throw new BackendError('IDEMPOTENCY_CONFLICT', 409, 'The request reservation no longer matches this checkout operation.');
            state.requests[key] = { digest, result, at: Date.now() }; coordinator.journal.write(state);
          });
          return result;
        });
      } catch (error) { return errorResult(error); }
    },
    async getReview({ id, token }) {
      const record = coordinator.get(id);
      if (!record || record.protocol !== 'ucp' || !token || tokenReference(record.reviewToken) !== tokenReference(token)) return null;
      const checkout = view(record);
      delete checkout.kya;
      const amount = (BigInt(record.amountMinor) / 100n).toString() + '.' + (BigInt(record.amountMinor) % 100n).toString().padStart(2, '0');
      const atomic = BigInt(record.quote.pricing.amountAtomic);
      const tokens = `${atomic / 1000000n}.${(atomic % 1000000n).toString().padStart(6, '0')}`;
      return { checkout, termsDigest: record.termsDigest, rail: record.rail,
        rateDisclosure: record.rail === 'x402'
          ? `CHF ${amount} = ${tokens} test USDC. ${record.paymentMode === 'sandbox' ? 'Sandbox: signature verification only; no blockchain transaction or funds movement.' : 'Base Sepolia testnet: test USDC transfer; no real funds.'} ${record.quote.pricing.note}`
          : `CHF ${amount}. Sandbox token only; no card network or funds movement.` };
    },
    async confirmReview({ id, token, termsDigest, origin: requestOrigin }) {
      if (requestOrigin !== origin) return { ok: false, code: 'ORIGIN_MISMATCH', content: 'Confirm from the merchant checkout page.', status: 403 };
      try {
        const record = coordinator.get(id);
        if (!record || record.protocol !== 'ucp') throw new Error('CHECKOUT_CONFIRMATION_INVALID');
        await coordinator.confirm(id, token, termsDigest);
        return { ok: true };
      } catch { return { ok: false, code: 'CHECKOUT_CONFIRMATION_INVALID', content: 'The checkout changed, expired, or was already completed. Review the current terms.', status: 409 }; }
    },
  };
}
