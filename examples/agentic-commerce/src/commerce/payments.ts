import { randomBytes, randomUUID } from 'node:crypto';
import type { DelegationCredential } from '@kya-os/mcp';
import { consentDigest, tokenReference } from '../lib/consent-evidence.js';
import { findCatalogItem, toMinor } from '../lib/product.js';
import { responseBody, type MerchantToolResult } from '../agent/authorization.js';
import type { OrderExecution } from '../merchant/server.js';
import { X402Rail, type X402Quote, type X402Settlement } from '../payments/x402.js';
import { CommerceJournal } from './journal.js';

export type CommerceRail = 'x402' | 'sandbox-token';
export interface CheckoutRecord extends Record<string, unknown> {
  id: string; owner: string; protocol: 'x402' | 'ucp'; product: string; productUri: string;
  quantity: number; rail: CommerceRail; amountMinor: number; currency: 'CHF';
  paymentMode: 'sandbox' | 'testnet';
  quote: X402Quote; termsDigest: string; reviewToken: string; confirmedDigest?: string;
  state: 'open' | 'settling' | 'settled' | 'failed' | 'canceled';
  paymentIdentity?: string; tokenHash?: string; payment?: Record<string, unknown>;
  result?: Record<string, unknown>; createdAt: string; expiresAt: string;
  completionEvidence?: { event: Record<string, unknown>; deliveredAt?: string };
}
export interface PaymentCoordinatorOptions {
  journal: CommerceJournal; rail: X402Rail; origin: string;
  authorize(args: Record<string, unknown>, execution?: OrderExecution): Promise<MerchantToolResult>;
  /** Refresh revocation/time immediately before a potentially slow rail commits. */
  beforeSettlement?: (credential: DelegationCredential) => Promise<void>;
  onPayment?: (event: Record<string, unknown>) => Promise<void>;
}
const fail = (error: string, message: string) => ({ body: { ok: false, error, message } });
const pending = () => fail('SETTLEMENT_PENDING', 'Payment outcome unresolved. Do not create another payment. Inspect this checkout before retrying.');
const authorityFailure = (error: unknown) => {
  const reason = error instanceof Error ? error.message : '';
  const code = reason.split(':')[0] ?? '';
  const messages: Record<string, string> = {
    AUTHORITY_REVOKED: 'The delegation was revoked before payment. No payment was submitted.',
    AUTHORITY_EXPIRED: 'The delegation expired before payment. No payment was submitted.',
    AUTHORITY_STATUS_UNAVAILABLE: 'Current revocation status could not be established. No payment was submitted.',
  };
  return messages[code]
    ? fail(code, messages[code])
    : fail('AUTHORITY_CHANGED', 'Authority changed before payment. No payment was submitted.');
};
// Nonce-based deduplication keys remain in private journal state, not receipts.
const publicPayment = (settlement: object): Record<string, unknown> => Object.fromEntries(Object.entries(settlement).filter(([key]) => key !== 'paymentIdentity'));

/** The same verified order intent can reach either payment adapter. Settlement
 * and order recovery live here, outside the identity/delegation protocol. */
export class PaymentCoordinator {
  readonly journal: CommerceJournal;
  readonly rail: X402Rail;
  constructor(private readonly options: PaymentCoordinatorOptions) {
    this.journal = options.journal; this.rail = options.rail;
  }

  get(id: string): CheckoutRecord | null {
    const record = this.journal.read().records[id];
    if (!record) return null;
    if (record.id !== id || typeof record.owner !== 'string' || typeof record.termsDigest !== 'string'
      || !['open', 'settling', 'settled', 'failed', 'canceled'].includes(String(record.state))) throw new Error('COMMERCE_STORAGE_INVALID: invalid checkout');
    return structuredClone(record) as CheckoutRecord;
  }

  async prepare(input: { id?: string; owner: string; protocol: 'x402' | 'ucp'; product: string; quantity: number; rail: CommerceRail }): Promise<CheckoutRecord> {
    return this.journal.exclusive(async () => {
      const id = input.id ?? randomUUID();
      if (!/^[a-zA-Z0-9_-]{1,100}$/.test(id) || !input.owner.startsWith('did:')) throw new Error('CHECKOUT_INVALID');
      if (!['x402', 'ucp'].includes(input.protocol) || !['x402', 'sandbox-token'].includes(input.rail)
        || (input.protocol === 'x402' && input.rail !== 'x402')) throw new Error('PAYMENT_RAIL_UNSUPPORTED');
      const previous = this.get(id);
      if (previous) {
        if (previous.owner !== input.owner || previous.protocol !== input.protocol || previous.product !== input.product
          || previous.quantity !== input.quantity || previous.rail !== input.rail) throw new Error('CHECKOUT_BINDING_MISMATCH');
        return previous;
      }
      const record = await this.build({ ...input, id });
      const state = this.journal.read();
      if (Object.keys(state.records).length >= 5000) throw new Error('COMMERCE_STORAGE_FULL: archive this demo volume before creating more checkouts');
      state.records[id] = record; this.journal.write(state);
      return record;
    });
  }

  private async build(input: { id: string; owner: string; protocol: 'x402' | 'ucp'; product: string; quantity: number; rail: CommerceRail }): Promise<CheckoutRecord> {
    const item = findCatalogItem(input.product);
    if (!item || !Number.isSafeInteger(input.quantity) || input.quantity < 1 || input.quantity > 999) throw new Error('CHECKOUT_INVALID');
    const amountMinor = Number(toMinor(item.unitPrice) * BigInt(input.quantity));
    const quote = await this.rail.createRequirements({ id: input.id, resource: `${this.options.origin}/payments/checkouts/${input.id}`, amountMinor: String(amountMinor), currency: 'CHF' });
    const paymentMode = input.rail === 'sandbox-token' ? 'sandbox' : this.rail.mode;
    const terms = { id: input.id, owner: input.owner, protocol: input.protocol, productUri: item.uri, quantity: input.quantity,
      amountMinor, currency: 'CHF' as const, rail: input.rail, paymentMode, quote };
    return { ...input, productUri: item.uri, amountMinor, currency: 'CHF', paymentMode, quote, termsDigest: consentDigest(terms),
      reviewToken: randomBytes(32).toString('base64url'), state: 'open', createdAt: new Date().toISOString(), expiresAt: quote.expiresAt };
  }

  async update(id: string, owner: string, input: { product: string; quantity: number; rail: CommerceRail }): Promise<CheckoutRecord> {
    return this.journal.exclusive(async () => {
      const previous = this.owned(id, owner);
      if (previous.state !== 'open') throw new Error('CHECKOUT_IMMUTABLE');
      const record = await this.build({ ...input, id, owner, protocol: previous.protocol });
      const state = this.journal.read(); state.records[id] = record; this.journal.write(state);
      return record;
    });
  }
  private owned(id: string, owner: string): CheckoutRecord {
    const record = this.get(id);
    if (!record || record.owner !== owner) throw new Error('CHECKOUT_NOT_FOUND');
    return record;
  }
  async cancel(id: string, owner: string): Promise<CheckoutRecord> {
    return this.journal.exclusive(() => {
      const record = this.owned(id, owner);
      if (!['open', 'canceled', 'failed'].includes(record.state)) throw new Error('CHECKOUT_IMMUTABLE');
      record.state = 'canceled';
      const state = this.journal.read(); state.records[id] = record; this.journal.write(state);
      return record;
    });
  }
  async confirm(id: string, token: string, termsDigest: string): Promise<CheckoutRecord> {
    return this.journal.exclusive(() => {
      const record = this.get(id);
      if (!record || tokenReference(record.reviewToken) !== tokenReference(token) || record.termsDigest !== termsDigest
        || record.state !== 'open' || Date.now() >= Date.parse(record.expiresAt)) throw new Error('CHECKOUT_CONFIRMATION_INVALID');
      record.confirmedDigest = termsDigest;
      const state = this.journal.read(); state.records[id] = record; this.journal.write(state);
      return record;
    });
  }
  async tokenize(id: string, owner: string): Promise<string> {
    return this.journal.exclusive(() => {
      const record = this.owned(id, owner);
      if (record.rail !== 'sandbox-token' || record.state !== 'open' || record.confirmedDigest !== record.termsDigest
        || Date.now() >= Date.parse(record.expiresAt)) throw new Error('CHECKOUT_CONFIRMATION_REQUIRED');
      const token = `sandbox_${randomBytes(32).toString('base64url')}`;
      record.tokenHash = tokenReference(token);
      const state = this.journal.read(); state.records[id] = record; this.journal.write(state);
      return token;
    });
  }

  /** Initial paid MCP call. Produces standard x402 PaymentRequired, with a
   * merchant-signed extension binding the exact checkout and conversion quote. */
  async requestPayment(args: Record<string, unknown>): Promise<MerchantToolResult> {
    return this.options.authorize(args, async ({ vc }) => {
      const checkout = args['checkout'] as Record<string, unknown> | undefined;
      if (!checkout || checkout['protocol'] !== 'x402' || typeof checkout['id'] !== 'string') return fail('CHECKOUT_INVALID', 'A stable checkout id is required.');
      const record = await this.prepare({ id: checkout['id'], owner: vc.credentialSubject.id, protocol: 'x402',
        product: String(args['product']), quantity: Number(args['quantity']), rail: 'x402' });
      return { body: this.paymentRequired(record) };
    });
  }

  paymentRequired(record: CheckoutRecord): Record<string, unknown> {
    return { ...record.quote.paymentRequired, error: 'PAYMENT_REQUIRED', extensions: {
      ...record.quote.paymentRequired.extensions,
      'org.kya-os/checkout': {
        info: { id: record.id, termsDigest: record.termsDigest, pricing: record.quote.pricing, mode: record.paymentMode },
        schema: { type: 'object', required: ['id', 'termsDigest', 'pricing', 'mode'], properties: {
          id: { type: 'string' }, termsDigest: { type: 'string', pattern: '^sha256:[a-f0-9]{64}$' },
          pricing: { type: 'object' }, mode: { enum: ['sandbox', 'testnet'] },
        } },
      },
    } };
  }

  /** Replay retained outcome evidence only. It neither authorizes nor settles. */
  async recoverCompletionEvidence(id: string): Promise<boolean> {
    return this.journal.exclusive(async () => {
      const record = this.get(id);
      if (!record || record.state !== 'settled') return false;
      return this.deliverCompletionEvidence(record);
    });
  }

  private async deliverCompletionEvidence(record: CheckoutRecord): Promise<boolean> {
    const evidence = record.completionEvidence;
    if (!evidence || evidence.deliveredAt) return true;
    if (!this.options.onPayment) return false;
    try {
      await this.options.onPayment(structuredClone(evidence.event));
      evidence.deliveredAt = new Date().toISOString();
      const state = this.journal.read(); state.records[record.id] = record; this.journal.write(state);
      return true;
    } catch { return false; }
  }

  async complete(args: Record<string, unknown>, payload: unknown): Promise<MerchantToolResult> {
    // Authorize before accessing any financial side effect, including retries.
    return this.options.authorize(args, async ({ outcome, vc, evidence }) => this.journal.exclusive(async () => {
      const intent = args['checkout'] as Record<string, unknown> | undefined;
      const record = typeof intent?.['id'] === 'string' ? this.get(intent['id']) : null;
      if (!record || record.owner !== vc.credentialSubject.id || intent?.['termsDigest'] !== record.termsDigest
        || intent['protocol'] !== record.protocol || args['product'] !== record.product || args['quantity'] !== record.quantity
        || outcome.item.uri !== record.productUri || outcome.quantity !== record.quantity
        || Number(toMinor(outcome.item.unitPrice) * BigInt(outcome.quantity)) !== record.amountMinor) {
        return fail('CHECKOUT_BINDING_MISMATCH', 'The signed action does not match this checkout and its final terms.');
      }
      if (record.state === 'settled' && record.result) {
        await this.deliverCompletionEvidence(record);
        return { body: record.result, committed: false };
      }
      if (record.state === 'settling') return pending();
      if (record.state !== 'open') return fail('CHECKOUT_IMMUTABLE', 'This checkout cannot be completed.');
      if (record.paymentMode !== (record.rail === 'sandbox-token' ? 'sandbox' : this.rail.mode)) return fail('PAYMENT_MODE_CHANGED', 'Payment configuration changed. Prepare and review a new checkout.');
      if (Date.now() >= Date.parse(record.expiresAt)) return fail('CHECKOUT_EXPIRED', 'Prepare a fresh quote and review its terms.');
      if (record.protocol === 'ucp' && record.confirmedDigest !== record.termsDigest) return fail('CHECKOUT_CONFIRMATION_REQUIRED', 'The human must confirm these exact checkout terms.');

      let paymentIdentity: string;
      if (record.rail === 'x402') {
        const verified = await this.rail.verify(record.quote, payload);
        if (!verified.isValid) return fail('PAYMENT_INVALID', verified.reason);
        paymentIdentity = verified.paymentIdentity;
      } else {
        if (typeof payload !== 'string' || !record.tokenHash || tokenReference(payload) !== record.tokenHash) return fail('PAYMENT_INVALID', 'The sandbox token is not bound to this checkout.');
        paymentIdentity = `sandbox-token:${record.tokenHash}`;
      }
      // A rail signature may authorize the same amount for a different resource.
      // One payment identity can fulfill only one immutable merchant checkout.
      const state = this.journal.read();
      if (state.payments[paymentIdentity] && state.payments[paymentIdentity] !== record.id) return fail('PAYMENT_REPLAY', 'This payment authorization belongs to another checkout.');
      try { await this.options.beforeSettlement?.(vc); }
      catch (error) { return authorityFailure(error); }
      await this.options.onPayment?.({ phase: 'authorized', checkoutId: record.id, protocol: record.protocol, rail: record.rail,
        termsDigest: record.termsDigest, amountMinor: record.amountMinor, currency: record.currency });
      // Auditing is asynchronous. A revocation during that wait must still
      // prevent the synchronous sandbox effect at its final reversible point.
      if (record.rail === 'sandbox-token') {
        try { await this.options.beforeSettlement?.(vc); }
        catch (error) { return authorityFailure(error); }
      }
      record.state = 'settling'; record.paymentIdentity = paymentIdentity;
      state.payments[paymentIdentity] = record.id; state.records[record.id] = record;
      this.journal.write(state); // Must finish before the external call.
      let settlement: X402Settlement | { status: 'simulated'; simulated: true; simulationId: string; note: string };
      try {
        settlement = record.rail === 'x402' ? await this.rail.settle(record.quote, payload, () => this.options.beforeSettlement?.(vc) ?? Promise.resolve())
          : { status: 'simulated', simulated: true, simulationId: `sandbox-token:${record.id}`, note: 'Checkout-bound demo token. No card network or funds movement.' };
      } catch { return pending(); }
      if (settlement.status === 'pending') { record.payment = publicPayment(settlement); state.records[record.id] = record; this.journal.write(state); return pending(); }
      if (settlement.status === 'failed') {
        record.state = 'failed'; record.payment = publicPayment(settlement); state.records[record.id] = record; this.journal.write(state);
        return settlement.reason.startsWith('AUTHORITY_') ? authorityFailure(new Error(settlement.reason)) : fail('PAYMENT_FAILED', settlement.reason);
      }
      record.state = 'settled'; record.payment = { ...publicPayment(settlement), rail: record.rail, protocol: record.protocol };
      record.result = { ...evidence, ok: true, orderId: `ORD-${record.id}`, checkoutId: record.id, termsDigest: record.termsDigest,
        payment: record.payment, verifiedAt: new Date().toISOString() };
      if (this.options.onPayment) record.completionEvidence = { event: {
        phase: 'completed', checkoutId: record.id, protocol: record.protocol, rail: record.rail,
        termsDigest: record.termsDigest, payment: record.payment, orderId: record.result['orderId'],
      } };
      state.records[record.id] = record;
      this.journal.write(state); // Recover the same order if the response is lost.
      await this.deliverCompletionEvidence(record);
      return { body: record.result, committed: true };
    }));
  }
}

export const paymentResultBody = responseBody;
