/**
 * The delegated action: `place_order`. By the time this handler runs, the
 * shipped delegation gate has verified the credential's signature (against
 * the Responsible Party's resolved DID document), its window and audience,
 * its revocation status (fetched from the RP's list on THIS call), the
 * holder-of-key proof (the caller holds the agent's key), and the flat
 * `commerce.order` scope.
 *
 * What is left is the merchant's job, read OUT OF the same credential:
 *   - the NOUN: is this product inside the delegated GS1 Digital Link class?
 *     (the shipped `scopeSatisfies` with the credential's own matcher)
 *   - the CAP: does quantity × price fit the per-order maximum?
 * The trust layer never touches the payment; the cap is enforced here, at the
 * merchant, and the receipt records that it was.
 */
import { scopeSatisfies, type DelegationCredential, type CrispScope } from '@kya-os/mcp';
import { CATALOG, findCatalogItem, formatMinor, parseDigitalLink, toMinor, type CatalogItem } from '../lib/product.js';

export interface OrderRequest {
  product: string; // sku or Digital Link URI
  quantity: number;
}

export interface Mandate {
  responsibleParty: string;
  agent: string;
  audience: string | string[] | null;
  scope: { resource: string; matcher: string } | null;
  cap: { maxAmount: string; currency: string; per: string } | null;
  validFrom: string | null;
  validUntil: string | null;
  statusList: { url: string; index: string } | null;
  credentialId: string | null;
}

export interface ApprovedOrderQuote {
  ok: true; item: CatalogItem; quantity: number; total: string; currency: string; mandate: Mandate; checks: Record<string, string>;
}
export type OrderQuoteOutcome =
  | ApprovedOrderQuote
  | { ok: false; error: 'UNKNOWN_PRODUCT' | 'INVALID_PRODUCT_URI' | 'INVALID_QUANTITY' | 'PRODUCT_OUT_OF_SCOPE' | 'CURRENCY_MISMATCH' | 'SPEND_CAP_EXCEEDED' | 'NO_CAP_IN_CREDENTIAL'; message: string; mandate: Mandate | null; detail?: Record<string, unknown> };
export type OrderOutcome = (ApprovedOrderQuote & { orderId: string }) | Extract<OrderQuoteOutcome, { ok: false }>;

export function summarizeMandate(vc: DelegationCredential): Mandate {
  const d = vc.credentialSubject.delegation;
  const scope = d.constraints.crisp?.scopes?.[0];
  const c = (scope?.constraints ?? {}) as Record<string, unknown>;
  const cap = typeof c['maxAmount'] === 'string' && typeof c['currency'] === 'string'
    ? { maxAmount: c['maxAmount'], currency: c['currency'], per: typeof c['per'] === 'string' ? c['per'] : 'order' }
    : null;
  return {
    responsibleParty: typeof vc.issuer === 'string' ? vc.issuer : vc.issuer.id,
    agent: vc.credentialSubject.id,
    audience: d.constraints.audience ?? null,
    scope: scope ? { resource: scope.resource, matcher: scope.matcher } : null,
    cap,
    validFrom: d.constraints.notBefore ? new Date(d.constraints.notBefore * 1000).toISOString() : vc.issuanceDate ?? null,
    validUntil: d.constraints.notAfter ? new Date(d.constraints.notAfter * 1000).toISOString() : vc.expirationDate ?? null,
    statusList: vc.credentialStatus ? { url: vc.credentialStatus.statusListCredential, index: vc.credentialStatus.statusListIndex } : null,
    credentialId: vc.id ?? null,
  };
}

/** The crisp scope whose matcher admitted `uri` (for reading its cap). */
function admittingScope(uri: string, vc: DelegationCredential): CrispScope | null {
  const scopes = vc.credentialSubject.delegation.constraints.crisp?.scopes ?? [];
  for (const s of scopes) {
    if (s.matcher === 'exact' && s.resource === uri) return s;
    if (s.matcher === 'prefix' && (uri === s.resource || uri.startsWith(s.resource.endsWith('/') ? s.resource : s.resource + '/'))) return s;
  }
  return null;
}

/** Pure policy evaluation; a quote is not a committed order or payment. */
export function evaluateOrder(req: OrderRequest, vc: DelegationCredential): OrderQuoteOutcome {
  const mandate = summarizeMandate(vc);

  const item = findCatalogItem(req.product);
  if (!item) {
    return { ok: false, error: 'UNKNOWN_PRODUCT', message: `No catalog item "${req.product}". Known: ${CATALOG.map((c) => c.sku).join(', ')}`, mandate };
  }
  const dl = parseDigitalLink(item.uri);
  if (!dl) {
    return { ok: false, error: 'INVALID_PRODUCT_URI', message: `"${item.uri}" is not a valid GS1 Digital Link`, mandate };
  }
  const quantity = Number(req.quantity);
  if (!Number.isInteger(quantity) || quantity < 1 || quantity > 999) {
    return { ok: false, error: 'INVALID_QUANTITY', message: `quantity must be an integer 1–999, got ${req.quantity}`, mandate };
  }

  // The NOUN. The credential's own matcher decides (shipped scopeSatisfies);
  // the path-boundary re-check keeps `prefix` honest for URIs, so
  // ".../01/0950600013435" can never admit ".../01/09506000134352X".
  const scopeResult = scopeSatisfies(item.uri, vc);
  const scope = scopeResult.satisfied ? admittingScope(item.uri, vc) : null;
  if (!scopeResult.satisfied || !scope) {
    return {
      ok: false,
      error: 'PRODUCT_OUT_OF_SCOPE',
      message: `${item.uri} is outside the delegated product class ${mandate.scope?.resource ?? '(none)'}`,
      mandate,
      detail: { requested: item.uri, gtin: dl.gtin, delegated: mandate.scope?.resource ?? null, matcher: mandate.scope?.matcher ?? null },
    };
  }

  // The CAP — read out of the credential the gate verified; enforced here.
  const c = (scope.constraints ?? {}) as Record<string, unknown>;
  if (typeof c['maxAmount'] !== 'string' || typeof c['currency'] !== 'string') {
    return { ok: false, error: 'NO_CAP_IN_CREDENTIAL', message: 'Fail-closed: the delegation carries no spend cap for this scope', mandate };
  }
  if (c['currency'] !== item.currency) {
    return { ok: false, error: 'CURRENCY_MISMATCH', message: `cap is in ${c['currency']}, item is priced in ${item.currency}`, mandate };
  }
  const total = toMinor(item.unitPrice) * BigInt(quantity);
  const cap = toMinor(c['maxAmount']);
  if (total > cap) {
    return {
      ok: false,
      error: 'SPEND_CAP_EXCEEDED',
      message: `${quantity} × ${formatMinor(toMinor(item.unitPrice), item.currency)} = ${formatMinor(total, item.currency)} exceeds the credential's cap of ${formatMinor(cap, item.currency)} per order`,
      mandate,
      detail: { total: formatMinor(total, item.currency), cap: formatMinor(cap, item.currency) },
    };
  }

  return {
    ok: true,
    item,
    quantity,
    total: formatMinor(total, item.currency),
    currency: item.currency,
    mandate,
    checks: {
      signature: 'verified against the Responsible Party DID document',
      window: 'inside notBefore/notAfter',
      audience: 'this merchant',
      revocation: 'status list fetched on this call, bit clear',
      holderKey: 'per-request proof signed by the agent key',
      productClass: `${dl.classUri} ⊆ ${scope.resource} (${scope.matcher})`,
      spendCap: `${formatMinor(total, item.currency)} ≤ ${formatMinor(cap, item.currency)}`,
    },
  };
}

let orderSeq = 0;
/** Allocate only once the caller has decided to commit the legacy demo order. */
export function allocateOrderId(): string {
  orderSeq += 1;
  return `ORD-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}-${String(orderSeq).padStart(4, '0')}`;
}

/** Compatibility helper for callers that intentionally create a legacy order. */
export function decideOrder(req: OrderRequest, vc: DelegationCredential): OrderOutcome {
  const outcome = evaluateOrder(req, vc);
  return outcome.ok ? { ...outcome, orderId: allocateOrderId() } : outcome;
}
