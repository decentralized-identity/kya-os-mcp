/**
 * GS1 Digital Link helpers + the demo catalog.
 *
 * A Digital Link URI names WHAT an agent is acting on, at the granularity the
 * situation needs:  /01/<GTIN>  the product class
 *                   /01/<GTIN>/10/<lot>            a batch
 *                   /01/<GTIN>/21/<serial>         one physical item
 *
 * A delegation scoped to the class URI with a `prefix` matcher therefore
 * covers every lot and serial beneath it — the GS1 hierarchy for free — while
 * any other GTIN is outside the grant. The parser runs BEFORE the matcher so a
 * malformed URI can never prefix-match its way into scope.
 *
 * GTIN 09506000134352 is GS1's own example GTIN (it resolves through
 * id.gs1.org to "Dal Giardino Risotto Rice with Mushrooms", the fictional
 * brand GS1 uses in its Digital Link demos). No real brand is implicated.
 */

export interface DigitalLink {
  uri: string;
  host: string;
  gtin: string;
  cpv?: string;
  lot?: string;
  serial?: string;
  /** The product-class URI: https://<host>/01/<gtin> */
  classUri: string;
}

const DL_RE = /^https:\/\/([^/]+)\/01\/(\d{8}|\d{12}|\d{13}|\d{14})(?:\/22\/([^/]+))?(?:\/10\/([^/]+))?(?:\/21\/([^/]+))?\/?$/;

export function parseDigitalLink(uri: string): DigitalLink | null {
  if (typeof uri !== 'string' || uri.length > 512) return null;
  const m = DL_RE.exec(uri);
  if (!m) return null;
  const [, host, gtin, cpv, lot, serial] = m;
  if (!host || !gtin || !gtinCheckDigitValid(gtin)) return null;
  return {
    uri,
    host,
    gtin,
    ...(cpv ? { cpv } : {}),
    ...(lot ? { lot } : {}),
    ...(serial ? { serial } : {}),
    classUri: `https://${host}/01/${gtin}`,
  };
}

/** GS1 check digit: weights 3,1,3,1… from the right (excluding the check digit). */
export function gtinCheckDigitValid(gtin: string): boolean {
  if (!/^\d+$/.test(gtin)) return false;
  const digits = gtin.split('').map(Number);
  const check = digits.pop()!;
  let sum = 0;
  for (let i = digits.length - 1, w = 3; i >= 0; i--, w = w === 3 ? 1 : 3) sum += digits[i]! * w;
  return (10 - (sum % 10)) % 10 === check;
}

/** Compute the check digit for a 13-digit GTIN-14 body (used to mint demo GTINs). */
export function withCheckDigit(body13: string): string {
  const digits = body13.split('').map(Number);
  let sum = 0;
  for (let i = digits.length - 1, w = 3; i >= 0; i--, w = w === 3 ? 1 : 3) sum += digits[i]! * w;
  return body13 + String((10 - (sum % 10)) % 10);
}

// ---------------------------------------------------------------------------
// Money, in minor units — never floats
// ---------------------------------------------------------------------------

export function toMinor(amount: string | number): bigint {
  const s = String(amount).trim();
  const m = /^(\d+)(?:\.(\d{1,2}))?$/.exec(s);
  if (!m) throw new Error(`amount must be a decimal with at most 2 places, got "${amount}"`);
  const whole = BigInt(m[1]!);
  const frac = BigInt((m[2] ?? '').padEnd(2, '0'));
  return whole * 100n + frac;
}

export function formatMinor(minor: bigint, currency: string): string {
  const sign = minor < 0n ? '-' : '';
  const abs = minor < 0n ? -minor : minor;
  const whole = abs / 100n;
  const frac = (abs % 100n).toString().padStart(2, '0');
  return `${sign}${currency} ${whole}.${frac}`;
}

// ---------------------------------------------------------------------------
// The demo catalog (the merchant's "agent-visible" surface)
// ---------------------------------------------------------------------------

export interface CatalogItem {
  sku: string;
  name: string;
  uri: string;
  gtin: string;
  unitPrice: string;
  currency: string;
  note?: string;
}

/** GS1's example GTIN — the one the delegation is scoped to. */
export const IN_SCOPE_GTIN = '09506000134352';
/** A second, fictional GTIN with a valid check digit — outside the grant. */
export const OUT_OF_SCOPE_GTIN = withCheckDigit('0950600013436');

export const CATALOG: CatalogItem[] = [
  {
    sku: 'risotto',
    name: 'Dal Giardino Risotto Rice with Mushrooms',
    uri: `https://id.gs1.org/01/${IN_SCOPE_GTIN}`,
    gtin: IN_SCOPE_GTIN,
    unitPrice: '19.90',
    currency: 'CHF',
    note: "GS1's example GTIN (resolves via id.gs1.org)",
  },
  {
    sku: 'risotto-lot',
    name: 'Dal Giardino Risotto Rice with Mushrooms — lot 2609A',
    uri: `https://id.gs1.org/01/${IN_SCOPE_GTIN}/10/2609A`,
    gtin: IN_SCOPE_GTIN,
    unitPrice: '19.90',
    currency: 'CHF',
    note: 'same product class, batch-level Digital Link',
  },
  {
    sku: 'olive-oil',
    name: 'Dal Giardino Extra Virgin Olive Oil (example product)',
    uri: `https://id.gs1.org/01/${OUT_OF_SCOPE_GTIN}`,
    gtin: OUT_OF_SCOPE_GTIN,
    unitPrice: '12.50',
    currency: 'CHF',
    note: 'a different GTIN — outside the delegation scope',
  },
];

export function findCatalogItem(skuOrUri: string): CatalogItem | undefined {
  return CATALOG.find((c) => c.sku === skuOrUri || c.uri === skuOrUri);
}
