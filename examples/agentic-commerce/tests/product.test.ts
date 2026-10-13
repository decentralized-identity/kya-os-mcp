/**
 * The noun and the cap: GS1 Digital Link parsing and the merchant's decision
 * against a credential — no network, no servers.
 */
import { describe, it, expect } from 'vitest';
import type { DelegationCredential } from '@kya-os/mcp';
import { gtinCheckDigitValid, parseDigitalLink, toMinor, withCheckDigit, IN_SCOPE_GTIN, OUT_OF_SCOPE_GTIN } from '../src/lib/product.js';
import { decideOrder } from '../src/merchant/place-order.js';

function credential(scopeResource: string, cap = '50.00', currency = 'CHF'): DelegationCredential {
  const now = Math.floor(Date.now() / 1000);
  return {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    id: 'urn:uuid:test',
    type: ['VerifiableCredential', 'DelegationCredential'],
    issuer: 'did:web:rp.example',
    issuanceDate: new Date().toISOString(),
    credentialSubject: {
      id: 'did:key:z6MkAgent',
      delegation: {
        id: 'test',
        issuerDid: 'did:web:rp.example',
        subjectDid: 'did:key:z6MkAgent',
        scopes: ['commerce.order'],
        constraints: {
          scopes: ['commerce.order'],
          notBefore: now - 60,
          notAfter: now + 3600,
          crisp: { scopes: [{ resource: scopeResource, matcher: 'prefix', constraints: { maxAmount: cap, currency, per: 'order' } }] },
        },
        status: 'active',
      },
    },
  };
}

describe('GS1 Digital Link parsing', () => {
  it('accepts the product class, a lot and a serial beneath it', () => {
    expect(parseDigitalLink(`https://id.gs1.org/01/${IN_SCOPE_GTIN}`)?.gtin).toBe(IN_SCOPE_GTIN);
    const lot = parseDigitalLink(`https://id.gs1.org/01/${IN_SCOPE_GTIN}/10/2609A`);
    expect(lot?.lot).toBe('2609A');
    expect(lot?.classUri).toBe(`https://id.gs1.org/01/${IN_SCOPE_GTIN}`);
    const serial = parseDigitalLink(`https://id.gs1.org/01/${IN_SCOPE_GTIN}/10/2609A/21/000123`);
    expect(serial?.serial).toBe('000123');
  });
  it('rejects malformed URIs, bad check digits and non-https', () => {
    expect(parseDigitalLink('http://id.gs1.org/01/09506000134352')).toBeNull();
    expect(parseDigitalLink('https://id.gs1.org/01/09506000134353')).toBeNull(); // wrong check digit
    expect(parseDigitalLink('https://id.gs1.org/01/095060001343521')).toBeNull(); // 15 digits
    expect(parseDigitalLink('https://id.gs1.org/gtin/09506000134352')).toBeNull();
  });
  it("validates GS1's example GTIN and mints valid demo GTINs", () => {
    expect(gtinCheckDigitValid(IN_SCOPE_GTIN)).toBe(true);
    expect(gtinCheckDigitValid(OUT_OF_SCOPE_GTIN)).toBe(true);
    expect(withCheckDigit('0950600013435')).toBe(IN_SCOPE_GTIN);
  });
  it('money in minor units, never floats', () => {
    expect(toMinor('19.90')).toBe(1990n);
    expect(toMinor('50')).toBe(5000n);
    expect(() => toMinor('1.234')).toThrow();
  });
});

describe('the merchant decision against the credential', () => {
  const vc = credential(`https://id.gs1.org/01/${IN_SCOPE_GTIN}`);

  it('allows the delegated class within the cap', () => {
    const o = decideOrder({ product: 'risotto', quantity: 2 }, vc);
    expect(o.ok).toBe(true);
    if (o.ok) expect(o.total).toBe('CHF 39.80');
  });
  it('allows a lot-level Digital Link beneath the class (prefix covers the hierarchy)', () => {
    expect(decideOrder({ product: 'risotto-lot', quantity: 1 }, vc).ok).toBe(true);
  });
  it('refuses another GTIN', () => {
    const o = decideOrder({ product: 'olive-oil', quantity: 1 }, vc);
    expect(o.ok).toBe(false);
    if (!o.ok) expect(o.error).toBe('PRODUCT_OUT_OF_SCOPE');
  });
  it('refuses when quantity × price exceeds the cap', () => {
    const o = decideOrder({ product: 'risotto', quantity: 5 }, vc);
    expect(o.ok).toBe(false);
    if (!o.ok) expect(o.error).toBe('SPEND_CAP_EXCEEDED');
  });
  it('refuses a cap in another currency and a credential with no cap (fail-closed)', () => {
    const eur = decideOrder({ product: 'risotto', quantity: 1 }, credential(`https://id.gs1.org/01/${IN_SCOPE_GTIN}`, '50.00', 'EUR'));
    expect(!eur.ok && eur.error).toBe('CURRENCY_MISMATCH');
    const noCap = credential(`https://id.gs1.org/01/${IN_SCOPE_GTIN}`);
    delete (noCap.credentialSubject.delegation.constraints.crisp!.scopes[0]! as { constraints?: unknown }).constraints;
    const o = decideOrder({ product: 'risotto', quantity: 1 }, noCap);
    expect(!o.ok && o.error).toBe('NO_CAP_IN_CREDENTIAL');
  });
  it('a prefix that is not a Digital Link path boundary cannot admit a longer GTIN', () => {
    // scope ".../01/0950600013435" (13 digits) must not admit ".../01/09506000134352"
    const sloppy = credential('https://id.gs1.org/01/0950600013435');
    const o = decideOrder({ product: 'risotto', quantity: 1 }, sloppy);
    expect(o.ok).toBe(false);
  });
  it('refuses unknown products and bad quantities', () => {
    expect(!decideOrder({ product: 'nope', quantity: 1 }, vc).ok).toBe(true);
    expect(!decideOrder({ product: 'risotto', quantity: 0 }, vc).ok).toBe(true);
  });
});
