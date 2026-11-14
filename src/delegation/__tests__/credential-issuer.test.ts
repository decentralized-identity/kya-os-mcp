/**
 * A delegation credential names its issuer as VC Data Model 2.0 §4.7 requires, by a URL or by an
 * object whose `id` is one, or the basic stage refuses it: it quotes a string that is not a URL as
 * it stands, one the WHATWG URL parser does not parse or one it would read otherwise than written,
 * and names the type of anything else in place of the URL, never converting it.
 */

import { describe, it, expect } from 'vitest';
import { credentialIssuerDid, credentialIssuerRefusal } from '../credential-issuer.js';
import type { DelegationCredential } from '../../types/protocol.js';

const ACME = 'did:web:acme.example';

/** A credential reduced to the member these functions read. */
const naming = (issuer: unknown): DelegationCredential => ({ issuer }) as unknown as DelegationCredential;

const throwingToString = {
  toString(): string {
    throw new Error('converted');
  },
};

describe('credentialIssuerDid', () => {
  it('reads the issuer as a string, or as the id of an issuer object', () => {
    expect(credentialIssuerDid(naming(ACME))).toBe(ACME);
    expect(credentialIssuerDid(naming({ id: ACME, name: 'Acme' }))).toBe(ACME);
  });

  it('reads no DID from an issuer that is neither', () => {
    const neither = [{ id: 5 }, {}, { id: null }, { id: [ACME] }, JSON.parse('{"id":{"toString":"x"}}'), [ACME], 5, null, undefined];
    for (const issuer of [...neither, Object.assign([ACME], { id: ACME })]) {
      expect(credentialIssuerDid(naming(issuer))).toBeUndefined();
    }
  });
});

describe('credentialIssuerRefusal', () => {
  it('refuses nothing in an issuer that names a DID', () => {
    for (const issuer of [ACME, { id: ACME }, { id: ACME, name: 'Acme' }]) {
      expect(credentialIssuerRefusal(naming(issuer))).toBeUndefined();
    }
  });

  it('refuses nothing in an issuer that is a URL, as every DID the package resolves is', () => {
    const urls = [
      'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      'did:web:acme.example',
      'did:web:acme.example%3A8443',
      'did:web:acme.example:users:alice',
      'did:web:%5B%3A%3A1%5D%3A8443',
      'did:web:xn--bcher-kva.example',
      `did:web:long.example:${'a'.repeat(400_000)}`,
      'did:cheqd:testnet:0f4d9c1e-6a5b-4f3e-9c2d-1b0a9f8e7d6c',
      'did:cheqd:mainnet:zF7rhDBfUt9d1gJPjx7s1J',
      'did:example:123456789abcdefghi',
      'https://issuer.example/acme',
      'https://issuer.example/caf\u00e9',
      'https://issuer.example/\u{1F600}',
    ];
    for (const url of urls) {
      expect(credentialIssuerRefusal(naming(url))).toBeUndefined();
      expect(credentialIssuerRefusal(naming({ id: url }))).toBeUndefined();
    }
  });

  it('refuses an issuer, or an issuer id, that is a string but not a URL, quoting it', () => {
    for (const notUrl of ['acme', 'acme.example', '#key-1', '/issuers/acme', 'did web:acme.example', '1did:web:acme.example']) {
      expect(credentialIssuerRefusal(naming(notUrl))).toBe(`Credential issuer "${notUrl}" is not a URL`);
      expect(credentialIssuerRefusal(naming({ id: notUrl }))).toBe(`Credential issuer id "${notUrl}" is not a URL`);
    }
    expect(credentialIssuerRefusal(naming(''))).toBe('Credential issuer "" is not a URL');
    expect(credentialIssuerRefusal(naming({ id: '' }))).toBe('Credential issuer id "" is not a URL');
    expect(credentialIssuerRefusal(naming('x'.repeat(100_000)))).toBe(`Credential issuer "${'x'.repeat(64)}"... is not a URL`);
  });

  it('refuses an issuer with white space or a control at either end, or a tab, CR or LF inside, as not a URL', () => {
    // The parser removes leading and trailing C0 controls and spaces, and every tab, CR and LF,
    // before it parses; each is a validation error, so such a string is not a URL as it stands.
    // Other white space at either end, a no-break space or a byte order mark, is refused too.
    const unclean: [string, string][] = [
      [` ${ACME}`, `" ${ACME}"`],
      [`${ACME} `, `"${ACME} "`],
      [`\u0000${ACME}`, `"\\u0000${ACME}"`],
      [`${ACME}\u001f`, `"${ACME}\\u001f"`],
      [`\u000b${ACME}`, `"\\u000b${ACME}"`],
      [`${ACME}\u00a0`, `"${ACME}\u00a0"`],
      [`\ufeff${ACME}`, `"\\ufeff${ACME}"`],
      ['did:web:acme\t.example', '"did:web:acme\\t.example"'],
      ['did:web:acme\n.example', '"did:web:acme\\n.example"'],
      ['did:web:acme\r.example', '"did:web:acme\\r.example"'],
      [`${ACME}#key\n-1`, `"${ACME}#key\\n-1"`],
    ];
    for (const [notUrl, quoted] of unclean) {
      expect(credentialIssuerRefusal(naming(notUrl))).toBe(`Credential issuer ${quoted} is not a URL`);
      expect(credentialIssuerRefusal(naming({ id: notUrl }))).toBe(`Credential issuer id ${quoted} is not a URL`);
    }
  });

  it('refuses an issuer holding a control or format character, a line or paragraph separator, or a lone surrogate anywhere', () => {
    // The parser accepts each of these, so the issuer would read as another DID: at the
    // end a C1 control, DEL, a zero width space or a lone surrogate; inside a bidirectional control,
    // a soft hyphen, a format character that renders, or a tag character outside the BMP.
    const unseen: [string, string][] = [
      [`${ACME}\u0085`, `"${ACME}\\u0085"`],
      [`${ACME}\u007f`, `"${ACME}\\u007f"`],
      [`${ACME}\u200b`, `"${ACME}\\u200b"`],
      [`${ACME}\ud800`, `"${ACME}\\ud800"`],
      ['did:web:acme\u0085.example', '"did:web:acme\\u0085.example"'],
      ['did:web:acme\u202e.example', '"did:web:acme\\u202e.example"'],
      ['did:web:acme\u2028.example', '"did:web:acme\\u2028.example"'],
      ['did:web:acme\u2029.example', '"did:web:acme\\u2029.example"'],
      ['did:web:acme\u00ad.example', '"did:web:acme\\u00ad.example"'],
      ['did:web:acme\u0600.example', '"did:web:acme\\u0600.example"'],
      ['did:web:acme\udc00.example', '"did:web:acme\\udc00.example"'],
      ['https://issuer.example/\u{E0041}', '"https://issuer.example/\\udb40\\udc41"'],
    ];
    for (const [notUrl, quoted] of unseen) {
      expect(credentialIssuerRefusal(naming(notUrl))).toBe(`Credential issuer ${quoted} is not a URL`);
      expect(credentialIssuerRefusal(naming({ id: notUrl }))).toBe(`Credential issuer id ${quoted} is not a URL`);
    }
  });

  it("names the type of an issuer object's id that is not a string", () => {
    const named: [unknown, string][] = [
      [{ id: 5 }, 'of type number'],
      [{}, 'of type undefined'],
      [{ id: null }, 'of type null'],
      [{ id: [ACME] }, 'of type array'],
      [{ id: { id: ACME } }, 'of type object'],
      [JSON.parse('{"id":{"toString":"x"}}'), 'of type object'],
      [{ id: throwingToString }, 'of type object'],
      [{ id: true }, 'of type boolean'],
    ];
    for (const [issuer, type] of named) {
      expect(credentialIssuerRefusal(naming(issuer))).toBe(`Credential issuer id ${type} is not a URL`);
    }
  });

  it('names the type of an issuer that is neither a string nor an object', () => {
    const named: [unknown, string][] = [
      [[ACME], 'of type array'],
      [[], 'of type array'],
      [5, 'of type number'],
      [null, 'of type null'],
      [undefined, 'of type undefined'],
      [false, 'of type boolean'],
    ];
    for (const [issuer, type] of named) {
      expect(credentialIssuerRefusal(naming(issuer))).toBe(`Credential issuer ${type} is not a URL`);
    }
  });
});
