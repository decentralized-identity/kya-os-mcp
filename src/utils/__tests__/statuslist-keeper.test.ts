/**
 * Every status-list URL has one keeper, decided from the verifier's configuration and the signed
 * credentials: the issuer the configuration binds the exact URL to, else the one it binds the URL's
 * origin to, else the pinned root when the root's own credential names the URL, else the
 * credential's own issuer. The rules are tried in that order, a binding is read only as SPEC.md
 * §6.6 reads it, an exact URL or an origin with nothing after it, matched on the bytes as written,
 * and a configuration that could not be applied, or that writes an origin or a prefix in a form
 * §6.6 does not read as one, is refused when it is given, naming the fix.
 */
import { describe, expect, it } from 'vitest';
import {
  assertStatusListIssuers,
  namesAnotherKeeper,
  statusListKeeperFor,
  type StatusListIssuers,
} from '../statuslist-keeper.js';

const ISSUER = 'did:web:issuer.example';
const ROOT = 'did:web:root.example';
const SERVICE = 'did:web:status.example';
const HERD = 'did:web:herd.example';
const URL = 'https://lists.issuer.example/1';
const ROOT_URL = 'https://lists.root.example/herd/1';
const pinned = { credentialIssuer: ISSUER, trustedRootIssuer: ROOT, trustedRootStatusList: ROOT_URL };

describe('statusListKeeperFor', () => {
  it("rule 4: a URL nobody else keeps is the credential's own issuer's", () => {
    const own = { did: ISSUER, why: 'credential-issuer' };
    expect(statusListKeeperFor(URL, { credentialIssuer: ISSUER })).toEqual(own);
    expect(statusListKeeperFor(URL, pinned)).toEqual(own);
    expect(statusListKeeperFor(URL, pinned, {})).toEqual(own);
    expect(statusListKeeperFor(URL, pinned, { [SERVICE]: ['https://status.example', 'https://lists.issuer.example/2'] })).toEqual(own);
  });

  it("rule 3: the URL the pinned root's own credential names is the root's, byte for byte", () => {
    expect(statusListKeeperFor(ROOT_URL, pinned)).toEqual({ did: ROOT, why: 'root-credential' });
    for (const near of [`${ROOT_URL}/`, `${ROOT_URL}?v=1`, `${ROOT_URL}#list`, ROOT_URL.toUpperCase(), ROOT_URL.slice(0, -1)]) {
      expect(statusListKeeperFor(near, pinned), near).toEqual({ did: ISSUER, why: 'credential-issuer' });
    }
  });

  it('rule 3 needs a pinned root: the URL of a root that is not named counts for nothing', () => {
    expect(statusListKeeperFor(ROOT_URL, { credentialIssuer: ISSUER, trustedRootStatusList: ROOT_URL })).toEqual({
      did: ISSUER,
      why: 'credential-issuer',
    });
    expect(statusListKeeperFor(ROOT_URL, { credentialIssuer: ISSUER, trustedRootIssuer: ROOT })).toEqual({
      did: ISSUER,
      why: 'credential-issuer',
    });
  });

  it('rule 1: the issuer the configuration binds the exact URL to keeps it', () => {
    const statusListIssuers = { [HERD]: [ROOT_URL, 'https://lists.root.example/herd/2'], [SERVICE]: [URL] };
    expect(statusListKeeperFor(URL, { credentialIssuer: ISSUER }, statusListIssuers)).toEqual({ did: SERVICE, why: 'configured-url' });
    expect(statusListKeeperFor('https://lists.root.example/herd/2', { credentialIssuer: ISSUER }, statusListIssuers)).toEqual({
      did: HERD,
      why: 'configured-url',
    });
    expect(statusListKeeperFor('https://lists.root.example/herd/3', { credentialIssuer: ISSUER }, statusListIssuers)).toEqual({
      did: ISSUER,
      why: 'credential-issuer',
    });
    expect(statusListKeeperFor('http://lists.plain.example/1', { credentialIssuer: ISSUER }, { [SERVICE]: ['http://lists.plain.example/1'] }))
      .toEqual({ did: SERVICE, why: 'configured-url' });
  });

  it('rule 2: the issuer the configuration binds the origin of the URL to keeps it', () => {
    const statusListIssuers = { [HERD]: ['https://other.example'], [SERVICE]: ['https://status.example', 'https://status.example:8443'] };
    const kept = { did: SERVICE, why: 'configured-origin' };
    // The origin itself, named as a URL, is the binding's own string, which rule 1 takes.
    expect(statusListKeeperFor('https://status.example', { credentialIssuer: ISSUER }, statusListIssuers)).toEqual({ did: SERVICE, why: 'configured-url' });
    for (const url of ['https://status.example/', 'https://status.example/lists/1', 'https://status.example?list=1',
      'https://status.example#list', 'https://status.example:8443/lists/1']) {
      expect(statusListKeeperFor(url, { credentialIssuer: ISSUER }, statusListIssuers), url).toEqual(kept);
    }
  });

  it.each([
    'https://status.example.evil.example/x',
    'https://status.example@evil.example/x',
    'https://status.example:8443/x',
    'https://status.example:443/x',
    'https://status.example\\@evil.example/x',
    'https://STATUS.example/x',
    'http://status.example/x',
    'https://status.exampl/x',
    'https://status.example%2Fx',
    'https://status.example x',
    'xhttps://status.example/x',
  ])('rule 2 does not hold %s to be at the origin https://status.example', (url) => {
    expect(statusListKeeperFor(url, { credentialIssuer: ISSUER }, { [SERVICE]: ['https://status.example'] })).toEqual({
      did: ISSUER,
      why: 'credential-issuer',
    });
  });

  it('rule 2 takes only an origin binding for an origin: a URL with a path binds itself alone', () => {
    const statusListIssuers = { [SERVICE]: ['https://status.example/lists'] };
    for (const url of ['https://status.example/lists/1', 'https://status.example/lists?x', 'https://Status.example/1', 'https://status.example//1']) {
      expect(statusListKeeperFor(url, { credentialIssuer: ISSUER }, statusListIssuers), url).toEqual({ did: ISSUER, why: 'credential-issuer' });
    }
    expect(statusListKeeperFor('https://status.example/lists', { credentialIssuer: ISSUER }, statusListIssuers)).toEqual({
      did: SERVICE,
      why: 'configured-url',
    });
  });

  it('rule 2 reads no other form of an origin: one followed by "/", or with an upper-case host, is refused, never read as it', () => {
    for (const binding of ['https://status.example/', 'https://status.example:8443/', 'https://Status.example']) {
      expect(() => statusListKeeperFor('https://status.example/lists/1', { credentialIssuer: ISSUER }, { [SERVICE]: [binding] }), binding)
        .toThrow(TypeError);
    }
  });

  it('rule 1 matches an exact URL with an upper-case host byte for byte, as an entry that writes it so names it', () => {
    const statusListIssuers = { [SERVICE]: ['https://Status.example/lists/1'] };
    expect(statusListKeeperFor('https://Status.example/lists/1', { credentialIssuer: ISSUER }, statusListIssuers)).toEqual({
      did: SERVICE,
      why: 'configured-url',
    });
    expect(statusListKeeperFor('https://status.example/lists/1', { credentialIssuer: ISSUER }, statusListIssuers)).toEqual({
      did: ISSUER,
      why: 'credential-issuer',
    });
  });

  it('tries the rules in order: an exact binding before an origin, and the configuration before the root', () => {
    const inside = 'https://status.example/herd/1';
    // The origin's keeper comes first in the map, so only the order of the rules gives the exact one.
    expect(statusListKeeperFor(inside, { credentialIssuer: ISSUER }, { [SERVICE]: ['https://status.example'], [HERD]: [inside] })).toEqual({
      did: HERD,
      why: 'configured-url',
    });
    expect(statusListKeeperFor(ROOT_URL, pinned, { [SERVICE]: [ROOT_URL] })).toEqual({ did: SERVICE, why: 'configured-url' });
    expect(statusListKeeperFor(ROOT_URL, pinned, { [SERVICE]: ['https://lists.root.example'] })).toEqual({
      did: SERVICE,
      why: 'configured-origin',
    });
    // The root before the credential's own issuer, when the issuer's entry names the root's URL.
    expect(statusListKeeperFor(ROOT_URL, { ...pinned, credentialIssuer: ISSUER })).toEqual({ did: ROOT, why: 'root-credential' });
  });

  it('counts only a binding the map owns', () => {
    const inherited = Object.create(null) as Record<string, string[]>;
    expect(statusListKeeperFor(URL, { credentialIssuer: ISSUER }, inherited)).toEqual({ did: ISSUER, why: 'credential-issuer' });
    expect(statusListKeeperFor('https://constructor.example/1', { credentialIssuer: 'constructor' }, {})).toEqual({
      did: 'constructor',
      why: 'credential-issuer',
    });
  });

  it('refuses a configuration it could not apply', () => {
    expect(() => statusListKeeperFor(URL, { credentialIssuer: ISSUER }, { [ISSUER]: [SERVICE] })).toThrow(TypeError);
  });
});

describe('assertStatusListIssuers', () => {
  const NOT_A_MAP = 'statusListIssuers must be a plain object mapping each status-list issuer DID to the status-list URLs or https origins it keeps';

  it('takes no map, an empty one, and one of origins and exact URLs', () => {
    for (const value of [undefined, {}, Object.create(null), { [SERVICE]: [] }, Object.freeze({ [SERVICE]: Object.freeze(['https://status.example']) }),
      { [SERVICE]: ['https://status.example', 'https://status.example:8443', 'https://status.example/lists/1', 'http://plain.example/1', 'https://[::1]/1'] },
      { [SERVICE]: [URL, URL] }]) {
      expect(() => assertStatusListIssuers(value)).not.toThrow();
    }
  });

  it.each([null, [], 'did:web:status.example', 7, new Map(), new (class Config {})()])('refuses %o, which is not a plain object', (value) => {
    expect(() => assertStatusListIssuers(value)).toThrow(new TypeError(NOT_A_MAP));
  });

  it('refuses an empty key', () => {
    expect(() => assertStatusListIssuers({ '': [URL] })).toThrow(
      new TypeError('statusListIssuers has an empty key, where it must name a status-list issuer DID'),
    );
  });

  it.each([
    ['a string', URL],
    ['null', null],
    ['an object', { 0: URL }],
  ])('refuses a value that is %s, not an array', (_label, bindings) => {
    expect(() => assertStatusListIssuers({ [SERVICE]: bindings })).toThrow(
      new TypeError(`statusListIssuers["${SERVICE}"] must be an array of status-list URLs or https origins`),
    );
  });

  it.each([
    ['a DID, as a map from a credential issuer to the issuers accepted for it holds', SERVICE, `"${SERVICE}"`],
    ['a number', 7, 'of type number'],
    ['null', null, 'of type null'],
    ['a host without a scheme', 'status.example', '"status.example"'],
    ['a URL of another scheme', 'ftp://status.example/1', '"ftp://status.example/1"'],
    ['a scheme in another case', 'HTTPS://status.example', '"HTTPS://status.example"'],
    ['an empty string', '', '""'],
    ['an array that holds a URL, which converts to one', ['https://status.example'], 'of type array'],
    ['an object that converts to a URL', { toString: () => 'https://status.example' }, 'of type object'],
  ])('refuses a binding that is %s, and says what a value must hold', (_label, binding, named) => {
    expect(() => assertStatusListIssuers({ [ISSUER]: [URL, binding] })).toThrow(
      new TypeError(
        `statusListIssuers["${ISSUER}"] holds ${named}, which is not a status-list URL or an https origin: ` +
          'each value names the URLs that issuer keeps, not the issuers accepted for a credential issuer',
      ),
    );
  });

  it('refuses one binding under two issuers, an origin or an exact URL, and quotes a long one cut', () => {
    for (const binding of ['https://status.example', URL]) {
      expect(() => assertStatusListIssuers({ [SERVICE]: [binding], [HERD]: ['https://herd.example', binding] })).toThrow(
        new TypeError(`statusListIssuers binds "${binding}" to both "${SERVICE}" and "${HERD}", and a URL has one keeper`),
      );
    }
    const long = `https://status.example/${'x'.repeat(200)}`;
    expect(() => assertStatusListIssuers({ [SERVICE]: [long], [HERD]: [long] })).toThrow(
      new TypeError(`statusListIssuers binds "${long.slice(0, 64)}"... to both "${SERVICE}" and "${HERD}", and a URL has one keeper`),
    );
  });

  it.each([
    ['https://status.example/', 'https://status.example'],
    ['https://status.example:8443/', 'https://status.example:8443'],
    ['https://Status.example/', 'https://status.example'],
  ])('refuses %s, an origin followed by "/", naming the origin to write', (binding, origin) => {
    expect(() => assertStatusListIssuers({ [SERVICE]: [binding] })).toThrow(
      new TypeError(
        `statusListIssuers["${SERVICE}"] holds "${binding}", an origin followed by "/", which binds only itself, as an exact URL, ` +
          `and no other URL at that origin: write it as "${origin}"`,
      ),
    );
  });

  it.each([
    ['https://Status.example', 'https://status.example'],
    ['https://STATUS.EXAMPLE:8443', 'https://status.example:8443'],
  ])('refuses %s, an origin whose host is not in lower case, naming the origin to write', (binding, origin) => {
    expect(() => assertStatusListIssuers({ [SERVICE]: [binding] })).toThrow(
      new TypeError(
        `statusListIssuers["${SERVICE}"] holds "${binding}", an origin whose host is not in lower case, which binds only itself, ` +
          `as an exact URL, and no URL at that origin: write the host in lower case, as "${origin}"`,
      ),
    );
  });

  it.each([
    ['a path prefix', 'https://status.example/lists/', 'bind the origin, "https://status.example", or each list URL'],
    ['a prefix at a port', 'https://status.example:8443/lists/', 'bind the origin, "https://status.example:8443", or each list URL'],
    ['a URL whose query ends in "/"', 'https://status.example/lists?after=/', 'bind the origin, "https://status.example", or each list URL'],
    ['a prefix whose host is not in lower case', 'https://Status.example/lists/', 'bind each list URL'],
    ['an http: origin', 'http://status.example/', 'bind each list URL'],
    ['an origin whose host is an IPv6 literal', 'https://[::1]/', 'bind each list URL'],
    ['a scheme alone', 'https://', 'bind each list URL'],
  ])('refuses %s, any other binding that ends in "/", naming what to bind instead', (_label, binding, fix) => {
    expect(() => assertStatusListIssuers({ [SERVICE]: [binding] })).toThrow(
      new TypeError(
        `statusListIssuers["${SERVICE}"] holds "${binding}", which ends in "/" as a path prefix would, ` +
          `but a binding is an https origin or a list's exact URL, never a prefix: ${fix}`,
      ),
    );
  });

  it('leaves alone an exact URL that ends in no "/", whatever the case of its host, and whether or not a URL parser takes it', () => {
    for (const binding of ['https://Status.example/lists/1', 'https://status.EXAMPLE/lists/1', 'https://user@Status.example/lists/1',
      'https://[::FFFF:7f00:1]/lists/1', 'http://Status.example', 'https://status.example/lists', 'https://status.example?list=1',
      'https://status.example#list', 'https://status example/1', 'https://status.example:99999', 'http://[::1/1', 'https://B\u00fccher.example']) {
      expect(() => assertStatusListIssuers({ [SERVICE]: [binding] }), binding).not.toThrow();
    }
  });

  it('refuses an origin followed by "/" as itself, not as the origin another issuer binds', () => {
    expect(() => assertStatusListIssuers({ [SERVICE]: ['https://status.example'], [HERD]: ['https://status.example/'] })).toThrow(
      new TypeError(
        `statusListIssuers["${HERD}"] holds "https://status.example/", an origin followed by "/", which binds only itself, ` +
          'as an exact URL, and no other URL at that origin: write it as "https://status.example"',
      ),
    );
  });

  it('lets an exact URL of one issuer lie inside an origin of another', () => {
    const statusListIssuers: StatusListIssuers = { [SERVICE]: ['https://status.example'], [HERD]: ['https://status.example/herd/1'] };
    expect(() => assertStatusListIssuers(statusListIssuers)).not.toThrow();
  });
});

describe('namesAnotherKeeper', () => {
  it('is true exactly when the map has a key other than the DID, whatever it binds', () => {
    expect(namesAnotherKeeper(undefined, ISSUER)).toBe(false);
    expect(namesAnotherKeeper({}, ISSUER)).toBe(false);
    expect(namesAnotherKeeper({ [ISSUER]: [URL] }, ISSUER)).toBe(false);
    expect(namesAnotherKeeper({ [SERVICE]: [] }, ISSUER)).toBe(true);
    expect(namesAnotherKeeper({ [ISSUER]: [URL], [SERVICE]: ['https://status.example'] }, ISSUER)).toBe(true);
  });
});
