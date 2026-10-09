import { describe, it, expect } from 'vitest';
import {
  bindClientId,
  didFromClientId,
  didKeyedJwks,
  toClientMetadata,
  cardFromClientMetadata,
  verifyCimdBind,
  PRIVATE_KEY_JWT,
  KYA_OS_DID_META_KEY,
  type EntityCard,
} from '../index.js';
import { extractPublicKeyFromDidKey, publicKeyToJwk } from '../../delegation/did-key-resolver.js';

const did = 'did:web:example.com:clients:acme';
const clientId = 'https://example.com/clients/acme';
const jwksUri = 'https://example.com/clients/acme/jwks.json';

const card: EntityCard = { id: did, entityType: 'client', name: 'Acme Client' };

/** A DID document whose Ed25519 key, alsoKnownAs, and origin all line up with `did`. */
const didDoc = {
  id: did,
  alsoKnownAs: [clientId],
  verificationMethod: [
    {
      id: `${did}#key-1`,
      type: 'JsonWebKey2020',
      controller: did,
      // a private `d` is present on purpose — it MUST be stripped from the JWKS projection.
      publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'PUB_X', d: 'PRIVATE_SECRET' },
    },
    {
      id: `${did}#key-ec`,
      type: 'JsonWebKey2020',
      controller: did,
      publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'ec-x', y: 'ec-y' },
    },
  ],
};

describe('bindClientId ⇄ didFromClientId (the W3C did:web ⇄ HTTPS bijection)', () => {
  it('maps a path-form did:web to its HTTPS client_id', () => {
    expect(bindClientId(did)).toBe(clientId);
  });

  it('maps a bare did:web to its origin', () => {
    expect(bindClientId('did:web:example.com')).toBe('https://example.com');
  });

  it('percent-decodes the authority colon for ports', () => {
    expect(bindClientId('did:web:localhost%3A3000:agents:bot')).toBe(
      'https://localhost:3000/agents/bot',
    );
  });

  it('round-trips path-form, bare, and ported DIDs', () => {
    for (const d of ['did:web:example.com:clients:acme', 'did:web:example.com', 'did:web:localhost%3A3000:agents:bot']) {
      expect(didFromClientId(bindClientId(d))).toBe(d);
    }
  });

  it('bindClientId is fail-closed for a non-did:web', () => {
    expect(() => bindClientId('did:key:z6Mkabc')).toThrow(/only did:web/);
  });

  it('didFromClientId rejects a non-https client_id', () => {
    expect(() => didFromClientId('http://example.com/clients/acme')).toThrow(/https/);
  });
});

describe('didKeyedJwks (verificationMethod → OKP JWK, kid preserved, d stripped)', () => {
  it('projects only Ed25519 keys and strips the private d', () => {
    const jwks = didKeyedJwks(didDoc);
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]).toEqual({ kty: 'OKP', crv: 'Ed25519', x: 'PUB_X', kid: `${did}#key-1` });
    expect('d' in jwks.keys[0]!).toBe(false);
  });

  it('preserves an explicit JWK kid over the verification-method id', () => {
    const jwks = didKeyedJwks({
      verificationMethod: [
        { id: `${did}#vm`, publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'X', kid: 'custom-kid' } },
      ],
    });
    expect(jwks.keys[0]?.kid).toBe('custom-kid');
  });

  it('projects an Ed25519 key published only as publicKeyMultibase, kid from the method id', () => {
    const keyDid = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
    const multibase = keyDid.slice('did:key:'.length);
    const vmId = `${keyDid}#${multibase}`;
    const jwks = didKeyedJwks({
      id: keyDid,
      verificationMethod: [
        { id: vmId, type: 'Ed25519VerificationKey2020', controller: keyDid, publicKeyMultibase: multibase },
        {
          // An X25519 multikey (multicodec 0xec01) is a key-agreement key, not a signing key.
          id: `${keyDid}#z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc`,
          type: 'X25519KeyAgreementKey2020',
          controller: keyDid,
          publicKeyMultibase: 'z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc',
        },
      ],
    });
    expect(jwks.keys).toEqual([
      { ...publicKeyToJwk(extractPublicKeyFromDidKey(keyDid)!), kid: vmId },
    ]);
  });

  it('returns an empty key set for a doc with no verification methods', () => {
    expect(didKeyedJwks({ id: did })).toEqual({ keys: [] });
    expect(didKeyedJwks(null)).toEqual({ keys: [] });
  });
});

describe('toClientMetadata (card → CIMD document)', () => {
  it('emits private_key_jwt, the HTTPS client_id, and the DID under _meta', () => {
    const meta = toClientMetadata(card, { jwksUri });
    expect(meta).toEqual({
      client_id: clientId,
      client_name: 'Acme Client',
      token_endpoint_auth_method: PRIVATE_KEY_JWT,
      jwks_uri: jwksUri,
      _meta: { [KYA_OS_DID_META_KEY]: did },
    });
  });
});

describe('cardFromClientMetadata (CIMD document → L1 card)', () => {
  it('derives an entityType:client L1 card carrying the CIMD coordinates', () => {
    const derived = cardFromClientMetadata(toClientMetadata(card, { jwksUri }));
    expect(derived.id).toBe(did);
    expect(derived.entityType).toBe('client');
    expect(derived.name).toBe('Acme Client');
    expect(derived.cimd).toEqual({ clientId, jwksUri });
  });

  it('mints a did:web from the client_id when no _meta DID is declared', () => {
    const derived = cardFromClientMetadata({ client_id: clientId, client_name: 'Bare' });
    expect(derived.id).toBe(did);
    expect(derived.cimd).toBeUndefined();
  });

  it('is fail-closed on metadata missing a string client_id', () => {
    expect(() => cardFromClientMetadata({ client_name: 'x' })).toThrow(/client_id/);
  });

  it('REJECTS a document that declares a did:web on another origin (substitution)', () => {
    // Served from attacker.example, claiming the victim's DID: the card would carry the victim's id.
    const hostile = {
      client_id: 'https://attacker.example/clients/x',
      client_name: 'Totally Acme',
      jwks_uri: 'https://attacker.example/clients/x/jwks.json',
      _meta: { [KYA_OS_DID_META_KEY]: 'did:web:victim.example:clients:acme' },
    };
    expect(() => cardFromClientMetadata(hostile)).toThrow(/not on the origin of client_id/);
    // A port is part of the origin.
    const otherPort = { client_id: 'https://example.com:8443/clients/acme', _meta: { [KYA_OS_DID_META_KEY]: did } };
    expect(() => cardFromClientMetadata(otherPort)).toThrow(/not on the origin of client_id/);
    // A client_id with no origin cannot vouch for any did:web.
    const opaque = { client_id: 'urn:client:acme', _meta: { [KYA_OS_DID_META_KEY]: did } };
    expect(() => cardFromClientMetadata(opaque)).toThrow(/not on the origin of client_id/);
  });

  it.each([
    ['the exact HTTPS form', clientId, did],
    ['a ported DID', 'https://localhost:3000/agents/bot', 'did:web:localhost%3A3000:agents:bot'],
    ['a root with a trailing slash', 'https://example.com/', 'did:web:example.com'],
    ['a query', `${clientId}?tenant=acme`, did],
    ['an explicit default port', 'https://example.com:443/clients/acme', did],
    ['a root DID declared on a path client_id', 'https://example.com/oauth/client.json', 'did:web:example.com'],
    ['a host in another case', 'https://Example.com/clients/acme', did],
  ])('still accepts a declared did:web on the client_id origin: %s', (_label, id, declared) => {
    expect(cardFromClientMetadata({ client_id: id, _meta: { [KYA_OS_DID_META_KEY]: declared } }).id).toBe(declared);
  });

  it('still accepts a declared did:key (an L1-only client has no origin to bind)', () => {
    const meta = { client_id: clientId, _meta: { [KYA_OS_DID_META_KEY]: 'did:key:z6Mkabc' } };
    expect(cardFromClientMetadata(meta).id).toBe('did:key:z6Mkabc');
  });

  it.each([
    ['a root with a trailing slash', 'https://example.com/', 'did:web:example.com'],
    ['a query', `${clientId}?tenant=acme`, did],
    ['an explicit default port', 'https://example.com:443/clients/acme', did],
  ])('still mints a DID from a client_id with %s', (_label, id, minted) => {
    expect(cardFromClientMetadata({ client_id: id }).id).toBe(minted);
  });
});

describe('verifyCimdBind (anti-substitution, FAIL-CLOSED)', () => {
  const cimd = { clientId, jwksUri };

  it('accepts a binding whose did:web, client_id, and jwks_uri share an origin and is reciprocally aliased', () => {
    expect(verifyCimdBind(cimd, didDoc)).toEqual({ ok: true, reasons: [] });
  });

  it('REJECTS a hostile jwks_uri pointing at a different origin (key substitution)', () => {
    const hostile = { clientId, jwksUri: 'https://evil.example/jwks.json' };
    const result = verifyCimdBind(hostile, didDoc);
    expect(result.ok).toBe(false);
    expect(result.reasons.some((r) => /jwks_uri/.test(r))).toBe(true);
  });

  it('REJECTS a client_id whose origin does not match the DID (DID hijack)', () => {
    const hostile = { clientId: 'https://evil.example/clients/acme', jwksUri };
    const result = verifyCimdBind(hostile, didDoc);
    expect(result.ok).toBe(false);
    expect(result.reasons.some((r) => /did:web/.test(r))).toBe(true);
  });

  it('REJECTS when the DID document does not reciprocally list the client_id in alsoKnownAs', () => {
    const result = verifyCimdBind(cimd, { ...didDoc, alsoKnownAs: [] });
    expect(result.ok).toBe(false);
    expect(result.reasons.some((r) => /alsoKnownAs/.test(r))).toBe(true);
  });

  it('REJECTS a non-did:web DID document id', () => {
    const result = verifyCimdBind(cimd, { ...didDoc, id: 'did:key:z6Mkabc' });
    expect(result.ok).toBe(false);
    expect(result.reasons.some((r) => /not a did:web/.test(r))).toBe(true);
  });

  it('REJECTS a non-https jwks_uri (fail-closed on scheme)', () => {
    const result = verifyCimdBind({ clientId, jwksUri: 'http://example.com/jwks.json' }, didDoc);
    expect(result.ok).toBe(false);
    expect(result.reasons.some((r) => /must be https/.test(r))).toBe(true);
  });

  it("REJECTS an attacker's self-consistent CIMD + DID document attached to a victim card's id", () => {
    // Everything the attacker controls agrees with itself; only the card's id is the victim's.
    const victimCard: EntityCard = {
      id: 'did:web:victim.example:clients:acme',
      entityType: 'client',
      name: 'Totally Acme',
      cimd: { clientId: 'https://attacker.example/clients/x', jwksUri: 'https://attacker.example/clients/x/jwks.json' },
    };
    const attackerDidDoc = { id: 'did:web:attacker.example:clients:x', alsoKnownAs: ['https://attacker.example/clients/x'] };
    const result = verifyCimdBind(victimCard.cimd!, attackerDidDoc, victimCard.id);
    expect(result.ok).toBe(false);
    expect(result.reasons.some((r) => /is not the card's DID/.test(r))).toBe(true);
    expect(result.reasons.some((r) => /origin mismatch: did:web/.test(r))).toBe(true);
    // The card the binding does belong to still verifies with its own id.
    expect(verifyCimdBind(cimd, didDoc, card.id)).toEqual({ ok: true, reasons: [] });
  });

  it("given the card's DID, REJECTS a client_id on its origin that is not the DID's HTTPS form", () => {
    const sibling = { clientId: 'https://example.com/clients/other', jwksUri };
    const doc = { ...didDoc, alsoKnownAs: ['https://example.com/clients/other'] };
    const result = verifyCimdBind(sibling, doc, did);
    expect(result.ok).toBe(false);
    expect(result.reasons.some((r) => /is not the HTTPS form of/.test(r))).toBe(true);
    // Without the card's DID the check is origin-only, as before.
    expect(verifyCimdBind(sibling, doc)).toEqual({ ok: true, reasons: [] });
  });

  it.each([
    ['a trailing slash', 'https://example.com/'],
    ['an explicit default port', 'https://example.com:443'],
    ['a host in another case', 'https://Example.com'],
  ])("given the card's DID, compares client_id as a normalized URL: %s", (_label, rootClientId) => {
    const rootDid = 'did:web:example.com';
    const doc = { id: rootDid, alsoKnownAs: [rootClientId] };
    const bind = { clientId: rootClientId, jwksUri: 'https://example.com/jwks.json' };
    expect(verifyCimdBind(bind, doc, rootDid)).toEqual({ ok: true, reasons: [] });
  });

  it.each([
    'https://example.com/',
    'https://example.com/oauth/client.json',
    'https://example.com:443',
    'https://Example.com',
  ])('without the card\'s DID, accepts any same-origin client_id as before: %s', (sameOriginClientId) => {
    const doc = { id: 'did:web:example.com', alsoKnownAs: [sameOriginClientId] };
    const bind = { clientId: sameOriginClientId, jwksUri: 'https://example.com/jwks.json' };
    expect(verifyCimdBind(bind, doc)).toEqual({ ok: true, reasons: [] });
  });
});

describe('CIMD inputs that cannot be parsed fail closed', () => {
  const cimd = { clientId, jwksUri };

  it('bindClientId refuses a did:web with no host authority', () => {
    expect(() => bindClientId('did:web:')).toThrow(/no host authority/);
  });

  it('didFromClientId refuses a client_id that is not a URL', () => {
    expect(() => didFromClientId('not a url')).toThrow(/not a valid URL/);
  });

  it('cardFromClientMetadata refuses metadata that is not an object', () => {
    expect(() => cardFromClientMetadata(null)).toThrow(/must be an object/);
    expect(() => cardFromClientMetadata(['client'])).toThrow(/must be an object/);
  });

  it('cardFromClientMetadata refuses a declared did:web that has no origin', () => {
    const meta = { client_id: clientId, _meta: { [KYA_OS_DID_META_KEY]: 'did:web:' } };
    expect(() => cardFromClientMetadata(meta)).toThrow(/is not on the origin of client_id/);
  });

  it('verifyCimdBind reads a missing or non-object DID document as no binding', () => {
    for (const doc of [null, 'did:web:example.com', { id: 42, alsoKnownAs: [clientId] }]) {
      const result = verifyCimdBind(cimd, doc);
      expect(result.ok).toBe(false);
      expect(result.reasons.some((r) => /not a did:web/.test(r))).toBe(true);
    }
  });

  it('verifyCimdBind reports a did:web id with no resolvable origin', () => {
    const result = verifyCimdBind(cimd, { ...didDoc, id: 'did:web:' });
    expect(result.ok).toBe(false);
    expect(result.reasons.some((r) => /no resolvable origin/.test(r))).toBe(true);
  });

  it('verifyCimdBind reports a client_id or jwks_uri that is not a URL', () => {
    const result = verifyCimdBind({ clientId: 'not a url', jwksUri: '::' }, didDoc);
    expect(result.ok).toBe(false);
    expect(result.reasons.some((r) => /client_id is not a valid URL/.test(r))).toBe(true);
    expect(result.reasons.some((r) => /jwks_uri is not a valid URL/.test(r))).toBe(true);
  });

  it('verifyCimdBind finds no reciprocal bind in a non-array or unparseable alsoKnownAs', () => {
    for (const alsoKnownAs of [clientId, ['not a url'], [42]]) {
      const result = verifyCimdBind(cimd, { ...didDoc, alsoKnownAs });
      expect(result.ok).toBe(false);
      expect(result.reasons.some((r) => /alsoKnownAs does not list/.test(r))).toBe(true);
    }
  });
});
