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

  it('REJECTS a document that declares a DID other than the did:web its client_id names (substitution)', () => {
    // Served from attacker.example, claiming the victim's DID: the card would carry the victim's id.
    const hostile = {
      client_id: 'https://attacker.example/clients/x',
      client_name: 'Totally Acme',
      jwks_uri: 'https://attacker.example/clients/x/jwks.json',
      _meta: { [KYA_OS_DID_META_KEY]: 'did:web:victim.example:clients:acme' },
    };
    expect(() => cardFromClientMetadata(hostile)).toThrow(/not the did:web of client_id/);
    // Same origin, different path is still a different entity.
    const sibling = { client_id: clientId, _meta: { [KYA_OS_DID_META_KEY]: 'did:web:example.com:clients:other' } };
    expect(() => cardFromClientMetadata(sibling)).toThrow(/not the did:web of client_id/);
    // The DID the client_id does name, ported or not, is still accepted.
    const ported = cardFromClientMetadata({
      client_id: 'https://localhost:3000/agents/bot',
      _meta: { [KYA_OS_DID_META_KEY]: 'did:web:localhost%3A3000:agents:bot' },
    });
    expect(ported.id).toBe('did:web:localhost%3A3000:agents:bot');
  });

  it('REJECTS a declared did:key (it has no HTTPS form, so the client_id cannot vouch for it)', () => {
    const meta = { client_id: clientId, _meta: { [KYA_OS_DID_META_KEY]: 'did:key:z6Mkabc' } };
    expect(() => cardFromClientMetadata(meta)).toThrow(/not the did:web of client_id/);
  });

  it.each([
    ['a query', `${clientId}?tenant=victim`],
    ['a fragment', `${clientId}#frag`],
    ['userinfo', 'https://victim@example.com/clients/acme'],
    ['a trailing slash', `${clientId}/`],
  ])('REJECTS a client_id with %s (no exact did:web form; it would round to a neighbour)', (_label, id) => {
    expect(() => cardFromClientMetadata({ client_id: id })).toThrow(/no exact did:web form/);
    expect(() => cardFromClientMetadata({ client_id: id, _meta: { [KYA_OS_DID_META_KEY]: did } })).toThrow();
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

  it('REJECTS a client_id on the DID origin that is not EXACTLY the DID\'s HTTPS form (bijection, not just origin)', () => {
    const sibling = { clientId: 'https://example.com/clients/other', jwksUri };
    const doc = { ...didDoc, alsoKnownAs: ['https://example.com/clients/other'] };
    for (const result of [verifyCimdBind(sibling, doc), verifyCimdBind(sibling, doc, did)]) {
      expect(result.ok).toBe(false);
      expect(result.reasons.some((r) => /is not the HTTPS form of/.test(r))).toBe(true);
    }
  });
});
