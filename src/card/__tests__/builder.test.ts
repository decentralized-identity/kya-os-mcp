import { describe, it, expect } from 'vitest';
import { card, CardBuilder, EntityCardSchema, parseCard, type EntityCard } from '../index.js';

const DID = 'did:web:example.com:agents:acme';
const ORG = 'did:web:example.com';
const VC = 'eyJhbGciOiJFZERTQSJ9.eyJ2YyI6e319.sig';

describe('card() fluent builder', () => {
  it('builds a minimal, schema-valid card from identity + type + name', () => {
    const built = card({ did: DID, entityType: 'agent', name: 'Acme Pay' }).build();
    expect(built).toEqual({ id: DID, entityType: 'agent', name: 'Acme Pay' });
    expect(() => EntityCardSchema.parse(built)).not.toThrow();
  });

  it('never sets conformanceLevel — it is derived, not asserted', () => {
    const built = card({ did: DID, entityType: 'agent', name: 'Acme' })
      .attestedCapability('payments.transfer', VC)
      .build();
    expect(built.conformanceLevel).toBeUndefined();
  });

  it('passes kid + createdAt through to the identity', () => {
    const built = card({
      did: DID,
      entityType: 'agent',
      name: 'Acme',
      kid: `${DID}#key-1`,
      createdAt: '2026-06-30T12:00:00Z',
    }).build();
    expect(built.kid).toBe(`${DID}#key-1`);
    expect(built.createdAt).toBe('2026-06-30T12:00:00Z');
  });

  it('.capability appends L1 bare-string capabilities in order', () => {
    const built = card({ did: DID, entityType: 'agent', name: 'Acme' })
      .capability('search')
      .capability('summarize')
      .build();
    expect(built.capabilities).toEqual(['search', 'summarize']);
  });

  it('.attestedCapability builds an L2 attested capability', () => {
    const built = card({ did: DID, entityType: 'agent', name: 'Acme' })
      .attestedCapability('payments.transfer', VC)
      .build();
    expect(built.capabilities).toEqual([
      { name: 'payments.transfer', attestations: [{ vc: VC }] },
    ]);
  });

  it('accumulates repeated attestations for the SAME capability onto one entry', () => {
    const other = { vc: { id: 'urn:vc:2' } };
    const built = card({ did: DID, entityType: 'agent', name: 'Acme' })
      .attestedCapability('payments.transfer', VC)
      .attestedCapability('payments.transfer', other.vc)
      .build();
    expect(built.capabilities).toEqual([
      { name: 'payments.transfer', attestations: [{ vc: VC }, { vc: other.vc }] },
    ]);
  });

  it('mixes L1 and L2 capabilities', () => {
    const built = card({ did: DID, entityType: 'agent', name: 'Acme' })
      .capability('search')
      .attestedCapability('payments.transfer', VC)
      .build();
    expect(built.capabilities).toEqual([
      'search',
      { name: 'payments.transfer', attestations: [{ vc: VC }] },
    ]);
  });

  it('.accountableTo sets responsibleParty, delegationRef (via), and principal', () => {
    const built = card({ did: DID, entityType: 'agent', name: 'Acme' })
      .accountableTo(ORG, { via: 'vc_root>del_123', principal: `${ORG}:humans:dana` })
      .build();
    expect(built.responsibleParty).toBe(ORG);
    expect(built.delegationRef).toBe('vc_root>del_123');
    expect(built.principal).toBe(`${ORG}:humans:dana`);
  });

  it('.accountableTo without options sets only responsibleParty', () => {
    const built = card({ did: DID, entityType: 'agent', name: 'Acme' })
      .accountableTo(ORG)
      .build();
    expect(built.responsibleParty).toBe(ORG);
    expect(built.delegationRef).toBeUndefined();
    expect(built.principal).toBeUndefined();
  });

  it('.attestation attaches a standalone (e.g. KYC) attestation', () => {
    const built = card({ did: DID, entityType: 'agent', name: 'Acme' })
      .attestation({ type: 'IdentityVerification', vc: VC, subject: ORG })
      .build();
    expect(built.attestations).toEqual([
      { type: 'IdentityVerification', vc: VC, subject: ORG },
    ]);
  });

  it('produces a full, schema-valid accountable card from a single fluent chain', () => {
    const built: EntityCard = card({ did: DID, entityType: 'agent', name: 'Acme Pay' })
      .capability('search')
      .attestedCapability('payments.transfer', VC)
      .accountableTo(ORG, { via: 'vc_root>del_123' })
      .build();
    expect(() => parseCard(built)).not.toThrow();
    expect(built.entityType).toBe('agent');
    expect(built.responsibleParty).toBe(ORG);
  });

  it('card() returns a CardBuilder and chaining is fluent (returns the builder)', () => {
    const builder = card({ did: DID, entityType: 'mcp', name: 'Tools' });
    expect(builder).toBeInstanceOf(CardBuilder);
    expect(builder.capability('a')).toBe(builder);
    expect(builder.accountableTo(ORG)).toBe(builder);
  });
});

describe('card() builder — infrastructure coordinates (finding 15)', () => {
  // Pre-fix the fluent builder could NOT set proofProfile / cimd / revocation (nor publicKeyJwk /
  // didDocument): the ergonomic 10-minute path could not emit a card that plugs into the proof /
  // CIMD / revocation machinery — a developer had to hand-author an EntityCard literal.
  const CLIENT_ID = 'https://example.com/agents/acme';
  const JWKS = 'https://example.com/agents/acme/jwks.json';
  const REVOCATION = { statusListCredential: 'https://example.com/status/1', statusListIndex: '42' };
  const DID_DOC = 'https://example.com/agents/acme/did.json';
  const JWK = { kty: 'OKP' as const, crv: 'Ed25519' as const, x: 'abc123' };

  it('.usesProof() advertises the org.kya-os/proof@1 profile', () => {
    const built = card({ did: DID, entityType: 'agent', name: 'Acme' }).usesProof().build();
    expect(built.proofProfile).toBe('org.kya-os/proof@1');
    expect(() => parseCard(built)).not.toThrow();
  });

  it('.cimd() binds the L1 CIMD on-ramp coordinates', () => {
    const built = card({ did: DID, entityType: 'agent', name: 'Acme' })
      .cimd({ clientId: CLIENT_ID, jwksUri: JWKS })
      .build();
    expect(built.cimd).toEqual({ clientId: CLIENT_ID, jwksUri: JWKS });
  });

  it('.revocation() attaches the Bitstring Status List kill switch', () => {
    const built = card({ did: DID, entityType: 'agent', name: 'Acme' }).revocation(REVOCATION).build();
    expect(built.revocation).toEqual(REVOCATION);
  });

  it('.didDocument() and .publicKey() record the DID-doc URL + inline verification key', () => {
    const built = card({ did: DID, entityType: 'agent', name: 'Acme' })
      .didDocument(DID_DOC)
      .publicKey(JWK)
      .build();
    expect(built.didDocument).toBe(DID_DOC);
    expect(built.publicKeyJwk).toEqual(JWK);
  });

  it('omits every infra coordinate when unset (claim-minimal, deterministic)', () => {
    const built = card({ did: DID, entityType: 'agent', name: 'Acme' }).build();
    expect(built.proofProfile).toBeUndefined();
    expect(built.cimd).toBeUndefined();
    expect(built.revocation).toBeUndefined();
    expect(built.didDocument).toBeUndefined();
    expect(built.publicKeyJwk).toBeUndefined();
  });

  it('emits a fully-provisioned, schema-valid card (proof + cimd + revocation) in one fluent chain', () => {
    const built: EntityCard = card({ did: DID, entityType: 'agent', name: 'Acme Pay' })
      .capability('search')
      .usesProof()
      .cimd({ clientId: CLIENT_ID, jwksUri: JWKS })
      .revocation(REVOCATION)
      .build();
    expect(() => parseCard(built)).not.toThrow();
    expect(built.proofProfile).toBe('org.kya-os/proof@1');
    expect(built.cimd).toEqual({ clientId: CLIENT_ID, jwksUri: JWKS });
    expect(built.revocation).toEqual(REVOCATION);
  });
});
