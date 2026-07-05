import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import {
  card as cardBuilder,
  parseCard,
  resolveCard,
  toDidServiceEntry,
  toServerCardMeta,
  toCatalogEntry,
  toA2AExtension,
  toAgentFacts,
  type EntityCard,
  type EntityCardSummary,
} from '../index.js';

/** Golden file: one canonical card + its expected projection onto every discovery surface. */
const golden = (() => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const raw = readFileSync(path.resolve(here, '__fixtures__/emit-golden.json'), 'utf8');
  return JSON.parse(raw) as Record<string, unknown>;
})();

const card = parseCard(golden.card);

describe('emit — discovery projections (golden file)', () => {
  it('toDidServiceEntry → the KyaOsEntityCard DID-document service entry', () => {
    expect(toDidServiceEntry(card)).toEqual(golden.didServiceEntry);
  });

  it('toServerCardMeta → inline org.kya-os/card summary', () => {
    expect(toServerCardMeta(card)).toEqual(golden.serverCardMeta);
  });

  it('toServerCardMeta({ byRef }) → an org.kya-os/cardRef lazy-fetch pointer', () => {
    expect(toServerCardMeta(card, { byRef: true })).toEqual(golden.serverCardMetaByRef);
  });

  it('toCatalogEntry → a by-ref catalog INDEX row', () => {
    expect(toCatalogEntry(card)).toEqual(golden.catalogEntry);
  });

  it('toA2AExtension → an A2A AgentExtension entry (required defaults to false)', () => {
    expect(toA2AExtension(card)).toEqual(golden.a2aExtension);
  });

  it('toAgentFacts → a NANDA AgentFacts projection (owner ← responsibleParty)', () => {
    expect(toAgentFacts(card)).toEqual(golden.agentFacts);
  });
});

describe('emit — invariants', () => {
  it('toA2AExtension honors required:true', () => {
    expect(toA2AExtension(card, { required: true }).required).toBe(true);
  });

  it('toA2AExtension is fail-closed for non-agent entities', () => {
    const mcp: EntityCard = { id: 'did:web:example.com:mcp:tools', entityType: 'mcp', name: 'Tools' };
    expect(() => toA2AExtension(mcp)).toThrow(/scoped to entityType "agent"/);
  });

  it('toAgentFacts omits owner when there is no responsibleParty', () => {
    const bare: EntityCard = { id: 'did:web:example.com:agents:solo', entityType: 'agent', name: 'Solo' };
    const facts = toAgentFacts(bare);
    expect(facts.owner).toBeUndefined();
    expect(facts['kya:entityType']).toBe('agent');
  });

  it('every did:web-anchored surface references the SAME card.json endpoint', () => {
    const endpoint = 'https://example.com/agents/acme-pay/card.json';
    expect(toDidServiceEntry(card).serviceEndpoint).toBe(endpoint);
    expect(toA2AExtension(card).params.cardUrl).toBe(endpoint);
    expect(toServerCardMeta(card, { byRef: true })['org.kya-os/card']).toEqual({
      'org.kya-os/cardRef': endpoint,
    });
  });
});

describe('emit — bare did:web org roots can publish (finding 7: emit/resolve symmetry)', () => {
  // A bare did:web:host is an org root — the shape of the DEFAULT trusted issuer did:web:example.com.
  // Pre-fix, every web-anchored projection threw for it (didWebToCardUrl had "no card path"), so the
  // trust anchors could not emit their own card via the shipped helpers even though resolveDidWeb
  // consumes such cards as first-class. The projections now anchor a bare root at the well-known path.
  const ORG = 'did:web:example.com';
  const bareCard: EntityCard = { id: ORG, entityType: 'verifier', name: 'Example Verifier' };
  const wellKnown = 'https://example.com/.well-known/kya-os-card.json';

  it('toDidServiceEntry anchors a bare org root at the well-known card path (no throw)', () => {
    expect(toDidServiceEntry(bareCard)).toEqual({
      id: '#kya-os-card',
      type: 'KyaOsEntityCard',
      serviceEndpoint: wellKnown,
    });
  });

  it('an explicit serviceEndpoint option overrides the derived URL for a non-conventional home', () => {
    const entry = toDidServiceEntry(bareCard, { serviceEndpoint: 'https://example.com/card.json' });
    expect(entry.serviceEndpoint).toBe('https://example.com/card.json');
    expect(toServerCardMeta(bareCard, { byRef: true, serviceEndpoint: 'https://example.com/card.json' })).toEqual({
      'org.kya-os/card': { 'org.kya-os/cardRef': 'https://example.com/card.json' },
    });
  });

  it('toServerCardMeta({ byRef }) points a bare root at the well-known card path', () => {
    expect(toServerCardMeta(bareCard, { byRef: true })['org.kya-os/card']).toEqual({
      'org.kya-os/cardRef': wellKnown,
    });
  });

  it('an inline bare-root summary resolves by deriving the SAME well-known card.json (emit ↔ resolve agree)', async () => {
    let fetchedUrl: string | undefined;
    const resolved = await resolveCard(
      { serverMeta: toServerCardMeta(bareCard) },
      {
        fetch: async (url) => {
          fetchedUrl = url;
          return { ok: true, status: 200, json: async () => bareCard };
        },
      },
    );
    expect(fetchedUrl).toBe(wellKnown); // the one URL emit anchors and resolve derives
    expect(resolved.id).toBe(ORG);
    expect(resolved.entityType).toBe('verifier');
  });
});

describe('emit — proofProfile consistent across all four projections (finding 14)', () => {
  // Pre-fix, toA2AExtension hardcoded proofProfile: org.kya-os/proof@1 while _meta and AgentFacts
  // gated it on card.proofProfile — so a builder-produced card (which could never set proofProfile)
  // advertised proof on the A2A rail but stayed silent on the others: one identity, divergent signals.
  const init = { did: 'did:web:example.com:agents:acme', entityType: 'agent' as const, name: 'Acme' };
  const summaryOf = (c: EntityCard) => toServerCardMeta(c)['org.kya-os/card'] as EntityCardSummary;

  it('a card WITHOUT a proof profile advertises it on NONE of the four rails', () => {
    const c = cardBuilder(init).build();
    expect(c.proofProfile).toBeUndefined();
    expect(toA2AExtension(c).params.proofProfile).toBeUndefined();
    expect(summaryOf(c).proofProfile).toBeUndefined();
    expect(toAgentFacts(c)['kya:proofProfile']).toBeUndefined();
  });

  it('a card WITH a proof profile advertises it on ALL four rails (they agree)', () => {
    const c = cardBuilder(init).usesProof().build();
    expect(c.proofProfile).toBe('org.kya-os/proof@1');
    expect(toA2AExtension(c).params.proofProfile).toBe('org.kya-os/proof@1');
    expect(summaryOf(c).proofProfile).toBe('org.kya-os/proof@1');
    expect(toAgentFacts(c)['kya:proofProfile']).toBe('org.kya-os/proof@1');
  });
});

describe('emit ↔ resolve round-trip', () => {
  it('an inline server.json _meta projection DEREFERENCES the canonical card.json (index, not authority)', async () => {
    // SECURITY: the inline summary is a discovery INDEX. resolveCard must NOT trust it as a
    // first-class card (that fails open on revocation) — it derives the canonical card URL from
    // the summary's `id` and fetches the entity's own card.json (the sole authority).
    let fetchedUrl: string | undefined;
    const resolved = await resolveCard(
      { serverMeta: toServerCardMeta(card) },
      {
        fetch: async (url) => {
          fetchedUrl = url;
          return { ok: true, status: 200, json: async () => golden.card };
        },
      },
    );
    expect(fetchedUrl).toBe('https://example.com/agents/acme-pay/card.json');
    expect(resolved.id).toBe(card.id);
    expect(resolved.entityType).toBe('agent');
    expect(resolved.name).toBe('Acme Pay Agent');
  });
});
