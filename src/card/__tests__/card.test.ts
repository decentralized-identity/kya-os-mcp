import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import {
  buildCard,
  verifyCard,
  resolveCard,
  toServerCardMeta,
  deriveConformanceLevel,
  parseCard,
  didWebToCardUrl,
  didWebToDidDocUrl,
  EntityCardSchema,
  type EntityCard,
  type CapabilityVerifier,
  type CardProofVerifier,
  type AccountabilityVerifier,
  type RevocationChecker,
} from '../index.js';

describe('buildCard', () => {
  it('builds a card from identity + facts and omits conformanceLevel (it is derived, not asserted)', () => {
    const card = buildCard(
      { did: 'did:web:example.com:agents:acme', kid: 'did:web:example.com:agents:acme#key-1' },
      { entityType: 'agent', name: 'Acme', capabilities: ['handshake'] },
    );
    expect(card.id).toBe('did:web:example.com:agents:acme');
    expect(card.entityType).toBe('agent');
    expect(card.kid).toBe('did:web:example.com:agents:acme#key-1');
    expect(card.conformanceLevel).toBeUndefined();
  });
});

describe('deriveConformanceLevel', () => {
  it('L1 when any capability is unverified', () => {
    expect(deriveConformanceLevel({ verified: ['a'], unverified: ['b'] }, false)).toBe('L1');
  });
  it('L1 when there is nothing attested', () => {
    expect(deriveConformanceLevel({ verified: [], unverified: [] }, false)).toBe('L1');
  });
  it('L2 when all capabilities attested and no live proof', () => {
    expect(deriveConformanceLevel({ verified: ['a', 'b'], unverified: [] }, false)).toBe('L2');
  });
  it('L3 when all capabilities attested and a valid live proof is present', () => {
    expect(deriveConformanceLevel({ verified: ['a'], unverified: [] }, true)).toBe('L3');
  });
  it('stays L1 with a live proof but unattested capabilities (proof does not lift a self-declared floor)', () => {
    expect(deriveConformanceLevel({ verified: [], unverified: ['a'] }, true)).toBe('L1');
  });
  it('defaults revocationFresh=true so the 2-arg call still reaches L3', () => {
    expect(deriveConformanceLevel({ verified: ['a'], unverified: [] }, true)).toBe('L3');
  });
  it('demotes L3 → L2 when revocation is unfresh (unreachable/stale status list)', () => {
    expect(deriveConformanceLevel({ verified: ['a'], unverified: [] }, true, false)).toBe('L2');
  });
  it('reaches L3 with a fresh revocation check and a valid proof', () => {
    expect(deriveConformanceLevel({ verified: ['a'], unverified: [] }, true, true)).toBe('L3');
  });
});

describe('verifyCard', () => {
  const card: EntityCard = {
    id: 'did:web:example.com:agents:acme',
    entityType: 'agent',
    name: 'Acme',
    capabilities: ['handshake', { name: 'payments.transfer', attestations: [{ vc: 'jwt' }] }],
    conformanceLevel: 'L3', // self-declared — MUST be ignored
    responsibleParty: 'did:web:example.com:org:acme',
  };

  const allAttested: CapabilityVerifier = async () => ({
    verified: ['handshake', 'payments.transfer'],
    unverified: [],
  });
  const partlyAttested: CapabilityVerifier = async () => ({
    verified: ['payments.transfer'],
    unverified: ['handshake'],
  });

  it('recomputes conformanceLevel and ignores the self-declared one', async () => {
    const res = await verifyCard(card, {
      capabilityVerifier: partlyAttested,
      accountabilityVerifier: async () => true,
    });
    expect(res.conformanceLevel).toBe('L1'); // NOT the card's self-declared L3
    expect(res.verifiedCapabilities).toEqual(['payments.transfer']);
  });

  it('is L2 when all capabilities attest, L3 when a valid live proof is also present', async () => {
    const l2 = await verifyCard(card, { capabilityVerifier: allAttested, accountabilityVerifier: async () => true });
    expect(l2.conformanceLevel).toBe('L2');

    const l3 = await verifyCard(card, {
      capabilityVerifier: allAttested,
      accountabilityVerifier: async () => true,
      proof: {},
      request: { method: 'tools/call' },
      proofVerifier: async () => ({ ok: true, reasons: [], level: 'L3-minus', did: card.id }),
    });
    expect(l3.conformanceLevel).toBe('L3');
  });

  it('ok=false when responsibleParty is present but unverified', async () => {
    const res = await verifyCard(card, { capabilityVerifier: partlyAttested });
    expect(res.accountability?.verified).toBe(false);
    expect(res.ok).toBe(false);
  });

  it('ok=true for a self-declared-only card with no trust-bearing claims', async () => {
    const plain: EntityCard = { id: 'did:key:z6Mkabc', entityType: 'client', name: 'Dev', capabilities: ['handshake'] };
    const res = await verifyCard(plain, {});
    expect(res.ok).toBe(true);
    expect(res.conformanceLevel).toBe('L1');
  });
});

describe('verifyCard — live proof, revocation, and CIMD seams', () => {
  const request = { method: 'tools/call', params: { name: 'search' } };
  const attestedCard: EntityCard = {
    id: 'did:web:example.com:agents:acme',
    entityType: 'agent',
    name: 'Acme',
    capabilities: [{ name: 'payments.transfer', attestations: [{ vc: 'jwt' }] }],
    responsibleParty: 'did:web:example.com:org:acme',
  };
  const allAttested: CapabilityVerifier = async () => ({ verified: ['payments.transfer'], unverified: [] });
  const accountable: AccountabilityVerifier = async () => true;
  /** A stub that recomputes a valid live holder-of-key proof — the real L2 → L3 seam. */
  const validLiveProof: CardProofVerifier = async () => ({
    ok: true,
    reasons: [],
    level: 'L3-minus',
    did: attestedCard.id,
  });

  const revocable: EntityCard = {
    ...attestedCard,
    revocation: { statusListCredential: 'https://example.com/status/1', statusListIndex: '94567' },
  };

  it('recomputes a valid proof to lift an attested card L2 → L3 and surfaces the verdict', async () => {
    const proofVerifier: CardProofVerifier = async () => ({
      ok: true,
      reasons: [],
      level: 'L3',
      did: 'did:web:example.com:agents:acme',
    });
    const res = await verifyCard(attestedCard, {
      capabilityVerifier: allAttested,
      accountabilityVerifier: accountable,
      proof: { prf: 'org.kya-os/proof.v1' },
      request,
      proofVerifier,
    });
    expect(res.conformanceLevel).toBe('L3');
    expect(res.proof).toEqual({ verified: true, did: 'did:web:example.com:agents:acme', level: 'L3', reasons: [] });
  });

  it('fail-closed: an invalid proof DEMOTES to L2 but keeps card validity (ok stays true)', async () => {
    const proofVerifier: CardProofVerifier = async () => ({ ok: false, reasons: ['expired'] });
    const res = await verifyCard(attestedCard, {
      capabilityVerifier: allAttested,
      accountabilityVerifier: accountable,
      proof: { prf: 'org.kya-os/proof.v1' },
      request,
      proofVerifier,
    });
    expect(res.conformanceLevel).toBe('L2');
    expect(res.ok).toBe(true);
    expect(res.proof?.verified).toBe(false);
  });

  it('fail-closed: a throwing proofVerifier never errors open (demotes to L2)', async () => {
    const proofVerifier: CardProofVerifier = async () => {
      throw new Error('boom');
    };
    const res = await verifyCard(attestedCard, {
      capabilityVerifier: allAttested,
      accountabilityVerifier: accountable,
      proof: {},
      request,
      proofVerifier,
    });
    expect(res.conformanceLevel).toBe('L2');
    expect(res.proof?.verified).toBe(false);
  });

  it('threads the recomputed proof.did into the accountability seam (leaf-invoker join)', async () => {
    let seenProofDid: string | undefined;
    const capturing: AccountabilityVerifier = async (_card, ctx) => {
      seenProofDid = ctx.proofDid;
      return true;
    };
    const proofVerifier: CardProofVerifier = async () => ({
      ok: true,
      reasons: [],
      level: 'L3',
      did: 'did:web:example.com:agents:acme',
    });
    await verifyCard(attestedCard, {
      capabilityVerifier: allAttested,
      accountabilityVerifier: capturing,
      proof: {},
      request,
      proofVerifier,
    });
    expect(seenProofDid).toBe('did:web:example.com:agents:acme');
  });

  it('L3 when the leaf status list is fresh and not revoked', async () => {
    const statusListChecker: RevocationChecker = async () => ({ revoked: false, fresh: true });
    const res = await verifyCard(revocable, {
      capabilityVerifier: allAttested,
      accountabilityVerifier: accountable,
      proof: {},
      request,
      proofVerifier: validLiveProof,
      statusListChecker,
    });
    expect(res.conformanceLevel).toBe('L3');
    expect(res.revocation).toEqual({ revoked: false, fresh: true });
  });

  it('fail-closed: an unreachable/stale status list (not fresh) demotes L3 → L2', async () => {
    const statusListChecker: RevocationChecker = async () => ({ revoked: false, fresh: false });
    const res = await verifyCard(revocable, {
      capabilityVerifier: allAttested,
      accountabilityVerifier: accountable,
      proof: {},
      request,
      proofVerifier: validLiveProof,
      statusListChecker,
    });
    expect(res.conformanceLevel).toBe('L2');
    expect(res.ok).toBe(true);
    expect(res.revocation?.fresh).toBe(false);
  });

  it('fail-closed: a REVOKED card credential collapses to L1 and fails validity (ok=false)', async () => {
    const statusListChecker: RevocationChecker = async () => ({ revoked: true, fresh: false });
    const res = await verifyCard(revocable, {
      capabilityVerifier: allAttested,
      accountabilityVerifier: accountable,
      proof: {},
      request,
      proofVerifier: validLiveProof,
      statusListChecker,
    });
    expect(res.conformanceLevel).toBe('L1');
    expect(res.ok).toBe(false);
    expect(res.revocation?.revoked).toBe(true);
  });

  it('fail-closed: a throwing statusListChecker is treated as revoked (L1, ok=false)', async () => {
    const statusListChecker: RevocationChecker = async () => {
      throw new Error('unreachable');
    };
    const res = await verifyCard(revocable, {
      capabilityVerifier: allAttested,
      accountabilityVerifier: accountable,
      proof: {},
      request,
      proofVerifier: validLiveProof,
      statusListChecker,
    });
    expect(res.conformanceLevel).toBe('L1');
    expect(res.ok).toBe(false);
  });

  it('leaves the level unchanged when the card declares no revocation entry', async () => {
    const statusListChecker: RevocationChecker = async () => ({ revoked: true, fresh: false });
    const res = await verifyCard(attestedCard, {
      capabilityVerifier: allAttested,
      accountabilityVerifier: accountable,
      proof: {},
      request,
      proofVerifier: validLiveProof,
      statusListChecker,
    });
    expect(res.conformanceLevel).toBe('L3');
    expect(res.revocation).toBeUndefined();
  });

  it('echoes cimdKeyProven into the result without altering the recomputed level', async () => {
    const res = await verifyCard(attestedCard, {
      capabilityVerifier: allAttested,
      accountabilityVerifier: accountable,
      cimdKeyProven: true,
    });
    expect(res.cimdKeyProven).toBe(true);
    expect(res.conformanceLevel).toBe('L2');
  });
});

describe('SECURITY: L3 requires a LIVE delegation-chain freshness check (§9.3/§10.6/§12.6)', () => {
  // Regression for the STALE-revocation fail-open: pre-fix, `AccountabilityVerifier` returned a bare
  // boolean, so `evaluateDelegationChain`'s `fresh` signal dead-ended and verifyCard granted L3 with
  // ZERO live status I/O on the leaf/chain — defeating the §12.6 revocation-race mitigation. The seam
  // now carries `fresh`; verifyCard ANDs it into the L3 gate (demote L3→L2) WITHOUT failing `ok`
  // (§10.6 keeps a non-revoked-but-stale chain acceptable at L2). `card.revocation` is omitted to
  // isolate the delegation-chain freshness gap from the card's own credential-status check.
  const request = { method: 'tools/call', params: { name: 'payments.transfer' } };
  const attestedCard: EntityCard = {
    id: 'did:web:example.com:agents:acme',
    entityType: 'agent',
    name: 'Acme',
    capabilities: [{ name: 'payments.transfer', attestations: [{ vc: 'jwt' }] }],
    responsibleParty: 'did:web:example.com:org:acme',
  };
  const allAttested: CapabilityVerifier = async () => ({ verified: ['payments.transfer'], unverified: [] });
  const validProof: CardProofVerifier = async () => ({
    ok: true,
    reasons: [],
    level: 'L3',
    did: 'did:web:example.com:agents:acme',
  });

  it('demotes L3 → L2 when the accountability seam reports a STALE (non-live) chain', async () => {
    const staleChain: AccountabilityVerifier = async () => ({ verified: true, fresh: false });
    const res = await verifyCard(attestedCard, {
      capabilityVerifier: allAttested,
      accountabilityVerifier: staleChain,
      proof: {},
      request,
      proofVerifier: validProof,
    });
    expect(res.conformanceLevel).toBe('L2'); // NOT L3 — leaf/chain status was not read live
    expect(res.ok).toBe(true); // §10.6: a non-revoked stale chain still accepts at L2
    expect(res.accountability).toMatchObject({ verified: true, fresh: false });
  });

  it('reaches L3 when the accountability seam reports a LIVE (fresh) chain and a valid proof', async () => {
    const freshChain: AccountabilityVerifier = async () => ({ verified: true, fresh: true });
    const res = await verifyCard(attestedCard, {
      capabilityVerifier: allAttested,
      accountabilityVerifier: freshChain,
      proof: {},
      request,
      proofVerifier: validProof,
    });
    expect(res.conformanceLevel).toBe('L3');
    expect(res.accountability?.fresh).toBe(true);
  });

  it('back-compat: a bare-boolean accountability seam leaves the level ungated (freshness unknown)', async () => {
    const res = await verifyCard(attestedCard, {
      capabilityVerifier: allAttested,
      accountabilityVerifier: async () => true, // DEPRECATED alias — no `fresh` channel
      proof: {},
      request,
      proofVerifier: validProof,
    });
    expect(res.conformanceLevel).toBe('L3');
    expect(res.accountability?.fresh).toBeUndefined();
  });

  it('demotes L3 → L2 when the capability seam reports a STALE (non-live) attestation status (§9.3)', async () => {
    const staleCaps: CapabilityVerifier = async () => ({
      verified: ['payments.transfer'],
      unverified: [],
      fresh: false, // attested, but the leaf capability status was NOT read live
    });
    const res = await verifyCard(attestedCard, {
      capabilityVerifier: staleCaps,
      accountabilityVerifier: async () => ({ verified: true, fresh: true }),
      proof: {},
      request,
      proofVerifier: validProof,
    });
    expect(res.conformanceLevel).toBe('L2'); // §9.3 leaf-credential liveness missing ⇒ not L3
    expect(res.ok).toBe(true);
  });
});

describe('resolveCard', () => {
  const did = 'did:web:example.com:agents:acme';
  const didDocUrl = 'https://example.com/agents/acme/did.json';
  const cardUrl = 'https://example.com/agents/acme/card.json';
  const card = { id: did, entityType: 'agent', name: 'Acme' };
  const didDoc = {
    id: did,
    service: [{ id: '#kya-os-card', type: 'KyaOsEntityCard', serviceEndpoint: cardUrl }],
  };

  type Reply = { ok: boolean; status: number; body: unknown };
  /** A SafeFetch mock that maps URLs to replies and records the request order. */
  const fetchMap = (overrides: Record<string, Reply> = {}) => {
    const requested: string[] = [];
    const map: Record<string, Reply> = {
      [didDocUrl]: { ok: true, status: 200, body: didDoc },
      [cardUrl]: { ok: true, status: 200, body: card },
      ...overrides,
    };
    const fetch = async (url: string) => {
      requested.push(url);
      const reply = map[url] ?? { ok: false, status: 404, body: {} };
      return { ok: reply.ok, status: reply.status, json: async () => reply.body };
    };
    return { fetch, requested };
  };

  it('rejects did:key (no domain anchor)', async () => {
    await expect(
      resolveCard('did:key:z6Mkabc', {
        fetch: async () => ({ ok: true, status: 200, json: async () => ({}) }),
      }),
    ).rejects.toThrow(/did:web/);
  });

  it('CONTRACT: fails CLOSED — rejects with a reasoned Error, never resolves to a null/undefined card', async () => {
    // Pins the documented throw contract (scoped OUT of the null-on-failure resolver rule): a
    // failed resolution must REJECT so an integrator cannot read a missing card as "no card = allow".
    const { fetch } = fetchMap({ [didDocUrl]: { ok: false, status: 500, body: {} } });
    const pending = resolveCard(did, { fetch });
    await expect(pending).rejects.toBeInstanceOf(Error); // not a silent null
    await expect(pending).rejects.toThrow(/resolveCard:/); // reason-carrying, namespaced message
  });

  it('resolves did:web in two steps: did.json → KyaOsEntityCard service → card.json', async () => {
    const { fetch, requested } = fetchMap();
    const res = await resolveCard(did, { fetch });
    expect(requested).toEqual([didDocUrl, cardUrl]);
    expect(res.id).toBe(did);
  });

  it('BINDS the resolved card to the DID: rejects a service entry pointing at a DIFFERENT-DID card', async () => {
    // A DID document (authoritative for `did`) whose card endpoint returns a card claiming ANOTHER
    // DID must fail closed — otherwise a cross-origin/compromised endpoint could attribute another
    // entity's claims to `did`.
    const foreign = { id: 'did:web:evil.example', entityType: 'agent', name: 'Evil' };
    const { fetch } = fetchMap({ [cardUrl]: { ok: true, status: 200, body: foreign } });
    await expect(resolveCard(did, { fetch })).rejects.toThrow(/identity mismatch/);
  });

  it('binds case-insensitively on the did:web host (normalized): a host-case-differing id still resolves', async () => {
    const mixedCase = { id: 'did:web:Example.com:agents:acme', entityType: 'agent', name: 'Acme' };
    const { fetch } = fetchMap({ [cardUrl]: { ok: true, status: 200, body: mixedCase } });
    const res = await resolveCard(did, { fetch });
    expect(res.id).toBe('did:web:Example.com:agents:acme');
  });

  it('does NOT bind the { cardUrl } path (no independent DID): a mismatched id resolves', async () => {
    // The cardUrl/A2A rails carry no DID to bind against — the URL itself is the trust root.
    const foreign = { id: 'did:web:other.example', entityType: 'agent', name: 'Other' };
    const { fetch } = fetchMap({ [cardUrl]: { ok: true, status: 200, body: foreign } });
    const res = await resolveCard({ cardUrl }, { fetch });
    expect(res.id).toBe('did:web:other.example');
  });

  it('throws when the DID document has no KyaOsEntityCard service entry', async () => {
    const { fetch } = fetchMap({ [didDocUrl]: { ok: true, status: 200, body: { id: did, service: [] } } });
    await expect(resolveCard(did, { fetch })).rejects.toThrow(/KyaOsEntityCard/);
  });

  it('throws on a non-ok DID-document fetch', async () => {
    const { fetch } = fetchMap({ [didDocUrl]: { ok: false, status: 404, body: {} } });
    await expect(resolveCard(did, { fetch })).rejects.toThrow(/404/);
  });

  it('resolves directly from a { cardUrl } reference (single fetch)', async () => {
    const { fetch, requested } = fetchMap();
    const res = await resolveCard({ cardUrl }, { fetch });
    expect(requested).toEqual([cardUrl]);
    expect(res.id).toBe(did);
  });

  it('dereferences an inline server.json _meta summary to the canonical card.json (index, not authority)', async () => {
    // SECURITY: the inline summary is an INDEX — resolveCard derives the canonical card URL from
    // its `id` and fetches the entity's card.json, never trusting the (trust-field-stripped) summary.
    const { fetch, requested } = fetchMap();
    const res = await resolveCard({ serverMeta: { 'org.kya-os/card': card } }, { fetch });
    expect(requested).toEqual([cardUrl]);
    expect(res.id).toBe(did);
  });

  it('resolves a by-ref server.json _meta card via org.kya-os/cardRef', async () => {
    const { fetch, requested } = fetchMap();
    const res = await resolveCard(
      { serverMeta: { 'org.kya-os/card': { 'org.kya-os/cardRef': cardUrl } } },
      { fetch },
    );
    expect(requested).toEqual([cardUrl]);
    expect(res.id).toBe(did);
  });

  it('resolves from an A2A extension params.cardUrl', async () => {
    const { fetch, requested } = fetchMap();
    const res = await resolveCard({ a2a: { uri: 'x', params: { cardUrl } } }, { fetch });
    expect(requested).toEqual([cardUrl]);
    expect(res.id).toBe(did);
  });

  it('resolves from a NANDA AgentFacts id (two-step did:web)', async () => {
    const { fetch, requested } = fetchMap();
    const res = await resolveCard({ agentFacts: { id: did, agent_name: 'Acme' } }, { fetch });
    expect(requested).toEqual([didDocUrl, cardUrl]);
    expect(res.id).toBe(did);
  });
});

describe('SECURITY: revoked card via the inline _meta discovery surface (fail-closed)', () => {
  // Regression for the discovery fail-open: the inline `org.kya-os/card` summary is claim-minimal
  // and (pre-fix) DROPPED the `revocation` pointer, so a verifier that trusted the summary as a
  // first-class card never consulted the status-list checker — a REVOKED card verified ok:true.
  // resolveCard must DEREFERENCE the summary to the entity's canonical card.json (which carries
  // `revocation`), so verifyCard fails closed. An mcp card with no `responsibleParty` isolates the
  // clean fail-open (no accountability path to coincidentally catch it).
  const revoked: EntityCard = {
    id: 'did:web:evil.example.com:agents:bot',
    entityType: 'mcp',
    name: 'Revoked Bot',
    revocation: { statusListCredential: 'https://issuer.example/status/1', statusListIndex: '7' },
  };
  const canonicalUrl = didWebToCardUrl(revoked.id);
  const revokedChecker: RevocationChecker = async () => ({ revoked: true, fresh: true });

  it('inline emit → resolve → verify yields ok:false (summary dereferenced, revocation survives)', async () => {
    const serverMeta = toServerCardMeta(revoked); // inline (default) discovery surface
    let fetched = 0;
    const resolved = await resolveCard(
      { serverMeta },
      {
        fetch: async (url) => {
          fetched += 1;
          expect(url).toBe(canonicalUrl); // dereferenced the entity's OWN card.json, not the summary
          return { ok: true, status: 200, json: async () => revoked };
        },
      },
    );
    expect(fetched).toBe(1);
    expect(resolved.revocation).toEqual(revoked.revocation); // the kill switch survived resolution

    const res = await verifyCard(resolved, { statusListChecker: revokedChecker });
    expect(res.ok).toBe(false);
    expect(res.revocation?.revoked).toBe(true);
  });

  it('the inline summary itself is self-verifiable — it carries the revocation kill switch', () => {
    // Defense-in-depth: even a consumer that reads the summary directly (against the resolve
    // contract) must see the `revocation` pointer, so the projection can never fail open.
    const summary = toServerCardMeta(revoked)['org.kya-os/card'];
    expect(summary).toMatchObject({ revocation: revoked.revocation });
  });
});

describe('SECURITY: did:key inline _meta summary (no web home — parse in place, still fail-closed)', () => {
  // Regression for the FIX-INDUCED regression from 7f87e04: `resolveFromServerMeta` derived the
  // canonical card URL via `didWebToCardUrl(id)` for EVERY inline summary, which THROWS "no web
  // home" for a did:key id — breaking inline `_meta` discovery for did:key entities (the schema
  // permits did:key; `toServerCardMeta` emits inline summaries for them; the consent examples use
  // did:key). A did:key has no card.json to dereference, so the summary is parsed in place. That
  // is safe now because the summary carries the `revocation` kill switch + `delegationRef`
  // (added in 7f87e04), so `verifyCard` still consults the status-list checker and fails closed.
  const didKey = 'did:key:z6MkExampleConsentHolderKeyMaterial';

  it('resolves a did:key inline summary directly (no throw, no fetch) and round-trips the identity', async () => {
    const card: EntityCard = {
      id: didKey,
      entityType: 'client',
      name: 'Consent Holder',
      capabilities: ['handshake'],
    };
    let fetched = 0;
    const resolved = await resolveCard(
      { serverMeta: toServerCardMeta(card) }, // inline (default) discovery surface
      {
        fetch: async () => {
          fetched += 1;
          return { ok: true, status: 200, json: async () => ({}) };
        },
      },
    );
    expect(fetched).toBe(0); // no web home to dereference — the summary is parsed in place
    expect(resolved.id).toBe(didKey);
    expect(resolved.entityType).toBe('client');
    expect(resolved.name).toBe('Consent Holder');
    expect(resolved.capabilities).toEqual(['handshake']);
  });

  it('a REVOKED did:key inline summary still verifies ok:false (kill switch survives resolution)', async () => {
    const revoked: EntityCard = {
      id: didKey,
      entityType: 'client',
      name: 'Revoked Consent Holder',
      revocation: { statusListCredential: 'https://issuer.example/status/1', statusListIndex: '7' },
    };
    const revokedChecker: RevocationChecker = async () => ({ revoked: true, fresh: true });
    const resolved = await resolveCard(
      { serverMeta: toServerCardMeta(revoked) },
      {
        fetch: async () => {
          throw new Error('a did:key inline summary must be parsed in place, never fetched');
        },
      },
    );
    expect(resolved.revocation).toEqual(revoked.revocation); // the kill switch survived resolution

    const res = await verifyCard(resolved, { statusListChecker: revokedChecker });
    expect(res.ok).toBe(false); // did:key summary path is fail-closed, exactly like did:web
    expect(res.revocation?.revoked).toBe(true);
  });
});

describe('didWebToCardUrl', () => {
  it('maps a path-form did:web to the per-entity card URL', () => {
    expect(didWebToCardUrl('did:web:example.com:agents:acme')).toBe('https://example.com/agents/acme/card.json');
  });
  // UPDATED (was: asserted a throw on a bare did:web). A bare org root — including the default
  // trusted issuer did:web:example.com — MUST be able to emit its own card via the shipped helpers,
  // so a bare did:web now maps to the well-known org-root card path instead of failing closed.
  it('maps a bare did:web to the well-known org-root card path', () => {
    expect(didWebToCardUrl('did:web:example.com')).toBe('https://example.com/.well-known/kya-os-card.json');
  });
  it('throws (non-circular guidance) for a non-did:web DID — a did:key has no web home', () => {
    expect(() => didWebToCardUrl('did:key:z6MkExampleKeyMaterial')).toThrow(/no web home/);
  });
});

describe('didWebToDidDocUrl', () => {
  it('maps a path-form did:web to its DID document URL', () => {
    expect(didWebToDidDocUrl('did:web:example.com:agents:acme')).toBe('https://example.com/agents/acme/did.json');
  });
  it('maps a bare did:web to the well-known DID document URL', () => {
    expect(didWebToDidDocUrl('did:web:example.com')).toBe('https://example.com/.well-known/did.json');
  });
});

describe('parseCard', () => {
  it('accepts a minimal valid card', () => {
    expect(parseCard({ id: 'did:web:example.com:agents:acme', entityType: 'agent', name: 'Acme' }).name).toBe('Acme');
  });
  it('rejects a card missing required fields', () => {
    expect(() => parseCard({ id: 'did:web:x', entityType: 'agent' })).toThrow(/name/);
  });
  it('rejects an unknown entityType', () => {
    expect(() => parseCard({ id: 'did:web:x', entityType: 'robot', name: 'X' })).toThrow(/entityType/);
  });
  it('accepts the additive proofProfile/cimd/revocation fields', () => {
    const card = parseCard({
      id: 'did:web:example.com:agents:acme',
      entityType: 'agent',
      name: 'Acme',
      proofProfile: 'org.kya-os/proof.v1',
      cimd: { clientId: 'https://example.com/agents/acme', jwksUri: 'https://example.com/agents/acme/jwks.json' },
      revocation: { statusListCredential: 'https://example.com/status/1', statusListIndex: '94567' },
    });
    expect(card.proofProfile).toBe('org.kya-os/proof.v1');
    expect(card.cimd?.jwksUri).toBe('https://example.com/agents/acme/jwks.json');
    expect(card.revocation?.statusListIndex).toBe('94567');
  });
  it('rejects a proofProfile other than the org.kya-os/proof.v1 literal', () => {
    expect(() =>
      parseCard({ id: 'did:web:x', entityType: 'agent', name: 'X', proofProfile: 'org.kya-os/proof@2' }),
    ).toThrow(/proofProfile/);
  });
  it('rejects an unknown top-level property (mirrors additionalProperties:false, no silent strip)', () => {
    expect(() =>
      parseCard({ id: 'did:web:example.com:agents:acme', entityType: 'agent', name: 'Acme', evilExtra: 'INJECTED' }),
    ).toThrow(/evilExtra|[Uu]nrecognized/);
  });
  it('rejects an unknown property on a nested strict object (revocation)', () => {
    expect(() =>
      parseCard({
        id: 'did:web:example.com:agents:acme',
        entityType: 'agent',
        name: 'Acme',
        revocation: {
          statusListCredential: 'https://example.com/status/1',
          statusListIndex: '94567',
          smuggled: true,
        },
      }),
    ).toThrow(/smuggled|[Uu]nrecognized/);
  });
});

describe('zod schema ↔ published JSON schema', () => {
  it('every example in schemas/kya-os-card.schema.json parses via the zod schema', () => {
    const here = path.dirname(fileURLToPath(import.meta.url));
    const schemaPath = path.resolve(here, '../../../schemas/kya-os-card.schema.json');
    const json = JSON.parse(readFileSync(schemaPath, 'utf8')) as { examples?: unknown[] };
    expect(Array.isArray(json.examples)).toBe(true);
    for (const example of json.examples ?? []) {
      expect(() => EntityCardSchema.parse(example)).not.toThrow();
    }
  });
});
