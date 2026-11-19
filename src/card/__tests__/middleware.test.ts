import { describe, it, expect } from 'vitest';
import {
  buildCardProof,
  card,
  readCardProof,
  requireProof,
  toDidServiceEntry,
  toServerCardMeta,
  withKyaOsCard,
  type CardProofMeta,
  type MinProofLevel,
  type ProofSigner,
} from '../index.js';
import { AUD, NONCE, PROOF_KEY, REQ, clock, deps, keypair } from './proof-helpers.js';

const CARD = card({ did: 'did:web:example.com:agents:acme', entityType: 'agent', name: 'Acme Pay' })
  .capability('search')
  .build();

/** Mint a proof bag (a `_meta` carrying only `org.kya-os/proof`) with the shared deterministic clock. */
async function mintMeta(signer: ProofSigner): Promise<{ [PROOF_KEY]: CardProofMeta }> {
  return buildCardProof(REQ, signer, { audience: AUD, nonce: NONCE, now: clock });
}

describe('withKyaOsCard — mount the discovery artifacts', () => {
  it('bundles the three artifacts as the emit projections', () => {
    const mount = withKyaOsCard(CARD);
    expect(mount.cardJson).toBe(CARD);
    expect(mount.didServiceEntry).toEqual(toDidServiceEntry(CARD));
    expect(mount.serverMeta).toEqual(toServerCardMeta(CARD));
  });

  it('byRef projects the _meta as a lazy-fetch cardRef', () => {
    const mount = withKyaOsCard(CARD, { byRef: true });
    expect(mount.serverMeta).toEqual(toServerCardMeta(CARD, { byRef: true }));
    expect(mount.serverMeta['org.kya-os/card']).toHaveProperty('org.kya-os/cardRef');
  });

  it('mountServerJson merges the card _meta while preserving existing keys (immutably)', () => {
    const serverJson = { name: 'acme-mcp', _meta: { 'io.modelcontextprotocol/x': 1 } };
    const mounted = withKyaOsCard(CARD).mountServerJson(serverJson);
    expect(mounted.name).toBe('acme-mcp');
    expect(mounted._meta['io.modelcontextprotocol/x']).toBe(1);
    expect(mounted._meta['org.kya-os/card']).toEqual(toServerCardMeta(CARD)['org.kya-os/card']);
    expect(serverJson._meta).not.toHaveProperty('org.kya-os/card'); // original untouched
  });

  it('mountServerJson works when the server.json has no _meta yet', () => {
    const mounted = withKyaOsCard(CARD).mountServerJson({ name: 'acme-mcp' });
    expect(mounted._meta['org.kya-os/card']).toBeDefined();
  });

  it('mountDidDocument appends the KyaOsEntityCard service entry (immutably)', () => {
    const didDoc = { id: CARD.id, service: [{ id: '#other', type: 'X', serviceEndpoint: 'https://x' }] };
    const mounted = withKyaOsCard(CARD).mountDidDocument(didDoc);
    expect(mounted.service).toHaveLength(2);
    expect(mounted.service).toContainEqual(toDidServiceEntry(CARD));
    expect(didDoc.service).toHaveLength(1); // original untouched
  });

  it('mountDidDocument is idempotent — a second mount dedupes by service id', () => {
    const once = withKyaOsCard(CARD).mountDidDocument({ id: CARD.id });
    const twice = withKyaOsCard(CARD).mountDidDocument(once);
    const cardServices = twice.service.filter(
      (s) => (s as { id?: string }).id === toDidServiceEntry(CARD).id,
    );
    expect(cardServices).toHaveLength(1);
  });
});

describe('readCardProof', () => {
  it('extracts the proof from a _meta bag', async () => {
    const { signer } = await keypair();
    const meta = await mintMeta(signer);
    expect(readCardProof(meta)).toBe(meta[PROOF_KEY]);
  });

  it('returns undefined for a missing key or a non-object', () => {
    expect(readCardProof({})).toBeUndefined();
    expect(readCardProof(null)).toBeUndefined();
    expect(readCardProof('nope')).toBeUndefined();
  });
});

describe('requireProof — the per-request holder-of-key guard', () => {
  it('passes a valid proof and returns the principal + assurance (L3-minus without an AS cnf)', async () => {
    const { signer, publicJwk } = await keypair();
    const guard = requireProof(deps(publicJwk));
    const result = await guard(REQ, await mintMeta(signer));
    // The proof carried a cnf but no token cnf was wired, so the guard surfaces the non-fatal
    // unfused-cnf warning (TM-1) alongside the valid L3-minus result — it does not fail the guard.
    // It hands back what the proof states of its delegation (SPEC.md §7.8): none, for this request.
    expect(result).toEqual({
      ok: true,
      did: signer.did,
      level: 'L3-minus',
      warnings: ['cnf_present_but_token_unfused'],
      statedDelegation: { kind: 'none' },
    });
  });

  it('derives L3 when the token cnf fuses with the proof key', async () => {
    const { signer, publicJwk } = await keypair();
    const guard = requireProof(deps(publicJwk, { tokenCnfJkt: signer.jkt }));
    const result = await guard(REQ, await mintMeta(signer));
    expect(result).toEqual({ ok: true, did: signer.did, level: 'L3', statedDelegation: { kind: 'none' } });
  });

  it('401s (proof_missing) when _meta carries no proof', async () => {
    const { publicJwk } = await keypair();
    const result = await requireProof(deps(publicJwk))(REQ, {});
    expect(result).toEqual({
      ok: false,
      status: 401,
      error: { code: 'proof_missing', message: expect.any(String), reasons: ['proof_missing'] },
    });
  });

  it('401s (proof_invalid) when the request body differs from the one signed', async () => {
    const { signer, publicJwk } = await keypair();
    const meta = await mintMeta(signer);
    const tampered = { method: REQ.method, params: { ...REQ.params, injected: 'evil' } };
    const result = await requireProof(deps(publicJwk))(tampered, meta);
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error('expected rejection');
    expect(result.status).toBe(401);
    expect(result.error.code).toBe('proof_invalid');
    expect(result.error.reasons).toContain('request_hash_mismatch');
  });

  it('401s (proof_invalid) when the audience does not match the verifier', async () => {
    const { signer, publicJwk } = await keypair();
    const guard = requireProof(deps(publicJwk, { expectedAudience: 'did:web:relay.evil' }));
    const result = await guard(REQ, await mintMeta(signer));
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error('expected rejection');
    expect(result.error.code).toBe('proof_invalid');
    expect(result.error.reasons).toContain('audience_mismatch');
  });

  it('enforces minLevel: an L3-minus proof is rejected when L3 is required', async () => {
    const { signer, publicJwk } = await keypair();
    const guard = requireProof(deps(publicJwk), { minLevel: 'L3' });
    const result = await guard(REQ, await mintMeta(signer));
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error('expected rejection');
    expect(result.error.code).toBe('proof_level_insufficient');
  });

  it('enforces minLevel: full L3 fusion satisfies an L3 requirement', async () => {
    const { signer, publicJwk } = await keypair();
    const guard = requireProof(deps(publicJwk, { tokenCnfJkt: signer.jkt }), { minLevel: 'L3' });
    const result = await guard(REQ, await mintMeta(signer));
    expect(result.ok).toBe(true);
  });

  it.each<[string, unknown, string]>([
    ['a level in the wrong case', 'l3', 'a value "l3"'],
    ['a level with a trailing space', 'L3 ', 'a value "L3 "'],
    ['a level the guard does not know', 'L4', 'a value "L4"'],
    ['a number', 3, '3'],
    ['an inherited member of an object', 'constructor', 'a value "constructor"'],
    ['the empty string', '', 'a value ""'],
    ['null', null, 'a value of type null'],
  ])('refuses %s as minLevel where the guard is built, naming the levels it knows', (_name, minLevel, named) => {
    expect(() => requireProof(deps({ kty: 'OKP', crv: 'Ed25519', x: 'x' }), { minLevel: minLevel as MinProofLevel })).toThrow(
      new TypeError(`[kya-os] minLevel must be "L3-minus" or "L3" (got ${named})`),
    );
  });

  it('builds a guard with minLevel L3-minus or left out, which passes an L3-minus proof', async () => {
    const { signer, publicJwk } = await keypair();
    for (const options of [{ minLevel: 'L3-minus' as const }, { minLevel: undefined }, {}]) {
      const result = await requireProof(deps(publicJwk), options)(REQ, await mintMeta(signer));
      expect(result).toMatchObject({ ok: true, level: 'L3-minus' });
    }
  });

  it('is fail-closed when the key resolver throws (proof_invalid, never escapes)', async () => {
    const { signer, publicJwk } = await keypair();
    const guard = requireProof(
      deps(publicJwk, {
        resolveKey: () => {
          throw new Error('kms down');
        },
      }),
    );
    const result = await guard(REQ, await mintMeta(signer));
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error('expected rejection');
    expect(result.error.code).toBe('proof_invalid');
  });
});
