/**
 * Conformance vectors — exercise the card primitives directly against the framework fixtures.
 *
 * These load the SAME committed vectors the implementation-agnostic harness runs
 * (`conformance/vectors/card-proof.json` + `entity-card.json`, in the `{ version, category,
 * vectors }` VectorFile format) and drive them through the card primitives at a finer grain than
 * the adapter-level `conformance/__tests__/conformance.test.ts` — the deterministic re-mint
 * (byte-identical round-trip), the L3-minus → L3 cnf fusion, the RFC 9421 sibling, and the
 * delegation/proof JOIN. `conformance/verify.py` verifies the SAME `card-proof.json` positive
 * vector in a second language, so a green TS suite + a green Python run prove cross-language JCS
 * (RFC 8785) + Ed25519 parity. Regenerate with `npm run conformance:generate:card`.
 */

import { readFileSync } from 'node:fs';
import { describe, it, expect } from 'vitest';
import {
  buildCardProof,
  verifyCardProof,
  verifyHttpSignature,
  validateDelegationChain,
  parseCard,
  ed25519SignerFromJwk,
  CardProofMetaSchema,
  DelegationCredentialSchema,
  InMemoryNonceCache,
  type CardProofMeta,
  type DelegationCredential,
  type Ed25519PrivateJwk,
  type Ed25519PublicJwk,
  type EntityType,
  type VerifyProofDeps,
} from '../index.js';
import { KYA_OS_CARD_PROOF_META_KEY } from '../proof/types.js';
import type { ToolRequest } from '../../proof/generator.js';

// ── Vector loading (the framework VectorFile format) ──────────────────────────────
interface FrameworkVector<I> {
  id: string;
  expected: 'pass' | 'fail';
  input: I;
}
interface FrameworkFile<I> {
  version: string;
  category: string;
  vectors: FrameworkVector<I>[];
}

interface CardProofVectorInput {
  proof: CardProofMeta;
  request: ToolRequest;
  jwks: { keys: Ed25519PublicJwk[] };
  expectedAudience: string;
  nowMs: number;
}
interface EntityCardAccountability {
  resourceOwner: string;
  resource: string;
  chain: unknown[];
  proofDid: string;
}
interface EntityCardVectorInput {
  card: unknown;
  accountability?: EntityCardAccountability;
}

function loadFile<I>(name: string): FrameworkFile<I> {
  return JSON.parse(
    readFileSync(new URL(`../../../conformance/vectors/${name}`, import.meta.url), 'utf8'),
  ) as FrameworkFile<I>;
}
function vectorById<I>(file: FrameworkFile<I>, id: string): FrameworkVector<I> {
  const found = file.vectors.find((v) => v.id === id);
  if (!found) throw new Error(`no vector "${id}"`);
  return found;
}

const cardProofFile = loadFile<CardProofVectorInput>('card-proof.json');
const entityCardFile = loadFile<EntityCardVectorInput>('entity-card.json');

const validProof = vectorById(cardProofFile, 'card-proof/valid').input;
const { proof, request, jwks } = validProof;

// The FIXED test key the card-proof/valid vector was signed with (private `d` is public —
// TEST-ONLY), so `buildCardProof` can be exercised by re-minting and asserting byte-identity.
const ENTITY_KEY: Ed25519PrivateJwk = {
  kty: 'OKP',
  crv: 'Ed25519',
  x: 'RvWVWwqcVO9f_7aQ8dXf0F16aoQsE4i_Ebjqo8mn_Ts',
  d: 'Yaa31QgNkAKKHjqn6yEu2vXQTMUEbeBMwIJ4h55Ukh4',
};

function resolveKey(kid: string): Ed25519PublicJwk {
  const key = jwks.keys.find((k) => k.kid === kid);
  if (!key) throw new Error(`no JWKS key for kid ${kid}`);
  return key;
}
function resolveDidKeys(did: string): Ed25519PublicJwk[] {
  return jwks.keys.filter((k) => k.kid?.split('#')[0] === did);
}
function proofDeps(over: Partial<VerifyProofDeps> = {}): VerifyProofDeps {
  return {
    resolveKey,
    resolveDidKeys, // the vectors ship a DID-keyed JWKS, so verify via the secure RFC 7638 membership seam
    expectedAudience: validProof.expectedAudience,
    consumeNonceIfFresh: new InMemoryNonceCache({ now: () => validProof.nowMs }).consume,
    now: () => validProof.nowMs,
    ...over,
  };
}

// ── card-proof/valid — the signed org.kya-os/proof@1 + its RFC 9421 sibling ──────────
describe('conformance vector: card-proof.json (org.kya-os/proof@1)', () => {
  it('is a schema-valid CardProofMeta carrying a detached JWS + an httpSig sibling', () => {
    const parsed = CardProofMetaSchema.parse(proof);
    expect(parsed.prf).toBe('org.kya-os/proof@1');
    expect(parsed.jws.split('.')[1]).toBe(''); // detached JWS: header..signature
    expect(parsed.httpSig).toBeTruthy();
  });

  it('verifyCardProof recomputes every binding → ok, L3-minus without a token cnf', async () => {
    const res = await verifyCardProof(proof, request, proofDeps());
    // The vector proof carries a cnf; with no token cnf wired it degrades to L3-minus and surfaces
    // the non-fatal unfused-cnf warning (TM-1). The pass/fail conformance outcome is unaffected.
    expect(res).toEqual({
      ok: true,
      reasons: [],
      level: 'L3-minus',
      did: proof.did,
      warnings: ['cnf_present_but_token_unfused'],
    });
  });

  it('verifyCardProof fuses the token cnf.jkt → L3', async () => {
    const res = await verifyCardProof(
      proof,
      request,
      proofDeps({ tokenCnfJkt: proof.cnf?.jkt, resolveDidKeys }),
    );
    expect(res.ok).toBe(true);
    expect(res.level).toBe('L3');
  });

  it('verifyHttpSignature verifies the RFC 9421 sibling against the DID key', async () => {
    expect(await verifyHttpSignature(proof, resolveKey(proof.kid))).toBe(true);
  });

  it('fails closed when verified against a tampered request (requestHash binding)', async () => {
    const tampered: ToolRequest = {
      method: 'tools/call',
      params: { name: 'payments.transfer', arguments: { amount: '9999.00' } },
    };
    const res = await verifyCardProof(proof, tampered, proofDeps());
    expect(res.ok).toBe(false);
    expect(res.reasons).toContain('request_hash_mismatch');
  });

  it('buildCardProof deterministically re-mints the exact committed proof (round-trip)', async () => {
    const signer = await ed25519SignerFromJwk({ did: proof.did, kid: proof.kid, privateJwk: ENTITY_KEY });
    const env = await buildCardProof(request, signer, {
      audience: validProof.expectedAudience,
      nonce: proof.nonce,
      now: () => validProof.nowMs,
    });
    expect(env[KYA_OS_CARD_PROOF_META_KEY]).toEqual(proof);
  });
});

// ── entity-card.json — the delegation chain carried by the agent accountability vector ──
describe('conformance vector: entity-card.json delegation chain (W3C VC 2.0 + ZCAP-LD)', () => {
  const accountability = vectorById(entityCardFile, 'entity-card/agent-accountable').input.accountability!;
  const chain = accountability.chain.map((vc): DelegationCredential => DelegationCredentialSchema.parse(vc));

  it('validateDelegationChain accepts the chain and recomputes the JOIN', () => {
    const res = validateDelegationChain(chain, {
      resourceOwner: accountability.resourceOwner,
      resource: accountability.resource,
      now: () => accountability.now ?? Date.parse('2026-06-30T12:00:00Z'),
    });
    expect(res.ok).toBe(true);
    expect(res.reasons).toEqual([]);
    expect(res.responsibleParty).toBe(accountability.resourceOwner);
    expect(res.leafInvoker).toBe(accountability.proofDid);
    expect(res.invocationTarget).toBe(accountability.resource);
    expect(res.allowedAction).toEqual(['payments.transfer']);
    expect(res.depth).toBe(2);
  });

  it('recomputed leaf-invoker equals the proof.did (the delegation/proof JOIN)', () => {
    expect(validateDelegationChain(chain).leafInvoker).toBe(proof.did);
  });
});

// ── entity-card.json — golden EntityCards per entityType ────────────────────────────
describe('conformance vector: entity-card.json (golden EntityCards per entityType)', () => {
  const byType: Record<EntityType, string> = {
    mcp: 'entity-card/mcp-valid',
    agent: 'entity-card/agent-accountable',
    client: 'entity-card/client-valid',
    verifier: 'entity-card/verifier-valid',
    human: 'entity-card/human-valid',
  };
  const entityTypes = Object.keys(byType) as EntityType[];

  it.each(entityTypes)('parseCard round-trips the %s card', (entityType) => {
    const card = parseCard(vectorById(entityCardFile, byType[entityType]).input.card);
    expect(card.entityType).toBe(entityType);
    expect(card.id).toMatch(/^did:(key|web):/);
  });
});
