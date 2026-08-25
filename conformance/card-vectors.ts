#!/usr/bin/env node
/**
 * Deterministic generator for the Entity Card conformance vectors —
 * `conformance/vectors/card-proof.json` + `conformance/vectors/entity-card.json`.
 *
 * It signs the golden `org.kya-os/proof.v1` proof (and the kid⇄did forgery) with the FIXED
 * {@link ENTITY_KEY} at the FIXED {@link T0_MS} clock, so re-running reproduces
 * byte-identical files. Every negative variant is derived by surgical tampering or
 * a pinned mismatch, so the positive/negative relationships hold by construction.
 * Unlike the fresh-key `generate-vectors.ts`, THIS generator is deterministic.
 *
 *   run:  tsx conformance/card-vectors.ts   (npm run conformance:generate:card)
 */

import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { buildCardProof, ed25519SignerFromJwk, type CardProofMeta } from '../src/card/index.js';
import { KYA_OS_CARD_PROOF_META_KEY } from '../src/card/index.js';
import { VECTORS_DIR } from './loader.js';
import type { ConformanceVector, VectorFile } from './types.js';
import {
  AUDIENCE,
  DELEGATION_CHAIN,
  ENTITY_DID,
  ENTITY_KEY,
  GOLDEN_CARDS,
  JWKS,
  KID,
  NONCE,
  OWNER,
  REQUEST,
  RESOURCE,
  T0_MS,
  VICTIM_DID,
} from './card-fixtures.js';

const clock = (): number => T0_MS;

/** Mint a signed `org.kya-os/proof.v1` for {@link REQUEST} under the given identity. */
async function mintProof(opts: {
  did: string;
  kid: string;
  nonce: string;
  audience: string;
}): Promise<CardProofMeta> {
  const signer = await ed25519SignerFromJwk({ did: opts.did, kid: opts.kid, privateJwk: ENTITY_KEY });
  const env = await buildCardProof(REQUEST, signer, { audience: opts.audience, nonce: opts.nonce, now: clock });
  return env[KYA_OS_CARD_PROOF_META_KEY];
}

/** Flip a base64url string's last char — a minimal, still-well-formed tamper. */
function flipLastChar(value: string): string {
  const last = value[value.length - 1];
  return value.slice(0, -1) + (last === 'A' ? 'B' : 'A');
}

interface ProofInputOverrides {
  proof?: unknown;
  request?: unknown;
  expectedAudience?: string;
  nowMs?: number;
  omitNonceSeam?: boolean;
}

/** A `CardProofInput` over the golden proof, with per-vector overrides. */
function proofInput(proof: CardProofMeta, over: ProofInputOverrides = {}): unknown {
  return {
    proof: over.proof ?? proof,
    request: over.request ?? REQUEST,
    jwks: JWKS,
    expectedAudience: over.expectedAudience ?? AUDIENCE,
    nowMs: over.nowMs ?? T0_MS,
    skewSeconds: 5,
    ...(over.omitNonceSeam ? { omitNonceSeam: true } : {}),
  };
}

export async function cardProofVectorFile(): Promise<VectorFile> {
  const valid = await mintProof({ did: ENTITY_DID, kid: KID, nonce: NONCE, audience: AUDIENCE });
  // A forgery: the proof CLAIMS `did = VICTIM_DID` while `kid` still names the real
  // signer — authentically signed, so only the kid⇄did binding rejects it.
  const forged = await mintProof({ did: VICTIM_DID, kid: KID, nonce: 'n-forgery-00000000000000000000', audience: AUDIENCE });
  const tamperedSig: CardProofMeta = { ...valid, jws: flipLastChar(valid.jws) };
  const tamperedRequest = {
    method: 'tools/call',
    params: { name: 'payments.transfer', arguments: { to: 'did:web:merchant.example', amount: '9999.00', currency: 'USD' } },
  };

  const vectors: ConformanceVector[] = [
    {
      id: 'card-proof/valid',
      category: 'card-proof',
      description: 'A well-formed org.kya-os/proof.v1 with a valid detached JWS, in-window and audience-bound',
      expected: 'pass',
      reason: 'Every binding — signature, requestHash, audience, nonce, window, kid⇄did — holds',
      input: proofInput(valid),
    },
    {
      id: 'card-proof/tampered-body',
      category: 'card-proof',
      description: 'The proof verified against a mutated request body (amount 42.00 → 9999.00)',
      expected: 'fail',
      reason: 'requestHash no longer recomputes to the signed value — the body binding breaks',
      input: proofInput(valid, { request: tamperedRequest }),
    },
    {
      id: 'card-proof/tampered-signature',
      category: 'card-proof',
      description: 'Proof whose detached JWS signature bytes were altered',
      expected: 'fail',
      reason: 'A mutated signature must fail EdDSA verification over the covered claims',
      input: proofInput(tamperedSig),
    },
    {
      id: 'card-proof/wrong-audience',
      category: 'card-proof',
      description: 'Valid proof presented to a verifier whose DID is not the proof audience',
      expected: 'fail',
      reason: 'Audience binding (anti-relay / confused-deputy) must reject a mismatched recipient',
      input: proofInput(valid, { expectedAudience: 'did:web:evil.example' }),
    },
    {
      id: 'card-proof/expired',
      category: 'card-proof',
      description: 'Authentically signed proof evaluated an hour after its expires window',
      expected: 'fail',
      reason: 'A stale proof outside created/expires (±skew) must fail closed (replay guard)',
      input: proofInput(valid, { nowMs: T0_MS + 3_600_000 }),
    },
    {
      id: 'card-proof/kid-did-forgery',
      category: 'card-proof',
      description: 'Proof claims did:web:victim.example while kid names the real signer DID',
      expected: 'fail',
      reason: 'kid⇄did binding (kid.split("#")[0] === did) closes the forgeable-principal gap',
      input: proofInput(forged),
    },
    {
      id: 'card-proof/nonce-seam-missing',
      category: 'card-proof',
      description: 'A valid proof verified by a verifier that supplies NO replay (nonce) seam',
      expected: 'fail',
      reason: 'Without an atomic consumeNonceIfFresh seam there is no replay defense — fail closed (nonce_seam_missing)',
      input: proofInput(valid, { omitNonceSeam: true }),
    },
  ];

  return { version: '1.1.0', category: 'card-proof', vectors };
}

export function entityCardVectorFile(): VectorFile {
  const accountability = { resourceOwner: OWNER, resource: RESOURCE, chain: DELEGATION_CHAIN, proofDid: ENTITY_DID, now: T0_MS };
  const vectors: ConformanceVector[] = [
    passCard('mcp', GOLDEN_CARDS.mcp, 'no responsibleParty/attestations/revocation ⇒ verifies (L1 floor)'),
    passCard('client', GOLDEN_CARDS.client, 'a CIMD on-ramp client card verifies structurally'),
    passCard('verifier', GOLDEN_CARDS.verifier, 'a self-declared-capability verifier card verifies (L1)'),
    passCard('human', GOLDEN_CARDS.human, 'a did:key delegating-principal card verifies'),
    {
      id: 'entity-card/agent-accountable',
      category: 'entity-card',
      description: 'An agent card whose responsibleParty === issuer(rootVC) and leaf-invoker === proof.did',
      expected: 'pass',
      reason: 'The recomputed delegation/accountability edge closes over the golden ZCAP chain',
      input: { card: GOLDEN_CARDS.agent, accountability },
    },
    {
      id: 'entity-card/malformed-unknown-field',
      category: 'entity-card',
      description: 'A card carrying an unknown top-level property',
      expected: 'fail',
      reason: 'The strict schema (SPEC §7, additionalProperties:false) rejects, never strips',
      input: { card: { ...GOLDEN_CARDS.mcp, bogusField: true } },
    },
    {
      id: 'entity-card/accountability-join-broken',
      category: 'entity-card',
      description: 'Agent card whose accountability proofDid does not equal the recomputed leaf invoker',
      expected: 'fail',
      reason: 'The delegation/proof JOIN (leaf-invoker === proof.did) fails ⇒ accountability fails closed',
      input: { card: GOLDEN_CARDS.agent, accountability: { ...accountability, proofDid: 'did:web:attacker.example' } },
    },
  ];
  return { version: '1.1.0', category: 'entity-card', vectors };
}

/** A positive `entity-card` vector for a card that verifies with no injected seams. */
function passCard(entityType: string, card: unknown, reason: string): ConformanceVector {
  return {
    id: `entity-card/${entityType}-valid`,
    category: 'entity-card',
    description: `The golden ${entityType} card parses and verifies`,
    expected: 'pass',
    reason,
    input: { card },
  };
}

function write(file: VectorFile, name: string): void {
  writeFileSync(join(VECTORS_DIR, name), JSON.stringify(file, null, 2) + '\n', 'utf8');
  console.log(`wrote ${name} (${file.vectors.length} vectors)`);
}

export async function generateCardVectors(): Promise<void> {
  write(await cardProofVectorFile(), 'card-proof.json');
  write(entityCardVectorFile(), 'entity-card.json');
  console.log('Entity Card conformance vectors generated (deterministic).');
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  generateCardVectors().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}
