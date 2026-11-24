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

import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { buildCardProof, ed25519SignerFromJwk, httpSignatureBaseBytes, type CardProofMeta } from '../src/card/index.js';
import { KYA_OS_CARD_PROOF_META_KEY } from '../src/card/index.js';
import { canonicalPayloadBytes } from '../src/card/proof/canonical.js';
import { statementParameters } from '../src/delegation/stated-delegation.js';
import { webCryptoSha256 } from '../src/utils/domain-digest.js';
import { cardChainVectors } from './card-chain-vectors.js';
import type { ConformanceVector, VectorFile } from './types.js';
import { flipSignatureChar } from './tampering.js';
import { SUITE_VERSION, writeVectorFile } from './vector-files.js';
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

/** Mint a signed `org.kya-os/proof.v1` for `opts.request` ({@link REQUEST} by default) under the given identity. */
async function mintProof(opts: {
  did: string;
  kid: string;
  nonce: string;
  audience: string;
  request?: { method: string; params?: unknown };
}): Promise<CardProofMeta> {
  const signer = await ed25519SignerFromJwk({ did: opts.did, kid: opts.kid, privateJwk: ENTITY_KEY });
  const env = await buildCardProof(opts.request ?? REQUEST, signer, { audience: opts.audience, nonce: opts.nonce, now: clock });
  return env[KYA_OS_CARD_PROOF_META_KEY];
}

/** A call with no params: `tools/list` as its caller makes it. */
const LIST_CALL = { method: 'tools/list' };

/** `call` as it travels with `proof` in its `params._meta` (SPEC-ENTITY-CARD §8.2). */
function carrying(call: { method: string; params?: Record<string, unknown> }, proof: CardProofMeta): unknown {
  return { ...call, params: { ...call.params, _meta: { [KYA_OS_CARD_PROOF_META_KEY]: proof } } };
}

/**
 * A proof for `tools/list` whose `requestHash` is over `{ method, params: {} }`, the form 1.26.0
 * and earlier minted for a call given `params: {}` (SPEC-ENTITY-CARD §8.3, legacy form in 1.x):
 * the claims of a proof minted now for the call, with that `requestHash`, signed again.
 */
async function mintOverEmptyParams(nonce: string): Promise<CardProofMeta> {
  const signer = await ed25519SignerFromJwk({ did: ENTITY_DID, kid: KID, privateJwk: ENTITY_KEY });
  const minted = await mintProof({ did: ENTITY_DID, kid: KID, nonce, audience: AUDIENCE, request: LIST_CALL });
  const legacy = createHash('sha256').update(JSON.stringify({ method: LIST_CALL.method, params: {} })).digest('base64');
  const { httpSig: _httpSig, ...claims } = minted;
  const unsigned: CardProofMeta = { ...claims, requestHash: `sha-256=:${legacy}:`, jws: '' };
  const stated = await statementParameters(undefined, undefined, webCryptoSha256);
  const signed: CardProofMeta = { ...unsigned, jws: await signer.sign(canonicalPayloadBytes(unsigned), stated) };
  if (!signer.signRaw) return signed;
  return { ...signed, httpSig: await signer.signRaw(httpSignatureBaseBytes(signed)) };
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
  const tamperedSig: CardProofMeta = { ...valid, jws: flipSignatureChar(valid.jws) };
  const noParams = await mintProof({ did: ENTITY_DID, kid: KID, nonce: 'n-no-params-000000000000000000000', audience: AUDIENCE, request: LIST_CALL });
  const overEmptyParams = await mintOverEmptyParams('n-empty-params-000000000000000000');
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
    {
      id: 'card-proof/no-params',
      category: 'card-proof',
      description: 'A proof minted for tools/list, a call with no params, held against the call as it travels: params holding only the _meta that carries the proof',
      expected: 'pass',
      reason: 'The covered request is read from the call alone: params left with no member once _meta is removed are left out, so minter and verifier both hash { method } (SPEC-ENTITY-CARD §8.3)',
      input: proofInput(noParams, { request: carrying(LIST_CALL, noParams) }),
    },
    {
      id: 'card-proof/no-params-legacy-form',
      category: 'card-proof',
      description: 'A proof for tools/list whose requestHash is over { method, params: {} }, held against the call as it travels',
      expected: 'pass',
      reason: 'For the 1.x line a verifier also accepts the legacy form { method, params: {} } when the covered request is { method } (SPEC-ENTITY-CARD §8.3)',
      input: proofInput(overEmptyParams, { request: carrying(LIST_CALL, overEmptyParams) }),
    },
    {
      id: 'card-proof/legacy-form-with-params',
      category: 'card-proof',
      description: 'The same legacy-form proof held against a tools/list call whose params hold a cursor',
      expected: 'fail',
      reason: 'The legacy form stands in only for a covered request with no params; a call with a params member is covered with it, and the hash no longer matches',
      input: proofInput(overEmptyParams, { request: carrying({ ...LIST_CALL, params: { cursor: 'c-2' } }, overEmptyParams) }),
    },
  ];

  return { version: SUITE_VERSION, category: 'card-proof', vectors };
}

export async function entityCardVectorFile(): Promise<VectorFile> {
  const accountability = { resourceOwner: OWNER, resource: RESOURCE, chain: DELEGATION_CHAIN, proofDid: ENTITY_DID, now: T0_MS };
  // The accountability vectors hold the JOIN alone, so their card declares no revocation entry (suite >= 1.8.0).
  const { revocation: _revocation, ...accountableAgent } = GOLDEN_CARDS.agent;
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
      input: { card: accountableAgent, accountability },
    },
    {
      id: 'entity-card/revocation-unchecked',
      category: 'entity-card',
      description: 'The accountable agent card declaring a revocation entry, with no status list supplied to check it',
      expected: 'fail',
      reason: 'A verifier with nothing to check the revocation entry cannot show the card is not revoked ⇒ it refuses the card (configuration_error)',
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
      input: { card: accountableAgent, accountability: { ...accountability, proofDid: 'did:web:attacker.example' } },
    },
    ...(await cardChainVectors(accountableAgent, accountability)),
  ];
  return { version: SUITE_VERSION, category: 'entity-card', vectors };
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

export async function generateCardVectors(): Promise<void> {
  writeVectorFile(await cardProofVectorFile(), 'card-proof.json');
  writeVectorFile(await entityCardVectorFile(), 'entity-card.json');
  console.log('Entity Card conformance vectors generated (deterministic).');
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  generateCardVectors().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}
