#!/usr/bin/env npx tsx
/**
 * KYA-OS Entity Card — the 10-minute server path (build → emit → guard).
 *
 * Exercises the three headline ergonomics end-to-end, in one runnable file:
 *   1. `card({ did, entityType, name })…build()`  — describe the entity, fluently.
 *   2. `withKyaOsCard(card)`                       — mount the three discovery artifacts
 *                                                    (card.json, the DID `KyaOsEntityCard`
 *                                                    service entry, the server.json `_meta`).
 *   3. `requireProof(deps, { minLevel })`          — the per-request holder-of-key guard.
 *
 * The guard's `VerifyProofDeps` is wired in FULL — `resolveKey`, `expectedAudience`, and a real
 * `InMemoryNonceCache.consume` (the ATOMIC test-AND-set) — so the nonce-replay footgun is defused
 * by construction: this example both ACCEPTS a valid proof and REJECTS a replayed nonce and a
 * tampered body.
 *
 * The card module is published as the `@kya-os/mcp/card` subpath (see package.json `exports`), which
 * is what an external adopter imports. This example imports from the local source (`../../src/card`)
 * so it runs against the working tree with no build step — mirroring `walkthrough.ts`.
 *
 * Run: npm run example:entity-card:server   (or: npx tsx examples/entity-card/server.ts)
 */

import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { exportJWK, generateKeyPair } from 'jose';
import {
  buildCardProof,
  card,
  ed25519SignerFromJwk,
  InMemoryNonceCache,
  requireProof,
  withKyaOsCard,
  type Ed25519PrivateJwk,
  type Ed25519PublicJwk,
  type EntityCard,
  type KyaOsCardMount,
  type ProofGateResult,
  type ProofSigner,
  type VerifyProofDeps,
} from '../../src/card/index.js';

/** The agent that holds the card (a path-form `did:web`, so it has an HTTPS card endpoint). */
export const AGENT_DID = 'did:web:example.com:agents:acme-pay';
/** The agent's signing-key id (the `kid` a verifier resolves to the Ed25519 public key). */
export const AGENT_KID = `${AGENT_DID}#key-1`;
/** The MCP server that verifies proofs — the `audience` every proof must be bound to (anti-relay). */
export const SERVER_DID = 'did:web:example.com:mcp:acme-server';

/** The tool call the agent makes — the exact `{ method, params }` body it SIGNS (no `_meta`). */
const REQUEST = { method: 'tools/call', params: { name: 'search', arguments: { q: 'invoices' } } };

/** 1. BUILD — the agent describes itself with the fluent `card()` chain. */
export function buildAcmeCard(): EntityCard {
  return card({ did: AGENT_DID, entityType: 'agent', name: 'Acme Pay Agent' })
    .capability('search') // L1: bare-string, self-declared
    .attestedCapability('payments.transfer', '<capability-vc-jwt>') // L2: VC-backed
    .accountableTo('did:web:example.com:org:acme', {
      via: 'vc_root>del_123',
      principal: 'did:web:example.com:users:jane',
    })
    .usesProof() // advertise the per-request holder-of-key proof profile
    .didDocument('https://example.com/agents/acme-pay/did.json')
    .build();
}

/** 2. EMIT — bundle the card's three discovery artifacts and the immutable mounters. */
export function emitArtifacts(entityCard: EntityCard): KyaOsCardMount {
  return withKyaOsCard(entityCard);
}

/** The server-side verify seams, wired in full — the resolver, the audience, and the replay cache. */
export function makeServerDeps(
  publicJwk: Ed25519PublicJwk,
  nonceCache: InMemoryNonceCache,
): VerifyProofDeps {
  return {
    resolveKey: (kid) => {
      if (kid !== AGENT_KID) throw new Error(`unknown kid: ${kid}`);
      return publicJwk; // a real resolver dereferences the DID document's verificationMethod
    },
    // The RFC 7638 DID-membership proof: the signing key MUST be a verificationMethod published by
    // the agent's DID. This is the SECURE binding a production verifier supplies (without it the
    // guard fails closed with `did_membership_unverifiable`). A real resolver reads the DID document.
    resolveDidKeys: (did) => (did === AGENT_DID ? [publicJwk] : []),
    expectedAudience: SERVER_DID,
    consumeNonceIfFresh: nonceCache.consume, // ATOMIC test-AND-set — the replay-safe default
  };
}

/** The agent's client key: a freshly generated Ed25519 signer + the public JWK a verifier resolves. */
async function makeClient(): Promise<{ signer: ProofSigner; publicJwk: Ed25519PublicJwk }> {
  const { publicKey, privateKey } = await generateKeyPair('EdDSA', { extractable: true });
  const priv = await exportJWK(privateKey);
  const pub = await exportJWK(publicKey);
  const privateJwk: Ed25519PrivateJwk = { kty: 'OKP', crv: 'Ed25519', x: priv.x ?? '', d: priv.d ?? '' };
  const signer = await ed25519SignerFromJwk({ did: AGENT_DID, kid: AGENT_KID, privateJwk });
  return { signer, publicJwk: { kty: 'OKP', crv: 'Ed25519', x: pub.x ?? '', kid: AGENT_KID } };
}

/** A fresh 128-bit nonce (the client-random single-use token the proof binds). */
function nonce(): string {
  return randomBytes(16).toString('hex');
}

/** The structured outcome of one end-to-end run — assertable by tests, printable by `main`. */
export interface DemoResult {
  card: EntityCard;
  mount: KyaOsCardMount;
  accepted: ProofGateResult; // a valid proof → { ok: true, did, level }
  replayed: ProofGateResult; // the SAME proof again → rejected (nonce_replayed)
  tampered: ProofGateResult; // a valid proof over a DIFFERENT body → rejected (request_hash_mismatch)
}

/** Drive the full build → emit → guard path and return every verdict (no I/O, no logging). */
export async function demoScenario(): Promise<DemoResult> {
  const entityCard = buildAcmeCard();
  const mount = emitArtifacts(entityCard);

  const { signer, publicJwk } = await makeClient();
  const nonceCache = new InMemoryNonceCache();
  const guard = requireProof(makeServerDeps(publicJwk, nonceCache), { minLevel: 'L3-minus' });

  // The agent mints a holder-of-key proof for THIS request, bound to the server audience + a nonce.
  const proofMeta = await buildCardProof(REQUEST, signer, { audience: SERVER_DID, nonce: nonce() });
  const accepted = await guard(REQUEST, proofMeta);
  const replayed = await guard(REQUEST, proofMeta); // same nonce → the cache rejects the replay

  // A fresh proof presented against a tampered body — the request hash no longer matches.
  const freshMeta = await buildCardProof(REQUEST, signer, { audience: SERVER_DID, nonce: nonce() });
  const tamperedReq = { method: REQUEST.method, params: { name: 'search', arguments: { q: 'HIJACKED' } } };
  const tampered = await guard(tamperedReq, freshMeta);

  return { card: entityCard, mount, accepted, replayed, tampered };
}

function section(title: string): void {
  console.log(`\n${'─'.repeat(66)}\n${title}\n${'─'.repeat(66)}`);
}

async function main(): Promise<void> {
  const { card: entityCard, mount, accepted, replayed, tampered } = await demoScenario();

  section('1. card() — build a typed, DID-anchored card (conformance is never self-claimed)');
  console.log(JSON.stringify(entityCard, null, 2));

  section('2. withKyaOsCard(card) — mount the three discovery artifacts');
  console.log('DID service entry :', JSON.stringify(mount.didServiceEntry));
  const serverJson = mount.mountServerJson({ name: 'acme-mcp', version: '1.0.0' });
  console.log("server.json _meta :", JSON.stringify(serverJson._meta['org.kya-os/card']));

  section('3. requireProof(deps) — per-request holder-of-key guard (fail-closed)');
  console.log('valid proof     →', JSON.stringify(accepted));
  console.log('replayed nonce  →', JSON.stringify(replayed));
  console.log('tampered body   →', JSON.stringify(tampered));

  section('done — discover like everyone, prove like no one');
}

const invokedDirectly =
  process.argv[1] !== undefined && process.argv[1] === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
