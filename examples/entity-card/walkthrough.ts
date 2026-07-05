#!/usr/bin/env npx tsx
/**
 * KYA-OS Entity Card — Walkthrough
 *
 * Builds a card, "resolves" it (a simulated did:web fetch), and verifies it —
 * demonstrating that `verifyCard` RECOMPUTES the conformance level from evidence
 * and ignores whatever the card claims about itself ("discover like everyone,
 * prove like no one").
 *
 * The card module is published as the `@kya-os/mcp/card` subpath (see package.json `exports`) —
 * that is the production import a consumer uses. This in-repo example imports from `../../src/card`
 * only so it runs against the local source without a build step.
 *
 * Run: npx tsx examples/entity-card/walkthrough.ts
 */

import {
  buildCard,
  resolveCard,
  verifyCard,
  type EntityCard,
  type CapabilityVerifier,
} from '../../src/card/index.js';

function section(title: string): void {
  console.log(`\n${'─'.repeat(66)}\n${title}\n${'─'.repeat(66)}`);
}

/**
 * A stub capability verifier. A real one resolves each attestation VC and checks
 * its signature + trusted issuer + expiry (e.g. an adapter over `validateLevel2`).
 * Here we simply treat any capability carrying an attestation as "attested" and
 * any bare-string capability as self-declared (L1).
 */
const checkAttestations: CapabilityVerifier = async (capabilities) => {
  const verified: string[] = [];
  const unverified: string[] = [];
  for (const cap of capabilities) {
    if (typeof cap === 'string') unverified.push(cap);
    else if (cap.attestations.length > 0) verified.push(cap.name);
    else unverified.push(cap.name);
  }
  return { verified, unverified };
};

/** A stub accountability verifier. A real one walks the signed delegation chain. */
const alwaysAccountable = async (): Promise<boolean> => true;

async function main(): Promise<void> {
  // 1. BUILD — an agent describes itself.
  section('1. buildCard — the agent describes itself');
  const card = buildCard(
    { did: 'did:web:example.com:agents:acme-pay', kid: 'did:web:example.com:agents:acme-pay#key-1' },
    {
      entityType: 'agent',
      name: 'Acme Pay Agent',
      capabilities: ['handshake', { name: 'payments.transfer', attestations: [{ vc: '<capability-vc-jwt>' }] }],
      responsibleParty: 'did:web:example.com:org:acme',
      principal: 'did:web:example.com:users:jane',
      delegationRef: 'vc_root>del_123',
      didDocument: 'https://example.com/agents/acme-pay/did.json',
    },
  );
  console.log(JSON.stringify(card, null, 2));
  console.log('\n→ Note: no conformanceLevel — it is derived by a verifier, never self-asserted.');

  // 2. RESOLVE — discovery: fetch a card by DID (unauthenticated, like a business card).
  //    Multi-surface, two-step: did.json → the KyaOsEntityCard service entry → card.json.
  section('2. resolveCard — discover a card by DID');
  const didDoc = {
    id: 'did:web:example.com:agents:acme-pay',
    service: [
      {
        id: '#kya-os-card',
        type: 'KyaOsEntityCard',
        serviceEndpoint: 'https://example.com/agents/acme-pay/card.json',
      },
    ],
  };
  const resolved = await resolveCard('did:web:example.com:agents:acme-pay', {
    fetch: async (url) => {
      console.log(`  fetching ${url}`);
      const body = url.endsWith('/did.json') ? didDoc : card;
      return { ok: true, status: 200, json: async () => body };
    },
  });
  console.log(`  → got a "${resolved.entityType}" named "${resolved.name}"`);

  // 3. VERIFY — recompute the trust level from evidence.
  section('3. verifyCard — recompute the truth (conformance is a FLOOR)');
  const honest = await verifyCard(resolved, {
    capabilityVerifier: checkAttestations,
    accountabilityVerifier: alwaysAccountable,
  });
  console.log(`  verifiedCapabilities : [${honest.verifiedCapabilities.join(', ')}]   (payments.transfer is attested)`);
  console.log(`  conformanceLevel     : ${honest.conformanceLevel}   (← L1: "handshake" is self-declared, so the floor is L1)`);
  console.log(`  accountability       : ${honest.accountability?.verified ? 'verified ✓' : 'UNVERIFIED'}`);
  console.log(`  ok                   : ${honest.ok}`);

  // 4. The card can't lie.
  section("4. The card can't talk itself up — a self-declared L3 verifies as L1");
  const boastful: EntityCard = { ...resolved, conformanceLevel: 'L3' };
  const judged = await verifyCard(boastful, {
    capabilityVerifier: checkAttestations,
    accountabilityVerifier: alwaysAccountable,
  });
  console.log(`  the card claims      : ${boastful.conformanceLevel}`);
  console.log(`  the verifier computes: ${judged.conformanceLevel}   (← the self-claim is ignored)`);

  // 5. The ladder: all capabilities attested → L2; plus a live holder-of-key proof → L3.
  section('5. The ladder — all attested → L2; + live holder-of-key proof → L3');
  const allAttested: EntityCard = {
    ...resolved,
    capabilities: [{ name: 'payments.transfer', attestations: [{ vc: '<vc>' }] }],
  };
  const l2 = await verifyCard(allAttested, {
    capabilityVerifier: checkAttestations,
    accountabilityVerifier: alwaysAccountable,
  });
  const l3 = await verifyCard(allAttested, {
    capabilityVerifier: checkAttestations,
    accountabilityVerifier: alwaysAccountable,
    // A live per-request holder-of-key proof lifts L2 → L3. The runtime pre-binds a real
    // `verifyCardProof` here; the walkthrough stubs a valid recompute for the DID it resolved.
    proof: {},
    request: { method: 'tools/call' },
    proofVerifier: async () => ({ ok: true, reasons: [], level: 'L3-minus', did: allAttested.id }),
  });
  console.log(`  all capabilities attested        → ${l2.conformanceLevel}`);
  console.log(`  all attested + valid live proof  → ${l3.conformanceLevel}`);

  section('done — discover like everyone, prove like no one');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
