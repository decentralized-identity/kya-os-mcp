/**
 * Regression coverage for the DevX / docs gap (red-team findings 11 & 13):
 *
 *   #11 — the README must actually DOCUMENT the Entity Card surface (the headline feature was
 *         undiscoverable from the front door). Asserts the front-door quickstart names every
 *         surface and the published import path.
 *
 *   #13 — a runnable example must exercise the advertised 10-minute path end-to-end
 *         (`card()` builder + `withKyaOsCard` + `requireProof`). Imports the example's own
 *         orchestration and asserts a valid proof is ACCEPTED while a replayed nonce and a
 *         tampered body FAIL CLOSED — the nonce-replay footgun the example exists to defuse.
 *
 * Both fail before their fix: the README grep is empty, and `examples/entity-card/server.ts`
 * does not exist (the import throws at collection).
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import {
  AGENT_DID,
  buildAcmeCard,
  demoScenario,
  emitArtifacts,
} from '../../../examples/entity-card/server.js';

// ── Finding #11: the README documents the Entity Card surface ────────────────

describe('README — Entity Card is discoverable from the front door (finding 11)', () => {
  const readme = readFileSync(fileURLToPath(new URL('../../../README.md', import.meta.url)), 'utf-8');

  it('names each headline surface of the card in the quickstart', () => {
    for (const surface of ['card(', 'withKyaOsCard', 'requireProof', 'verifyCard']) {
      expect(readme).toContain(surface);
    }
  });

  it('shows the published import path and links the runnable example', () => {
    expect(readme).toContain('@kya-os/mcp/card');
    expect(readme).toContain('examples/entity-card');
    expect(readme).toMatch(/Entity Card/);
  });
});

// ── Finding #13: the runnable example exercises card() + withKyaOsCard + requireProof ─────

describe('examples/entity-card/server.ts — the 10-minute path runs end-to-end (finding 13)', () => {
  it('build: card() emits a typed card with no self-claimed conformance level', () => {
    const entityCard = buildAcmeCard();
    expect(entityCard.entityType).toBe('agent');
    expect(entityCard.id).toBe(AGENT_DID);
    expect(entityCard.proofProfile).toBe('org.kya-os/proof.v1');
    expect(entityCard).not.toHaveProperty('conformanceLevel');
  });

  it('emit: withKyaOsCard mounts the three discovery artifacts', () => {
    const mount = emitArtifacts(buildAcmeCard());
    expect(mount.cardJson.id).toBe(AGENT_DID);
    expect(mount.didServiceEntry.type).toBe('KyaOsEntityCard');
    expect(mount.serverMeta).toHaveProperty('org.kya-os/card');
  });

  it('guard: a valid holder-of-key proof is accepted with the principal + assurance', async () => {
    const { accepted } = await demoScenario();
    expect(accepted.ok).toBe(true);
    if (!accepted.ok) throw new Error('expected the valid proof to be accepted');
    expect(accepted.did).toBe(AGENT_DID);
    expect(accepted.level).toBe('L3-minus');
  });

  it('guard: a replayed nonce fails closed (the nonce cache rejects it)', async () => {
    const { replayed } = await demoScenario();
    expect(replayed.ok).toBe(false);
    if (replayed.ok) throw new Error('expected the replayed nonce to be rejected');
    expect(replayed.status).toBe(401);
    expect(replayed.error.reasons).toContain('nonce_replayed');
  });

  it('guard: a tampered request body fails closed (request hash no longer matches)', async () => {
    const { tampered } = await demoScenario();
    expect(tampered.ok).toBe(false);
    if (tampered.ok) throw new Error('expected the tampered body to be rejected');
    expect(tampered.error.reasons).toContain('request_hash_mismatch');
  });
});
