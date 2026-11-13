/**
 * What the audit trail says of a delegation, on the events a proof wrapper
 * records, is what the context it is handed says (SPEC.md §7.8), and the
 * proof it makes names no delegation whatever the context says.
 */
import { afterEach, describe, it, expect, vi } from 'vitest';
import type { AuthorizationEvidence } from '../../audit/types.js';
import { makeServer } from './helpers/delegation-gate-server.js';
import { ARGS, SCOPE, TOOL, released } from './helpers/delegated-call.js';
import { proofOf } from './helpers/received-proof.js';
import { delegationClaims } from './helpers/server-answers.js';

describe('what the audit trail says of the delegation', () => {
  it('is left as the server gave it, and the proof names none of it', async () => {
    const { kyaos, recorded } = await makeServer();
    // A server that verifies delegations itself, and says so in the context
    // it passes. The middleware has nothing of its own to put in its place.
    const own = {
      source: 'delegation',
      decision: 'allowed',
      delegationRef: 'urn:uuid:verified-elsewhere',
      delegationCredentialDigest: `sha256:${'2'.repeat(64)}`,
    } as AuthorizationEvidence;
    const handler = kyaos.wrapWithProof(TOOL, released);

    const result = await handler({ ...ARGS }, undefined, { scopeId: SCOPE, authorization: own });

    expect(recorded.map((event) => [event.eventType, event.authorization])).toEqual([
      ['tool.call.started', own],
      ['proof.generated', own],
      ['tool.call.completed', own],
    ]);
    // The proof states the scope it was told, and names no delegation.
    expect(proofOf(result)!.meta.scopeId).toBe(SCOPE);
    expect(delegationClaims(result)).toEqual({});
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});
