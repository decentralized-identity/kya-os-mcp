/**
 * `examples/chain-by-value/walkthrough.ts` runs end to end: the merchant cannot resolve the chain
 * by reference, accepts it carried by value, and rejects a hop edited after signing, the chain
 * presented by another key, and the chain once its Responsible Party revokes the root. What the
 * registry answered goes to the merchant's log, not to the caller.
 */

import { afterAll, beforeAll, describe, it, expect, vi, type MockInstance } from 'vitest';
import { demoScenario, type DemoResult } from '../../../examples/chain-by-value/walkthrough.js';

describe('examples/chain-by-value: carrying the delegation chain with the request', () => {
  let run: Promise<DemoResult> | undefined;
  const result = () => (run ??= demoScenario());
  let warn: MockInstance<typeof console.warn>;
  beforeAll(() => {
    warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
  });
  afterAll(() => {
    warn.mockRestore();
  });

  it('fails by reference when the Responsible Party registry will not answer the merchant', async () => {
    expect((await result()).byReference).toEqual({
      status: 403,
      code: 'delegation_unresolvable',
      reason: 'delegation chain could not be resolved: the delegation registry is unavailable',
    });
    expect(warn).toHaveBeenCalledWith('[merchant] registry.acme.example answered 403');
  });

  it('accepts the same call with the chain carried, and recomputes Acme as the Responsible Party', async () => {
    const { carried, parties } = await result();
    expect(carried).toEqual({
      status: 200,
      responsibleParty: parties.acme.did,
      caller: parties.worker.did,
      source: 'carried',
      depth: 2,
      fresh: true,
    });
  });

  it('rejects a hop edited after signing, though the edit still attenuates', async () => {
    expect((await result()).tampered).toEqual({
      status: 403,
      code: 'delegation_invalid',
      reason: 'hop 1: proof did not verify',
    });
  });

  it('rejects the chain presented by a key the leaf does not name', async () => {
    const { replayedByAnother, parties } = await result();
    expect(replayedByAnother).toMatchObject({ status: 403, code: 'delegation_invalid' });
    if (replayedByAnother.status === 200) throw new Error('unreachable');
    expect(replayedByAnother.reason).toContain(parties.worker.did);
    expect(replayedByAnother.reason).toContain(parties.other.did);
  });

  it('rejects the accepted chain once Acme revokes its root', async () => {
    expect((await result()).revoked).toMatchObject({ status: 403, code: 'delegation_revoked' });
  });
});
