/**
 * The delegation gate names the Responsible Party of an allowed call from the root of the chain
 * the walk validated: the issuer that root names (SPEC.md §2). The walk refuses a root that names
 * no issuer, so a valid chain always has one. Were a walk ever to answer otherwise, the gate
 * refuses the credential rather than run the tool with no Responsible Party. The walk is replaced
 * here, in this file alone, to give that answer.
 */

import { describe, expect, it, vi } from 'vitest';
import { makeServer } from './helpers/delegation-gate-server.js';
import { ARGS, CONSENT, TOOL, released } from './helpers/delegated-call.js';
import { delegate, party } from './helpers/delegating-party.js';

vi.mock('../../delegation/chain-enforcement.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../delegation/chain-enforcement.js')>();
  // A walk that validates a chain whose root names no issuer, which the real walk never does: the
  // root is the presented credential as it was signed, but for its issuer.
  return {
    ...actual,
    validateDelegationChain: async (leaf: { issuer?: unknown }) => {
      const { issuer: _named, ...root } = leaf;
      return { valid: true, evaluated: [root, leaf] };
    },
  };
});

describe('a chain the walk calls valid, whose root names no issuer', () => {
  it('is refused, and the tool does not run', async () => {
    const { kyaos, recorded } = await makeServer();
    const [user, agent] = await Promise.all([party(), party()]);
    const credential = await delegate(user, agent.did);
    const tool = vi.fn(released);
    const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, tool);

    const result = await handler({ ...ARGS, _kyaos_delegation: credential });

    expect(tool).not.toHaveBeenCalled();
    expect(result.isError).toBe(true);
    expect(JSON.parse((result.content[0] as { text: string }).text)).toEqual({
      error: 'delegation_invalid',
      reason: 'Delegation credential could not be verified',
    });
    expect(recorded.slice(0, 3).map(({ eventType, reason }) => [eventType, reason])).toEqual([
      ['delegation.rejected', 'DELEGATION_VERIFICATION_FAILED'],
      ['authorization.denied', 'AUTHORIZATION_DENIED'],
      ['tool.call.denied', 'AUTHORIZATION_DENIED'],
    ]);
  });
});
