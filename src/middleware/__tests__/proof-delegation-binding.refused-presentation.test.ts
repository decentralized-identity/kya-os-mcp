/**
 * The audit trail records what a refused call presented (SPEC.md §7.8): the
 * credential as it was presented, or nothing when no credential was. A fault
 * that keeps a chain from being digested refuses the call, and an id that
 * cannot be recorded verbatim is recorded by its digest. The proof of every
 * refusal signs neither delegation claim.
 */
import { afterEach, describe, it, expect, vi } from 'vitest';
import { sha256Of } from '../../__tests__/utils/digests.js';
import { generateRequestProof } from '../../delegation/holder-binding.js';
import { logger } from '../../logging/index.js';
import { crypto, failCredentialDigests, makeServer } from './helpers/delegation-gate-server.js';
import { ARGS, CONSENT, SCOPE, TOOL, released } from './helpers/delegated-call.js';
import { party } from './helpers/delegating-party.js';
import { threeHops } from './helpers/delegation-chains.js';
import { proofOf } from './helpers/received-proof.js';
import { delegationClaims, delegationEvidence, recordedReferences, refusal } from './helpers/server-answers.js';

/** The events of a call refused after its chain verified, none of which records the delegation. */
const UNNAMED_REFUSAL = [
  ['authorization.denied', {}],
  ['tool.call.denied', {}],
  ['proof.generated', {}],
];

describe('a refused call', () => {
  it('records a credential whose signature does not verify, as it was presented', async () => {
    const { kyaos, server, ancestors, recorded } = await makeServer();
    const { root, middle, leaf } = await threeHops(server.did);
    ancestors.push(root, middle);
    const tampered = structuredClone(leaf);
    tampered.credentialSubject.delegation.constraints.scopes = [SCOPE, 'records:delete'];
    const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));

    const result = await handler({ ...ARGS, _kyaos_delegation: tampered });

    expect(result.isError).toBe(true);
    expect(proofOf(result)!.meta.outcome).toBe('denied');
    expect(delegationClaims(result)).toEqual({});
    expect(recordedReferences(recorded, 'delegation.rejected')).toEqual([leaf.id]);
  });

  it('names no delegation when the caller does not hold the leaf key', async () => {
    const { kyaos, server, ancestors, recorded } = await makeServer({ holderBinding: 'enforce' });
    const { subAgent, root, middle, leaf } = await threeHops(server.did);
    ancestors.push(root, middle);
    const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));

    const missing = await handler({ ...ARGS, _kyaos_delegation: leaf });
    expect(refusal(missing).error).toBe('holder_binding_failed');
    expect(proofOf(missing)!.meta.outcome).toBe('denied');
    expect(delegationClaims(missing)).toEqual({});
    // The refusal is recorded as in 1.22.0, by its outcome alone.
    expect(recorded.map((event) => [event.eventType, delegationEvidence(event)])).toEqual(UNNAMED_REFUSAL);

    // A proof of possession by someone who is not the leaf subject.
    const thief = await party();
    const stolen = await handler({
      ...ARGS,
      _kyaos_delegation: leaf,
      _kyaos_proof: await generateRequestProof({
        identity: thief,
        crypto,
        toolName: TOOL,
        args: ARGS,
        audience: server.did,
      }),
    });
    expect(refusal(stolen).error).toBe('holder_binding_failed');
    expect(delegationClaims(stolen)).toEqual({});

    // The leaf subject itself is let through, under the same chain.
    const held = await handler({
      ...ARGS,
      _kyaos_delegation: leaf,
      _kyaos_proof: await generateRequestProof({
        identity: subAgent,
        crypto,
        toolName: TOOL,
        args: ARGS,
        audience: server.did,
      }),
    });
    expect(held.isError).toBeUndefined();
    expect(delegationClaims(held)).toEqual({});
    expect(recordedReferences(recorded, 'delegation.verified')).toEqual([leaf.id]);
  });

  it('names no delegation when the verified chain does not grant the tool scope', async () => {
    const { kyaos, server, ancestors, recorded } = await makeServer();
    const { root, middle, leaf } = await threeHops(server.did);
    ancestors.push(root, middle);
    const handler = kyaos.wrapWithDelegation(
      'records.delete',
      { ...CONSENT, scopeId: 'records:delete' },
      kyaos.wrapWithProof('records.delete', released),
    );

    const result = await handler({ ...ARGS, _kyaos_delegation: leaf });

    expect(refusal(result).error).toBe('insufficient_scope');
    expect(proofOf(result)!.meta.outcome).toBe('denied');
    expect(delegationClaims(result)).toEqual({});
    expect(recorded.map((event) => [event.eventType, delegationEvidence(event)])).toEqual(UNNAMED_REFUSAL);
  });

  it.each([
    ['a number', 42],
    ['an array', [{ id: 'urn:uuid:x' }]],
    ['a boolean', true],
  ])('names nothing for %s: no credential was presented', async (_name, presented) => {
    const { kyaos } = await makeServer();
    const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));

    const result = await handler({ ...ARGS, _kyaos_delegation: presented });

    expect(result.isError).toBe(true);
    expect(proofOf(result)!.meta.outcome).toBe('denied');
    expect(delegationClaims(result)).toEqual({});
  });

  it.each([
    ['an object that is no credential', { bogus: true }],
    ['a credential with no signature', { id: 'urn:uuid:unsigned', credentialSubject: {} }],
    ['a string that is no compact JWS', 'not-a-jwt'],
  ])('binds nothing for %s: it has no signed form', async (_name, presented) => {
    const { kyaos } = await makeServer();
    const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));

    const result = await handler({ ...ARGS, _kyaos_delegation: presented });

    expect(result.isError).toBe(true);
    expect(proofOf(result)!.meta.outcome).toBe('denied');
    expect(delegationClaims(result)).toEqual({});
  });

  describe('when a fault keeps the chain from being digested', () => {
    /** A three-hop chain presented to a gate whose hash provider fails on credential digests. */
    async function presentUnderFault(fault: unknown, leafScopes: string[] = [SCOPE]) {
      const error = vi.spyOn(logger, 'error').mockImplementation(() => {});
      const { kyaos, server, ancestors, recorded } = await makeServer();
      const { root, middle, leaf } = await threeHops(server.did, leafScopes);
      ancestors.push(root, middle);
      let ran = false;
      const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, async (...call) => {
        ran = true;
        return released(...call);
      }));
      failCredentialDigests(fault);
      const result = await handler({ ...ARGS, _kyaos_delegation: leaf });
      return { result, leaf, recorded, error, ran: () => ran };
    }

    it('refuses a call whose chain verified, records the credential, and signs that refusal', async () => {
      // A fault need not throw an Error at all. It is reported all the same,
      // by what it threw.
      const { result, leaf, recorded, error, ran } = await presentUnderFault('hash service unavailable');

      // The chain verified. What failed is the server's own, and says nothing
      // against the credential, so the reason given is the generic one.
      expect(ran()).toBe(false);
      expect(refusal(result).reason).toBe('Delegation credential could not be verified');
      expect(proofOf(result)!.meta.outcome).toBe('denied');
      expect(delegationClaims(result)).toEqual({});
      expect(recorded.map((event) => [event.eventType, delegationEvidence(event)])).toEqual([
        ['delegation.rejected', { delegationRef: leaf.id }],
        ...UNNAMED_REFUSAL,
      ]);
      expect(error).toHaveBeenCalledWith(
        '[kya-os] A verified delegation could not be described; the call is refused',
        { error: 'hash service unavailable' },
      );
    });

    it('reports it for a chain it refused, and still signs that refusal', async () => {
      // A fault throws what it likes, a TypeError here, as a value with no
      // signed form does. It is reported all the same: nothing was wrong with
      // what was presented.
      const { result, leaf, recorded, error } = await presentUnderFault(new TypeError('hash service unavailable'), [
        SCOPE,
        'records:delete',
      ]);

      expect(refusal(result).reason).toContain('widens scopes beyond parent');
      expect(proofOf(result)!.meta.outcome).toBe('denied');
      expect(delegationClaims(result)).toEqual({});
      expect(recordedReferences(recorded, 'delegation.rejected')).toEqual([leaf.id]);
      expect(error).toHaveBeenCalledWith(
        '[kya-os] A refused delegation could not be described in full',
        { error: 'hash service unavailable' },
      );
    });
  });

  it('refuses, and still signs, a presentation that cannot be digested', async () => {
    const error = vi.spyOn(logger, 'error');
    const { kyaos, recorded } = await makeServer();
    const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));
    const cyclic: Record<string, unknown> = { id: 'urn:uuid:loop' };
    cyclic.self = cyclic;

    const result = await handler({ ...ARGS, _kyaos_delegation: cyclic });

    expect(result.isError).toBe(true);
    expect(proofOf(result)!.meta.outcome).toBe('denied');
    expect(delegationClaims(result)).toEqual({});
    expect(recordedReferences(recorded, 'delegation.rejected')).toEqual(['urn:uuid:loop']);
    // It has no signed form, which is no fault of the server's: nothing is logged as one.
    expect(error).not.toHaveBeenCalled();
  });

  it('records an id that is too long, ill-formed, has control characters or is written as a digest by its digest', async () => {
    const { kyaos, recorded } = await makeServer();
    const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));
    const shared = 'a'.repeat(300);
    const ids = [
      `${shared}-one`,
      // The same first 300 units: cutting to a bound would name both alike.
      `${shared}-two`,
      // A surrogate pair straddling unit 256, so cutting there leaves half of it.
      `${'b'.repeat(255)}\u{1F512}tail`,
      'urn:uuid:line\nbreak',
      // An id a caller wrote to read as the reference of the first one. Kept
      // as it is, the two refusals would be recorded alike.
      sha256Of(`${shared}-one`),
      'urn:uuid:plain',
    ];

    for (const id of ids) {
      const result = await handler({ ...ARGS, _kyaos_delegation: { id } });
      expect(result.isError).toBe(true);
      expect(delegationClaims(result)).toEqual({});
    }

    const rejected = recorded.filter((event) => event.eventType === 'delegation.rejected');
    const references = rejected.map((event) => event.details.delegationRef);
    expect(references).toEqual([
      sha256Of(ids[0]!),
      sha256Of(ids[1]!),
      sha256Of(ids[2]!),
      sha256Of(ids[3]!),
      sha256Of(sha256Of(ids[0]!)),
      'urn:uuid:plain',
    ]);
    expect(new Set(references).size).toBe(ids.length);
    // The event's details and its authorization evidence carry one reference.
    expect(rejected.map((event) => event.authorization?.delegationRef)).toEqual(references);
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});
