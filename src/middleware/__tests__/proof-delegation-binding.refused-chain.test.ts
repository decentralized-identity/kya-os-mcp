/**
 * The audit trail records the delegation a refused call presented (SPEC.md
 * §7.8): the chain the gate examined by the digest of each credential, and
 * only the presented credential's own digest when an ancestor has no signed
 * form, nests too deep, or could not be resolved. The proof of the refusal
 * signs neither delegation claim.
 */
import { afterEach, describe, it, expect, vi } from 'vitest';
import { arrays } from '../../__tests__/utils/nesting.js';
import { digestDelegationChain } from '../../delegation/chain-digest.js';
import { logger } from '../../logging/index.js';
import type { DelegationCredential } from '../../types/protocol.js';
import { hash, makeServer } from './helpers/delegation-gate-server.js';
import { ARGS, CONSENT, SCOPE, TOOL, released } from './helpers/delegated-call.js';
import { jwtParty, threeHops } from './helpers/delegation-chains.js';
import { proofOf, verifyReceived } from './helpers/received-proof.js';
import { delegationClaims, delegationEvidence, recordedReferences, refusal } from './helpers/server-answers.js';

/** The events of a call the gate refused, after its own: none carries what was presented. */
const OUTCOME_EVENTS = [
  ['authorization.denied', {}],
  ['tool.call.denied', {}],
  ['proof.generated', {}],
];

describe('a refused call', () => {
  it('signs a refusal that names no delegation, and records the refused chain by digest', async () => {
    const { kyaos, server, ancestors, recorded } = await makeServer();
    const widened = await threeHops(server.did, [SCOPE, 'records:delete']);
    ancestors.push(widened.root, widened.middle);
    const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));

    const result = await handler({ ...ARGS, _kyaos_delegation: widened.leaf });

    expect(proofOf(result)!.meta.outcome).toBe('denied');
    expect(delegationClaims(result)).toEqual({});
    const verified = await verifyReceived(result, {
      signer: server.did,
      toolName: TOOL,
      params: ARGS,
      binds: 'nothing',
    });
    expect(verified).toEqual({ valid: true });
    // The audit trail says which chain was refused, by digest.
    const rejected = recorded.find((event) => event.eventType === 'delegation.rejected')!;
    expect(rejected.authorization!.delegationChainDigests)
      .toEqual((await digestDelegationChain(widened.chain, hash)).credentials);
  });

  it('records the refused chain\u2019s per-hop digests on the event that records the refusal', async () => {
    const { kyaos, server, ancestors, recorded } = await makeServer();
    const widened = await threeHops(server.did, [SCOPE, 'records:delete']);
    ancestors.push(widened.root, widened.middle);
    const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));

    await handler({ ...ARGS, _kyaos_delegation: widened.leaf });

    const rejected = recorded.find((event) => event.eventType === 'delegation.rejected')!;
    const perHop = (await digestDelegationChain(widened.chain, hash)).credentials;
    expect(rejected.authorization).toEqual({
      source: 'delegation',
      decision: 'denied',
      delegationRef: widened.leaf.id,
      delegationCredentialDigest: perHop.at(-1),
      delegationChainDigests: perHop,
      // What the verification came to: a re-delegation wider than its parent.
      verificationCode: 'chain_invalid',
    });
    // The gate's event is the one that says what was presented: the
    // refusal's other events are recorded as in 1.22.0, with none.
    expect(recorded.map((event) => [event.eventType, delegationEvidence(event)])).toEqual([
      ['delegation.rejected', delegationEvidence(rejected)],
      ...OUTCOME_EVENTS,
    ]);
  });

  it("lists no chain when an ancestor it read has no signed form, and still records the presented credential's own digest", async () => {
    const error = vi.spyOn(logger, 'error');
    const { kyaos, server, ancestors, recorded } = await makeServer();
    const { root, middle, leaf } = await threeHops(server.did);
    // The root as a store that lost its signature hands it back.
    const { proofValue: _lost, ...unsigned } = root.proof!;
    ancestors.push({ ...root, proof: unsigned } as DelegationCredential, middle);
    const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));

    const result = await handler({ ...ARGS, _kyaos_delegation: leaf });

    expect(refusal(result)).toEqual({
      error: 'delegation_invalid',
      reason: `Delegation ${root.credentialSubject.delegation.id} invalid: Missing proofValue in proof`,
    });
    // SPEC §7.8: a refusal in which a credential the server read has no
    // signed form has no digest of its chain.
    expect(proofOf(result)!.meta.outcome).toBe('denied');
    expect(delegationClaims(result)).toEqual({});
    // The presented credential has a signed form of its own. The gate's
    // event carries its digest beside its reference, and lists no chain:
    // there is none to list.
    const own = await digestDelegationChain([leaf], hash);
    const presented = { delegationRef: leaf.id, delegationCredentialDigest: own.credentials[0] };
    expect(recorded.map((event) => [event.eventType, delegationEvidence(event)])).toEqual([
      ['delegation.rejected', presented],
      ...OUTCOME_EVENTS,
    ]);
    // A value with no signed form is no fault of the server's.
    expect(error).not.toHaveBeenCalled();
    const verified = await verifyReceived(result, {
      signer: server.did,
      toolName: TOOL,
      params: ARGS,
      binds: 'nothing',
      outcome: 'denied',
    });
    expect(verified).toEqual({ valid: true });
  });

  // SPEC §7.8: the arrays and objects of a credential nest at most 64 levels
  // deep. The credential is level 1 and its `proof` level 2, so 63 arrays in
  // a member of `proof`, which no signature covers, make it 65 deep.
  it('records a presented credential nested deeper than one may be by its reference, and takes no digest of it', async () => {
    const error = vi.spyOn(logger, 'error');
    const { kyaos, server, ancestors, recorded } = await makeServer();
    const { root, middle, leaf } = await threeHops(server.did);
    ancestors.push(root, middle);
    const nestedTo = (levels: number) => ({ ...leaf, proof: { ...leaf.proof!, note: arrays(levels - 2) } });
    const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));

    const result = await handler({ ...ARGS, _kyaos_delegation: nestedTo(65) });

    expect(refusal(result)).toEqual({
      error: 'delegation_invalid',
      reason: 'Malformed delegation credential: it nests more than 64 levels deep',
    });
    // An id is read however deep the rest nests, so the trail names what
    // was presented. It has no signed form, so nothing is digested: no event
    // carries a digest.
    expect(proofOf(result)!.meta.outcome).toBe('denied');
    expect(delegationClaims(result)).toEqual({});
    expect(recorded.map((event) => [event.eventType, delegationEvidence(event)])).toEqual([
      ['delegation.rejected', { delegationRef: leaf.id }],
      ...OUTCOME_EVENTS,
    ]);
    // That is the protocol's answer and no fault of the server's: nothing
    // is logged as one, and the refusal is signed.
    expect(error).not.toHaveBeenCalled();
    expect(await verifyReceived(result, {
      signer: server.did,
      toolName: TOOL,
      params: ARGS,
      binds: 'nothing',
      outcome: 'denied',
    })).toEqual({ valid: true });

    // One level less, and the same credential is allowed under its chain.
    const allowed = await handler({ ...ARGS, _kyaos_delegation: nestedTo(64) });
    expect(allowed.isError).toBeUndefined();
  });

  it("refuses a chain whose ancestor nests deeper than a credential may, and still records the presented credential's own digest", async () => {
    const error = vi.spyOn(logger, 'error');
    const { kyaos, server, ancestors, recorded } = await makeServer();
    const { root, middle, leaf } = await threeHops(server.did);
    const nestedTo = (levels: number) =>
      ({ ...middle, proof: { ...middle.proof!, note: arrays(levels - 2) } }) as DelegationCredential;
    // The root is read first and is as it was issued. The credential after it is 65 levels deep.
    ancestors.push(root, nestedTo(65));
    const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));

    const result = await handler({ ...ARGS, _kyaos_delegation: leaf });

    expect(refusal(result)).toEqual({
      error: 'delegation_invalid',
      reason: `Resolved delegation chain for ${leaf.credentialSubject.delegation.id} holds a value that could not be copied`,
    });
    // A credential the server read has no signed form, so no event lists the
    // chain: not as the root and the presented credential, which would say
    // the server read nothing between them.
    expect(delegationClaims(result)).toEqual({});
    const own = await digestDelegationChain([leaf], hash);
    const presented = { delegationRef: leaf.id, delegationCredentialDigest: own.credentials[0] };
    expect(recorded.map((event) => [event.eventType, delegationEvidence(event)])).toEqual([
      ['delegation.rejected', presented],
      ...OUTCOME_EVENTS,
    ]);
    expect(error).not.toHaveBeenCalled();

    // One level less, and the same chain is allowed.
    ancestors.splice(0, ancestors.length, root, nestedTo(64));
    const allowed = await handler({ ...ARGS, _kyaos_delegation: leaf });
    expect(allowed.isError).toBeUndefined();
  });

  it('reads a VC-JWT whose payload nests 64 levels deep, and refuses one that nests 65 without reading it', async () => {
    const { kyaos, recorded } = await makeServer();
    const issuer = await jwtParty();
    // The payload is level 1, `vc` 2, the credentialSubject 3, the delegation
    // 4 and its metadata 5: the arrays in it are the rest.
    const mint = (levels: number) =>
      issuer.issue({
        id: `urn:uuid:jwt-${levels}-deep`,
        delegationId: `del-jwt-${levels}-deep`,
        metadata: { nested: arrays(levels - 5) },
      });
    const [atBound, pastBound] = await Promise.all([mint(64), mint(65)]);
    const payloadOf = (jwt: string) => Buffer.from(jwt.split('.')[1]!, 'base64url').toString('utf8');
    const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));

    const allowed = await handler({ ...ARGS, _kyaos_delegation: atBound });

    expect(allowed.isError).toBeUndefined();
    expect(recordedReferences(recorded, 'delegation.verified')).toEqual(['urn:uuid:jwt-64-deep']);

    recorded.length = 0;
    const parse = vi.spyOn(JSON, 'parse');
    const result = await handler({ ...ARGS, _kyaos_delegation: pastBound });
    const parsed = parse.mock.calls.map(([text]) => text);
    parse.mockRestore();

    expect(refusal(result)).toEqual({ error: 'delegation_invalid', reason: 'Invalid VC-JWT format' });
    // Its payload is JSON, and no parser was handed it: how deep a text a
    // parser reads is not what the verdict turns on.
    expect(() => JSON.parse(payloadOf(pastBound))).not.toThrow();
    expect(parsed).not.toContain(payloadOf(pastBound));
    // A credential that is not read shows no id, so the trail names none.
    // Its segments are digested as they came, which takes no reading of them.
    expect(proofOf(result)!.meta.outcome).toBe('denied');
    expect(delegationClaims(result)).toEqual({});
    const own = (await digestDelegationChain([pastBound], hash)).credentials;
    expect(recorded.map((event) => [event.eventType, delegationEvidence(event)])).toEqual([
      ['delegation.rejected', { delegationCredentialDigest: own[0], delegationChainDigests: own }],
      ...OUTCOME_EVENTS,
    ]);
  });

  it.each([
    ['a number', 42],
    ['an object that is no credential', { id: 'urn:uuid:not-a-credential' }],
  ])('records the presented credential when the ancestors resolved for it hold %s', async (_name, value) => {
    const { kyaos, server, ancestors, recorded } = await makeServer();
    const { root, leaf } = await threeHops(server.did);
    ancestors.push(root, value as never);
    const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));

    const result = await handler({ ...ARGS, _kyaos_delegation: leaf });

    // Refused for what it is, not as a fault: the ancestors were not
    // resolved into a chain of credentials.
    expect(refusal(result)).toEqual({
      error: 'delegation_invalid',
      reason: `Resolved delegation chain for ${leaf.credentialSubject.delegation.id} holds a value that is not a delegation credential`,
    });
    expect(recordedReferences(recorded, 'delegation.rejected')).toEqual([leaf.id]);
    expect(delegationClaims(result)).toEqual({});
  });

  it('records the presented credential when its ancestors could not be resolved', async () => {
    const { kyaos, server, recorded } = await makeServer({
      resolveDelegationChain: async () => {
        throw new Error('registry unreachable');
      },
    });
    const { leaf } = await threeHops(server.did);
    const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));

    const result = await handler({ ...ARGS, _kyaos_delegation: leaf });

    expect(refusal(result).reason).toContain('Failed to resolve delegation chain');
    expect(recordedReferences(recorded, 'delegation.rejected')).toEqual([leaf.id]);
    expect(delegationClaims(result)).toEqual({});
  });

  it('does not digest a chain longer than it agreed to evaluate', async () => {
    const { kyaos, server, ancestors, recorded } = await makeServer({ maxChainLength: 2 });
    const { root, middle, leaf } = await threeHops(server.did);
    ancestors.push(root, middle);
    const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));

    const result = await handler({ ...ARGS, _kyaos_delegation: leaf });

    expect(refusal(result).reason).toContain('exceeds the maximum of 2');
    // maxChainLength bounds the server's work, and digesting is work: the
    // refusal's event lists the presented credential alone.
    const own = (await digestDelegationChain([leaf], hash)).credentials;
    expect(recorded.map((event) => [event.eventType, delegationEvidence(event)])).toEqual([
      ['delegation.rejected', { delegationRef: leaf.id, delegationCredentialDigest: own[0], delegationChainDigests: own }],
      ...OUTCOME_EVENTS,
    ]);
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});
