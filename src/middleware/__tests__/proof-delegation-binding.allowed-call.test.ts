/**
 * An allowed call under a delegation (SPEC.md §7.8).
 *
 * The delegation gate verifies a whole chain: the credential the caller
 * presents and the ancestors the server resolves. These tests hold the
 * server's answer to an allowed call to that: the audit trail records the
 * presented credential's reference and the digest of every hop, and the
 * proof signs neither delegation claim, so a verifier that asks for the
 * chain refuses it.
 *
 * Every proof here is verified the way a client or auditor would: with the
 * server's public key, the request, the result as received, and the chain.
 */
import { afterEach, describe, it, expect, vi } from 'vitest';
import type { KyaOsCallContext } from '../with-kya-os.js';
import { digestDelegationChain } from '../../delegation/chain-digest.js';
import { PROOF_VERIFICATION_ERROR_CODES } from '../../proof/errors.js';
import { hash, makeServer, makeUnserved } from './helpers/delegation-gate-server.js';
import { ARGS, CONSENT, TOOL, released } from './helpers/delegated-call.js';
import { delegate, party } from './helpers/delegating-party.js';
import { jwtParty, linearChain, threeHops } from './helpers/delegation-chains.js';
import { handshake, verifyReceived } from './helpers/received-proof.js';
import { delegationClaims, delegationEvidence, recordedReferences, signedClaims } from './helpers/server-answers.js';

describe('an allowed call', () => {
  it('signs neither delegation claim, in claims every earlier verifier already signs over', async () => {
    const { kyaos, server, ancestors } = await makeServer();
    const { root, middle, leaf, chain } = await threeHops(server.did);
    ancestors.push(root, middle);
    const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));

    const result = await handler({ ...ARGS, _kyaos_delegation: leaf });

    expect(result.isError).toBeUndefined();
    expect(delegationClaims(result)).toEqual({});
    // The claim set of 1.22.0 and before: a verifier of that vintage rebuilds
    // exactly these from `meta`, so it still verifies this proof.
    const known = ['aud', 'sub', 'iss', 'requestHash', 'responseHash', 'ts', 'nonce', 'sessionId',
      'scopeId', 'delegationRef', 'clientDid', 'outcome', 'reason', 'prf'];
    expect(Object.keys(signedClaims(result)).filter((claim) => !known.includes(claim))).toEqual([]);

    // A verifier that asks for the chain is not satisfied by a proof that binds none.
    const asked = await verifyReceived(result, {
      signer: server.did,
      toolName: TOOL,
      params: ARGS,
      binds: 'content',
      delegationChain: chain,
    });
    expect(asked.valid).toBe(false);
    expect(asked.errorCode).toBe(PROOF_VERIFICATION_ERROR_CODES.DELEGATION_BINDING_MISMATCH);
    expect(asked.details).toEqual({ binding: 'delegation-chain-unbound' });
  });

  it('records a VC-JWT leaf by its credential id, under ancestors presented as objects', async () => {
    const { kyaos, server, ancestors, recorded } = await makeServer();
    // The middle party signs its hop as a JWT, so its key is a CryptoKey.
    const [user, middle, subAgent] = await Promise.all([party(), jwtParty(), party()]);
    const root = await delegate(user, middle.did);
    ancestors.push(root);
    const jwt = await middle.issue({
      id: 'urn:uuid:jwt-leaf',
      delegationId: 'del-jwt-leaf',
      subject: subAgent.did,
      parent: root,
      audience: server.did,
    });
    const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));

    const result = await handler({ ...ARGS, _kyaos_delegation: jwt });

    expect(result.isError).toBeUndefined();
    expect(recordedReferences(recorded, 'delegation.verified')).toEqual(['urn:uuid:jwt-leaf']);
    expect(delegationClaims(result)).toEqual({});
  });

  it('records the delegation by its own id when the credential carries none', async () => {
    const { kyaos, recorded } = await makeServer();
    // A VC-JWT whose credential has no top-level `id`, only the delegation's.
    const jwt = await (await jwtParty()).issue({ delegationId: 'del-without-credential-id' });
    const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));

    const result = await handler({ ...ARGS, _kyaos_delegation: jwt });

    expect(result.isError).toBeUndefined();
    expect(recordedReferences(recorded, 'delegation.verified')).toEqual(['del-without-credential-id']);
  });

  it('records a VC-JWT without a credential id by its jti', async () => {
    const { kyaos, recorded } = await makeServer();
    const jwt = await (await jwtParty()).issue({ delegationId: 'del-with-jti', jti: 'urn:uuid:from-jti' });
    const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));

    const result = await handler({ ...ARGS, _kyaos_delegation: jwt });

    expect(result.isError).toBeUndefined();
    expect(recordedReferences(recorded, 'delegation.verified')).toEqual(['urn:uuid:from-jti']);
  });

  it.each([
    // An audit event's delegationChainDigests admits 256 digests.
    ['as long as the audit trail lists', 256, true],
    ['one credential longer than the audit trail lists', 257, false],
  ])('allows a chain %s when maxChainLength admits it', async (_name, length, listed) => {
    const { kyaos, server, ancestors, recorded } = await makeServer({ maxChainLength: 300 });
    const chain = await linearChain(length, server.did);
    ancestors.push(...chain.slice(0, -1));
    const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));

    const result = await handler({ ...ARGS, _kyaos_delegation: chain.at(-1) });

    expect(result.isError).toBeUndefined();
    const digests = await digestDelegationChain(chain, hash);
    // The event that lists a chain's credentials lists all of them, or
    // leaves the list out: it never cuts it.
    const verified = recorded.find((event) => event.eventType === 'delegation.verified')!;
    expect(verified.authorization!.delegationChainDigests).toEqual(listed ? digests.credentials : undefined);
    expect(verified.authorization!.delegationCredentialDigest).toBe(digests.credentials.at(-1));
  }, 30_000);

  describe('with no maxChainLength set', () => {
    it('a server evaluates a chain of any length, as before', async () => {
      const { kyaos, server, ancestors } = await makeServer();
      const chain = await linearChain(33, server.did);
      ancestors.push(...chain.slice(0, -1));
      const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));

      const result = await handler({ ...ARGS, _kyaos_delegation: chain.at(-1) });

      expect(result.isError).toBeUndefined();
    });
  });

  it('records the per-hop digests once, with the verdict on the delegation', async () => {
    const { kyaos, server, ancestors, recorded } = await makeServer();
    const { root, middle, leaf, chain } = await threeHops(server.did);
    ancestors.push(root, middle);
    const contexts: Array<KyaOsCallContext | undefined> = [];
    const handler = kyaos.wrapWithDelegation(
      TOOL,
      CONSENT,
      kyaos.wrapWithProof(TOOL, async (args, sessionId, context) => {
        contexts.push(context);
        return released(args, sessionId, context);
      }),
    );

    await handler({ ...ARGS, _kyaos_delegation: leaf });

    const perHop = (await digestDelegationChain(chain, hash)).credentials;
    const reference = { delegationRef: leaf.id, delegationCredentialDigest: perHop.at(-1) };
    // An auditor with only the audit trail recomputes the chain the call was decided under.
    expect(recorded.map((event) => event.eventType)).toEqual([
      'delegation.verified',
      'authorization.approved',
      'tool.call.started',
      'proof.generated',
      'tool.call.completed',
    ]);
    const [verified, ...rest] = recorded;
    expect(delegationEvidence(verified!)).toEqual({ ...reference, delegationChainDigests: perHop });
    // The event that records the verdict names the credential in its own
    // details too, and the credential it was issued under.
    expect(verified!.details).toEqual({
      family: 'delegation',
      phase: 'verified',
      delegationRef: leaf.id,
      parentRef: middle.credentialSubject.delegation.id,
    });
    // A chain may be long. The call's other events, and the handler, refer
    // to the credential by its reference and its digest.
    for (const event of rest) expect(delegationEvidence(event)).toEqual(reference);
    expect(contexts[0]!.authorization).toMatchObject(reference);
    expect(contexts[0]!.authorization).not.toHaveProperty('delegationChainDigests');
  });

  it.each([
    ['undefined', undefined],
    ['null', null],
  ])('returns a handler result of %s as the handler gave it, under a delegation or a grant', async (_name, nothing) => {
    const { kyaos } = await makeUnserved();
    const [user, agent] = await Promise.all([party(), party()]);
    const credential = await delegate(user, agent.did);
    const sessionId = await handshake(kyaos);
    // A handler in plain JavaScript, or one that answers through another
    // channel, may return nothing. The gate has no say in that.
    const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, async () => nothing as never);

    await expect(handler({ ...ARGS, _kyaos_delegation: credential }, sessionId)).resolves.toBe(nothing);
    // The retry presents nothing, and is allowed by the grant the first call left.
    await expect(handler({ ...ARGS }, sessionId)).resolves.toBe(nothing);
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});
