/**
 * A tool call's arguments are JSON a caller wrote, and JSON may hold a member named `__proto__`.
 * `JSON.parse` keeps it as an own member. A copy made by assigning each member to a new object
 * turns it into the copy's prototype, so the copy answers for members the call never stated, and
 * the call's own keys, which a request hash and an approval cover, no longer say what a handler
 * reads. Every copy of a call's arguments without its `_kyaos*` control arguments is therefore one
 * function, `withoutControlArgs`, which keeps `__proto__` a member: the copy a gate hands its
 * handler, the copy an approval binds, and the request a holder-binding proof covers.
 *
 * A tool's response is JSON too. Under the envelope profile a response proof covers the whole
 * result without its top-level `_meta`, and that copy keeps a `__proto__` member a member as well,
 * so the response is proven and `responseHash` covers the member.
 */

import { describe, expect, it } from 'vitest';
import { toHolderBindingRequest } from '../../delegation/holder-binding.js';
import { withoutControlArgs } from '../../proof/covered-request.js';
import { computeCanonicalHashes, RESPONSE_PROOF_PROFILE_ENVELOPE } from '../../proof/generator.js';
import { keyOf, delegationRecord, signedCredential } from '../../__tests__/utils/delegation-credentials.js';
import { issuerDidDocument, methodOf } from '../../__tests__/utils/did-documents.js';
import type { PolicyEngine } from '../../policy/engine.js';
import { didKeyFragment, generateDidKeyFromBase64 } from '../../utils/did-helpers.js';
import { createKyaOsMiddleware } from '../with-kya-os.js';
import { createMiddleware, crypto, handshake, served, verifyReceived } from './helpers/received-proof.js';

/** `call` as it arrives off the wire, with a member named `__proto__` that holds `amount`. */
const withProtoMember = (call: Record<string, unknown>): Record<string, unknown> =>
  JSON.parse(JSON.stringify(call).replace(/}$/, ',"__proto__":{"amount":999999}}')) as Record<string, unknown>;

/** What a copy shows of a call sent with `to` and a `__proto__` member: its keys, prototype and `amount`. */
const shape = (copy: Record<string, unknown>) => ({
  keys: Object.keys(copy),
  plain: Object.getPrototypeOf(copy) === Object.prototype,
  amount: copy.amount,
});
const AS_SENT = { keys: ['to', '__proto__'], plain: true, amount: undefined };

async function middleware(delegation = {}) {
  const keys = await crypto.generateKeyPair();
  const did = generateDidKeyFromBase64(keys.publicKey);
  return served(createKyaOsMiddleware(
    { identity: { did, kid: `${did}#${didKeyFragment(did)}`, ...keys }, session: { sessionTtlMinutes: 60 }, delegation },
    crypto,
  ));
}

describe('a copy of a call without its control arguments', () => {
  it('keeps a __proto__ member a member, and drops only the _kyaos control arguments', () => {
    const call = withProtoMember({ to: 'bob', _kyaos_delegation: 'x', _kyaos_approvals: [] });
    expect(shape(withoutControlArgs(call))).toEqual(AS_SENT);
    expect(shape(toHolderBindingRequest('orders.place', call).params as Record<string, unknown>)).toEqual(AS_SENT);
    expect(toHolderBindingRequest('orders.place', call).method).toBe('orders.place');
    // Only a name that starts with the prefix is a control argument.
    expect(Object.keys(withoutControlArgs({ note_kyaos_x: 1, _kyaos_x: 2 }))).toEqual(['note_kyaos_x']);
  });

  it('gives the tool behind the delegation gate the members the call stated and no others', async () => {
    const issuer = await keyOf('did:web:root.example', 'key');
    const kyaos = await middleware({
      trustedRootIssuers: [issuer.did],
      didResolver: { resolve: async (did: string) => (did === issuer.did ? issuerDidDocument(methodOf(issuer)) : null) },
    });
    const seen: Record<string, unknown>[] = [];
    const tool = kyaos.wrapWithDelegation('orders.place', { scopeId: 'orders:place', consentUrl: 'https://root.example/consent' },
      async (args) => { seen.push(args); return { content: [{ type: 'text', text: 'placed' }] }; });
    const delegation = await signedCredential(issuer, { record: delegationRecord(issuer.did) });
    const sessionId = await handshake(kyaos);
    await tool(withProtoMember({ to: 'bob', _kyaos_delegation: delegation }), sessionId);
    // A later call in the session runs under the stored grant, and its arguments are copied the same way.
    await tool(withProtoMember({ to: 'bob', _kyaos_approvals: [] }), sessionId);
    expect(seen.map(shape)).toEqual([AS_SENT, AS_SENT]);
  });

  it('holds an approval to the call it was given for: a __proto__ member is part of the call', async () => {
    const kyaos = await middleware();
    const engine: PolicyEngine = {
      evaluate: async () => ({ decision: 'step_up', quorum: { n: 1, approvers: [] }, reason: 'transfer' }),
    };
    const ran: Record<string, unknown>[] = [];
    const tool = kyaos.withPolicyGate!('orders.place',
      async (args) => { ran.push(args); return { content: [{ type: 'text', text: 'placed' }] }; },
      { engine, scopeMatched: true, isValidApprovalSignature: async () => true });
    const challenge = JSON.parse((await tool({ to: 'bob' })).content[0]!.text) as { requestHash: string };
    const approval = {
      approvalRequestId: 'r1', approverDid: 'did:example:approver', requestHash: challenge.requestHash,
      decision: 'approve', ts: Math.floor(Date.now() / 1000), signature: 'sig',
    };
    // The approved call runs, and the same approval does not cover a call that states more.
    await tool({ to: 'bob', _kyaos_approvals: [approval] });
    await tool({ to: 'bob', amount: 999999, _kyaos_approvals: [approval] });
    await tool(withProtoMember({ to: 'bob', _kyaos_approvals: [approval] }));
    expect(ran.map(shape)).toEqual([{ keys: ['to'], plain: true, amount: undefined }]);
  });
});

describe('a tool response with a member named __proto__, under the envelope profile', () => {
  const PLAIN = '{"content":[{"type":"text","text":"ok"}]}';
  const WITH_MEMBER = '{"content":[{"type":"text","text":"ok"}],"__proto__":{"isError":true}}';

  it('is covered by responseHash as the member it is, with _meta still left out', async () => {
    const hashOf = async (text: string) => (await computeCanonicalHashes(
      { method: 'orders.place', params: {} }, { data: JSON.parse(text) }, (bytes) => crypto.hash(bytes), RESPONSE_PROOF_PROFILE_ENVELOPE,
    )).responseHash;
    const covered = await hashOf(WITH_MEMBER);
    expect(covered).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(covered).not.toBe(await hashOf(PLAIN));
    expect(await hashOf(WITH_MEMBER.replace(/}$/, ',"_meta":{"note":1}}'))).toBe(covered);
  });

  it('is proven as its client received it, and a member added after signing breaks the proof', async () => {
    const kyaos = await served(await createMiddleware({ responseProofProfile: RESPONSE_PROOF_PROFILE_ENVELOPE }));
    const sessionId = await handshake(kyaos);
    const answer = (text: string) =>
      kyaos.wrapWithProof('orders.place', async () => JSON.parse(text) as { content: [] })({ to: 'bob' }, sessionId);
    const expected = { signer: kyaos.identity.did, toolName: 'orders.place', params: { to: 'bob' }, binds: 'envelope' as const };

    const received = await answer(WITH_MEMBER);
    expect(Object.keys(received)).toEqual(['content', '__proto__', '_meta']);
    expect((await verifyReceived(received, expected)).valid).toBe(true);
    const withoutMember = Object.fromEntries(Object.entries(received).filter(([key]) => key !== '__proto__'));
    expect((await verifyReceived(withoutMember, expected)).valid).toBe(false);

    const plain = await answer(PLAIN);
    expect((await verifyReceived(plain, expected)).valid).toBe(true);
    const altered = JSON.parse(JSON.stringify(plain).replace(/}$/, ',"__proto__":{"isError":true}}')) as Record<string, unknown>;
    expect((await verifyReceived(altered, expected)).valid).toBe(false);
  });
});
