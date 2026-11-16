/**
 * The Responsible Party of a delegated call is the root issuer of its chain (SPEC.md §2, §6.4): the
 * issuer whose signature on the root credential the gate verified, and whom `trustedRootIssuers`
 * admits. A credential's `controller` is a value its own issuer writes, so a delegate that
 * re-delegates can write any DID there. The gate therefore names the verified root issuer, never
 * the leaf's `controller`, in the context it hands the tool, in its audit events and in the grant
 * it stores, and names it again when a later call runs under that grant.
 */

import { beforeAll, describe, expect, it } from 'vitest';
import type { AuditTrailEventInput } from '../../audit/service.js';
import { credentialNaming, keyOf, delegationRecord, signedCredential, signedJwt } from '../../__tests__/utils/delegation-credentials.js';
import { issuerDidDocument, methodOf } from '../../__tests__/utils/did-documents.js';
import type { AgentIdentity } from '../../providers/base.js';
import type { PolicyRequest } from '../../policy/types.js';
import { MemoryGrantStore } from '../../providers/grant-store.js';
import type { DelegationCredential } from '../../types/protocol.js';
import { didKeyFragment, generateDidKeyFromBase64 } from '../../utils/did-helpers.js';
import { createKyaOsMiddleware } from '../with-kya-os.js';
import type { KyaOsCallContext } from '../with-kya-os.types.js';
import { crypto, handshake, served } from './helpers/received-proof.js';

const ALICE = 'did:web:alice.example';
const VICTIM = 'did:web:victim.example';
const AGENT = 'did:web:agent.example';

let root: AgentIdentity;
let delegate: AgentIdentity;
beforeAll(async () => {
  [root, delegate] = await Promise.all([keyOf('did:web:root.example', 'key'), keyOf('did:web:delegate.example', 'key')]);
});

/** A server that trusts `root` alone, with a tool behind its delegation gate, and what the gate recorded. */
async function server() {
  const keys = await crypto.generateKeyPair();
  const did = generateDidKeyFromBase64(keys.publicKey);
  const events: AuditTrailEventInput[] = [];
  const contexts: (KyaOsCallContext | undefined)[] = [];
  const grantStore = new MemoryGrantStore();
  let ancestors: DelegationCredential[] = [];
  const kyaos = await served(createKyaOsMiddleware({
    identity: { did, kid: `${did}#${didKeyFragment(did)}`, ...keys },
    session: { sessionTtlMinutes: 60 },
    delegation: {
      trustedRootIssuers: [root.did],
      didResolver: { resolve: async (asked: string) => {
        const key = [root, delegate].find(candidate => candidate.did === asked);
        return key ? issuerDidDocument(methodOf(key)) : null;
      } },
      resolveDelegationChain: async () => ancestors,
    },
    audit: { record: async (event) => { events.push(event); return { status: 'pending', event: event as never }; } },
    grantStore,
  }, crypto));
  const handler = kyaos.wrapWithDelegation('orders.place', { scopeId: 'orders:place', consentUrl: 'https://root.example/consent' },
    async (_args, _sessionId, context) => { contexts.push(context); return { content: [{ type: 'text', text: 'placed' }] }; });
  const constraints = { scopes: ['orders:place'], audience: did, notAfter: Math.floor(Date.now() / 1000) + 3600 };
  return {
    kyaos, events, contexts, grantStore, constraints,
    /** Call the tool in `sessionId`, presenting `delegation` (or nothing) below `chain`. */
    call: async (sessionId: string | undefined, delegation?: unknown, chain: DelegationCredential[] = []) => {
      ancestors = chain;
      const result = await handler(delegation === undefined ? {} : { _kyaos_delegation: delegation }, sessionId);
      return result.content[0]!.text;
    },
  };
}

/** The DID each audit event of `type` names as the responsible party. */
const namedBy = (events: AuditTrailEventInput[], type: string) =>
  events.filter(event => event.eventType === type).map(({ responsibleParty: party }) => (party && 'did' in party ? party.did : undefined));

describe('the Responsible Party the delegation gate names', () => {
  it('is the root issuer of a two-hop chain, whatever controller the delegate writes on the leaf', async () => {
    const s = await server();
    const rootRecord = delegationRecord(root.did, { subjectDid: delegate.did, controller: ALICE, constraints: s.constraints });
    const rootCredential = await signedCredential(root, { record: rootRecord });
    const leafRecord = delegationRecord(delegate.did, { subjectDid: AGENT, parentId: rootRecord.id, controller: VICTIM, constraints: s.constraints });
    for (const leaf of [await signedCredential(delegate, { record: leafRecord }), await signedJwt(delegate, { record: leafRecord, kid: delegate.kid })]) {
      s.events.length = 0;
      s.contexts.length = 0;
      expect(await s.call(undefined, leaf, [rootCredential])).toBe('placed');
      expect(s.contexts[0]?.responsibleParty).toEqual({ kind: 'pairwise_did', did: root.did });
      expect(s.contexts[0]?.principal?.responsibleParty).toBe(root.did);
      expect(namedBy(s.events, 'delegation.verified')).toEqual([root.did]);
      expect(namedBy(s.events, 'authorization.approved')).toEqual([root.did]);
      expect(JSON.stringify([s.events, s.contexts])).not.toContain(VICTIM);
    }
  });

  it('is the issuer of a single credential, not the controller it names', async () => {
    const s = await server();
    const record = delegationRecord(root.did, { subjectDid: AGENT, controller: ALICE, constraints: s.constraints });
    expect(await s.call(undefined, await signedCredential(root, { record }))).toBe('placed');
    expect(s.contexts[0]?.principal?.responsibleParty).toBe(root.did);
    expect(namedBy(s.events, 'delegation.verified')).toEqual([root.did]);
    // With no controller at all the call still has its Responsible Party.
    const bare = delegationRecord(root.did, { subjectDid: AGENT, constraints: s.constraints });
    expect(await s.call(undefined, await signedCredential(root, { record: bare }))).toBe('placed');
    expect(s.contexts[1]?.responsibleParty).toEqual({ kind: 'pairwise_did', did: root.did });
  });

  it('is one DID: a root whose issuerDid is not the issuer that signed its credential is refused', async () => {
    const s = await server();
    // The trusted root signs both, and each names ALICE as the issuerDid of its delegation.
    const solo = delegationRecord(ALICE, { subjectDid: AGENT, constraints: s.constraints });
    const rootRecord = delegationRecord(ALICE, { subjectDid: delegate.did, constraints: s.constraints });
    const leafRecord = delegationRecord(delegate.did, { subjectDid: AGENT, parentId: rootRecord.id, constraints: s.constraints });
    const refusals = [
      [solo.id, await s.call(undefined, await credentialNaming(root, root.did, root.kid, solo))],
      [rootRecord.id, await s.call(undefined, await signedCredential(delegate, { record: leafRecord }), [await credentialNaming(root, root.did, root.kid, rootRecord)])],
    ];
    for (const [id, refusal] of refusals) {
      expect(JSON.parse(refusal!)).toEqual({
        error: 'delegation_invalid',
        reason: `Root delegation ${id} names issuerDid "${ALICE}" but its credential names issuer "${root.did}"`,
      });
    }
    expect(s.contexts).toHaveLength(0);
    expect(namedBy(s.events, 'delegation.verified')).toEqual([]);
  });

  it('is stored in the grant, and named again when a later call runs under it', async () => {
    const s = await server();
    const rootRecord = delegationRecord(root.did, { subjectDid: delegate.did, controller: ALICE, constraints: s.constraints });
    const rootCredential = await signedCredential(root, { record: rootRecord });
    const leafRecord = delegationRecord(delegate.did, { subjectDid: AGENT, parentId: rootRecord.id, controller: VICTIM, constraints: s.constraints });
    const sessionId = await handshake(s.kyaos);
    expect(await s.call(sessionId, await signedCredential(delegate, { record: leafRecord }), [rootCredential])).toBe('placed');
    const grants = await s.grantStore.getByAgent(AGENT);
    expect(grants.map(grant => [grant.responsibleParty, grant.userDid])).toEqual([[root.did, undefined]]);

    s.events.length = 0;
    expect(await s.call(sessionId, undefined, [rootCredential])).toBe('placed');
    expect(s.contexts[1]?.responsibleParty).toEqual({ kind: 'pairwise_did', did: root.did });
    expect(s.contexts[1]?.principal?.responsibleParty).toBe(root.did);
    expect(namedBy(s.events, 'grant.used')).toEqual([root.did]);
    // The grant keeps the signed credential as presented, controller included; nothing else names it.
    const ownFields = grants.map(({ delegationCredential: _kept, ...fields }) => fields);
    expect(JSON.stringify([s.events, s.contexts, ownFields])).not.toContain(VICTIM);
  });

  it('is the root issuer for a grant 1.22.0 stored, which recorded the controller of its credential as userDid', async () => {
    const s = await server();
    const record = delegationRecord(root.did, { subjectDid: AGENT, controller: ALICE, constraints: s.constraints });
    const sessionId = await handshake(s.kyaos);
    // The row as 1.22.0 wrote it: no responsibleParty, and the credential's controller as userDid.
    await s.grantStore.bind({
      id: 'grant-stored-by-1.22.0', agentDid: AGENT, userDid: ALICE, scopes: ['orders:place'], sessionId,
      authorization: { type: 'delegation' }, delegationCredential: await signedCredential(root, { record }),
      issuedAt: Date.now(), status: 'active',
    });
    expect(await s.call(sessionId)).toBe('placed');
    expect(s.contexts[0]?.responsibleParty).toEqual({ kind: 'pairwise_did', did: root.did });
    expect(s.contexts[0]?.principal?.responsibleParty).toBe(root.did);
    expect(namedBy(s.events, 'grant.used')).toEqual([root.did]);
  });

  it('does not run a call under a stored grant that names another Responsible Party than its chain verifies to', async () => {
    const s = await server();
    const record = delegationRecord(root.did, { subjectDid: AGENT, constraints: s.constraints });
    const sessionId = await handshake(s.kyaos);
    expect(await s.call(sessionId, await signedCredential(root, { record }))).toBe('placed');
    const [grant] = await s.grantStore.getByAgent(AGENT);
    await s.grantStore.bind({ ...grant!, responsibleParty: VICTIM });
    expect(await s.call(sessionId)).not.toBe('placed');
    expect(s.contexts).toHaveLength(1);
  });
});

describe('the Responsible Party a policy gate names', () => {
  it('is none when no delegation gate verified the delegation the call presents', async () => {
    const s = await server();
    const requests: PolicyRequest[] = [];
    const gated = s.kyaos.withPolicyGate!('orders.place', async () => ({ content: [{ type: 'text', text: 'placed' }] }), {
      engine: { evaluate: async (request) => { requests.push(request); return { decision: 'allow' }; } },
    });
    // Nothing verifies this credential here, so the controller it states is only its author's claim.
    const record = delegationRecord(root.did, { subjectDid: AGENT, controller: VICTIM, constraints: s.constraints });
    const result = await gated({ _kyaos_delegation: await signedCredential(delegate, { record }) });
    expect(result.content[0]!.text).toBe('placed');
    expect(requests.map(request => request.principal)).toEqual([{ agentDid: AGENT }]);
  });
});
