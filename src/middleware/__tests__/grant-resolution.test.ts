import { describe, it, expect } from 'vitest';
import { createKyaOsMiddleware, type KyaOsDelegationConfig } from '../with-kya-os.js';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { generateDidKeyFromBase64 } from '../../utils/did-helpers.js';
import { DelegationCredentialIssuer } from '../../delegation/vc-issuer.js';
import { createUnsignedVCJWT, completeVCJWT } from '../../delegation/utils.js';
import { generateRequestProof } from '../../delegation/holder-binding.js';
import { MemoryGrantStore, type Grant } from '../../providers/grant-store.js';
import type { DelegationCredential, Proof } from '../../types/protocol.js';
import type { ProofAgentIdentity } from '../../proof/generator.js';
import { base64urlEncodeFromBytes } from '../../utils/base64.js';

/**
 * Durable-grant retry resolution (spec §A). On a no-delegation (retry) call the
 * middleware resolves an existing grant from the GrantStore — holder-of-key
 * first (agent-anchored, proof-gated), then the session bearer capability — so a
 * fresh instance with empty memory authorizes the retry with NO re-paste of the
 * VC. The confused-deputy gate (§A.4) is the security crux: a grant for agent A
 * must never resolve without A's verified holder-of-key proof.
 */

const crypto = new NodeCryptoProvider();
const SCOPE = 'cart:write';
const TOOL = 'checkout';

async function makeIdentity(): Promise<ProofAgentIdentity> {
  const kp = await crypto.generateKeyPair();
  const did = generateDidKeyFromBase64(kp.publicKey);
  return {
    did,
    kid: `${did}#${did.replace('did:key:', '')}`,
    privateKey: kp.privateKey,
    publicKey: kp.publicKey,
  };
}

async function makeServer(opts: {
  server?: ProofAgentIdentity;
  holderBinding?: KyaOsDelegationConfig['holderBinding'];
  grantStore?: MemoryGrantStore;
} = {}) {
  const server = opts.server ?? (await makeIdentity());
  const middleware = createKyaOsMiddleware(
    {
      identity: server,
      session: { sessionTtlMinutes: 60 },
      ...(opts.holderBinding ? { delegation: { holderBinding: opts.holderBinding } } : {}),
      ...(opts.grantStore ? { grantStore: opts.grantStore } : {}),
    },
    crypto,
  );
  return { server, middleware };
}

/** Issue a delegation VC (issuer-signed) naming `subjectDid` as the holder. */
async function issueVC(
  subjectDid: string,
  scopes: string[] = [SCOPE],
  controller?: string,
  crisp?: { resource: string; matcher: 'exact' | 'prefix' | 'regex' }[],
): Promise<DelegationCredential> {
  const issuer = await makeIdentity();
  const signingFn = async (canonicalVC: string, _issuerDid: string, kid: string): Promise<Proof> => {
    const sig = await crypto.sign(new TextEncoder().encode(canonicalVC), issuer.privateKey);
    return {
      type: 'Ed25519Signature2020',
      created: new Date().toISOString(),
      verificationMethod: kid,
      proofPurpose: 'assertionMethod',
      proofValue: base64urlEncodeFromBytes(sig),
    };
  };
  const credentialIssuer = new DelegationCredentialIssuer(
    { getDid: () => issuer.did, getKeyId: () => issuer.kid, getPrivateKey: () => issuer.privateKey },
    signingFn,
  );
  return credentialIssuer.createAndIssueDelegation({
    id: `del-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    issuerDid: issuer.did,
    subjectDid,
    ...(controller ? { controller } : {}),
    constraints: {
      scopes,
      ...(crisp ? { crisp: { scopes: crisp } } : {}),
      notAfter: Math.floor(Date.now() / 1000) + 3600,
    },
  });
}

/** Issue a delegation as a VC-JWT string (compact JWT), naming `subjectDid`. */
async function issueVCJWT(subjectDid: string, scopes: string[] = [SCOPE]): Promise<string> {
  const issuer = await makeIdentity();
  const signingFn = async (canonicalVC: string, _issuerDid: string, kid: string): Promise<Proof> => {
    const sig = await crypto.sign(new TextEncoder().encode(canonicalVC), issuer.privateKey);
    return {
      type: 'Ed25519Signature2020',
      created: new Date().toISOString(),
      verificationMethod: kid,
      proofPurpose: 'assertionMethod',
      proofValue: base64urlEncodeFromBytes(sig),
    };
  };
  const credentialIssuer = new DelegationCredentialIssuer(
    { getDid: () => issuer.did, getKeyId: () => issuer.kid, getPrivateKey: () => issuer.privateKey },
    signingFn,
  );
  const vc = await credentialIssuer.createAndIssueDelegation({
    id: `del-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    issuerDid: issuer.did,
    subjectDid,
    constraints: { scopes, notAfter: Math.floor(Date.now() / 1000) + 3600 },
  });
  const vcWithoutProof = { ...vc } as Record<string, unknown>;
  delete vcWithoutProof['proof'];
  const { signingInput } = createUnsignedVCJWT(vcWithoutProof, { keyId: issuer.kid });
  const sig = await crypto.sign(new TextEncoder().encode(signingInput), issuer.privateKey);
  return completeVCJWT(signingInput, base64urlEncodeFromBytes(sig));
}

async function openSession(
  middleware: Awaited<ReturnType<typeof makeServer>>['middleware'],
  serverDid: string,
): Promise<string> {
  const hs = await middleware.handleHandshake({
    nonce: `hs-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    audience: serverDid,
    timestamp: Math.floor(Date.now() / 1000),
  });
  return JSON.parse(hs.content[0].text).sessionId as string;
}

function activeGrant(over: Partial<Grant>): Grant {
  return {
    id: over.id ?? `grant-${Math.random().toString(16).slice(2)}`,
    agentDid: over.agentDid ?? 'did:key:zUnknown',
    scopes: over.scopes ?? [SCOPE],
    issuedAt: over.issuedAt ?? Date.now(),
    status: over.status ?? 'active',
    ...over,
  };
}

const REACHED = { content: [{ type: 'text' as const, text: 'reached-handler' }] };
const handlerThatRuns = async () => REACHED;
const reached = (r: { content: Array<{ text: string }> }) => r.content[0]!.text === 'reached-handler';
const challenged = (r: { content: Array<{ text: string }> }) =>
  JSON.parse(r.content[0]!.text).error === 'needs_authorization';

function delegationHandler(middleware: Awaited<ReturnType<typeof makeServer>>['middleware']) {
  return middleware.wrapWithDelegation(
    TOOL,
    { scopeId: SCOPE, consentUrl: 'https://example.com/consent' },
    handlerThatRuns,
  );
}

describe('wrapWithDelegation — grant retry resolution', () => {
  it('getBySession: a no-delegation retry on the same session reuses the grant (no re-paste)', async () => {
    const store = new MemoryGrantStore();
    const { server, middleware } = await makeServer({ grantStore: store });
    const sessionId = await openSession(middleware, server.did);
    store.bind(activeGrant({ agentDid: 'did:key:zAgent', sessionId }));

    const result = await delegationHandler(middleware)({ item: 'laptop' }, sessionId);
    expect(reached(result)).toBe(true);
  });

  it('getByAgent: a session-less grant resolves behind a valid holder-of-key proof (portable)', async () => {
    const store = new MemoryGrantStore();
    const agent = await makeIdentity();
    const { server, middleware } = await makeServer({ holderBinding: 'enforce', grantStore: store });
    store.bind(activeGrant({ agentDid: agent.did })); // no sessionId → agent-anchored

    const args = { item: 'laptop' };
    // The proof carries the agent's own session id (for structural validity);
    // the grant is agent-anchored, so resolution needs no server-side session.
    const proof = await generateRequestProof({
      identity: agent, crypto, toolName: TOOL, args, audience: server.did, sessionId: 'kyaos_agent_local',
    });
    // No server session and no delegation — only the proof proves possession.
    const result = await delegationHandler(middleware)({ ...args, _kyaos_proof: proof });
    expect(reached(result)).toBe(true);
  });

  it('end-to-end: first call challenges, a verified delegation binds a grant, the retry reuses it', async () => {
    const store = new MemoryGrantStore();
    const agent = await makeIdentity();
    const { server, middleware } = await makeServer({ grantStore: store });
    const sessionId = await openSession(middleware, server.did);
    const handler = delegationHandler(middleware);

    // 1. No delegation, no grant yet → needs_authorization.
    const first = await handler({ item: 'laptop' }, sessionId);
    expect(challenged(first)).toBe(true);

    // 2. Paste the delegation once → handler runs AND a grant is bound.
    const vc = await issueVC(agent.did);
    const second = await handler({ item: 'laptop', _kyaos_delegation: vc }, sessionId);
    expect(reached(second)).toBe(true);
    const bound = await store.getByAgent(agent.did, [SCOPE]);
    expect(bound).toHaveLength(1);
    expect(bound[0]!.sessionId).toBe(sessionId);

    // 3. Retry with NO delegation on the same session → reused, no re-paste.
    const third = await handler({ item: 'laptop' }, sessionId);
    expect(reached(third)).toBe(true);
  });

  it('cross-instance: a grant bound on instance A is resolved on a fresh instance B via the shared store', async () => {
    const store = new MemoryGrantStore();
    const server = await makeIdentity();
    const agent = await makeIdentity();

    // Instance A: paste the delegation once (binds a session grant into the store).
    const a = await makeServer({ server, grantStore: store });
    const sessionId = await openSession(a.middleware, server.did);
    const vc = await issueVC(agent.did);
    const rA = await delegationHandler(a.middleware)(
      { item: 'laptop', _kyaos_delegation: vc },
      sessionId,
    );
    expect(reached(rA)).toBe(true);

    // Instance B: fresh middleware, EMPTY memory, same shared store + server DID.
    // The client resends its sessionId; the grant resolves with no re-paste.
    const b = await makeServer({ server, grantStore: store });
    const rB = await delegationHandler(b.middleware)({ item: 'laptop' }, sessionId);
    expect(reached(rB)).toBe(true);
  });

  // ── Confused-deputy safety (spec §A.4) ────────────────────────────────────

  it('CONFUSED DEPUTY: an agent grant never resolves without a holder-of-key proof', async () => {
    const store = new MemoryGrantStore();
    const agent = await makeIdentity();
    const { server, middleware } = await makeServer({ holderBinding: 'enforce', grantStore: store });
    const sessionId = await openSession(middleware, server.did);
    // A session-less, agent-anchored grant exists for the agent.
    store.bind(activeGrant({ agentDid: agent.did }));

    // A caller who merely knows the agent DID but presents NO proof must be
    // challenged — the agent grant is unreachable without proven possession.
    const result = await delegationHandler(middleware)({ item: 'laptop' }, sessionId);
    expect(challenged(result)).toBe(true);
  });

  it('CONFUSED DEPUTY: a proof claiming agent A but signed by another key cannot resolve A\'s grant', async () => {
    const store = new MemoryGrantStore();
    const agentA = await makeIdentity();
    const attacker = await makeIdentity();
    const { server, middleware } = await makeServer({ holderBinding: 'enforce', grantStore: store });
    store.bind(activeGrant({ agentDid: agentA.did }));

    const args = { item: 'laptop' };
    // Forge a proof that DECLARES agent A as its subject but is signed by the
    // attacker's key (attacker knows A's DID, not A's private key).
    const forged = await generateRequestProof({
      identity: { did: agentA.did, kid: agentA.kid, privateKey: attacker.privateKey, publicKey: attacker.publicKey },
      crypto, toolName: TOOL, args, audience: server.did, sessionId: 'kyaos_attacker_local',
    });
    const result = await delegationHandler(middleware)({ ...args, _kyaos_proof: forged });
    expect(challenged(result)).toBe(true);
  });

  it('CONFUSED DEPUTY: a session-bound grant never resolves from another session', async () => {
    const store = new MemoryGrantStore();
    const { server, middleware } = await makeServer({ grantStore: store });
    const s1 = await openSession(middleware, server.did);
    const s2 = await openSession(middleware, server.did);
    store.bind(activeGrant({ agentDid: 'did:key:zAgent', sessionId: s1 }));

    // The grant is bound to s1; a call on s2 must be challenged.
    const result = await delegationHandler(middleware)({ item: 'laptop' }, s2);
    expect(challenged(result)).toBe(true);
  });

  it('a malformed string _kyaos_proof falls through to the challenge (no crash, no resolution)', async () => {
    const store = new MemoryGrantStore();
    const { server, middleware } = await makeServer({ holderBinding: 'enforce', grantStore: store });
    const sessionId = await openSession(middleware, server.did);
    store.bind(activeGrant({ agentDid: 'did:key:zAgent' }));

    const result = await delegationHandler(middleware)(
      { item: 'laptop', _kyaos_proof: 'not-json{{{' },
      sessionId,
    );
    expect(challenged(result)).toBe(true);
  });

  it('getByAgent: resolves when the holder-of-key proof is passed as a JSON string', async () => {
    const store = new MemoryGrantStore();
    const agent = await makeIdentity();
    const { server, middleware } = await makeServer({ holderBinding: 'enforce', grantStore: store });
    store.bind(activeGrant({ agentDid: agent.did }));

    const args = { item: 'laptop' };
    const proof = await generateRequestProof({
      identity: agent, crypto, toolName: TOOL, args, audience: server.did, sessionId: 'kyaos_agent_local',
    });
    const result = await delegationHandler(middleware)(
      { ...args, _kyaos_proof: JSON.stringify(proof) },
      undefined,
    );
    expect(reached(result)).toBe(true);
  });

  it('binds the user (controller) onto the grant when the delegation names one', async () => {
    const store = new MemoryGrantStore();
    const agent = await makeIdentity();
    const { server, middleware } = await makeServer({ grantStore: store });
    const sessionId = await openSession(middleware, server.did);
    const userDid = 'did:web:user.example.com';
    const vc = await issueVC(agent.did, [SCOPE], userDid);

    const result = await delegationHandler(middleware)(
      { item: 'laptop', _kyaos_delegation: vc },
      sessionId,
    );
    expect(reached(result)).toBe(true);

    const [bound] = await store.getByAgent(agent.did, [SCOPE]);
    expect(bound?.userDid).toBe(userDid);
    expect(bound?.scopes).toContain(SCOPE);
  });

  it('with the default (un-injected) grant store, a no-delegation call still challenges', async () => {
    const { server, middleware } = await makeServer(); // default MemoryGrantStore
    const sessionId = await openSession(middleware, server.did);
    const result = await delegationHandler(middleware)({ item: 'laptop' }, sessionId);
    expect(challenged(result)).toBe(true);
  });

  it('does NOT bind an unresolvable session-less grant under holderBinding off', async () => {
    const store = new MemoryGrantStore();
    const agent = await makeIdentity();
    const { middleware } = await makeServer({ grantStore: store }); // holderBinding 'off' (default)
    const vc = await issueVC(agent.did);
    // No sessionId threaded → a bound grant would be unresolvable on retry, so
    // the bind is skipped (no orphan row). The verified call still runs.
    const result = await delegationHandler(middleware)({ item: 'laptop', _kyaos_delegation: vc });
    expect(reached(result)).toBe(true);
    expect(await store.getByAgent(agent.did, [SCOPE])).toEqual([]);
  });

  it('binds the required scope so a prefix-scoped delegation resolves on retry (F1)', async () => {
    const store = new MemoryGrantStore();
    const agent = await makeIdentity();
    const { server, middleware } = await makeServer({ grantStore: store });
    const sessionId = await openSession(middleware, server.did);

    // The delegation grants a PREFIX scope ("cart:") with NO exact "cart:write";
    // getDelegationScopes returns [] for it, so without storing the required
    // scope the retry would re-challenge (exact coversScopes can't match "cart:").
    const vc = await issueVC(agent.did, [], undefined, [{ resource: 'cart:', matcher: 'prefix' }]);
    const first = await delegationHandler(middleware)({ item: 'laptop', _kyaos_delegation: vc }, sessionId);
    expect(reached(first)).toBe(true);

    const retry = await delegationHandler(middleware)({ item: 'laptop' }, sessionId);
    expect(reached(retry)).toBe(true);

    const [bound] = await store.getBySession(sessionId, [SCOPE]);
    expect(bound?.scopes).toContain(SCOPE);
  });

  it('upserts a single grant for repeated VC-paste of the same tuple (deterministic id) (F2)', async () => {
    const store = new MemoryGrantStore();
    const agent = await makeIdentity();
    const { server, middleware } = await makeServer({ grantStore: store });
    const sessionId = await openSession(middleware, server.did);

    const vc = await issueVC(agent.did);
    await delegationHandler(middleware)({ item: 'laptop', _kyaos_delegation: vc }, sessionId);
    await delegationHandler(middleware)({ item: 'laptop', _kyaos_delegation: vc }, sessionId);

    // Same (agentDid, sessionId, scopes) ⇒ one deterministic id ⇒ one row.
    expect(await store.getByAgent(agent.did, [SCOPE])).toHaveLength(1);
  });

  // ── Branch coverage: VC-JWT bind, non-did:key proof, bind failure ─────────

  it('binds a grant carrying the credentialJwt when the delegation is a VC-JWT string', async () => {
    const store = new MemoryGrantStore();
    const agent = await makeIdentity();
    const { server, middleware } = await makeServer({ grantStore: store });
    const sessionId = await openSession(middleware, server.did);

    const jwt = await issueVCJWT(agent.did);
    const result = await delegationHandler(middleware)(
      { item: 'laptop', _kyaos_delegation: jwt },
      sessionId,
    );
    expect(reached(result)).toBe(true);

    const [bound] = await store.getByAgent(agent.did, [SCOPE]);
    expect(bound?.credentialJwt).toBe(jwt);
  });

  it('resolveAgentGrant ignores a proof with no subject DID', async () => {
    const store = new MemoryGrantStore();
    const { server, middleware } = await makeServer({ holderBinding: 'enforce', grantStore: store });
    const sessionId = await openSession(middleware, server.did);
    const result = await delegationHandler(middleware)(
      { item: 'laptop', _kyaos_proof: { jws: 'x.y.z', meta: {} } },
      sessionId,
    );
    expect(challenged(result)).toBe(true);
  });

  it('resolveAgentGrant ignores a proof whose subject is not did:key (deferred to cnf binding)', async () => {
    const store = new MemoryGrantStore();
    const { server, middleware } = await makeServer({ holderBinding: 'enforce', grantStore: store });
    const sessionId = await openSession(middleware, server.did);
    const result = await delegationHandler(middleware)(
      { item: 'laptop', _kyaos_proof: { jws: 'x.y.z', meta: { did: 'did:web:agent.example.com' } } },
      sessionId,
    );
    expect(challenged(result)).toBe(true);
  });

  it('a grant-store bind failure does not break the already-authorized response', async () => {
    class ThrowingBindStore extends MemoryGrantStore {
      override async bind(): Promise<void> {
        throw new Error('store unavailable');
      }
    }
    const store = new ThrowingBindStore();
    const agent = await makeIdentity();
    const { server, middleware } = await makeServer({ grantStore: store });
    const sessionId = await openSession(middleware, server.did);

    const vc = await issueVC(agent.did);
    const result = await delegationHandler(middleware)(
      { item: 'laptop', _kyaos_delegation: vc },
      sessionId,
    );
    // bindGrantOnSuccess swallows the store failure — the handler still runs.
    expect(reached(result)).toBe(true);
  });
});
