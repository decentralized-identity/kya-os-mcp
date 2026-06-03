import { describe, it, expect } from 'vitest';
import { createKyaOsMiddleware, type KyaOsDelegationConfig } from '../with-kya-os.js';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { generateDidKeyFromBase64 } from '../../utils/did-helpers.js';
import { DelegationCredentialIssuer } from '../../delegation/vc-issuer.js';
import { generateRequestProof } from '../../delegation/holder-binding.js';
import type { DelegationCredential, Proof } from '../../types/protocol.js';
import type { ProofAgentIdentity } from '../../proof/generator.js';
import type { NonceCacheProvider } from '../../providers/base.js';
import { MemoryNonceCacheProvider } from '../../providers/memory.js';
import { base64urlEncodeFromBytes } from '../../utils/base64.js';

/**
 * Holder binding at the PEP (spec §11.8). The gate already validates the
 * delegation *credential*; these tests prove it now also enforces that the
 * caller holds the delegation *subject's* key — closing theft-replay for the
 * key-bearing did:key population. Enforcement is opt-in (off | warn | enforce).
 */

const crypto = new NodeCryptoProvider();
const SCOPE = 'vault:read';

async function makeIdentity(): Promise<ProofAgentIdentity> {
  const kp = await crypto.generateKeyPair();
  const did = generateDidKeyFromBase64(kp.publicKey);
  return { did, kid: `${did}#${did.replace('did:key:', '')}`, privateKey: kp.privateKey, publicKey: kp.publicKey };
}

function makeServer(
  holderBinding?: KyaOsDelegationConfig['holderBinding'],
  nonceCache?: NonceCacheProvider,
) {
  // The server identity (the PEP's own DID).
  return makeIdentity().then((server) => ({
    server,
    middleware: createKyaOsMiddleware(
      {
        identity: server,
        session: { sessionTtlMinutes: 60 },
        delegation: holderBinding ? { holderBinding } : undefined,
        ...(nonceCache ? { nonceCache } : {}),
      },
      crypto,
    ),
  }));
}

/** A nonce cache that records every nonce added, to prove one instance is shared. */
class RecordingNonceCache extends MemoryNonceCacheProvider {
  readonly added = new Set<string>();
  async add(nonce: string, ttlSeconds: number, agentDid?: string): Promise<void> {
    this.added.add(nonce);
    return super.add(nonce, ttlSeconds, agentDid);
  }
}

/** Issue a delegation VC (issuer-signed) naming `subjectDid` as the holder. */
async function issueVC(subjectDid: string, scopes: string[] = [SCOPE]): Promise<DelegationCredential> {
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
    constraints: { scopes, notAfter: Math.floor(Date.now() / 1000) + 3600 },
  });
}

async function openSession(middleware: Awaited<ReturnType<typeof makeServer>>['middleware'], serverDid: string) {
  const hs = await middleware.handleHandshake({
    nonce: `hs-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    audience: serverDid,
    timestamp: Math.floor(Date.now() / 1000),
  });
  return JSON.parse(hs.content[0].text).sessionId as string;
}

const REACHED = { content: [{ type: 'text' as const, text: 'reached-handler' }] };
const handlerThatRuns = async () => REACHED;

function parse(result: Awaited<ReturnType<typeof handlerThatRuns>> & { isError?: boolean }) {
  return JSON.parse(result.content[0].text);
}

describe('wrapWithDelegation — holder binding', () => {
  it("enforce: a call carrying the subject's request proof reaches the handler", async () => {
    const { server, middleware } = await makeServer('enforce');
    const agent = await makeIdentity();
    const vc = await issueVC(agent.did);
    const sessionId = await openSession(middleware, server.did);

    const args = { path: '/secret', _kyaos_delegation: vc };
    const proof = await generateRequestProof({
      identity: agent, crypto, toolName: 'my-tool', args, audience: server.did, sessionId,
    });

    const handler = middleware.wrapWithDelegation(
      'my-tool',
      { scopeId: SCOPE, consentUrl: 'https://example.com/consent' },
      handlerThatRuns,
    );
    const result = await handler({ ...args, _kyaos_proof: proof }, sessionId);

    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toBe('reached-handler');
  });

  it('enforce: a call with NO request proof is rejected (holder binding required)', async () => {
    const { server, middleware } = await makeServer('enforce');
    const agent = await makeIdentity();
    const vc = await issueVC(agent.did);
    const sessionId = await openSession(middleware, server.did);

    const handler = middleware.wrapWithDelegation(
      'my-tool',
      { scopeId: SCOPE, consentUrl: 'https://example.com/consent' },
      handlerThatRuns,
    );
    const result = await handler({ path: '/secret', _kyaos_delegation: vc }, sessionId);

    expect(result.isError).toBe(true);
    expect(parse(result).error).toBe('holder_binding_failed');
  });

  it('enforce: a proof signed by a DIFFERENT key (stolen credential) is rejected', async () => {
    const { server, middleware } = await makeServer('enforce');
    const agent = await makeIdentity();
    const attacker = await makeIdentity();
    const vc = await issueVC(agent.did); // VC names the agent as subject
    const sessionId = await openSession(middleware, server.did);

    const args = { path: '/secret', _kyaos_delegation: vc };
    // The attacker holds the leaked VC but signs with their own key.
    const forgedProof = await generateRequestProof({
      identity: attacker, crypto, toolName: 'my-tool', args, audience: server.did, sessionId,
    });

    const handler = middleware.wrapWithDelegation(
      'my-tool',
      { scopeId: SCOPE, consentUrl: 'https://example.com/consent' },
      handlerThatRuns,
    );
    const result = await handler({ ...args, _kyaos_proof: forgedProof }, sessionId);

    expect(result.isError).toBe(true);
    expect(parse(result).error).toBe('holder_binding_failed');
  });

  it('warn: a call with no proof still reaches the handler (logged, not enforced)', async () => {
    const { server, middleware } = await makeServer('warn');
    const agent = await makeIdentity();
    const vc = await issueVC(agent.did);
    const sessionId = await openSession(middleware, server.did);

    const handler = middleware.wrapWithDelegation(
      'my-tool',
      { scopeId: SCOPE, consentUrl: 'https://example.com/consent' },
      handlerThatRuns,
    );
    const result = await handler({ path: '/secret', _kyaos_delegation: vc }, sessionId);

    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toBe('reached-handler');
  });

  it('off (default): no proof required — behavior is unchanged', async () => {
    const { middleware } = await makeServer(); // no holderBinding config
    const agent = await makeIdentity();
    const vc = await issueVC(agent.did);

    const handler = middleware.wrapWithDelegation(
      'my-tool',
      { scopeId: SCOPE, consentUrl: 'https://example.com/consent' },
      handlerThatRuns,
    );
    const result = await handler({ path: '/secret', _kyaos_delegation: vc });

    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toBe('reached-handler');
  });

  it('enforce: a non-did:key (did:web) subject is deferred (not_applicable), not rejected', async () => {
    const { server, middleware } = await makeServer('enforce');
    const vc = await issueVC('did:web:agent.example.com');
    const sessionId = await openSession(middleware, server.did);

    const handler = middleware.wrapWithDelegation(
      'my-tool',
      { scopeId: SCOPE, consentUrl: 'https://example.com/consent' },
      handlerThatRuns,
    );
    // No proof, did:web subject → phase-1 cannot bind it → deferred (allowed).
    const result = await handler({ path: '/secret', _kyaos_delegation: vc }, sessionId);

    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toBe('reached-handler');
  });

  it('enforce: a proof minted for a DIFFERENT server (wrong audience) is rejected', async () => {
    const { server, middleware } = await makeServer('enforce');
    const agent = await makeIdentity();
    const vc = await issueVC(agent.did);
    const sessionId = await openSession(middleware, server.did);

    const args = { path: '/secret', _kyaos_delegation: vc };
    const proof = await generateRequestProof({
      identity: agent,
      crypto,
      toolName: 'my-tool',
      args,
      audience: 'did:web:evil.example.com', // minted for someone else
      sessionId,
    });

    const handler = middleware.wrapWithDelegation(
      'my-tool',
      { scopeId: SCOPE, consentUrl: 'https://example.com/consent' },
      handlerThatRuns,
    );
    const result = await handler({ ...args, _kyaos_proof: proof }, sessionId);

    expect(result.isError).toBe(true);
    expect(parse(result).error).toBe('holder_binding_failed');
  });

  it('enforce: replaying the same _kyaos_proof is rejected the second time (nonce replay)', async () => {
    const { server, middleware } = await makeServer('enforce');
    const agent = await makeIdentity();
    const vc = await issueVC(agent.did);
    const sessionId = await openSession(middleware, server.did);

    const args = { path: '/secret', _kyaos_delegation: vc };
    const proof = await generateRequestProof({
      identity: agent, crypto, toolName: 'my-tool', args, audience: server.did, sessionId,
    });
    const handler = middleware.wrapWithDelegation(
      'my-tool',
      { scopeId: SCOPE, consentUrl: 'https://example.com/consent' },
      handlerThatRuns,
    );

    const first = await handler({ ...args, _kyaos_proof: proof }, sessionId);
    const second = await handler({ ...args, _kyaos_proof: proof }, sessionId);

    expect(first.content[0].text).toBe('reached-handler');
    expect(second.isError).toBe(true);
    expect(parse(second).error).toBe('holder_binding_failed');
  });

  it('a caller-injected NonceCacheProvider is shared by the handshake and holder binding', async () => {
    const cache = new RecordingNonceCache();
    const { server, middleware } = await makeServer('enforce', cache);
    const agent = await makeIdentity();
    const vc = await issueVC(agent.did);
    const sessionId = await openSession(middleware, server.did); // handshake adds a nonce

    const args = { path: '/secret', _kyaos_delegation: vc };
    const proof = await generateRequestProof({
      identity: agent, crypto, toolName: 'my-tool', args, audience: server.did, sessionId,
    });
    const handler = middleware.wrapWithDelegation(
      'my-tool',
      { scopeId: SCOPE, consentUrl: 'https://example.com/consent' },
      handlerThatRuns,
    );
    await handler({ ...args, _kyaos_proof: proof }, sessionId); // holder binding adds the proof nonce

    // ONE injected instance saw both the handshake nonce and the holder-binding proof nonce.
    expect(cache.added.has(proof.meta.nonce)).toBe(true);
    expect(cache.added.size).toBeGreaterThanOrEqual(2);
  });

  it('enforce: the _kyaos_proof control arg never leaks into the handler args', async () => {
    const { server, middleware } = await makeServer('enforce');
    const agent = await makeIdentity();
    const vc = await issueVC(agent.did);
    const sessionId = await openSession(middleware, server.did);

    const args = { path: '/secret', _kyaos_delegation: vc };
    const proof = await generateRequestProof({
      identity: agent, crypto, toolName: 'my-tool', args, audience: server.did, sessionId,
    });

    let seenArgs: Record<string, unknown> | undefined;
    const handler = middleware.wrapWithDelegation(
      'my-tool',
      { scopeId: SCOPE, consentUrl: 'https://example.com/consent' },
      async (a) => {
        seenArgs = a;
        return REACHED;
      },
    );
    await handler({ ...args, _kyaos_proof: proof }, sessionId);

    expect(seenArgs).toBeDefined();
    expect(Object.keys(seenArgs!)).not.toContain('_kyaos_proof');
    expect(Object.keys(seenArgs!)).not.toContain('_kyaos_delegation');
    expect(seenArgs!.path).toBe('/secret');
  });

  it('warn: a present-but-forged proof is logged but still reaches the handler', async () => {
    // warn-mode contract: detect AND allow. A forged proof during rollout must be
    // logged yet not block the call.
    const { server, middleware } = await makeServer('warn');
    const agent = await makeIdentity();
    const attacker = await makeIdentity();
    const vc = await issueVC(agent.did);
    const sessionId = await openSession(middleware, server.did);

    const args = { path: '/secret', _kyaos_delegation: vc };
    const forged = await generateRequestProof({
      identity: attacker, crypto, toolName: 'my-tool', args, audience: server.did, sessionId,
    });
    const handler = middleware.wrapWithDelegation(
      'my-tool',
      { scopeId: SCOPE, consentUrl: 'https://example.com/consent' },
      handlerThatRuns,
    );
    const result = await handler({ ...args, _kyaos_proof: forged }, sessionId);

    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toBe('reached-handler');
  });

  it('enforce: a proof minted for different business args is rejected (content binding through the gate)', async () => {
    const { server, middleware } = await makeServer('enforce');
    const agent = await makeIdentity();
    const vc = await issueVC(agent.did);
    const sessionId = await openSession(middleware, server.did);

    // Proof binds path:/a; the call substitutes path:/b.
    const proof = await generateRequestProof({
      identity: agent, crypto, toolName: 'my-tool', args: { path: '/a', _kyaos_delegation: vc }, audience: server.did, sessionId,
    });
    const handler = middleware.wrapWithDelegation(
      'my-tool',
      { scopeId: SCOPE, consentUrl: 'https://example.com/consent' },
      handlerThatRuns,
    );
    const result = await handler({ path: '/b', _kyaos_delegation: vc, _kyaos_proof: proof }, sessionId);

    expect(result.isError).toBe(true);
    expect(parse(result).error).toBe('holder_binding_failed');
  });

  it('enforce: a valid proof passed as a JSON string round-trips to bound', async () => {
    const { server, middleware } = await makeServer('enforce');
    const agent = await makeIdentity();
    const vc = await issueVC(agent.did);
    const sessionId = await openSession(middleware, server.did);

    const args = { path: '/secret', _kyaos_delegation: vc };
    const proof = await generateRequestProof({
      identity: agent, crypto, toolName: 'my-tool', args, audience: server.did, sessionId,
    });
    const handler = middleware.wrapWithDelegation(
      'my-tool',
      { scopeId: SCOPE, consentUrl: 'https://example.com/consent' },
      handlerThatRuns,
    );
    const result = await handler({ ...args, _kyaos_proof: JSON.stringify(proof) }, sessionId);

    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toBe('reached-handler');
  });

  it('enforce: a malformed string _kyaos_proof fails closed (holder_binding_failed), not a crash', async () => {
    const { server, middleware } = await makeServer('enforce');
    const agent = await makeIdentity();
    const vc = await issueVC(agent.did);
    const sessionId = await openSession(middleware, server.did);

    const handler = middleware.wrapWithDelegation(
      'my-tool',
      { scopeId: SCOPE, consentUrl: 'https://example.com/consent' },
      handlerThatRuns,
    );
    const result = await handler(
      { path: '/secret', _kyaos_delegation: vc, _kyaos_proof: 'not-json{{{' },
      sessionId,
    );

    expect(result.isError).toBe(true);
    expect(parse(result).error).toBe('holder_binding_failed');
  });

  it('enforce: reserved _kyaos* args never reach the handler (strip symmetric with the bound hash)', async () => {
    const { server, middleware } = await makeServer('enforce');
    const agent = await makeIdentity();
    const vc = await issueVC(agent.did);
    const sessionId = await openSession(middleware, server.did);

    const args = { path: '/secret', _kyaos_delegation: vc };
    const proof = await generateRequestProof({
      identity: agent, crypto, toolName: 'my-tool', args, audience: server.did, sessionId,
    });
    let seenArgs: Record<string, unknown> | undefined;
    const handler = middleware.wrapWithDelegation(
      'my-tool',
      { scopeId: SCOPE, consentUrl: 'https://example.com/consent' },
      async (a) => {
        seenArgs = a;
        return REACHED;
      },
    );
    // Smuggle an extra reserved-namespace key. It is excluded from the bound hash
    // (so binding still passes) and MUST also be stripped before the handler.
    const result = await handler(
      { ...args, _kyaos_proof: proof, _kyaos_extra: 'smuggled' },
      sessionId,
    );

    expect(result.content[0].text).toBe('reached-handler');
    expect(Object.keys(seenArgs!)).not.toContain('_kyaos_extra');
  });
});
