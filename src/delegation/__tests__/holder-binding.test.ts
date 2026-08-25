import { describe, it, expect, beforeAll } from 'vitest';
import {
  assertHolderBinding,
  generateRequestProof,
  toHolderBindingRequest,
  HOLDER_BINDING_ERROR,
} from '../holder-binding.js';
import { ProofGenerator } from '../../proof/generator.js';
import { ProofVerifier } from '../../proof/verifier.js';
import type { ToolRequest } from '../../proof/generator.js';
import type { DetachedProof } from '../../types/protocol.js';
import type { AgentIdentity } from '../../providers/base.js';
import { didKeyFragment } from '../../utils/did-helpers.js';
import {
  createRealCryptoProvider,
  createRealIdentity,
  RealClockProvider,
  RealFetchProvider,
  MemoryNonceCacheProvider,
} from '../../__tests__/audit/helpers/crypto-helpers.js';

/**
 * Holder binding closes the §11.8 theft-replay residual. A delegation names a
 * subject DID; the caller must prove possession of that DID's key on the
 * request. For a did:key subject the DID *is* the key, so proving possession =
 * the request proof verifying against the subject DID's key. A proof signed by
 * any other key — a thief replaying a stolen credential — does not verify and is
 * rejected. did:web subjects (key not encoded in the DID) are out of phase-1
 * scope and reported `not_applicable` so the gate can defer them to cnf binding
 * rather than reject legitimate traffic.
 */

const crypto = createRealCryptoProvider();
const AUDIENCE = 'did:web:server.example.com';

function makeVerifier(): ProofVerifier {
  return new ProofVerifier({
    cryptoProvider: crypto,
    clockProvider: new RealClockProvider(),
    nonceCacheProvider: new MemoryNonceCacheProvider(),
    fetchProvider: new RealFetchProvider(),
    timestampSkewSeconds: 300,
  });
}

const request: ToolRequest = { method: 'tools/call', params: { name: 'read_vault' } };

/**
 * A request-only detached proof signed by `identity` — the realistic inbound
 * shape (the agent has no response yet when it makes the call).
 */
async function signRequestProof(identity: AgentIdentity): Promise<DetachedProof> {
  const gen = new ProofGenerator(
    {
      did: identity.did,
      kid: identity.kid,
      privateKey: identity.privateKey,
      publicKey: identity.publicKey,
    },
    crypto,
  );
  const now = Math.floor(Date.now() / 1000);
  return gen.generateProof(request, undefined, {
    sessionId: 'sess-1',
    audience: AUDIENCE,
    nonce: `nonce-${now}-${Math.random().toString(36).slice(2)}`,
    timestamp: now,
    createdAt: now,
    lastActivity: now,
    ttlMinutes: 30,
    identityState: 'anonymous',
  });
}

describe('assertHolderBinding', () => {
  let agent: AgentIdentity;
  let attacker: AgentIdentity;

  beforeAll(async () => {
    agent = await createRealIdentity(crypto);
    attacker = await createRealIdentity(crypto);
  });

  it("binds a proof signed by the delegation subject's own key", async () => {
    const proof = await signRequestProof(agent);
    const result = await assertHolderBinding({
      proof,
      subjectDid: agent.did,
      request,
      proofVerifier: makeVerifier(),
    });
    expect(result.status).toBe('bound');
    expect(result.errorCode).toBeUndefined();
  });

  it('rejects a proof whose subject does not match the delegation subject', async () => {
    // Attacker holds the leaked VC (subject = agent) but signs as themselves, so
    // the proof self-declares the attacker. Caught by the pre-crypto check.
    const proof = await signRequestProof(attacker);
    const result = await assertHolderBinding({
      proof,
      subjectDid: agent.did,
      request,
      proofVerifier: makeVerifier(),
    });
    expect(result.status).toBe('unbound');
    expect(result.errorCode).toBe(HOLDER_BINDING_ERROR);
    expect(result.reason).toBeTruthy();
  });

  it('rejects a stolen-credential replay: proof claims the subject but is signed by another key', async () => {
    // The crucial cryptographic case. Attacker forges BOTH meta.did and meta.kid
    // to impersonate the subject — defeating the subject pre-check AND the kid
    // check — but cannot sign with the subject's key. The reconstructed payload
    // binds sub/iss = subject, so the attacker's signature cannot verify against
    // the subject's key: only the Ed25519 check can reject this, and it does.
    const attackerProof = await signRequestProof(attacker);
    const forged: DetachedProof = {
      jws: attackerProof.jws,
      meta: {
        ...attackerProof.meta,
        did: agent.did,
        kid: `${agent.did}#${didKeyFragment(agent.did)}`,
      },
    };
    const result = await assertHolderBinding({
      proof: forged,
      subjectDid: agent.did,
      request,
      proofVerifier: makeVerifier(),
    });
    expect(result.status).toBe('unbound');
    expect(result.errorCode).toBe(HOLDER_BINDING_ERROR);
  });

  it('rejects a tampered request (content binding) even from the right signer', async () => {
    const proof = await signRequestProof(agent);
    const result = await assertHolderBinding({
      proof,
      subjectDid: agent.did,
      request: { method: 'tools/call', params: { name: 'DIFFERENT_tool' } },
      proofVerifier: makeVerifier(),
    });
    expect(result.status).toBe('unbound');
    expect(result.errorCode).toBe(HOLDER_BINDING_ERROR);
  });

  it('reports not_applicable for a non-did:key subject (deferred to phase-2 cnf binding)', async () => {
    const proof = await signRequestProof(agent);
    const result = await assertHolderBinding({
      proof,
      subjectDid: 'did:web:agent.example.com',
      request,
      proofVerifier: makeVerifier(),
    });
    // Phase 1 binds did:key subjects (DID == key). did:web needs an explicit cnf
    // claim; report not_applicable so the gate defers rather than rejects.
    expect(result.status).toBe('not_applicable');
    expect(result.errorCode).toBeUndefined();
  });

  it('fails closed (unbound) on a structurally malformed proof — never throws', async () => {
    // A proof object with no meta (e.g. the gate's {} substitution after a failed
    // JSON.parse) must fail closed, not throw an uncaught error.
    const result = await assertHolderBinding({
      proof: {} as unknown as DetachedProof,
      subjectDid: agent.did,
      request,
      proofVerifier: makeVerifier(),
    });
    expect(result.status).toBe('unbound');
    expect(result.errorCode).toBe(HOLDER_BINDING_ERROR);
  });
});

describe('generateRequestProof + toHolderBindingRequest (client mint <-> PEP assert)', () => {
  let agent: AgentIdentity;

  beforeAll(async () => {
    agent = await createRealIdentity(crypto);
  });

  it('toHolderBindingRequest binds tool name + business args, stripping _kyaos_* control keys', () => {
    expect(
      toHolderBindingRequest('read_vault', {
        path: '/x',
        _kyaos_delegation: { id: 'vc-1' },
        _kyaos_proof: { jws: 'x', meta: {} },
      }),
    ).toEqual({ method: 'read_vault', params: { path: '/x' } });
  });

  it('a proof minted by the subject round-trips to bound at the PEP', async () => {
    const args = { path: '/secret', _kyaos_delegation: { id: 'vc-1' } };
    const proof = await generateRequestProof({
      identity: agent,
      crypto,
      toolName: 'read_vault',
      args,
      audience: AUDIENCE,
      sessionId: 'sess-1',
    });
    const result = await assertHolderBinding({
      proof,
      subjectDid: agent.did,
      request: toHolderBindingRequest('read_vault', args),
      proofVerifier: makeVerifier(),
    });
    expect(result.status).toBe('bound');
  });

  it('a proof minted WITHOUT a sessionId still binds (sessionless request proof)', async () => {
    // `sessionId` is optional on GenerateRequestProofInput - a request proof can
    // precede any handshake, which is the normal case for a stateless MCP core.
    // But `meta.sessionId` is a required NON-EMPTY string in the proof schema,
    // so defaulting it to '' minted a proof that could never verify: the
    // legitimate holder came back `unbound`/INVALID_PROOF_STRUCTURE, exactly
    // like a thief. Every other test here passes a sessionId explicitly, which
    // is why that never surfaced.
    const args = { path: '/secret' };
    const proof = await generateRequestProof({
      identity: agent,
      crypto,
      toolName: 'read_vault',
      args,
      audience: AUDIENCE,
    });
    expect(proof.meta.sessionId).not.toBe('');
    const result = await assertHolderBinding({
      proof,
      subjectDid: agent.did,
      request: toHolderBindingRequest('read_vault', args),
      proofVerifier: makeVerifier(),
    });
    expect(result.status).toBe('bound');
  });

  it('a proof minted for one call does not bind a different call (content binding)', async () => {
    const proof = await generateRequestProof({
      identity: agent,
      crypto,
      toolName: 'read_vault',
      args: { path: '/a' },
      audience: AUDIENCE,
      sessionId: 'sess-1',
    });
    const result = await assertHolderBinding({
      proof,
      subjectDid: agent.did,
      request: toHolderBindingRequest('read_vault', { path: '/b' }),
      proofVerifier: makeVerifier(),
    });
    expect(result.status).toBe('unbound');
  });

  it('each minted proof carries a fresh nonce (replay protection)', async () => {
    const base = { identity: agent, crypto, toolName: 't', args: {}, audience: AUDIENCE, sessionId: 's' };
    const p1 = await generateRequestProof(base);
    const p2 = await generateRequestProof(base);
    expect(p1.meta.nonce).not.toBe(p2.meta.nonce);
  });
});

describe('assertHolderBinding — audience binding (confused-deputy guard)', () => {
  let agent: AgentIdentity;

  beforeAll(async () => {
    agent = await createRealIdentity(crypto);
  });

  it('accepts when expectedAudience matches the proof audience', async () => {
    const proof = await signRequestProof(agent);
    const result = await assertHolderBinding({
      proof,
      subjectDid: agent.did,
      request,
      expectedAudience: AUDIENCE,
      proofVerifier: makeVerifier(),
    });
    expect(result.status).toBe('bound');
  });

  it('accepts when expectedAudience is an array containing the proof audience (rotation / multi-DID)', async () => {
    const proof = await signRequestProof(agent);
    const result = await assertHolderBinding({
      proof,
      subjectDid: agent.did,
      request,
      expectedAudience: ['did:web:old.example.com', AUDIENCE],
      proofVerifier: makeVerifier(),
    });
    expect(result.status).toBe('bound');
  });

  it('rejects a proof minted for a different server (audience mismatch)', async () => {
    const proof = await signRequestProof(agent);
    const result = await assertHolderBinding({
      proof,
      subjectDid: agent.did,
      request,
      expectedAudience: 'did:web:other-server.example.com',
      proofVerifier: makeVerifier(),
    });
    expect(result.status).toBe('unbound');
    expect(result.errorCode).toBe(HOLDER_BINDING_ERROR);
    expect(result.cause).toBe('audience_mismatch');
  });

  it('omitting expectedAudience preserves prior behavior (no audience check)', async () => {
    const proof = await signRequestProof(agent);
    const result = await assertHolderBinding({
      proof,
      subjectDid: agent.did,
      request,
      proofVerifier: makeVerifier(),
    });
    expect(result.status).toBe('bound');
  });
});
