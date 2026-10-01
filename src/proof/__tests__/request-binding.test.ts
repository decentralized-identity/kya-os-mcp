/**
 * The request a proof binds (SPEC §7.3, Appendix C.1).
 *
 * Producers in 1.x hash a tool call's legacy shape `{method: <tool name>,
 * params: <arguments>}`. Verifiers accept a hash over that shape or over the
 * §7.3 covered `tools/call` request, whichever shape the caller holds the call
 * in. These tests pin both halves: what producers emit, and what every
 * verifier of a received request hash accepts and rejects.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  ProofGenerator,
  acceptedRequestHashes,
  computeCanonicalHashes,
  type ToolRequest,
  type ToolResponse,
} from '../generator.js';
import { alternateRequestShapes } from '../covered-request.js';
import { ProofVerifier } from '../verifier.js';
import { KYA_OS_PROOF_META_KEY } from '../index.js';
import { createKyaOsMiddleware } from '../../middleware/with-kya-os.js';
import {
  assertHolderBinding,
  generateRequestProof,
  toHolderBindingRequest,
} from '../../delegation/holder-binding.js';
import { extractPublicKeyFromDidKey, publicKeyToJwk } from '../../delegation/did-key-resolver.js';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import {
  createRealIdentity,
  MemoryNonceCacheProvider,
  RealClockProvider,
  RealFetchProvider,
} from '../../__tests__/audit/helpers/crypto-helpers.js';
import type { AgentIdentity } from '../../providers/base.js';
import type { DetachedProof, SessionContext } from '../../types/protocol.js';
import type { Ed25519JWK } from '../../utils/crypto-service.js';
import type { PolicyEngine } from '../../policy/engine.js';

const crypto = new NodeCryptoProvider();
const hash = (bytes: Uint8Array) => crypto.hash(bytes);

/** SPEC Appendix C.1: {"method":"tools/call","params":{"name":"echo","arguments":{}}} */
const C1_REQUEST_HASH =
  'sha256:5057521f310b536837b619f0ac040ef8064f8c597da8ec22a56801b435744033';

/** The hash producers sign: computeCanonicalHashes over the request as given. */
async function requestHashOf(request: ToolRequest): Promise<string> {
  return (await computeCanonicalHashes(request, undefined, hash)).requestHash;
}

/** The legacy shape 1.x producers hash. */
const legacyCall = (name: string, args: Record<string, unknown>): ToolRequest => ({
  method: name,
  params: args,
});

/** The SPEC §7.3 covered request, as a producer following the specification hashes it. */
const coveredCall = (name: string, args: Record<string, unknown>): ToolRequest => ({
  method: 'tools/call',
  params: { name, arguments: args },
});

/** A tools/call as a client puts it on the wire, transport metadata included. */
const wireCall = (name: string, args: Record<string, unknown>): ToolRequest => ({
  method: 'tools/call',
  params: {
    name,
    arguments: args,
    _meta: { traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01' },
  },
});

const SERVER = 'did:web:server.example.com';

function session(audience = SERVER): SessionContext {
  const now = Math.floor(Date.now() / 1000);
  return {
    sessionId: 'sess_request_binding',
    audience,
    nonce: 'session-nonce',
    timestamp: now,
    createdAt: now,
    lastActivity: now,
    ttlMinutes: 30,
    identityState: 'anonymous',
  };
}

function makeVerifier(): ProofVerifier {
  return new ProofVerifier({
    cryptoProvider: crypto,
    clockProvider: new RealClockProvider(),
    nonceCacheProvider: new MemoryNonceCacheProvider(),
    fetchProvider: new RealFetchProvider(),
    timestampSkewSeconds: 300,
  });
}

/** The signer's key, read from its did:key. */
function signerKey(proof: DetachedProof): Ed25519JWK {
  const jwk = publicKeyToJwk(extractPublicKeyFromDidKey(proof.meta.did)!) as Ed25519JWK;
  jwk.kid = proof.meta.kid;
  return jwk;
}

async function verifyAgainst(proof: DetachedProof, request: ToolRequest, response?: ToolResponse) {
  return makeVerifier().verifyProof(proof, signerKey(proof), {
    request,
    ...(response !== undefined ? { response } : {}),
  });
}

async function middlewareWithSession() {
  const signer = await createRealIdentity(crypto);
  const middleware = createKyaOsMiddleware({ identity: signer }, crypto);
  const hs = await middleware.handleHandshake({
    nonce: `nonce-${Math.random().toString(36).slice(2)}`,
    audience: signer.did,
    timestamp: Math.floor(Date.now() / 1000),
  });
  const sessionId = JSON.parse(hs.content[0]!.text).sessionId as string;
  return { middleware, sessionId };
}

const proofOf = (result: Record<string, unknown>): DetachedProof =>
  (result._meta as Record<string, unknown>)[KYA_OS_PROOF_META_KEY] as DetachedProof;

describe('producers keep the legacy request hash', () => {
  it('binds a response proof to {method: <tool name>, params: <arguments>}', async () => {
    const { middleware, sessionId } = await middlewareWithSession();
    const handler = middleware.wrapWithProof('echo', async () => ({
      content: [{ type: 'text', text: 'hi' }],
    }));

    const proof = proofOf(await handler({ msg: 'hi' }, sessionId));

    expect(proof.meta.requestHash).toBe(await requestHashOf(legacyCall('echo', { msg: 'hi' })));
  });

  it('advertises the legacy hash in a step-up challenge', async () => {
    const { middleware, sessionId } = await middlewareWithSession();
    const handler = middleware.withPolicyGate!(
      'db.drop',
      async () => ({ content: [{ type: 'text', text: 'ran' }] }),
      { resolveNamespace: () => 'prod', scopeMatched: true },
    );

    const result = await handler({ table: 'users', _kyaos_approvals: [] }, sessionId);
    const challenge = JSON.parse(result.content[0]!.text) as { requestHash: string };

    expect(challenge.requestHash).toBe(await requestHashOf(legacyCall('db.drop', { table: 'users' })));
  });

  it('mints a holder-binding request proof over the legacy shape', async () => {
    const agent = await createRealIdentity(crypto);
    const proof = await generateRequestProof({
      identity: agent,
      crypto,
      toolName: 'read_vault',
      args: { path: '/secret', _kyaos_delegation: { id: 'vc-1' } },
      audience: SERVER,
    });

    expect(proof.meta.requestHash).toBe(await requestHashOf(legacyCall('read_vault', { path: '/secret' })));
  });
});

describe('verifiers accept either shape of the same call', () => {
  let signer: AgentIdentity;
  let generator: ProofGenerator;
  const response: ToolResponse = { data: [{ type: 'text', text: 'hi' }] };

  beforeAll(async () => {
    signer = await createRealIdentity(crypto);
    generator = new ProofGenerator(signer, crypto);
  });

  it('verifies a legacy-shaped proof against the request as sent', async () => {
    const proof = await generator.generateProof(legacyCall('echo', { msg: 'hi' }), response, session());

    const sent = wireCall('echo', { msg: 'hi', _kyaos_delegation: { id: 'vc-1' } });
    expect(await verifyAgainst(proof, sent, response)).toMatchObject({ valid: true });
    expect(await verifyAgainst(proof, legacyCall('echo', { msg: 'hi' }), response))
      .toMatchObject({ valid: true });
  });

  it('verifies a proof over the §7.3 covered request against either shape', async () => {
    const proof = await generator.generateProof(coveredCall('echo', { msg: 'hi' }), response, session());

    const sent = wireCall('echo', { msg: 'hi', _kyaos_proof: { jws: 'a..b', meta: {} } });
    expect(await verifyAgainst(proof, sent, response)).toMatchObject({ valid: true });
    expect(await verifyAgainst(proof, legacyCall('echo', { msg: 'hi' }), response))
      .toMatchObject({ valid: true });
  });

  it('verifies proofs over the Appendix C.1 covered-request vectors', async () => {
    const wire = (json: string) => JSON.parse(json) as ToolRequest;
    const empty = await generator.generateProof(coveredCall('echo', {}), undefined, session());
    expect(empty.meta.requestHash).toBe(C1_REQUEST_HASH);
    for (const json of [
      '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"_kyaos_proof":{"jws":"...","meta":{}}},"_meta":{"traceparent":"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"}}}',
      '{"method":"tools/call","params":{"name":"echo"}}',
    ]) {
      expect(await verifyAgainst(empty, wire(json))).toMatchObject({ valid: true });
    }

    const withMsg = await generator.generateProof(coveredCall('echo', { msg: 'hi' }), undefined, session());
    expect(withMsg.meta.requestHash).toBe(
      'sha256:c8f3d59959c9247211de8c76b94ef17f0c279f09362350ced67f69ecdb89d6c7',
    );
    expect(
      await verifyAgainst(
        withMsg,
        wire('{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"hi","_kyaos_delegation":{"id":"urn:uuid:1111-aaaa"}},"_meta":{"progressToken":7}}}'),
      ),
    ).toMatchObject({ valid: true });
  });

  it('still rejects a hash of a different call in either shape', async () => {
    for (const minted of [legacyCall('echo', { msg: 'hi' }), coveredCall('echo', { msg: 'hi' })]) {
      const proof = await generator.generateProof(minted, response, session());
      for (const other of [
        legacyCall('echo', { msg: 'bye' }),
        wireCall('echo', { msg: 'bye' }),
        wireCall('shout', { msg: 'hi' }),
        coveredCall('echo', { msg: 'hi', extra: true }),
      ]) {
        expect(await verifyAgainst(proof, other, response)).toMatchObject({
          valid: false,
          errorCode: 'CONTENT_BINDING_MISMATCH',
        });
      }
    }
  });

  it('applies the same rule in ProofGenerator.verifyProof', async () => {
    const legacy = await generator.generateProof(legacyCall('echo', { msg: 'hi' }), response, session());
    const covered = await generator.generateProof(coveredCall('echo', { msg: 'hi' }), response, session());

    expect(await generator.verifyProof(legacy, wireCall('echo', { msg: 'hi' }), response)).toBe(true);
    expect(await generator.verifyProof(covered, legacyCall('echo', { msg: 'hi' }), response)).toBe(true);
    expect(await generator.verifyProof(covered, legacyCall('echo', { msg: 'bye' }), response)).toBe(false);
  });

  it('binds a holder proof over the §7.3 request at the PEP, as well as a legacy one', async () => {
    const agent = await createRealIdentity(crypto);
    const client = new ProofGenerator(agent, crypto);
    const business = { path: '/secret' };
    const legacyProof = await generateRequestProof({
      identity: agent, crypto, toolName: 'read_vault', args: business, audience: SERVER,
    });
    const coveredProof = await client.generateProof(
      coveredCall('read_vault', business),
      undefined,
      { ...session(), sessionId: 'req-covered', nonce: 'covered' },
    );

    for (const proof of [legacyProof, coveredProof]) {
      // The PEP holds the arguments as received, the proof among them.
      const received = { ...business, _kyaos_delegation: { id: 'vc-1' }, _kyaos_proof: proof };
      const binding = await assertHolderBinding({
        proof,
        subjectDid: agent.did,
        request: toHolderBindingRequest('read_vault', received),
        expectedAudience: SERVER,
        proofVerifier: makeVerifier(),
      });
      expect(binding.status).toBe('bound');
    }

    const elsewhere = await assertHolderBinding({
      proof: coveredProof,
      subjectDid: agent.did,
      request: toHolderBindingRequest('read_vault', { path: '/other' }),
      proofVerifier: makeVerifier(),
    });
    expect(elsewhere.status).toBe('unbound');
  });

  it('satisfies a step-up with an approval over the §7.3 request hash', async () => {
    const { middleware, sessionId } = await middlewareWithSession();
    const engine: PolicyEngine = {
      async evaluate() {
        return { decision: 'step_up', quorum: { n: 1, approvers: [] }, reason: 'destructive' };
      },
    };
    const handler = middleware.withPolicyGate!(
      'db.drop',
      async () => ({ content: [{ type: 'text', text: 'ran' }] }),
      { engine, scopeMatched: true, isValidApprovalSignature: async () => true },
    );
    const approval = async (args: Record<string, unknown>) => ({
      approvalRequestId: 'r1',
      approverDid: 'did:example:approver',
      requestHash: await requestHashOf(coveredCall('db.drop', args)),
      decision: 'approve',
      ts: Math.floor(Date.now() / 1000),
      signature: 'sig',
    });

    const approved = await handler(
      { table: 'users', _kyaos_approvals: [await approval({ table: 'users' })] },
      sessionId,
    );
    expect(approved.content[0]!.text).toBe('ran');

    const misdirected = await handler(
      { table: 'users', _kyaos_approvals: [await approval({ table: 'orders' })] },
      sessionId,
    );
    expect(JSON.parse(misdirected.content[0]!.text).error).toBe('needs_approval');
  });
});

describe('the shapes of one call', () => {
  it('derives the same shapes from the legacy and the wire form of a call', () => {
    const args = { msg: 'hi', _kyaos_proof: { jws: 'a..b', meta: {} } };

    expect(alternateRequestShapes(wireCall('echo', args))).toEqual(
      alternateRequestShapes(legacyCall('echo', args)),
    );
    expect(alternateRequestShapes(legacyCall('echo', args))).toEqual([
      coveredCall('echo', { msg: 'hi' }),
      legacyCall('echo', args),
      legacyCall('echo', { msg: 'hi' }),
    ]);
  });

  it('keeps params members other than _meta in the covered request', () => {
    const sent: ToolRequest = {
      method: 'tools/call',
      params: { name: 'echo', arguments: { msg: 'hi' }, task: { ttl: 1 }, _meta: { progressToken: 1 } },
    };

    expect(alternateRequestShapes(sent)[0]).toEqual({
      method: 'tools/call',
      params: { name: 'echo', arguments: { msg: 'hi' }, task: { ttl: 1 } },
    });
  });

  it('accepts only the hash of the request as given when its arguments are not an object', async () => {
    for (const request of [
      { method: 'tools/call', params: { name: 'echo', arguments: ['hi'] } },
      { method: 'echo', params: ['hi'] },
      { method: 'echo', params: 'hi' },
    ]) {
      expect(alternateRequestShapes(request)).toEqual([]);
      expect(await acceptedRequestHashes(request, hash)).toEqual([await requestHashOf(request)]);
    }
  });
});
