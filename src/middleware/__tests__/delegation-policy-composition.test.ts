/**
 * `withPolicyGate` composed inside `wrapWithDelegation`, the documented usage.
 *
 * The delegation gate withholds every `_kyaos*` argument from the handler it
 * wraps, so the policy gate receives the verified principal, its scopes and
 * the approval grants through the call context instead.
 */

import { describe, it, expect } from 'vitest';
import { createKyaOsMiddleware, type KyaOsDelegationConfig } from '../with-kya-os.js';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { generateDidKeyFromBase64, didKeyFragment } from '../../utils/did-helpers.js';
import { DelegationCredentialIssuer } from '../../delegation/vc-issuer.js';
import { generateRequestProof } from '../../delegation/holder-binding.js';
import { ProofGenerator } from '../../proof/generator.js';
import { base64urlEncodeFromBytes } from '../../utils/base64.js';
import type { ProofAgentIdentity } from '../../proof/generator.js';
import type { Proof } from '../../types/protocol.js';
import type { PolicyEngine } from '../../policy/engine.js';
import type { PolicyRequest } from '../../policy/types.js';

const crypto = new NodeCryptoProvider();

async function didKeyIdentity(): Promise<ProofAgentIdentity> {
  const keyPair = await crypto.generateKeyPair();
  const did = generateDidKeyFromBase64(keyPair.publicKey);
  return {
    did,
    kid: `${did}#${didKeyFragment(did)}`,
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
  };
}

async function issueVC(subjectDid: string, scopes: string[], controller: string) {
  const issuer = await didKeyIdentity();
  const sign = async (canonicalVC: string, _issuerDid: string, keyId: string): Promise<Proof> => ({
    type: 'Ed25519Signature2020',
    created: new Date().toISOString(),
    verificationMethod: keyId,
    proofPurpose: 'assertionMethod',
    proofValue: base64urlEncodeFromBytes(
      await crypto.sign(new TextEncoder().encode(canonicalVC), issuer.privateKey as string),
    ),
  });
  return new DelegationCredentialIssuer(
    { getDid: () => issuer.did, getKeyId: () => issuer.kid, getPrivateKey: () => issuer.privateKey as string },
    sign,
  ).createAndIssueDelegation({
    id: `del-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    issuerDid: issuer.did,
    subjectDid,
    controller,
    constraints: { scopes, notAfter: Math.floor(Date.now() / 1000) + 3600 },
  });
}

const text = (result: { content: Array<{ text: string }> }) => result.content[0]!.text;

const approvalFor = (requestHash: string) => ({
  approvalRequestId: 'r1',
  approverDid: 'did:example:approver',
  requestHash,
  decision: 'approve',
  ts: Math.floor(Date.now() / 1000),
  signature: 'sig',
});

async function composed(delegation: KyaOsDelegationConfig = {}) {
  const server = await didKeyIdentity();
  const kyaos = createKyaOsMiddleware(
    { identity: server, session: { sessionTtlMinutes: 60 }, autoSession: true, delegation },
    crypto,
  );
  const agent = await didKeyIdentity();
  const requests: PolicyRequest[] = [];
  const engine: PolicyEngine = {
    async evaluate(request) {
      requests.push(request);
      return { decision: 'step_up', quorum: { n: 1, approvers: [] }, reason: 'destructive' };
    },
  };
  const handlerArgs: Array<Record<string, unknown>> = [];
  const handler = kyaos.wrapWithDelegation(
    'db.drop',
    { scopeId: 'db:admin', consentUrl: 'https://example.com/consent' },
    kyaos.withPolicyGate!(
      'db.drop',
      async (args) => {
        handlerArgs.push(args);
        return { content: [{ type: 'text', text: 'dropped' }] };
      },
      { engine, scopeMatched: true, isValidApprovalSignature: async () => true },
    ),
  );
  const vc = await issueVC(agent.did, ['db:admin', 'db:read'], 'did:web:owner.example');
  return { kyaos, server, agent, vc, handler, requests, handlerArgs };
}

describe('withPolicyGate composed after wrapWithDelegation', () => {
  it('lets approvals in _kyaos_approvals satisfy the step-up', async () => {
    const { vc, handler, handlerArgs } = await composed();
    const challenge = JSON.parse(text(await handler({ table: 'users', _kyaos_delegation: vc })));
    expect(challenge.error).toBe('needs_approval');

    const resumed = await handler({
      table: 'users',
      _kyaos_delegation: vc,
      _kyaos_approvals: [approvalFor(challenge.requestHash)],
    });

    expect(resumed.isError).toBeUndefined();
    expect(text(resumed)).toBe('dropped');
    // Neither gate leaks a control argument into the protected handler.
    expect(handlerArgs).toEqual([{ table: 'users' }]);
  });

  it('gives the engine the principal and scopes the delegation gate verified', async () => {
    const { vc, agent, handler, requests } = await composed();
    await handler({ table: 'users', _kyaos_delegation: vc });

    expect(requests[0]!.principal).toEqual({
      agentDid: agent.did,
      responsibleParty: 'did:web:owner.example',
    });
    expect(requests[0]!.context.delegatedScopes).toEqual(['db:admin', 'db:read']);
  });

  it('gives the engine the verified principal on a durable-grant retry', async () => {
    const { kyaos, server, vc, agent, handler, requests } = await composed();
    const hs = await kyaos.handleHandshake({
      nonce: `grant-retry-${Math.random().toString(16).slice(2)}`,
      audience: server.did,
      timestamp: Math.floor(Date.now() / 1000),
    });
    const sessionId = JSON.parse(text(hs)).sessionId as string;
    await handler({ table: 'users', _kyaos_delegation: vc }, sessionId);

    await handler({ table: 'users' }, sessionId);

    expect(requests).toHaveLength(2);
    expect(requests[1]!.principal.agentDid).toBe(agent.did);
    expect(requests[1]!.context.delegatedScopes).toEqual(['db:admin', 'db:read']);
  });

  it('keeps approvals out of the holder-binding request hash', async () => {
    const { server, agent, vc, handler } = await composed({ holderBinding: 'enforce' });
    const call = async (extra: Record<string, unknown>) => {
      // The agent signs only the business arguments; control args ride alongside.
      const _kyaos_proof = await generateRequestProof({
        identity: agent, crypto, toolName: 'db.drop', args: { table: 'users' }, audience: server.did,
      });
      return handler({ table: 'users', _kyaos_delegation: vc, _kyaos_proof, ...extra });
    };
    const challenge = JSON.parse(text(await call({})));
    expect(challenge.error).toBe('needs_approval');

    const resumed = await call({ _kyaos_approvals: [approvalFor(challenge.requestHash)] });

    expect(text(resumed)).toBe('dropped');
  });

  it('binds a holder proof over the SPEC §7.3 tools/call request', async () => {
    const { server, agent, vc, handler } = await composed({ holderBinding: 'enforce' });
    const now = Math.floor(Date.now() / 1000);
    // A client following SPEC §7.3 signs the tools/call request it sends.
    const _kyaos_proof = await new ProofGenerator(agent, crypto).generateProof(
      { method: 'tools/call', params: { name: 'db.drop', arguments: { table: 'users' } } },
      undefined,
      {
        sessionId: 'req-spec-client',
        audience: server.did,
        nonce: 'spec-client',
        timestamp: now,
        createdAt: now,
        lastActivity: now,
        ttlMinutes: 30,
        identityState: 'anonymous',
      },
    );

    const result = await handler({ table: 'users', _kyaos_delegation: vc, _kyaos_proof });

    // Past the holder binding, the policy gate asks for approval.
    expect(JSON.parse(text(result)).error).toBe('needs_approval');
  });
});
