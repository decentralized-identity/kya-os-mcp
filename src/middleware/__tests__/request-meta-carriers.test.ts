/**
 * Where a `tools/call` carries what KYA-OS reads of it (SPEC.md §14): its session, its delegation,
 * its holder-of-key proof and its approval grants each ride the call's `params._meta`, under a key of
 * their own, and stay out of the tool's arguments. For the 1.x line the `_kyaos_*` arguments are read
 * too; a call that carries a datum both ways is read from `params._meta`.
 *
 * The MCP SDK hands a tool callback the call's `params._meta` in its request context (`extra._meta`,
 * or `ctx.mcpReq._meta` from SDK 2), and the withKyaOs transport sees the request itself. A session a
 * call names is its claim, and every proof carries session ids, so a call is proved under the session
 * it names only where a call that names none would be, and never under another.
 */
import { describe, expect, it, vi } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { withKyaOs } from '../with-kya-os-server.js';
import { createKyaOsMiddleware } from '../with-kya-os.js';
import { toMcpToolCallback } from '../mcp-tool-callback.js';
import {
  KYA_OS_APPROVALS_META_KEY,
  KYA_OS_DELEGATION_META_KEY,
  KYA_OS_HOLDER_PROOF_META_KEY,
  KYA_OS_SESSION_META_KEY,
} from '../request-meta.js';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { generateDidKeyFromBase64, didKeyFragment } from '../../utils/did-helpers.js';
import { DelegationCredentialIssuer } from '../../delegation/vc-issuer.js';
import { generateRequestProof } from '../../delegation/holder-binding.js';
import { base64urlEncodeFromBytes } from '../../utils/base64.js';
import type { ProofAgentIdentity } from '../../proof/generator.js';
import type { DelegationCredential, Proof } from '../../types/protocol.js';
import type { PolicyEngine } from '../../policy/engine.js';
import type { KyaOsCallContext, KyaOsDelegationConfig } from '../with-kya-os.js';
import { createMiddleware, handshake, proofOf, served } from './helpers/received-proof.js';
import { MemorySessionStore } from '../../session/session-store.js';
import { anyRootUnlessListed } from './helpers/root-issuers.js';

const crypto = new NodeCryptoProvider();
const SCOPE = 'vault:read';
const CONSENT = { scopeId: SCOPE, consentUrl: 'https://example.com/consent' };

const ran = async () => ({ content: [{ type: 'text' as const, text: 'ran' }] });
const text = (result: { content: Array<{ text: string }> }) => result.content[0]!.text;

async function didKeyIdentity(): Promise<ProofAgentIdentity> {
  const keyPair = await crypto.generateKeyPair();
  const did = generateDidKeyFromBase64(keyPair.publicKey);
  return { did, kid: `${did}#${didKeyFragment(did)}`, privateKey: keyPair.privateKey, publicKey: keyPair.publicKey };
}

async function issueVC(subjectDid: string, scopes: string[] = [SCOPE]): Promise<DelegationCredential> {
  const issuer = await didKeyIdentity();
  const sign = async (canonicalVC: string, _issuerDid: string, keyId: string): Promise<Proof> => ({
    type: 'Ed25519Signature2020',
    created: new Date().toISOString(),
    verificationMethod: keyId,
    proofPurpose: 'assertionMethod',
    proofValue: base64urlEncodeFromBytes(await crypto.sign(new TextEncoder().encode(canonicalVC), issuer.privateKey as string)),
  });
  return new DelegationCredentialIssuer(
    { getDid: () => issuer.did, getKeyId: () => issuer.kid, getPrivateKey: () => issuer.privateKey as string },
    sign,
  ).createAndIssueDelegation({
    id: `del-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    issuerDid: issuer.did,
    subjectDid,
    constraints: { scopes, notAfter: Math.floor(Date.now() / 1000) + 3600 },
  });
}

async function gated(delegation: KyaOsDelegationConfig = {}) {
  const server = await didKeyIdentity();
  const kyaos = await served(createKyaOsMiddleware(
    { identity: server, session: { sessionTtlMinutes: 60 }, delegation: anyRootUnlessListed(delegation) },
    crypto,
  ));
  return { server, kyaos };
}

describe('the session a call names in params._meta', () => {
  it('proves a call that names the only live session as it proves one that names none, through the MCP tool adapter', async () => {
    const kyaos = await served(await createMiddleware());
    const only = await handshake(kyaos);
    const callback = toMcpToolCallback(kyaos.wrapWithProof('echo', ran));

    expect(proofOf(await callback({}, { _meta: { [KYA_OS_SESSION_META_KEY]: only } }))?.meta.sessionId).toBe(only);
    expect(proofOf(await callback({}, { mcpReq: { _meta: { [KYA_OS_SESSION_META_KEY]: only } } }))?.meta.sessionId).toBe(only);
  });

  it.each([
    ['opened before the caller\'s', false],
    ['opened last, so the server\'s latest', true],
  ])('proves nothing for a call that names another client\'s session, %s, with two sessions live', async (_when, victimLast) => {
    const kyaos = await served(await createMiddleware());
    if (victimLast) await handshake(kyaos);
    const victim = await handshake(kyaos);
    if (!victimLast) await handshake(kyaos);
    const callback = toMcpToolCallback(kyaos.wrapWithProof('echo', ran));

    const result = await callback({}, { _meta: { [KYA_OS_SESSION_META_KEY]: victim } });
    expect(text(result)).toBe('ran');
    expect(proofOf(result)).toBeUndefined();
  });

  it.each([
    ['opened before the caller\'s', false],
    ['opened last, so the server\'s latest', true],
  ])('keeps no session alive for a call that names it, the session %s, with two sessions live', async (_when, victimLast) => {
    vi.useFakeTimers({ toFake: ['Date'] });
    try {
      const kyaos = await served(await createMiddleware({ session: { sessionTtlMinutes: 10 } }));
      if (victimLast) await handshake(kyaos);
      const victim = await handshake(kyaos);
      if (!victimLast) await handshake(kyaos);
      const callback = toMcpToolCallback(kyaos.wrapWithProof('echo', ran));

      vi.advanceTimersByTime(8 * 60_000);
      const result = await callback({}, { _meta: { [KYA_OS_SESSION_META_KEY]: victim } });
      expect(proofOf(result)).toBeUndefined();
      vi.advanceTimersByTime(8 * 60_000);
      expect(await kyaos.sessionManager.getSession(victim)).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });

  it('proves a call under the session it names only where a call naming none would be, so not once the latest has idled out', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    try {
      const kyaos = await served(await createMiddleware({ session: { sessionTtlMinutes: 10 } }));
      const echo = kyaos.wrapWithProof('echo', ran);
      const callback = toMcpToolCallback(echo);
      const first = await handshake(kyaos);
      vi.advanceTimersByTime(6 * 60_000);
      await handshake(kyaos);
      vi.advanceTimersByTime(3 * 60_000);
      // The host threads the first session, which keeps it alive.
      await echo({}, first);
      vi.advanceTimersByTime(8 * 60_000);

      // The latest session has idled out and the first is the only one live, but a call that
      // names none is not proved under it either: only the server's own record of its latest
      // handshake, which no caller sets, chooses a session a call names.
      const result = await callback({}, { _meta: { [KYA_OS_SESSION_META_KEY]: first } });
      expect(proofOf(result)?.meta.sessionId).not.toBe(first);
    } finally {
      vi.useRealTimers();
    }
  });

  it.each([
    ['this instance', false],
    ['another instance sharing its store', true],
  ])('proves nothing under another client\'s session a call names on %s, where the store counts its sessions only roughly', async (_where, elsewhere) => {
    // A durable store reports a best-effort count (SessionStore.size), here none at all.
    class RoughlyCounted extends MemorySessionStore {
      override size(): number {
        return 0;
      }
    }
    const sessionStore = new RoughlyCounted();
    const opened = await served(await createMiddleware({ session: { sessionTtlMinutes: 60, sessionStore } }));
    const victim = await handshake(opened);
    await handshake(opened);
    const serving = elsewhere ? await served(await createMiddleware({ session: { sessionTtlMinutes: 60, sessionStore } })) : opened;
    const callback = toMcpToolCallback(serving.wrapWithProof('echo', ran));

    const result = await callback({}, { _meta: { [KYA_OS_SESSION_META_KEY]: victim } });
    expect(proofOf(result)?.meta.sessionId).not.toBe(victim);
  });

  it('proves a result the transport proves under the session its call names when it is the only live one', async () => {
    const kyaos = await createMiddleware();
    const wired = await served(kyaos);
    const only = await handshake(kyaos);

    const sent = await wired.wire.send(await ran(), { toolName: 'echo', meta: { [KYA_OS_SESSION_META_KEY]: only } });
    expect(proofOf(sent)?.meta.sessionId).toBe(only);
  });

  it('proves no result the transport proves under another client\'s session its call names', async () => {
    const kyaos = await createMiddleware();
    const wired = await served(kyaos);
    const victim = await handshake(kyaos);
    await handshake(kyaos);

    const sent = await wired.wire.send(await ran(), { toolName: 'echo', meta: { [KYA_OS_SESSION_META_KEY]: victim } });
    expect(proofOf(sent)).toBeUndefined();
  });

  it('proves nothing under another session when the session a call names is not live', async () => {
    const kyaos = await served(await createMiddleware());
    await handshake(kyaos);
    const callback = toMcpToolCallback(kyaos.wrapWithProof('echo', ran));

    const result = await callback({}, { _meta: { [KYA_OS_SESSION_META_KEY]: 'kyaos_not-a-live-session' } });
    expect(text(result)).toBe('ran');
    expect(proofOf(result)).toBeUndefined();
  });

  it('reads the session a call names through the MCP SDK, after a handshake over the _kyaos tool', async () => {
    const server = new McpServer({ name: 'named-session-test', version: '1.0.0' });
    const kyaos = await withKyaOs(server, { crypto });
    server.registerTool('echo', { inputSchema: {} }, toMcpToolCallback(kyaos.wrapWithProof('echo', ran)));
    const [clientEnd, serverEnd] = InMemoryTransport.createLinkedPair();
    await server.connect(serverEnd);
    const client = new Client({ name: 'named-session-client', version: '1.0.0' });
    await client.connect(clientEnd);
    try {
      const opened = await client.callTool({
        name: '_kyaos',
        arguments: { action: 'handshake', nonce: `nonce-${Math.random().toString(36).slice(2)}`, audience: kyaos.identity.did, timestamp: Math.floor(Date.now() / 1000) },
      });
      const session = JSON.parse((opened.content as Array<{ text: string }>)[0]!.text).sessionId as string;
      const named = () => client.callTool({ name: 'echo', arguments: {}, _meta: { [KYA_OS_SESSION_META_KEY]: session } });

      expect(proofOf(await named())?.meta.sessionId).toBe(session);
      // A second client's session: the first is no longer the one a call naming none is proved under.
      await handshake(kyaos);
      expect(proofOf(await named())).toBeUndefined();
    } finally {
      await client.close();
    }
  });
});

describe('the delegation and holder-of-key proof a call carries in params._meta', () => {
  it('reaches the handler with the delegation in params._meta and none in the arguments', async () => {
    const { kyaos } = await gated();
    const agent = await didKeyIdentity();
    const vc = await issueVC(agent.did);
    const seen: Array<Record<string, unknown>> = [];
    const callback = toMcpToolCallback(kyaos.wrapWithDelegation('vault.read', CONSENT, async (args) => {
      seen.push(args);
      return ran();
    }));

    const result = await callback({ path: '/a' }, { _meta: { [KYA_OS_DELEGATION_META_KEY]: vc } });
    expect(text(result)).toBe('ran');
    expect(seen).toEqual([{ path: '/a' }]);
  });

  it('binds the holder-of-key proof it carries in params._meta to the delegation beside it', async () => {
    const { server, kyaos } = await gated({ holderBinding: 'enforce' });
    const agent = await didKeyIdentity();
    const vc = await issueVC(agent.did);
    const args = { path: '/a' };
    const proof = await generateRequestProof({ identity: agent, crypto, toolName: 'vault.read', args, audience: server.did, delegation: vc });
    const callback = toMcpToolCallback(kyaos.wrapWithDelegation('vault.read', CONSENT, ran));

    const result = await callback(args, { _meta: { [KYA_OS_DELEGATION_META_KEY]: vc, [KYA_OS_HOLDER_PROOF_META_KEY]: proof } });
    expect(result.isError).toBeUndefined();
    expect(text(result)).toBe('ran');
  });

  it('refuses a holder-of-key proof in params._meta made for another delegation of the same agent', async () => {
    const { server, kyaos } = await gated({ holderBinding: 'enforce' });
    const agent = await didKeyIdentity();
    const presented = await issueVC(agent.did);
    const other = await issueVC(agent.did);
    const args = { path: '/a' };
    const proof = await generateRequestProof({ identity: agent, crypto, toolName: 'vault.read', args, audience: server.did, delegation: other });
    const callback = toMcpToolCallback(kyaos.wrapWithDelegation('vault.read', CONSENT, ran));

    const result = await callback(args, { _meta: { [KYA_OS_DELEGATION_META_KEY]: presented, [KYA_OS_HOLDER_PROOF_META_KEY]: proof } });
    expect(result.isError).toBe(true);
    expect(JSON.parse(text(result)).error).toBe('holder_binding_failed');
  });

  it('reads params._meta and not the argument when a call carries its delegation both ways', async () => {
    const { kyaos } = await gated();
    const agent = await didKeyIdentity();
    const vc = await issueVC(agent.did);
    const unscoped = await issueVC(agent.did, ['vault:write']);
    const callback = toMcpToolCallback(kyaos.wrapWithDelegation('vault.read', CONSENT, ran));

    const metaWins = await callback({ _kyaos_delegation: unscoped }, { _meta: { [KYA_OS_DELEGATION_META_KEY]: vc } });
    expect(text(metaWins)).toBe('ran');
    const refused = await callback({ _kyaos_delegation: vc }, { _meta: { [KYA_OS_DELEGATION_META_KEY]: unscoped } });
    expect(JSON.parse(text(refused)).error).toBe('insufficient_scope');
  });

  it('still reads the _kyaos_delegation argument of a 1.x client', async () => {
    const { kyaos } = await gated();
    const agent = await didKeyIdentity();
    const callback = toMcpToolCallback(kyaos.wrapWithDelegation('vault.read', CONSENT, ran));

    expect(text(await callback({ _kyaos_delegation: await issueVC(agent.did) }, {}))).toBe('ran');
  });
});

describe('the approval grants a call carries in params._meta', () => {
  const approvalFor = (requestHash: string) => ({
    approvalRequestId: 'r1',
    approverDid: 'did:example:approver',
    requestHash,
    decision: 'approve',
    ts: Math.floor(Date.now() / 1000),
    signature: 'sig',
  });
  const stepUp: PolicyEngine = {
    async evaluate() {
      return { decision: 'step_up', quorum: { n: 1, approvers: [] }, reason: 'destructive' };
    },
  };
  const dropped = async () => ({ content: [{ type: 'text' as const, text: 'dropped' }] });

  it('hands them to a policy gate composed inside the delegation gate', async () => {
    const { kyaos } = await gated();
    const agent = await didKeyIdentity();
    const vc = await issueVC(agent.did, ['db:admin']);
    const contexts: Array<KyaOsCallContext | undefined> = [];
    const handler = kyaos.wrapWithDelegation('db.drop', { scopeId: 'db:admin', consentUrl: 'https://example.com/consent' },
      kyaos.withPolicyGate!('db.drop', async (_args, _session, context) => {
        contexts.push(context);
        return dropped();
      }, { engine: stepUp, scopeMatched: true, isValidApprovalSignature: async () => true }));
    const callback = toMcpToolCallback(handler);

    const challenge = JSON.parse(text(await callback({ table: 'users' }, { _meta: { [KYA_OS_DELEGATION_META_KEY]: vc } })));
    expect(challenge.error).toBe('needs_approval');
    const resumed = await callback({ table: 'users' }, {
      _meta: { [KYA_OS_DELEGATION_META_KEY]: vc, [KYA_OS_APPROVALS_META_KEY]: [approvalFor(challenge.requestHash)] },
    });
    expect(text(resumed)).toBe('dropped');
  });

  it('lets a policy gate on its own read them, and the principal of the delegation in params._meta', async () => {
    const { kyaos } = await gated();
    const agent = await didKeyIdentity();
    const vc = await issueVC(agent.did, ['db:admin']);
    const agents: string[] = [];
    const engine: PolicyEngine = {
      async evaluate(request) {
        agents.push(request.principal.agentDid);
        return stepUp.evaluate(request);
      },
    };
    const callback = toMcpToolCallback(kyaos.withPolicyGate!('db.drop', dropped, {
      engine, scopeMatched: true, isValidApprovalSignature: async () => true,
    }));

    const challenge = JSON.parse(text(await callback({ table: 'users' }, { _meta: { [KYA_OS_DELEGATION_META_KEY]: vc } })));
    expect(challenge.error).toBe('needs_approval');
    const resumed = await callback({ table: 'users' }, {
      _meta: { [KYA_OS_DELEGATION_META_KEY]: vc, [KYA_OS_APPROVALS_META_KEY]: [approvalFor(challenge.requestHash)] },
    });
    expect(text(resumed)).toBe('dropped');
    expect(agents[0]).toBe(agent.did);
  });

  it('proves a policy gate\'s step-up under the session a call names only where a call naming none would be', async () => {
    const { kyaos } = await gated();
    const first = await handshake(kyaos);
    const vc = await issueVC((await didKeyIdentity()).did, ['db:admin']);
    const callback = toMcpToolCallback(kyaos.withPolicyGate!('db.drop', dropped, {
      engine: stepUp, scopeMatched: true, isValidApprovalSignature: async () => true,
    }));
    const named = { [KYA_OS_DELEGATION_META_KEY]: vc, [KYA_OS_SESSION_META_KEY]: first };

    const only = await callback({ table: 'users' }, { _meta: named });
    expect(JSON.parse(text(only)).error).toBe('needs_approval');
    expect(proofOf(only)?.meta.sessionId).toBe(first);
    await handshake(kyaos);
    const claimed = await callback({ table: 'users' }, { _meta: named });
    expect(JSON.parse(text(claimed)).error).toBe('needs_approval');
    expect(proofOf(claimed)).toBeUndefined();
  });
});

describe('a session a call names is no authority', () => {
  it.each(['off', 'warn'] as const)(
    'serves no call on a grant bound to the session it names, with holderBinding %s',
    async (holderBinding) => {
      const { kyaos } = await gated({ holderBinding });
      const victim = await didKeyIdentity();
      const session = await handshake(kyaos);
      const callback = toMcpToolCallback(kyaos.wrapWithDelegation('vault.read', CONSENT, ran));
      const named = { [KYA_OS_SESSION_META_KEY]: session };

      expect(text(await callback({}, { _meta: { ...named, [KYA_OS_DELEGATION_META_KEY]: await issueVC(victim.did) } }))).toBe('ran');
      const stranger = await callback({}, { _meta: named });
      expect(JSON.parse(text(stranger)).error).toBe('needs_authorization');
    },
  );

  it('lets no delegation presented under a session a call names answer a later call that names it', async () => {
    const { kyaos } = await gated();
    const attacker = await didKeyIdentity();
    const session = await handshake(kyaos);
    const agents: string[] = [];
    const callback = toMcpToolCallback(kyaos.wrapWithDelegation('vault.read', CONSENT, async (_args, _session, context) => {
      agents.push(context?.principal?.agentDid ?? 'none');
      return ran();
    }));
    const named = { [KYA_OS_SESSION_META_KEY]: session };

    await callback({}, { _meta: { ...named, [KYA_OS_DELEGATION_META_KEY]: await issueVC(attacker.did) } });
    const victim = await callback({}, { _meta: named });
    expect(JSON.parse(text(victim)).error).toBe('needs_authorization');
    expect(agents).toEqual([attacker.did]);
  });

  it('still proves an outcome under the session a call names when it is the only live one', async () => {
    const { kyaos } = await gated();
    const only = await handshake(kyaos);
    const callback = toMcpToolCallback(kyaos.wrapWithDelegation('vault.read', CONSENT, ran));

    const challenged = await callback({}, { _meta: { [KYA_OS_SESSION_META_KEY]: only } });
    expect(JSON.parse(text(challenged)).error).toBe('needs_authorization');
    expect(proofOf(challenged)?.meta.sessionId).toBe(only);
  });

  it('proves no outcome under another client\'s session a call names', async () => {
    const { kyaos } = await gated();
    const victim = await handshake(kyaos);
    await handshake(kyaos);
    const callback = toMcpToolCallback(kyaos.wrapWithDelegation('vault.read', CONSENT, ran));

    const challenged = await callback({}, { _meta: { [KYA_OS_SESSION_META_KEY]: victim } });
    expect(JSON.parse(text(challenged)).error).toBe('needs_authorization');
    expect(proofOf(challenged)).toBeUndefined();
  });
});

describe('which carrier is read', () => {
  it('reads the holder proof in params._meta and not the argument, both ways', async () => {
    const { server, kyaos } = await gated({ holderBinding: 'enforce' });
    const agent = await didKeyIdentity();
    const stranger = await didKeyIdentity();
    const vc = await issueVC(agent.did);
    const args = { path: '/a' };
    const proofBy = (identity: ProofAgentIdentity) =>
      generateRequestProof({ identity, crypto, toolName: 'vault.read', args, audience: server.did, delegation: vc });
    const callback = toMcpToolCallback(kyaos.wrapWithDelegation('vault.read', CONSENT, ran));

    const good = await callback({ ...args, _kyaos_proof: await proofBy(stranger) }, {
      _meta: { [KYA_OS_DELEGATION_META_KEY]: vc, [KYA_OS_HOLDER_PROOF_META_KEY]: await proofBy(agent) },
    });
    expect(text(good)).toBe('ran');
    const bad = await callback({ ...args, _kyaos_proof: await proofBy(agent) }, {
      _meta: { [KYA_OS_DELEGATION_META_KEY]: vc, [KYA_OS_HOLDER_PROOF_META_KEY]: await proofBy(stranger) },
    });
    expect(JSON.parse(text(bad)).error).toBe('holder_binding_failed');
  });

  it('resolves a retained grant behind a holder proof in params._meta, with no delegation presented', async () => {
    const { server, kyaos } = await gated({ holderBinding: 'enforce' });
    const agent = await didKeyIdentity();
    const vc = await issueVC(agent.did);
    const args = { path: '/a' };
    const proof = () => generateRequestProof({ identity: agent, crypto, toolName: 'vault.read', args, audience: server.did, delegation: vc });
    const callback = toMcpToolCallback(kyaos.wrapWithDelegation('vault.read', CONSENT, ran));

    await callback(args, { _meta: { [KYA_OS_DELEGATION_META_KEY]: vc, [KYA_OS_HOLDER_PROOF_META_KEY]: await proof() } });
    const retried = await callback(args, { _meta: { [KYA_OS_HOLDER_PROOF_META_KEY]: await proof() } });
    expect(text(retried)).toBe('ran');
  });

  it('reads approvals stated as null in params._meta as the call\'s approvals, and not the argument', async () => {
    const { kyaos } = await gated();
    const agent = await didKeyIdentity();
    const vc = await issueVC(agent.did, ['db:admin']);
    const stepUp: PolicyEngine = {
      async evaluate() {
        return { decision: 'step_up', quorum: { n: 1, approvers: [] }, reason: 'destructive' };
      },
    };
    const callback = toMcpToolCallback(kyaos.withPolicyGate!('db.drop', ran, {
      engine: stepUp, scopeMatched: true, isValidApprovalSignature: async () => true,
    }));
    const challenge = JSON.parse(text(await callback({ table: 'users' }, { _meta: { [KYA_OS_DELEGATION_META_KEY]: vc } })));
    const approvals = [{
      approvalRequestId: 'r1', approverDid: 'did:example:approver', requestHash: challenge.requestHash,
      decision: 'approve', ts: Math.floor(Date.now() / 1000), signature: 'sig',
    }];

    const resumed = await callback({ table: 'users', _kyaos_approvals: approvals }, {
      _meta: { [KYA_OS_DELEGATION_META_KEY]: vc, [KYA_OS_APPROVALS_META_KEY]: null },
    });
    expect(JSON.parse(text(resumed)).error).toBe('needs_approval');
  });
});
