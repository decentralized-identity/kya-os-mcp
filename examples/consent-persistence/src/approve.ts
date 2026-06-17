/**
 * Approval: mint the delegation VC and BIND a durable, agent-anchored grant into
 * the shared store. This is the durable-storage write that makes consent
 * survive: after `approve()`, a retry of the protected tool on ANY instance (or
 * after a restart) resolves the grant via `getByAgent` — behind the agent's
 * per-request holder-of-key proof — with no re-paste and no shared session.
 *
 * Shared by the HTTP consent server (`consent-server.ts`) and the headless
 * scenario scripts, so both exercise the identical write path.
 */

import { NodeCryptoProvider, type Grant } from '@kya-os/mcp';
import { createDelegationIssuerFromIdentity } from './delegation-issuer.js';
import { FileGrantStore } from './file-grant-store.js';
import type { AgentIdentity } from './instance.js';

export interface ApproveInput {
  /** Issuer identity (single trust domain: the server's own DID issues + verifies). */
  identity: AgentIdentity;
  /** The shared, durable grant store both instances read. */
  grantStore: FileGrantStore;
  /** The agent the grant authorizes (the durable, portable anchor). */
  agentDid: string;
  /** Granted scopes. */
  scopes: string[];
  /** Grant lifetime in seconds (default 1 hour). */
  ttlSeconds?: number;
}

export interface ApproveResult {
  grantId: string;
}

export async function approve(input: ApproveInput): Promise<ApproveResult> {
  const crypto = new NodeCryptoProvider();
  const { issuer } = createDelegationIssuerFromIdentity(crypto, input.identity);
  const ttlSeconds = input.ttlSeconds ?? 3600;
  const notAfter = Math.floor(Date.now() / 1000) + ttlSeconds;

  // Mint the delegation VC — the durable proof of authority the grant caches.
  await issuer.createAndIssueDelegation({
    id: `del-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    issuerDid: input.identity.did,
    subjectDid: input.agentDid,
    constraints: { scopes: input.scopes, notAfter },
  });

  const idBytes = await crypto.randomBytes(16);
  const grantId = `grant_${Array.from(idBytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')}`;

  // Agent-anchored grant — NO sessionId — so it is portable: a retry resolves it
  // via getByAgent (behind the agent's holder-of-key proof) on any instance.
  const grant: Grant = {
    id: grantId,
    agentDid: input.agentDid,
    scopes: input.scopes,
    authorization: { type: 'delegation', provider: 'consent-persistence' },
    issuedAt: Date.now(),
    expiresAt: notAfter * 1000,
    status: 'active',
  };
  await input.grantStore.bind(grant);

  return { grantId };
}
