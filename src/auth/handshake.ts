/**
 * Authorization Handshake — Platform-agnostic Protocol Reference
 *
 * Orchestrates the KYA-OS authorization flow:
 * 1. Check agent reputation (optional)
 * 2. Verify delegation exists
 * 3. Return needs_authorization error if missing
 *
 * Uses only the global fetch API — no Node-specific imports.
 * Safe to run on Node.js, Cloudflare Workers, and any fetch-capable runtime.
 */

import type {
  NeedsAuthorizationError,
  AuthorizationDisplay,
} from '../types/protocol.js';
import { createNeedsAuthorizationError } from '../types/protocol.js';
import type { DelegationRecord } from '../types/protocol.js';
import { logger } from '../logging/index.js';
import type { DelegationVerifier, VerifyDelegationResult } from './types.js';

export type { DelegationVerifier, VerifyDelegationResult };

export interface AgentReputation {
  agentDid: string;
  score: number | null;
  totalInteractions: number;
  successRate: number;
  riskLevel: 'low' | 'medium' | 'high' | 'unknown';
  updatedAt: number;
}

/**
 * Policy for handling agents with no reputation history.
 *
 * - 'deny'            — reject unknown agents outright (strict environments)
 * - 'require-consent' — route to the consent/authorization flow (default)
 * - 'allow'           — let unknown agents through (reputation is advisory only)
 */
export type UnknownAgentPolicy = 'deny' | 'require-consent' | 'allow';

export interface AuthHandshakeConfig {
  delegationVerifier: DelegationVerifier;
  resumeTokenStore: ResumeTokenStore;
  reputationService?: {
    apiUrl: string;
    apiKey?: string;
    apiFormat?: 'v1' | 'v2';
  };
  authorization: {
    authorizationUrl: string;
    resumeTokenTtl?: number;
    /**
     * How to handle agents with no reputation history (404 from reputation
     * service, network error, or first-time agent).
     *
     * - 'deny'            — reject outright
     * - 'require-consent' — route to consent flow (default)
     * - 'allow'           — skip reputation gate for unknowns
     */
    unknownAgentPolicy?: UnknownAgentPolicy;
    minReputationScore?: number;
  };
  debug?: boolean;
}

export interface VerifyOrHintsResult {
  authorized: boolean;
  delegation?: DelegationRecord;
  credential?: {
    agent_did: string;
    user_did: string;
    scopes: string[];
    authorization: {
      type:
        | 'oauth'
        | 'oauth2'
        | 'password'
        | 'credential'
        | 'webauthn'
        | 'siwe'
        | 'none';
      provider?: string;
      credentialType?: string;
      rpId?: string;
      userVerification?: 'required' | 'preferred' | 'discouraged';
      chainId?: number;
      domain?: string;
    };
    [key: string]: unknown;
  };
  authError?: NeedsAuthorizationError;
  reputation?: AgentReputation;
  reason?: string;
}

export interface ResumeTokenStore {
  create(
    agentDid: string,
    scopes: string[],
    metadata?: Record<string, unknown>
  ): Promise<string>;

  get(token: string): Promise<{
    agentDid: string;
    scopes: string[];
    createdAt: number;
    expiresAt: number;
    metadata?: Record<string, unknown>;
  } | null>;

  fulfill(token: string): Promise<void>;
}

export class MemoryResumeTokenStore implements ResumeTokenStore {
  private tokens = new Map<
    string,
    {
      agentDid: string;
      scopes: string[];
      createdAt: number;
      expiresAt: number;
      metadata?: Record<string, unknown>;
      fulfilled: boolean;
    }
  >();
  private ttl: number;

  constructor(ttlMs = 600_000) {
    this.ttl = ttlMs;
  }

  async create(
    agentDid: string,
    scopes: string[],
    metadata?: Record<string, unknown>
  ): Promise<string> {
    const bytes = new Uint8Array(16);
    globalThis.crypto.getRandomValues(bytes);
    const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    const token = `rt_${hex}`;
    const now = Date.now();

    this.tokens.set(token, {
      agentDid,
      scopes,
      createdAt: now,
      expiresAt: now + this.ttl,
      metadata,
      fulfilled: false,
    });

    return token;
  }

  async get(token: string): Promise<{
    agentDid: string;
    scopes: string[];
    createdAt: number;
    expiresAt: number;
    metadata?: Record<string, unknown>;
  } | null> {
    const data = this.tokens.get(token);
    if (!data) return null;

    if (Date.now() > data.expiresAt) {
      this.tokens.delete(token);
      return null;
    }

    if (data.fulfilled) return null;

    return {
      agentDid: data.agentDid,
      scopes: data.scopes,
      createdAt: data.createdAt,
      expiresAt: data.expiresAt,
      metadata: data.metadata,
    };
  }

  async fulfill(token: string): Promise<void> {
    const data = this.tokens.get(token);
    if (data) {
      data.fulfilled = true;
    }
  }

  clear(): void {
    this.tokens.clear();
  }
}

/**
 * Verify agent delegation or return authorization hints.
 *
 * Orchestrates the authorization flow:
 * 1. Optionally check agent reputation against threshold
 * 2. Verify existing delegation via DelegationVerifier
 * 3. Return authorization hints if delegation is missing/invalid
 *
 * @param agentDid - The agent's DID to verify
 * @param scopes - Required scopes for the operation
 * @param config - Authorization configuration including verifier, token store, etc.
 * @returns Result indicating authorization status, delegation, or auth hints
 */
export async function verifyOrHints(
  agentDid: string,
  scopes: string[],
  config: AuthHandshakeConfig,
): Promise<VerifyOrHintsResult> {
  const startTime = Date.now();

  if (config.debug) {
    logger.debug(`[AuthHandshake] Verifying ${agentDid} for scopes: ${scopes.join(', ')}`);
  }

  let reputation: AgentReputation | undefined;
  if (config.reputationService && config.authorization.minReputationScore !== undefined) {
    const unknownPolicy = config.authorization.unknownAgentPolicy ?? 'require-consent';

    try {
      reputation = await fetchAgentReputation(agentDid, config.reputationService);
    } catch (error) {
      logger.error('[AuthHandshake] Reputation service unreachable, treating agent as unknown:', error);
      reputation = {
        agentDid,
        score: null,
        totalInteractions: 0,
        successRate: 0,
        riskLevel: 'unknown',
        updatedAt: Date.now(),
      };
    }

    if (config.debug) {
      logger.debug(`[AuthHandshake] Reputation score: ${reputation.score}`);
    }

    // Unknown agent (no reputation data)
    if (reputation.score === null) {
      if (unknownPolicy === 'deny') {
        const authError = await buildNeedsAuthorizationError(
          agentDid,
          scopes,
          config,
          'Unknown agent denied by policy'
        );
        return {
          authorized: false,
          authError,
          reputation,
          reason: 'Unknown agent — policy: deny',
        };
      }

      if (unknownPolicy === 'require-consent') {
        const authError = await buildNeedsAuthorizationError(
          agentDid,
          scopes,
          config,
          'Unknown agent requires consent'
        );
        return {
          authorized: false,
          authError,
          reputation,
          reason: 'Unknown agent — policy: require-consent',
        };
      }

      // unknownPolicy === 'allow' — skip reputation gate, continue to delegation check
      if (config.debug) {
        logger.debug('[AuthHandshake] Unknown agent allowed by policy, skipping reputation gate');
      }
    }

    // Known agent with score below threshold
    if (reputation.score !== null && reputation.score < config.authorization.minReputationScore) {
      if (config.debug) {
        logger.debug(
          `[AuthHandshake] Reputation ${reputation.score} < ${config.authorization.minReputationScore}, requiring authorization`
        );
      }

      const authError = await buildNeedsAuthorizationError(
        agentDid,
        scopes,
        config,
        'Agent reputation score below threshold'
      );

      return {
        authorized: false,
        authError,
        reputation,
        reason: 'Low reputation score',
      };
    }
  }

  let delegationResult: VerifyDelegationResult;

  try {
    delegationResult = await config.delegationVerifier.verify(agentDid, scopes);
  } catch (error) {
    logger.error('[AuthHandshake] Delegation verification failed:', error);
    const errorMessage = `Delegation verification error: ${error instanceof Error ? error.message : 'Unknown error'}`;

    const authError = await buildNeedsAuthorizationError(agentDid, scopes, config, errorMessage);

    return {
      authorized: false,
      authError,
      reason: errorMessage,
    };
  }

  if (delegationResult.valid && delegationResult.delegation) {
    if (config.debug) {
      logger.debug(
        `[AuthHandshake] Delegation valid, authorized (${Date.now() - startTime}ms)`
      );
    }

    return {
      authorized: true,
      delegation: delegationResult.delegation,
      credential: delegationResult.credential,
      reputation,
      reason: 'Valid delegation found',
    };
  }

  if (config.debug) {
    logger.debug(
      `[AuthHandshake] No delegation found, returning needs_authorization (${Date.now() - startTime}ms)`
    );
  }

  const authError = await buildNeedsAuthorizationError(
    agentDid,
    scopes,
    config,
    delegationResult.reason ?? 'No valid delegation found'
  );

  return {
    authorized: false,
    authError,
    reputation,
    reason: delegationResult.reason ?? 'No delegation',
  };
}

async function fetchAgentReputation(
  agentDid: string,
  reputationConfig: { apiUrl: string; apiKey?: string; apiFormat?: 'v1' | 'v2' }
): Promise<AgentReputation> {
  const apiUrl = reputationConfig.apiUrl.replace(/\/$/, '');
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  if (reputationConfig.apiKey) {
    headers['X-API-Key'] = reputationConfig.apiKey;
  }

  const isV2Format = reputationConfig.apiFormat === 'v2';
  let response: Response;

  if (isV2Format) {
    response = await fetch(
      `${apiUrl}/v1/reputation/${encodeURIComponent(agentDid)}`,
      {
        method: 'POST',
        headers,
        body: JSON.stringify({ include_details: false }),
      }
    );
  } else {
    response = await fetch(
      `${apiUrl}/api/v1/reputation/${encodeURIComponent(agentDid)}`,
      { method: 'GET', headers }
    );
  }

  if (!response.ok) {
    if (response.status === 404) {
      return {
        agentDid,
        score: null,
        totalInteractions: 0,
        successRate: 0,
        riskLevel: 'unknown',
        updatedAt: Date.now(),
      };
    }
    throw new Error(`Reputation API error: ${response.status} ${response.statusText}`);
  }

  const data = (await response.json()) as Record<string, unknown>;

  const score = (data['score'] as number | undefined) ?? 0;
  const levelRaw = (
    (data['level'] as string | undefined) ??
    (data['riskLevel'] as string | undefined) ??
    'unknown'
  ).toLowerCase();
  const riskLevel: AgentReputation['riskLevel'] =
    levelRaw === 'low' || levelRaw === 'medium' || levelRaw === 'high' ? levelRaw : 'unknown';

  return {
    agentDid:
      (data['agent_did'] as string | undefined) ??
      (data['agentDid'] as string | undefined) ??
      agentDid,
    score,
    totalInteractions: (data['totalInteractions'] as number | undefined) ?? 0,
    successRate: (data['successRate'] as number | undefined) ?? 0,
    riskLevel,
    updatedAt: data['calculatedAt']
      ? new Date(data['calculatedAt'] as string).getTime()
      : ((data['updatedAt'] as number | undefined) ?? Date.now()),
  };
}

async function buildNeedsAuthorizationError(
  agentDid: string,
  scopes: string[],
  config: AuthHandshakeConfig,
  message: string
): Promise<NeedsAuthorizationError> {
  const resumeToken = await config.resumeTokenStore.create(agentDid, scopes, {
    requestedAt: Date.now(),
  });

  const expiresAt = Date.now() + (config.authorization.resumeTokenTtl ?? 600_000);

  const authUrl = new URL(config.authorization.authorizationUrl);
  authUrl.searchParams.set('agent_did', agentDid);
  authUrl.searchParams.set('scopes', scopes.join(','));
  authUrl.searchParams.set('resume_token', resumeToken);

  const authCode = resumeToken.substring(0, 8).toUpperCase();

  const display: AuthorizationDisplay = {
    title: 'Authorization Required',
    hint: ['link', 'qr'],
    authorizationCode: authCode,
    qrUrl: `https://api.qrserver.com/v1/create-qr-code/?data=${encodeURIComponent(authUrl.toString())}`,
  };

  return createNeedsAuthorizationError({
    message,
    authorizationUrl: authUrl.toString(),
    resumeToken,
    expiresAt,
    scopes,
    display,
  });
}

export function hasSensitiveScopes(scopes: string[]): boolean {
  const sensitivePatterns = [
    'write',
    'delete',
    'admin',
    'payment',
    'transfer',
    'execute',
    'modify',
  ];

  return scopes.some((scope) =>
    sensitivePatterns.some((pattern) => scope.toLowerCase().includes(pattern))
  );
}
