/**
 * Outbound Delegation Headers
 *
 * Builds the full set of outbound delegation headers for forwarding
 * delegation context to downstream services.
 *
 * Headers (KYA-OS §7):
 * - KYA-Agent-DID: the original agent's DID
 * - KYA-Delegation-Chain: the delegation chain ID (vcId of the root delegation)
 * - KYA-Session-Id: the current session ID
 * - KYA-Delegation-Proof: a signed JWT proving the delegation is being forwarded
 *
 * Related Spec: KYA-OS §7 — Outbound Delegation Propagation
 */

import type { SessionContext, DelegationRecord } from '../types/protocol.js';
import { buildDelegationProofJWT, type Ed25519PrivateJWK } from './outbound-proof.js';
import { extractPublicKeyFromDidKey, isEd25519DidKey } from './did-key-resolver.js';
import { base64ToBytes, base64urlEncodeFromBytes } from '../utils/base64.js';
import { logger } from '../logging/index.js';

/**
 * Header names for outbound delegation propagation
 */
export const OUTBOUND_HEADER_NAMES = {
  AGENT_DID: 'KYA-Agent-DID',
  DELEGATION_CHAIN: 'KYA-Delegation-Chain',
  SESSION_ID: 'KYA-Session-Id',
  DELEGATION_PROOF: 'KYA-Delegation-Proof',
} as const;

/**
 * Context required to build outbound delegation headers
 */
export interface OutboundDelegationContext {
  /** The current session context */
  session: SessionContext;
  /** The delegation record being forwarded */
  delegation: DelegationRecord;
  /** The MCP server's identity for signing the proof */
  serverIdentity: {
    did: string;
    kid: string;
    privateKey: string;
  };
  /** The downstream URL being called */
  targetUrl: string;
}

/**
 * Outbound delegation headers to attach to downstream requests
 */
export interface OutboundDelegationHeaders {
  'KYA-Agent-DID': string;
  'KYA-Delegation-Chain': string;
  'KYA-Session-Id': string;
  'KYA-Delegation-Proof': string;
}

/**
 * Extract hostname from a URL
 */
function extractHostname(url: string): string {
  try {
    const parsed = new URL(url);
    return parsed.hostname;
  } catch {
    logger.warn('Failed to parse target URL, using as-is', { url });
    return url;
  }
}

/**
 * Convert base64 private key and DID to Ed25519 JWK format
 */
function buildPrivateKeyJwk(
  privateKeyBase64: string,
  serverDid: string
): Ed25519PrivateJWK {
  // Decode the private key from base64
  const privateKeyBytes = base64ToBytes(privateKeyBase64);

  // Extract the 32-byte seed (handle both 32-byte and 64-byte formats)
  const seed = privateKeyBytes.length === 64
    ? privateKeyBytes.subarray(0, 32)
    : privateKeyBytes;

  // Extract public key from did:key
  if (!isEd25519DidKey(serverDid)) {
    throw new Error(`Server DID must be did:key with Ed25519: ${serverDid}`);
  }

  const publicKeyBytes = extractPublicKeyFromDidKey(serverDid);
  if (!publicKeyBytes) {
    throw new Error(`Failed to extract public key from DID: ${serverDid}`);
  }

  return {
    kty: 'OKP',
    crv: 'Ed25519',
    x: base64urlEncodeFromBytes(publicKeyBytes),
    d: base64urlEncodeFromBytes(seed),
  };
}

/**
 * Build outbound delegation headers for forwarding to downstream services.
 *
 * When an MCP server calls a downstream service on behalf of an agent,
 * it MUST forward the delegation context using these headers so the
 * downstream service can independently verify the delegation chain.
 *
 * @param context - The delegation context including session, delegation, and server identity
 * @returns Headers object to attach to the outbound request
 *
 * @throws {Error} If session is missing agentDid or sessionId
 * @throws {Error} If delegation is missing vcId
 * @throws {Error} If serverIdentity.did is not a valid Ed25519 did:key
 *
 * @example
 * ```typescript
 * const headers = await buildOutboundDelegationHeaders({
 *   session,
 *   delegation,
 *   serverIdentity: { did: serverDid, kid: serverKid, privateKey },
 *   targetUrl: 'https://downstream-api.example.com/resource',
 * });
 *
 * // Attach headers to your HTTP request
 * fetch(targetUrl, { headers });
 * ```
 */
export async function buildOutboundDelegationHeaders(
  context: OutboundDelegationContext,
): Promise<OutboundDelegationHeaders> {
  const { session, delegation, serverIdentity, targetUrl } = context;

  // Validate required fields
  if (!session.agentDid) {
    throw new Error('Session must have agentDid for outbound delegation');
  }

  if (!session.sessionId) {
    throw new Error('Session must have sessionId for outbound delegation');
  }

  if (!delegation.vcId) {
    throw new Error('Delegation must have vcId for outbound delegation');
  }

  // Extract hostname for JWT audience
  const targetHostname = extractHostname(targetUrl);

  // Build the private key JWK from the server identity
  const privateKeyJwk = buildPrivateKeyJwk(
    serverIdentity.privateKey,
    serverIdentity.did
  );

  // Build the delegation proof JWT
  // Per KYA-OS §7, the JWT has:
  // - iss: serverDid (the MCP server forwarding the request)
  // - sub: agentDid (the original agent)
  // - aud: targetHostname (the downstream service)
  // - scope: "delegation:propagate"
  const jwt = await buildDelegationProofJWT({
    agentDid: serverIdentity.did,     // becomes iss (server forwarding)
    userDid: session.agentDid,        // becomes sub (original agent)
    delegationId: delegation.id,
    delegationChain: delegation.vcId,
    scopes: ['delegation:propagate'],
    privateKeyJwk,
    kid: serverIdentity.kid,
    targetHostname,
  });

  logger.debug('Built outbound delegation headers', {
    agentDid: session.agentDid,
    delegationChain: delegation.vcId,
    sessionId: session.sessionId,
    targetHostname,
  });

  return {
    'KYA-Agent-DID': session.agentDid,
    'KYA-Delegation-Chain': delegation.vcId,
    'KYA-Session-Id': session.sessionId,
    'KYA-Delegation-Proof': jwt,
  };
}
