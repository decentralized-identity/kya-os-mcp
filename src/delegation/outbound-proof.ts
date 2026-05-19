/**
 * Outbound Delegation Proof
 *
 * Builds signed delegation proof JWTs for injection on outbound HTTP requests.
 * Enables downstream services to independently verify the delegation chain.
 *
 * Wire format: signed compact EdDSA JWT (60s TTL, per-call jti)
 * Header injection: KYA-Delegation-Id, KYA-Delegation-Chain, KYA-Delegation-Proof, KYA-Granted-Scopes
 *
 * Related Spec: KYA-OS §2 — Outbound Delegation Propagation
 */

import { SignJWT, importJWK } from 'jose';
import type { DelegationRecord } from '../types/protocol.js';

export interface Ed25519PrivateJWK {
  kty: 'OKP';
  crv: 'Ed25519';
  x: string;
  d: string;
  kid?: string;
  use?: string;
}

export interface DelegationProofOptions {
  agentDid: string;
  userDid: string;
  delegationId: string;
  delegationChain: string;
  scopes: string[];
  privateKeyJwk: Ed25519PrivateJWK;
  kid: string;
  targetHostname: string;
}

/**
 * Build a signed delegation proof JWT for outbound HTTP requests.
 *
 * Creates a short-lived (60s) EdDSA-signed JWT containing delegation context
 * that can be verified by downstream services without access to the MCP server.
 *
 * @param options - Proof options including DIDs, delegation info, scopes, and signing key
 * @returns Compact JWS string (header.payload.signature)
 * @throws {Error} If key import or signing fails
 */
export async function buildDelegationProofJWT(
  options: DelegationProofOptions
): Promise<string> {
  const {
    agentDid,
    userDid,
    delegationId,
    delegationChain,
    scopes,
    privateKeyJwk,
    kid,
    targetHostname,
  } = options;

  const privateKey = await importJWK(privateKeyJwk, 'EdDSA');

  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + 60;

  const jwt = await new SignJWT({
    delegation_id: delegationId,
    delegation_chain: delegationChain,
    scope: scopes.join(','),
  })
    .setProtectedHeader({ alg: 'EdDSA', kid })
    .setIssuer(agentDid)
    .setSubject(userDid)
    .setJti(crypto.randomUUID())
    .setAudience(targetHostname)
    .setIssuedAt(iat)
    .setExpirationTime(exp)
    .sign(privateKey);

  return jwt;
}

export function buildChainString(delegation: DelegationRecord): string {
  if (!delegation.id && !delegation.vcId) {
    return '';
  }
  if (!delegation.vcId) {
    return delegation.id;
  }
  return `${delegation.vcId}>${delegation.id}`;
}
