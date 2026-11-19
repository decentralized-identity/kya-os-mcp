/**
 * Outbound Delegation Headers
 *
 * Builds the full set of outbound delegation headers for forwarding
 * delegation context to downstream services.
 *
 * Headers (KYA-OS §8.1):
 * - KYA-OS-Delegation-Credential: the delegation credential as a VC-JWT, which
 *   a verifier derives authorization from; sent when the caller passes `credentialJwt`
 * - KYA-OS-Agent-DID: the original agent's DID
 * - KYA-OS-Delegation-Chain: the delegation chain ID (vcId of the root delegation), advisory only
 * - KYA-OS-Session-Id: an anchor of the current session for the target's host, never the session's id
 * - KYA-OS-Delegation-Proof: a signed JWT proving the delegation is being forwarded
 *
 * Related Spec: KYA-OS §8, Outbound Delegation Propagation
 */

import type { SessionContext, DelegationRecord } from '../types/protocol.js';
import { buildDelegationProofJWT, type Ed25519PrivateJWK } from './outbound-proof.js';
import { extractPublicKeyFromDidKey, isEd25519DidKey } from './did-key-resolver.js';
import { parseVCJWT } from './utils.js';
import { verifyDelegationAudience } from './audience-validator.js';
import { describeValue } from '../utils/describe-value.js';
import { base64ToBytes, base64urlEncodeFromBytes } from '../utils/base64.js';
import { strictBase64urlBytes } from '../utils/base64-reading.js';
import { isRecord } from '../utils/guards.js';
import { canonicalizeJsonBytes } from '../utils/canonical-json.js';
import { domainDigest, webCryptoSha256 } from '../utils/domain-digest.js';
import { warnOncePerProcess } from '../utils/warn-once.js';
import { logger } from '../logging/index.js';

/**
 * Header names for outbound delegation propagation
 */
export const OUTBOUND_HEADER_NAMES = {
  AGENT_DID: 'KYA-OS-Agent-DID',
  DELEGATION_CHAIN: 'KYA-OS-Delegation-Chain',
  SESSION_ID: 'KYA-OS-Session-Id',
  DELEGATION_PROOF: 'KYA-OS-Delegation-Proof',
  DELEGATION_CREDENTIAL: 'KYA-OS-Delegation-Credential',
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
  /**
   * The credential of `delegation`, as the compact VC-JWT its issuer signed (SPEC §6.2, "The
   * VC-JWT form"), such as the one the agent presented or a grant's `credentialJwt`. It is sent
   * unchanged as `KYA-OS-Delegation-Credential`, the header a verifier that follows SPEC §8.1
   * derives authorization from. Without it that header is not sent, so such a verifier can
   * authorize nothing, and the first call in a process that omits it warns through `logger.warn`.
   */
  credentialJwt?: string;
}

/**
 * Outbound delegation headers to attach to downstream requests
 */
export interface OutboundDelegationHeaders {
  'KYA-OS-Agent-DID': string;
  'KYA-OS-Delegation-Chain': string;
  /**
   * An anchor of the session for the target's host, `sha256:` and 64 lowercase hex digits: one value
   * for every call of the session to that host, and never the session's id (SPEC §8.1).
   */
  'KYA-OS-Session-Id': string;
  'KYA-OS-Delegation-Proof': string;
  /** The delegation credential as a VC-JWT (SPEC §8.1); present only when `credentialJwt` was given. */
  'KYA-OS-Delegation-Credential'?: string;
}

/** Where every copy of this package records that the missing-credential warning was given. */
const CREDENTIAL_WARNED = Symbol.for('@kya-os/mcp/outbound-credential-warned');

/** Fixed words, so nothing a caller or an agent passed is ever written into the log line. */
const NO_CREDENTIAL_WARNING =
  '[kya-os] buildOutboundDelegationHeaders was given no credentialJwt, so the request carries no ' +
  'KYA-OS-Delegation-Credential header, the credential a service that follows SPEC §8.1 derives authorization ' +
  'from. Pass the delegation credential, as the VC-JWT its issuer signed, in credentialJwt.';

/** Fixed words, so a refusal never repeats the value it refuses. */
const NOT_A_VC_JWT =
  'OutboundDelegationContext.credentialJwt must be the delegation credential as a compact VC-JWT: ' +
  'three base64url segments whose payload carries a vc claim';

/**
 * Whether `value` is a compact VC-JWT as `parseVCJWT`, which the verifier reads one with, reads it,
 * written in base64url alone (RFC 7515 §2), so no white space or line break reaches a header.
 */
function isCompactVcJwt(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const segments = value.split('.');
  if (segments.length !== 3 || segments.some((segment) => segment === '' || strictBase64urlBytes(segment) === undefined)) {
    return false;
  }
  const parsed = parseVCJWT(value);
  return parsed !== null && isRecord(parsed.header) && isRecord(parsed.payload) && isRecord(parsed.payload.vc);
}

/**
 * The `KYA-OS-Delegation-Credential` member for `credentialJwt`: none when it is absent, with one
 * warning per process, and the value unchanged when it is a compact VC-JWT.
 *
 * @throws {TypeError} for any other value, in words that do not repeat it
 */
function credentialHeader(credentialJwt: unknown): Pick<OutboundDelegationHeaders, 'KYA-OS-Delegation-Credential'> {
  if (credentialJwt === undefined) {
    warnOncePerProcess(CREDENTIAL_WARNED, NO_CREDENTIAL_WARNING);
    return {};
  }
  if (!isCompactVcJwt(credentialJwt)) throw new TypeError(NOT_A_VC_JWT);
  return { [OUTBOUND_HEADER_NAMES.DELEGATION_CREDENTIAL]: credentialJwt };
}

/** Whether `bound`, a bound in epoch seconds, is one: a finite number. */
const isEpochSeconds = (bound: unknown): bound is number => typeof bound === 'number' && Number.isFinite(bound);

/**
 * Why the server must not forward `delegation` now, or `undefined` when it may. The proof the
 * helper signs tells the target that this server is propagating the delegation, and the target may
 * act on that alone, so the server signs it only for a record that is in force: active, inside its
 * `notBefore` and `notAfter`, held exactly as the gate holds a credential's and with a bound that is
 * no number read as passed, and addressed to this server, as the gate requires of what it accepts.
 */
function forwardingRefusal(delegation: DelegationRecord, serverDid: string): string | undefined {
  if (delegation.status !== 'active') {
    return `Delegation must be active for outbound delegation (its status is ${describeValue(delegation.status)})`;
  }
  const { notBefore, notAfter } = delegation.constraints;
  const nowSec = Math.floor(Date.now() / 1000);
  if (notAfter !== undefined && !(isEpochSeconds(notAfter) && nowSec <= notAfter)) {
    return 'Delegation must not be past its notAfter for outbound delegation';
  }
  if (notBefore !== undefined && !(isEpochSeconds(notBefore) && nowSec >= notBefore)) {
    return 'Delegation must not be before its notBefore for outbound delegation';
  }
  if (!verifyDelegationAudience(delegation, serverDid)) {
    return 'Delegation audience must admit the forwarding server for outbound delegation';
  }
  return undefined;
}

/** Domain of a session anchor: `SHA-256(UTF8(domain) || 0x00 || JCS([sessionId, target host]))`. */
const SESSION_ANCHOR_DOMAIN = 'org.kya-os.outbound.session-anchor.v1';

/**
 * The `KYA-OS-Session-Id` a target is sent: an anchor of the session for the target's host, the
 * host the proof is addressed to. It is one value for every call of one session to one host, so the
 * target can tell which of its calls one session made, and it is never the session's id. The gate
 * resolves a grant it bound in a session by the session's id alone (`GrantStore.getBySession`), so
 * the id is a bearer of the session: sent as it is, every downstream service, and whatever logs or
 * proxies its headers, could call the server's gate in that session as the agent.
 */
function sessionAnchor(sessionId: string, targetHostname: string): Promise<string> {
  return domainDigest(SESSION_ANCHOR_DOMAIN, canonicalizeJsonBytes([sessionId, targetHostname]), webCryptoSha256);
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
 * A verifier that follows SPEC §8.1 derives authorization from the
 * delegation credential, so pass it as `credentialJwt`.
 *
 * @param context - The delegation context including session, delegation, credential, and server identity
 * @returns Headers object to attach to the outbound request
 *
 * @throws {Error} If session is missing agentDid or sessionId
 * @throws {Error} If delegation is missing vcId
 * @throws {Error} If delegation is not active, is before its notBefore or past its notAfter, or
 *   names an audience that does not admit serverIdentity.did
 * @throws {TypeError} If credentialJwt is given and is not a compact VC-JWT
 * @throws {Error} If serverIdentity.did is not a valid Ed25519 did:key
 *
 * @example
 * ```typescript
 * const headers = await buildOutboundDelegationHeaders({
 *   session,
 *   delegation,
 *   credentialJwt, // the delegation credential as a VC-JWT
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
  const { session, delegation, serverIdentity, targetUrl, credentialJwt } = context;

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

  const refusal = forwardingRefusal(delegation, serverIdentity.did);
  if (refusal !== undefined) {
    throw new Error(refusal);
  }

  const credential = credentialHeader(credentialJwt);

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

  const anchor = await sessionAnchor(session.sessionId, targetHostname);

  logger.debug('Built outbound delegation headers', {
    agentDid: session.agentDid,
    delegationChain: delegation.vcId,
    sessionAnchor: anchor,
    targetHostname,
  });

  return {
    'KYA-OS-Agent-DID': session.agentDid,
    'KYA-OS-Delegation-Chain': delegation.vcId,
    'KYA-OS-Session-Id': anchor,
    'KYA-OS-Delegation-Proof': jwt,
    ...credential,
  };
}
