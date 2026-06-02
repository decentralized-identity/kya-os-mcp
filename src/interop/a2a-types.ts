/**
 * A2A wire-format interop — structural types.
 *
 * These are KYA-OS for MCP's own minimal *structural* views of foreign
 * agent-to-agent envelope formats (Google A2A `AgentCard`/`Message`, Adobe A2A
 * envelope). They are NOT the vendors' canonical schemas, and they intentionally
 * depend on no vendor SDK — the package stays dependency-light. Every field is
 * optional unless the wire format guarantees it, because envelopes arrive
 * untrusted over the wire and must never be assumed well-formed.
 *
 * The codec performs **no** signature verification and resolves **no** DIDs. A
 * foreign envelope's `signature` is preserved as an opaque passthrough on
 * {@link DelegationRecord.signature} for the downstream KYA-OS verify path; the
 * codec's only job is shape translation onto the canonical `DelegationRecord`.
 */
import type { DelegationRecord } from '../types/protocol.js';
import type { ScopeMatcher } from '../delegation/scope-matcher.js';

/** Detected wire format of an unknown inbound envelope. */
export type EnvelopeFormat = 'google-a2a' | 'adobe-a2a' | 'kya-os-vc' | 'unknown';

// ============================================================================
// Google A2A — modeled on the public A2A `AgentCard` + `Message`
// ============================================================================

export interface GoogleAgentSkill {
  id: string;
  name?: string;
  description?: string;
  tags?: string[];
  examples?: string[];
}

export interface GoogleAgentCard {
  name?: string;
  description?: string;
  url?: string;
  provider?: { organization?: string; url?: string };
  version?: string;
  skills?: GoogleAgentSkill[];
  securitySchemes?: Record<string, unknown>;
  [k: string]: unknown;
}

export interface GoogleA2APart {
  kind?: 'text' | 'data' | 'file';
  text?: string;
  data?: Record<string, unknown>;
}

export interface GoogleA2AMessage {
  role?: 'user' | 'agent';
  parts?: GoogleA2APart[];
  messageId?: string;
  taskId?: string;
  contextId?: string;
  metadata?: Record<string, unknown>;
  [k: string]: unknown;
}

/**
 * The authority block carried inside a Google A2A envelope — the part that maps
 * to a {@link DelegationRecord}.
 */
export interface GoogleA2ADelegation {
  id?: string;
  issuer?: string;
  subject?: string;
  parent?: string;
  scopes?: string[];
  audience?: string | string[];
  notBefore?: number;
  notAfter?: number;
  signature?: string;
  [k: string]: unknown;
}

/** The wire object the Google codec accepts. */
export interface GoogleA2AEnvelope {
  agentCard?: GoogleAgentCard;
  message?: GoogleA2AMessage;
  delegation?: GoogleA2ADelegation;
  [k: string]: unknown;
}

// ============================================================================
// Adobe A2A — flat, header-style envelope
// ============================================================================

export interface AdobeA2AParty {
  did?: string;
  agentId?: string;
  org?: string;
}

/**
 * A single authorization grant. `match` reuses the canonical {@link ScopeMatcher}
 * union from the delegation scope-matcher (no second scope vocabulary); the
 * adapter defaults an absent `match` to `'exact'`.
 */
export interface AdobeA2AGrant {
  resource: string;
  match?: ScopeMatcher;
  actions?: string[];
}

export interface AdobeA2AAuthorization {
  delegationId?: string;
  parentId?: string;
  grants?: AdobeA2AGrant[];
  audience?: string | string[];
  validFrom?: number;
  validUntil?: number;
}

export interface AdobeA2AEnvelope {
  protocol?: string;
  version?: string;
  from?: AdobeA2AParty;
  to?: AdobeA2AParty;
  authorization?: AdobeA2AAuthorization;
  payload?: Record<string, unknown>;
  signature?: string;
  [k: string]: unknown;
}

// ============================================================================
// Codec result envelopes
// ============================================================================

/**
 * Result of decoding a foreign envelope into a canonical `DelegationRecord`.
 * Adapters never throw — a structurally unmappable envelope yields
 * `{ success: false, error }`, mirroring the repo's `validateDelegationCredential`
 * result convention.
 */
export interface FromA2AResult {
  success: boolean;
  error?: { message: string };
  record?: DelegationRecord;
  warnings?: string[];
}

/** Result of encoding a canonical `DelegationRecord` back into a foreign envelope. */
export interface ToA2AResult<E> {
  success: boolean;
  error?: { message: string };
  envelope?: E;
}
