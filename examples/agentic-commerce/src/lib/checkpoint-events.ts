/**
 * Store decisions as Checkpoint audit events (SPEC-EVENTS v0.1), the body of
 * `POST /api/v1/kya-os/events`. Pure functions: no I/O, no clock, no env.
 *
 * The shapes mirror Checkpoint's ingest schemas
 * (apps/web/lib/api/schemas/kya-os-events.ts). Checkpoint strips keys it does
 * not know, so nothing here invents a field: a fact without a schema field
 * (order id, receipt, payment) is not sent. Tool arguments and results never
 * appear; a refusal carries one short sentence a person can read aloud, led by
 * the machine code, as `CODE: sentence`.
 *
 * Three events:
 *   - `tool.invoked`        one per `place_order` decision, allowed or refused (merchant)
 *   - `delegation.observed` when the shopper approves a grant (authorization hub)
 *   - `delegation.revoked`  when the hub revokes that grant (hub)
 */
import type { DelegationCredential } from '@kya-os/mcp';
import { findCatalogItem } from './product.js';

export const SPEC_VERSION = '0.1';

/** Checkpoint keeps at most this many characters of a refusal reason. */
export const MAX_REASON_LENGTH = 200;

export interface EventSource {
  /** The DID of the server that saw the fact. */
  readonly serverDid: string;
  readonly sdk?: { readonly name: string; readonly version: string; readonly runtime: 'node' };
}

/** This example's self-identification, as in package.json. */
export const EXAMPLE_SDK = { name: 'kya-os-example-agentic-commerce', version: '0.1.0', runtime: 'node' } as const;

export interface ToolInvokedEvent {
  readonly specVersion: typeof SPEC_VERSION;
  readonly type: 'tool.invoked';
  readonly ts: string;
  readonly source: EventSource;
  readonly session?: { readonly id: string; readonly agent?: { readonly did: string } };
  readonly tool: { readonly name: string; readonly capability?: string };
  readonly verdict: 'pass' | 'fail';
  readonly error?: { readonly excerpt: string };
  readonly principal?: { readonly did: string };
  readonly delegation?: { readonly jti: string };
}

export interface DelegationObservedEvent {
  readonly specVersion: typeof SPEC_VERSION;
  readonly type: 'delegation.observed';
  readonly ts: string;
  readonly source: EventSource;
  readonly delegation: {
    readonly jti: string;
    readonly issuerDid: string;
    readonly audience?: string;
    readonly scopes: readonly string[];
    readonly issuedAt?: string;
    readonly expiresAt?: string;
  };
}

export interface DelegationRevokedEvent {
  readonly specVersion: typeof SPEC_VERSION;
  readonly type: 'delegation.revoked';
  readonly ts: string;
  readonly source: EventSource;
  readonly delegation: { readonly jti: string };
  readonly reason?: string;
}

export type CheckpointEvent = ToolInvokedEvent | DelegationObservedEvent | DelegationRevokedEvent;

/** The merchant's gate states, as its console shows them. `pending` is consent not yet given. */
export type GateState = 'pass' | 'fail' | 'skip' | 'pending';

/** The three credential gates that decide whether a call carries a verified grant. */
export type CredentialGate = 'signature' | 'revocation' | 'holder';

/** One `place_order` decision, as the merchant saw it. */
export interface OrderDecision {
  /** ISO 8601 time of the decision. */
  readonly at: string;
  readonly allowed: boolean;
  /** The merchant's or the gate's machine code on a refusal, e.g. `SPEND_CAP_EXCEEDED`. */
  readonly code?: string;
  /** The merchant's or the gate's own message on a refusal. */
  readonly message?: string;
  readonly product: string;
  readonly quantity: number;
  /** On a spend-limit refusal, the merchant's computed total and the cap, e.g. `CHF 59.70`. */
  readonly total?: string;
  readonly cap?: string;
  /** The merchant's credential checks for this call. Other gates are not reported. */
  readonly gates: Readonly<Record<CredentialGate, GateState>>;
  /** The credential presented. Sent as the grant link only when its checks passed. */
  readonly credential?: { readonly jti: string; readonly issuerDid: string } | null;
  /** The agent DID the merchant bound by a holder-of-key proof on this call, if any. */
  readonly verifiedAgentDid?: string | null;
  /** The merchant's KYA-OS session for this call. */
  readonly sessionId?: string | null;
}

/** The stable credential id both parties use: the gate's own `delegationRef`. */
export function credentialJti(vc: DelegationCredential): string {
  return vc.id ?? vc.credentialSubject.delegation.id;
}

export function credentialIssuer(vc: DelegationCredential): string {
  return typeof vc.issuer === 'string' ? vc.issuer : vc.issuer.id;
}

function clip(text: string): string {
  return text.length <= MAX_REASON_LENGTH ? text : `${text.slice(0, MAX_REASON_LENGTH - 3)}...`;
}

/** A catalog sku for the product, never the caller's raw input. */
function productLabel(product: string): string {
  return findCatalogItem(product)?.sku ?? 'an unlisted product';
}

/** The gate reports a revoked credential as `delegation_invalid` with a reason that says so. */
function isRevocation(code: string | undefined, message: string): boolean {
  return /revoked/i.test(message) || code === 'AUTHORITY_REVOKED';
}

/**
 * The refusal as `CODE: sentence`, at most 200 characters. A salesperson can
 * read the sentence aloud; the code matches the merchant's own ledger.
 *
 * @example
 * refusalReason({ code: 'SPEND_CAP_EXCEEDED', product: 'risotto', quantity: 3, total: 'CHF 59.70', cap: 'CHF 50.00', ... })
 * // 'SPEND_CAP_EXCEEDED: Over the spending limit. 3 x risotto = CHF 59.70, the limit is CHF 50.00 per order. Nothing was ordered.'
 */
export function refusalReason(decision: OrderDecision): string {
  const code = decision.code ?? 'REFUSED';
  const message = decision.message ?? '';
  const product = productLabel(decision.product);
  if (isRevocation(decision.code, message)) {
    return 'delegation_revoked: This authorization was revoked. Nothing was ordered.';
  }
  switch (code) {
    case 'needs_authorization':
      return 'needs_authorization: No grant yet. The shopper must approve before the agent can buy. Nothing was ordered.';
    case 'SPEND_CAP_EXCEEDED':
      return clip(
        decision.total && decision.cap
          ? `SPEND_CAP_EXCEEDED: Over the spending limit. ${decision.quantity} x ${product} = ${decision.total}, the limit is ${decision.cap} per order. Nothing was ordered.`
          : 'SPEND_CAP_EXCEEDED: Over the per-order spending limit. Nothing was ordered.',
      );
    case 'PRODUCT_OUT_OF_SCOPE':
      return clip(`PRODUCT_OUT_OF_SCOPE: ${product} is not a product the shopper approved. Nothing was ordered.`);
    case 'holder_binding_failed':
      return "holder_binding_failed: The caller could not prove it holds the agent's key. Nothing was ordered.";
    case 'UNKNOWN_PRODUCT':
      return 'UNKNOWN_PRODUCT: That product is not in the catalog. Nothing was ordered.';
    case 'INVALID_QUANTITY':
      return 'INVALID_QUANTITY: The quantity must be a whole number from 1 to 999. Nothing was ordered.';
    case 'AUTHORITY_EXPIRED':
      return 'AUTHORITY_EXPIRED: The grant has expired. Nothing was ordered.';
    default:
      return clip(`${code}: ${message || 'The merchant refused this order.'} Nothing was ordered.`);
  }
}

/**
 * One `tool.invoked` per `place_order` decision.
 *
 * The grant link (`delegation.jti`) and the authorizing party go in only when
 * the credential's signature, revocation status and agent key all passed:
 * Checkpoint labels a row that carries a jti as delegation-verified.
 *
 * No `stages`: Checkpoint's Activity inspector shows a per-stage trace INSTEAD
 * of the refusal reason when stages are present, and the reason is what the
 * demo reads aloud. The merchant's own console keeps the seven-gate view.
 */
export function orderDecisionEvent(decision: OrderDecision, source: EventSource): ToolInvokedEvent {
  const { gates } = decision;
  const credentialVerified = Boolean(decision.credential)
    && gates.signature === 'pass' && gates.revocation === 'pass' && gates.holder === 'pass';
  const agentDid = gates.holder === 'pass' ? decision.verifiedAgentDid : null;
  return {
    specVersion: SPEC_VERSION,
    type: 'tool.invoked',
    ts: decision.at,
    source,
    ...(decision.sessionId
      ? { session: { id: decision.sessionId, ...(agentDid ? { agent: { did: agentDid } } : {}) } }
      : {}),
    tool: { name: 'place_order', capability: 'commerce.order' },
    verdict: decision.allowed ? 'pass' : 'fail',
    ...(decision.allowed ? {} : { error: { excerpt: refusalReason(decision) } }),
    ...(credentialVerified && decision.credential
      ? { principal: { did: decision.credential.issuerDid }, delegation: { jti: decision.credential.jti } }
      : {}),
  };
}

function isoFromSeconds(seconds: number | undefined): string | undefined {
  return seconds === undefined ? undefined : new Date(seconds * 1000).toISOString();
}

/** The audience as one DID, or nothing when the credential names several. */
function singleAudience(audience: string | string[] | undefined): string | undefined {
  if (typeof audience === 'string') return audience;
  return Array.isArray(audience) && audience.length === 1 ? audience[0] : undefined;
}

/**
 * The grant the shopper just approved, from the credential the hub issued.
 * `scopes` are the credential's flat action scopes; the product class and the
 * spend limit live in its signed constraints, which this schema has no field for.
 */
export function grantApprovedEvent(vc: DelegationCredential, source: EventSource, at: string): DelegationObservedEvent {
  const constraints = vc.credentialSubject.delegation.constraints;
  const audience = singleAudience(constraints.audience);
  const issuedAt = vc.issuanceDate ?? isoFromSeconds(constraints.notBefore);
  const expiresAt = vc.expirationDate ?? isoFromSeconds(constraints.notAfter);
  return {
    specVersion: SPEC_VERSION,
    type: 'delegation.observed',
    ts: at,
    source,
    delegation: {
      jti: credentialJti(vc),
      issuerDid: credentialIssuer(vc),
      ...(audience ? { audience } : {}),
      scopes: [...(constraints.scopes ?? [])],
      ...(issuedAt ? { issuedAt } : {}),
      ...(expiresAt ? { expiresAt } : {}),
    },
  };
}

/** The grant the hub just revoked. */
export function grantRevokedEvent(vc: DelegationCredential, source: EventSource, at: string, reason: string): DelegationRevokedEvent {
  return {
    specVersion: SPEC_VERSION,
    type: 'delegation.revoked',
    ts: at,
    source,
    delegation: { jti: credentialJti(vc) },
    reason: reason.slice(0, 500),
  };
}
