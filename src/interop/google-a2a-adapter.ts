/**
 * Google A2A ⇄ `DelegationRecord` codec.
 *
 * Translates the authority block carried in a Google A2A envelope (modeled on the
 * public A2A `AgentCard` + `Message`) to and from the canonical KYA-OS
 * `DelegationRecord`. Pure shape translation: no signature verification, no DID
 * resolution, no key material. Neither function throws — unmappable input yields
 * `{ success: false, error }`.
 */
import type { DelegationConstraints, DelegationRecord } from '../types/protocol.js';
import type {
  FromA2AResult,
  GoogleA2ADelegation,
  GoogleA2AEnvelope,
  GoogleAgentCard,
  ToA2AResult,
} from './a2a-types.js';

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

/** First argument that is a non-empty string, else undefined. */
function firstNonEmptyString(...candidates: unknown[]): string | undefined {
  for (const c of candidates) {
    if (typeof c === 'string' && c.length > 0) return c;
  }
  return undefined;
}

function reconstructAgentCard(metadata: Record<string, unknown> | undefined): GoogleAgentCard | undefined {
  if (!metadata) return undefined;
  const card: GoogleAgentCard = {};
  if (typeof metadata['agentCardName'] === 'string') card.name = metadata['agentCardName'];
  if (typeof metadata['agentCardUrl'] === 'string') card.url = metadata['agentCardUrl'];
  if (typeof metadata['agentCardProviderOrg'] === 'string') {
    card.provider = { organization: metadata['agentCardProviderOrg'] };
  }
  return Object.keys(card).length > 0 ? card : undefined;
}

/**
 * Decode a Google A2A envelope into a `DelegationRecord`.
 *
 * Rejects when the authority block (`delegation`) is missing/non-object, when
 * `issuer`/`subject` are absent, or when no stable id can be derived from
 * `delegation.id` / `message.messageId` / `message.taskId` — a random id is never
 * minted silently, because round-trip identity must be deterministic.
 */
export function fromGoogleA2A(envelope: GoogleA2AEnvelope): FromA2AResult {
  if (!isObject(envelope)) {
    return { success: false, error: { message: 'Envelope is not an object' } };
  }
  const delegation = envelope.delegation;
  if (!isObject(delegation)) {
    return { success: false, error: { message: 'Google A2A envelope is missing a delegation block' } };
  }

  const issuerDid = firstNonEmptyString(delegation.issuer);
  const subjectDid = firstNonEmptyString(delegation.subject);
  if (!issuerDid) {
    return { success: false, error: { message: 'delegation.issuer is required' } };
  }
  if (!subjectDid) {
    return { success: false, error: { message: 'delegation.subject is required' } };
  }

  const message = envelope.message;
  const id = firstNonEmptyString(delegation.id, message?.messageId, message?.taskId);
  if (!id) {
    return {
      success: false,
      error: { message: 'No stable delegation id (delegation.id / message.messageId / message.taskId)' },
    };
  }

  const constraints: DelegationConstraints = { scopes: delegation.scopes ?? [] };
  if (delegation.audience !== undefined) constraints.audience = delegation.audience;
  if (delegation.notBefore !== undefined) constraints.notBefore = delegation.notBefore;
  if (delegation.notAfter !== undefined) constraints.notAfter = delegation.notAfter;

  const agentCard = envelope.agentCard;
  const metadata: Record<string, unknown> = { sourceFormat: 'google-a2a' };
  if (typeof agentCard?.name === 'string') metadata['agentCardName'] = agentCard.name;
  if (typeof agentCard?.url === 'string') metadata['agentCardUrl'] = agentCard.url;
  if (typeof agentCard?.provider?.organization === 'string') {
    metadata['agentCardProviderOrg'] = agentCard.provider.organization;
  }

  const record: DelegationRecord = {
    id,
    issuerDid,
    subjectDid,
    vcId: `urn:uuid:${id}`,
    constraints,
    signature: delegation.signature ?? '',
    status: 'active',
    metadata,
  };
  const parentId = firstNonEmptyString(delegation.parent);
  if (parentId) record.parentId = parentId;

  return { success: true, record };
}

/**
 * Encode a `DelegationRecord` back into a Google A2A envelope. Inverse of
 * {@link fromGoogleA2A}; reconstructs a minimal `agentCard` from metadata
 * provenance when available.
 */
export function toGoogleA2A(record: DelegationRecord): ToA2AResult<GoogleA2AEnvelope> {
  if (!isObject(record)) {
    return { success: false, error: { message: 'Record is not an object' } };
  }
  if (!firstNonEmptyString(record.id) || !firstNonEmptyString(record.issuerDid) || !firstNonEmptyString(record.subjectDid)) {
    return { success: false, error: { message: 'Record is missing id/issuerDid/subjectDid' } };
  }

  const constraints = record.constraints ?? {};
  const delegation: GoogleA2ADelegation = {
    id: record.id,
    issuer: record.issuerDid,
    subject: record.subjectDid,
    scopes: constraints.scopes ?? [],
    signature: record.signature ?? '',
  };
  if (record.parentId !== undefined) delegation.parent = record.parentId;
  if (constraints.audience !== undefined) delegation.audience = constraints.audience;
  if (constraints.notBefore !== undefined) delegation.notBefore = constraints.notBefore;
  if (constraints.notAfter !== undefined) delegation.notAfter = constraints.notAfter;

  const envelope: GoogleA2AEnvelope = { delegation };
  const agentCard = reconstructAgentCard(record.metadata);
  if (agentCard) envelope.agentCard = agentCard;

  return { success: true, envelope };
}
