/**
 * Adobe A2A ⇄ `DelegationRecord` codec.
 *
 * Translates the flat, header-style Adobe A2A envelope to and from the canonical
 * KYA-OS `DelegationRecord`. Pure shape translation: no signature verification,
 * no DID resolution. Neither function throws — unmappable input yields
 * `{ success: false, error }`.
 *
 * Scope mapping reuses the canonical scope vocabulary (`ScopeMatcher` /
 * `CrispScope`) from the delegation scope-matcher — there is no second scope
 * engine. An `exact` grant lands in flat `constraints.scopes`; a `prefix`/`regex`
 * grant lands in `constraints.crisp.scopes` with its matcher preserved, and a
 * warning is surfaced because non-exact matchers widen effective authority
 * (mirrors `ScopeSatisfaction.usedNonExactMatcher`). The codec never *executes*
 * a matcher pattern — it carries it as inert data for the downstream verify path.
 */
import type { CrispScope, DelegationConstraints, DelegationRecord } from '../types/protocol.js';
import type {
  AdobeA2AAuthorization,
  AdobeA2AEnvelope,
  AdobeA2AGrant,
  AdobeA2AParty,
  FromA2AResult,
  ToA2AResult,
} from './a2a-types.js';

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function nonEmptyString(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

/**
 * Decode an Adobe A2A envelope into a `DelegationRecord`.
 *
 * Rejects when `authorization` is missing/non-object, when `from.did`/`to.did`
 * are absent, or when `authorization.delegationId` is absent (no random id is
 * minted — round-trip identity must be deterministic).
 */
export function fromAdobeA2A(envelope: AdobeA2AEnvelope): FromA2AResult {
  if (!isObject(envelope)) {
    return { success: false, error: { message: 'Envelope is not an object' } };
  }
  const authorization = envelope.authorization;
  // Type-preserving presence check (a widening `Record<string, unknown>` guard
  // would erase the named field types on this index-signature-free interface).
  if (!authorization || typeof authorization !== 'object' || Array.isArray(authorization)) {
    return { success: false, error: { message: 'Adobe A2A envelope is missing an authorization block' } };
  }

  const issuerDid = nonEmptyString(envelope.from?.did);
  const subjectDid = nonEmptyString(envelope.to?.did);
  if (!issuerDid) {
    return { success: false, error: { message: 'from.did is required' } };
  }
  if (!subjectDid) {
    return { success: false, error: { message: 'to.did is required' } };
  }

  const id = nonEmptyString(authorization.delegationId);
  if (!id) {
    return { success: false, error: { message: 'authorization.delegationId is required (no stable id)' } };
  }

  const scopes: string[] = [];
  const crispScopes: CrispScope[] = [];
  const warnings: string[] = [];
  const grants = Array.isArray(authorization.grants) ? authorization.grants : [];
  for (const grant of grants) {
    if (grant === null || typeof grant !== 'object' || typeof grant.resource !== 'string') continue;
    // Conservative mapping: only the recognized non-exact matchers (`prefix`/`regex`)
    // become CrispScopes; an absent or unrecognized matcher maps to a flat EXACT
    // scope — the narrowest authority — so a hostile `match` value never widens.
    const match = grant.match;
    if (match === 'prefix' || match === 'regex') {
      crispScopes.push({ resource: grant.resource, matcher: match });
      warnings.push(
        `Grant "${grant.resource}" uses a non-exact (${match}) matcher — effective authority is widened.`,
      );
    } else {
      scopes.push(grant.resource);
    }
  }

  const constraints: DelegationConstraints = { scopes };
  if (crispScopes.length > 0) constraints.crisp = { scopes: crispScopes };
  if (authorization.audience !== undefined) constraints.audience = authorization.audience;
  if (authorization.validFrom !== undefined) constraints.notBefore = authorization.validFrom;
  if (authorization.validUntil !== undefined) constraints.notAfter = authorization.validUntil;

  const metadata: Record<string, unknown> = { sourceFormat: 'adobe-a2a' };
  if (typeof envelope.from?.org === 'string') metadata['fromOrg'] = envelope.from.org;
  if (typeof envelope.to?.agentId === 'string') metadata['toAgentId'] = envelope.to.agentId;
  if (typeof envelope.protocol === 'string') metadata['adobeProtocol'] = envelope.protocol;
  if (typeof envelope.version === 'string') metadata['adobeVersion'] = envelope.version;

  const record: DelegationRecord = {
    id,
    issuerDid,
    subjectDid,
    vcId: `urn:uuid:${id}`,
    constraints,
    signature: envelope.signature ?? '',
    status: 'active',
    metadata,
  };
  const parentId = nonEmptyString(authorization.parentId);
  if (parentId) record.parentId = parentId;

  const result: FromA2AResult = { success: true, record };
  if (warnings.length > 0) result.warnings = warnings;
  return result;
}

/**
 * Encode a `DelegationRecord` back into an Adobe A2A envelope. Inverse of
 * {@link fromAdobeA2A}: flat scopes become exact grants, `crisp.scopes` become
 * grants preserving their matcher, and `from`/`to`/`authorization` are
 * reconstructed from the record plus metadata provenance.
 */
export function toAdobeA2A(record: DelegationRecord): ToA2AResult<AdobeA2AEnvelope> {
  if (!isObject(record)) {
    return { success: false, error: { message: 'Record is not an object' } };
  }
  if (!nonEmptyString(record.id) || !nonEmptyString(record.issuerDid) || !nonEmptyString(record.subjectDid)) {
    return { success: false, error: { message: 'Record is missing id/issuerDid/subjectDid' } };
  }

  const constraints = record.constraints ?? {};
  const grants: AdobeA2AGrant[] = [];
  for (const scope of constraints.scopes ?? []) {
    grants.push({ resource: scope, match: 'exact' });
  }
  for (const cs of constraints.crisp?.scopes ?? []) {
    grants.push({ resource: cs.resource, match: cs.matcher });
  }

  const metadata = record.metadata ?? {};
  const from: AdobeA2AParty = { did: record.issuerDid };
  if (typeof metadata['fromOrg'] === 'string') from.org = metadata['fromOrg'];
  const to: AdobeA2AParty = { did: record.subjectDid };
  if (typeof metadata['toAgentId'] === 'string') to.agentId = metadata['toAgentId'];

  const authorization: AdobeA2AAuthorization = { delegationId: record.id, grants };
  if (record.parentId !== undefined) authorization.parentId = record.parentId;
  if (constraints.audience !== undefined) authorization.audience = constraints.audience;
  if (constraints.notBefore !== undefined) authorization.validFrom = constraints.notBefore;
  if (constraints.notAfter !== undefined) authorization.validUntil = constraints.notAfter;

  const envelope: AdobeA2AEnvelope = { protocol: 'adobe-a2a', from, to, authorization };
  if (typeof metadata['adobeVersion'] === 'string') envelope.version = metadata['adobeVersion'];
  if (record.signature) envelope.signature = record.signature;

  return { success: true, envelope };
}
