import { canonicalizeJson } from '../utils/canonical-json.js';
import type { AuditSigner } from './crypto.js';
import { AUDIT_ERROR_CODES, AuditProtocolError } from './errors.js';
import type { AuditRecorderSubmission } from './providers/recorder-client.js';
import type { AuthenticatedAuditSubmissionContext } from './recorder-config.js';
import type { AuditProducerEventCoreV1, PartyRef } from './types.js';

export function sameSigner(left: AuditSigner['ref'], right: AuditSigner['ref']): boolean {
  return left.did === right.did && left.kid === right.kid && left.alg === right.alg;
}

export function sameParty(left: PartyRef, right: PartyRef): boolean {
  return canonicalizeJson(left) === canonicalizeJson(right);
}

function authorityMatchesParty(
  authority: string,
  boundRef: PartyRef | undefined,
  claimedRef: PartyRef,
): boolean {
  if (boundRef !== undefined) return sameParty(boundRef, claimedRef);
  return (claimedRef.kind === 'public_did' || claimedRef.kind === 'pairwise_did') &&
    claimedRef.did === authority;
}

export function validateSubmissionEnvelope(
  ledgerId: string,
  submission: AuditRecorderSubmission,
  context: AuthenticatedAuditSubmissionContext,
): void {
  if (!context.producerAuthority || !context.tenantAuthority) {
    throw new AuditProtocolError(
      AUDIT_ERROR_CODES.UNAUTHORIZED_SUBMISSION,
      'Authenticated producer and tenant authority are required',
    );
  }
  if (submission.ledgerId !== ledgerId) {
    throw new AuditProtocolError(AUDIT_ERROR_CODES.LEDGER_MISMATCH, 'Wrong audit ledger');
  }
}

export function validateEventAuthority(
  tenantRef: PartyRef,
  event: AuditProducerEventCoreV1,
  context: AuthenticatedAuditSubmissionContext,
): void {
  if (!authorityMatchesParty(
    context.producerAuthority,
    context.producerRef,
    event.source.producer,
  )) {
    throw new AuditProtocolError(
      AUDIT_ERROR_CODES.UNAUTHORIZED_SUBMISSION,
      'Event producer does not match the authenticated producer authority',
    );
  }
  if (!sameParty(event.tenantRef, tenantRef) ||
    !authorityMatchesParty(context.tenantAuthority, context.tenantRef, event.tenantRef)) {
    throw new AuditProtocolError(
      AUDIT_ERROR_CODES.UNAUTHORIZED_SUBMISSION,
      'Event tenant does not match the authenticated tenant authority',
    );
  }
}
