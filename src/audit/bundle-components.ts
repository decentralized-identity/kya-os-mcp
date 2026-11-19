/**
 * The parts of a replay bundle as the verifier reads them: the media types of its components, safe
 * component paths, the inventory metadata of a component, the artifacts an included component
 * carries, and how those artifacts are keyed by ledger epoch and ordered by sequence.
 */

import type { AuditBundleComponentV1, AuditLedgerRef, AuditReplayBundleV1 } from './types.js';

export const AUDIT_BUNDLE_MEDIA_TYPES = Object.freeze({
  entries: 'application/vnd.kya-os.audit.entries.v1+json',
  checkpoints: 'application/vnd.kya-os.audit.checkpoints.v1+json',
  inclusionProofs: 'application/vnd.kya-os.audit.inclusion-proofs.v1+json',
  consistencyProofs: 'application/vnd.kya-os.audit.consistency-proofs.v1+json',
  observations: 'application/vnd.kya-os.audit.observations.v1+json',
  anchors: 'application/vnd.kya-os.audit.anchors.v1+json',
  verificationReport: 'application/vnd.kya-os.audit.verification-report.v1+json',
});

export function assertPath(path: string): void {
  if (path.length === 0 || path.startsWith('/') || path.includes('\\') ||
    path.split('/').some((segment) => segment === '' || segment === '.' || segment === '..')) {
    throw new TypeError('Bundle component path must be a safe canonical relative path');
  }
}

export function componentMetadata(component: AuditBundleComponentV1): Omit<AuditBundleComponentV1, 'content'> {
  return {
    path: component.path,
    mediaType: component.mediaType,
    disposition: component.disposition,
    ...(component.digest === undefined ? {} : { digest: component.digest }),
    ...(component.size === undefined ? {} : { size: component.size }),
    ...(component.reasonCode === undefined ? {} : { reasonCode: component.reasonCode }),
  };
}

/**
 * The items of every included component of `mediaType`, in bundle order. Appended one by one: a
 * component's array is the sender's to size, and spread into one call it would exceed the
 * engine's argument limit.
 */
export function includedArrays<T>(
  bundle: AuditReplayBundleV1,
  mediaType: string,
): T[] {
  const result: T[] = [];
  for (const component of bundle.components) {
    if (component.disposition !== 'included' || component.mediaType !== mediaType ||
      !Array.isArray(component.content)) continue;
    for (const item of component.content as T[]) result.push(item);
  }
  return result;
}

export function ledgerEpochKey(value: { ledgerId: string; ledgerEpochId: string }): string {
  return `${value.ledgerId}\0${value.ledgerEpochId}`;
}

export function sameLedgerEpoch(left: AuditLedgerRef, right: AuditLedgerRef): boolean {
  return left.ledgerId === right.ledgerId && left.ledgerEpochId === right.ledgerEpochId;
}

export function compareDecimal(left: string, right: string): number {
  const a = BigInt(left);
  const b = BigInt(right);
  return a < b ? -1 : a > b ? 1 : 0;
}
