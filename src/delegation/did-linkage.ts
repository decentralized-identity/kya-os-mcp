import type { DIDDocument } from './vc-verifier.js';
import { isRecord } from '../utils/index.js';

export interface VerifyDidLinkageOptions {
  primaryDid: string;
  secondaryDid: string;
  primaryDidDocument: DIDDocument | null | undefined;
  secondaryDidDocument: DIDDocument | null | undefined;
  requireBidirectional?: boolean;
}

export interface DidLinkageVerificationResult {
  valid: boolean;
  reason?: string;
  checks: {
    primaryReferencesSecondary: boolean;
    secondaryReferencesPrimary: boolean;
    primaryDocumentMatches: boolean;
    secondaryDocumentMatches: boolean;
  };
}

export function verifyDidLinkage(
  options: VerifyDidLinkageOptions,
): DidLinkageVerificationResult {
  const requireBidirectional = options.requireBidirectional ?? true;
  const primaryDid = normalizeDid(options.primaryDid);
  const secondaryDid = normalizeDid(options.secondaryDid);
  const primaryDoc = options.primaryDidDocument;
  const secondaryDoc = options.secondaryDidDocument;

  const checks = {
    primaryReferencesSecondary: false,
    secondaryReferencesPrimary: false,
    primaryDocumentMatches: false,
    secondaryDocumentMatches: false,
  };

  if (!isDidDocument(primaryDoc)) {
    return { valid: false, reason: 'Primary DID Document is missing or malformed', checks };
  }
  if (!isDidDocument(secondaryDoc)) {
    return { valid: false, reason: 'Secondary DID Document is missing or malformed', checks };
  }

  checks.primaryDocumentMatches = normalizeDid(primaryDoc.id) === primaryDid;
  checks.secondaryDocumentMatches = normalizeDid(secondaryDoc.id) === secondaryDid;
  if (!checks.primaryDocumentMatches || !checks.secondaryDocumentMatches) {
    return { valid: false, reason: 'DID Document id does not match expected DID', checks };
  }

  checks.primaryReferencesSecondary = hasAlsoKnownAs(primaryDoc, secondaryDid);
  checks.secondaryReferencesPrimary = hasAlsoKnownAs(secondaryDoc, primaryDid);

  if (requireBidirectional) {
    if (!checks.primaryReferencesSecondary || !checks.secondaryReferencesPrimary) {
      return { valid: false, reason: 'Bidirectional alsoKnownAs linkage is not present', checks };
    }
    return { valid: true, checks };
  }

  if (!checks.primaryReferencesSecondary && !checks.secondaryReferencesPrimary) {
    return { valid: false, reason: 'No alsoKnownAs linkage is present', checks };
  }

  return { valid: true, checks };
}

export function hasAlsoKnownAs(document: DIDDocument, did: string): boolean {
  return (document.alsoKnownAs ?? []).some((entry) => normalizeDid(entry) === did);
}

export function normalizeDid(did: string): string {
  return did.trim();
}

export function isDidDocument(value: unknown): value is DIDDocument {
  if (!isRecord(value)) {
    return false;
  }
  if (typeof value['id'] !== 'string' || value['id'].trim().length === 0) {
    return false;
  }
  if (value['alsoKnownAs'] !== undefined) {
    return Array.isArray(value['alsoKnownAs']) &&
      value['alsoKnownAs'].every((entry) => typeof entry === 'string');
  }
  return true;
}
