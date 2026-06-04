import type { DIDDocument } from './vc-verifier.js';
import type {
  CheqdDidRegistrarClient,
  CheqdRegistrarResult,
  CheqdRegistrarSigner,
} from '../cheqd/registrar.js';

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

export interface UpdateCheqdAlsoKnownAsOptions {
  didWeb: string;
  didCheqd: string;
  resolver: { resolve(did: string): Promise<DIDDocument | null> };
  registrar: CheqdDidRegistrarClient;
  signer: CheqdRegistrarSigner;
  verificationMethodId?: string;
}

export interface UpdateCheqdAlsoKnownAsResult {
  changed: boolean;
  didDocument?: DIDDocument;
  registrarResult?: CheqdRegistrarResult;
  reason?: string;
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

export async function updateCheqdAlsoKnownAs(
  options: UpdateCheqdAlsoKnownAsOptions,
): Promise<UpdateCheqdAlsoKnownAsResult> {
  const didCheqd = normalizeDid(options.didCheqd);
  const didWeb = normalizeDid(options.didWeb);
  const didDocument = await options.resolver.resolve(didCheqd);

  if (!isDidDocument(didDocument) || normalizeDid(didDocument.id) !== didCheqd) {
    return {
      changed: false,
      reason: `Could not resolve DID Document for ${didCheqd}`,
    };
  }

  if (hasAlsoKnownAs(didDocument, didWeb)) {
    return { changed: false, didDocument };
  }

  const nextDocument: DIDDocument = {
    ...didDocument,
    alsoKnownAs: [...(didDocument.alsoKnownAs ?? []), didWeb],
  };

  const registrarResult = await options.registrar.updateDid({
    did: didCheqd,
    didDocument: nextDocument,
    signer: options.signer,
    verificationMethodId: options.verificationMethodId,
  });

  return {
    changed: registrarResult.success,
    didDocument: nextDocument,
    registrarResult,
    ...(registrarResult.success ? {} : { reason: registrarResult.reason }),
  };
}

function hasAlsoKnownAs(document: DIDDocument, did: string): boolean {
  return (document.alsoKnownAs ?? []).some((entry) => normalizeDid(entry) === did);
}

function normalizeDid(did: string): string {
  return did.trim();
}

function isDidDocument(value: unknown): value is DIDDocument {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const doc = value as Record<string, unknown>;
  if (typeof doc['id'] !== 'string' || doc['id'].trim().length === 0) {
    return false;
  }
  if (doc['alsoKnownAs'] !== undefined) {
    return Array.isArray(doc['alsoKnownAs']) &&
      doc['alsoKnownAs'].every((entry) => typeof entry === 'string');
  }
  return true;
}
