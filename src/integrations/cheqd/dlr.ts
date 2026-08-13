import { canonicalize } from 'json-canonicalize';
import type { CryptoProvider } from '../../providers/base.js';
import { bytesToBase64 } from '../../utils/base64.js';
import { isRecord, stripTrailingSlashes } from '../../utils/index.js';
import { assertAnchorableStatusListCredential } from '../../utils/statuslist-bits.js';
import type { CheqdCreateResourceBody } from './registrar.js';

/**
 * Artifact kinds KYA-OS anchors as DID-Linked Resources. The taxonomy — and
 * the JCS-canonicalize → sha256 content addressing in
 * {@link prepareCheqdDlrResource} — is protocol-level rather than
 * cheqd-specific: the day a SECOND anchoring integration lands, both graduate
 * to a central module with deprecated aliases kept here (rule-of-two,
 * recorded now so that PR is mechanical).
 */
export const CHEQD_DLR_ARTIFACT_TYPES = [
  'CapabilityManifest',
  'ConformanceManifest',
  'AccessHashManifest',
  'TrustConfigManifest',
  'StatusListCredential',
] as const;

export type CheqdDlrArtifactType = (typeof CHEQD_DLR_ARTIFACT_TYPES)[number];

export interface CheqdDlrArtifact {
  id?: string;
  type: CheqdDlrArtifactType;
  version?: string;
  subjectDid: string;
  createdAt?: string;
  contentHash?: string;
  content: unknown;
  name?: string;
  resourceType?: string;
  mediaType?: string;
  metadata?: Record<string, unknown>;
}

export interface CheqdDlrReference {
  did: string;
  resourceId?: string;
  resourceName: string;
  resourceType: string;
  url: string;
}

export interface PreparedCheqdDlrResource {
  artifact: CheqdDlrArtifact;
  resource: CheqdCreateResourceBody;
  contentHash: string;
  canonicalContent: string;
}

const SHA256_HASH_REGEX = /^sha256:[a-f0-9]{64}$/;
const RESOURCE_ID_REGEX = /^[a-z0-9-]{36}$/;

export function validateCheqdDlrArtifact(
  artifact: unknown,
): { valid: boolean; reason?: string } {
  if (!isRecord(artifact)) {
    return { valid: false, reason: 'DLR artifact must be an object' };
  }

  if (!isSupportedCheqdDlrArtifactType(artifact['type'])) {
    return { valid: false, reason: 'Unsupported DLR artifact type' };
  }

  if (typeof artifact['subjectDid'] !== 'string' || artifact['subjectDid'].trim().length === 0) {
    return { valid: false, reason: 'DLR artifact subjectDid is required' };
  }

  if (artifact['content'] === undefined) {
    return { valid: false, reason: 'DLR artifact content is required' };
  }

  // A status list's content is the WHOLE SIGNED VC (hash-what-you-publish:
  // the canonical bytes anchored on-chain are exactly the credential a
  // verifier fetches). The shared guard enforces anchor-fitness — signed,
  // bitstring present — method-agnostically.
  if (artifact['type'] === 'StatusListCredential') {
    try {
      assertAnchorableStatusListCredential(artifact['content']);
    } catch (error) {
      return {
        valid: false,
        reason: error instanceof Error ? error.message : String(error),
      };
    }
  }

  if (
    artifact['contentHash'] !== undefined &&
    (typeof artifact['contentHash'] !== 'string' || !SHA256_HASH_REGEX.test(artifact['contentHash']))
  ) {
    return { valid: false, reason: 'DLR artifact contentHash must match sha256:<64 hex chars>' };
  }

  if (artifact['id'] !== undefined && (typeof artifact['id'] !== 'string' || !RESOURCE_ID_REGEX.test(artifact['id']))) {
    return { valid: false, reason: 'DLR artifact id must be a 36-character lowercase resource id' };
  }

  return { valid: true };
}

export function isSupportedCheqdDlrArtifactType(
  value: unknown,
): value is CheqdDlrArtifactType {
  return typeof value === 'string' &&
    (CHEQD_DLR_ARTIFACT_TYPES as readonly string[]).includes(value);
}

export async function prepareCheqdDlrResource(
  artifact: CheqdDlrArtifact,
  cryptoProvider: CryptoProvider,
): Promise<PreparedCheqdDlrResource> {
  const validation = validateCheqdDlrArtifact(artifact);
  if (!validation.valid) {
    throw new Error(validation.reason ?? 'Invalid DLR artifact');
  }

  const canonicalContent = canonicalize(artifact.content as Parameters<typeof canonicalize>[0]);
  const contentBytes = new TextEncoder().encode(canonicalContent);
  const contentHash = artifact.contentHash ?? await cryptoProvider.hash(contentBytes);

  if (!SHA256_HASH_REGEX.test(contentHash)) {
    throw new Error('DLR content hash must match sha256:<64 hex chars>');
  }

  const normalizedArtifact: CheqdDlrArtifact = {
    ...artifact,
    contentHash,
  };

  return {
    artifact: normalizedArtifact,
    resource: {
      name: artifact.name ?? artifact.type,
      type: artifact.resourceType ?? artifact.type,
      data: bytesToBase64(contentBytes),
      ...(artifact.version ? { version: artifact.version } : {}),
      ...(artifact.mediaType ? { mediaType: artifact.mediaType } : { mediaType: 'application/json' }),
      ...(artifact.metadata ? { metadata: artifact.metadata } : {}),
    },
    contentHash,
    canonicalContent,
  };
}
export function buildCheqdDlrReference(options: {
  did: string;
  resolverUrl?: string;
  resourceId?: string;
  resourceName: string;
  resourceType: string;
}): CheqdDlrReference {
  if (options.resourceId !== undefined && !RESOURCE_ID_REGEX.test(options.resourceId)) {
    throw new Error('resourceId must be a 36-character lowercase resource id');
  }

  const base = stripTrailingSlashes(options.resolverUrl ?? 'https://resolver.cheqd.net');
  const identifiersBase = base.endsWith('/1.0/identifiers')
    ? base
    : `${base}/1.0/identifiers`;
  const url = options.resourceId
    ? `${identifiersBase}/${options.did}/resources/${options.resourceId}`
    : `${identifiersBase}/${options.did}?resourceName=${encodeURIComponent(options.resourceName)}&resourceType=${encodeURIComponent(options.resourceType)}`;

  return {
    did: options.did,
    ...(options.resourceId ? { resourceId: options.resourceId } : {}),
    resourceName: options.resourceName,
    resourceType: options.resourceType,
    url,
  };
}
