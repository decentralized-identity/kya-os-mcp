/**
 * Produces replay bundles: a signed manifest over an inventory of components, each included with
 * its digest and size, or omitted with a reason. `./replay-bundle.ts` verifies them and
 * re-exports this module, so imports from there are unchanged.
 */

import { canonicalizeJson, canonicalizeJsonBytes } from '../utils/canonical-json.js';
import { assertPath, componentMetadata } from './bundle-components.js';
import type { AuditHasher, AuditSigner } from './crypto.js';
import { hashAuditValue } from './crypto.js';
import { AUDIT_DIGEST_DOMAINS } from './integrity.js';
import { parseAuditBundleManifestCore } from './schemas.js';
import type {
  AuditBundleComponentV1,
  AuditBundleDisposition,
  AuditBundleSelectionV1,
  AuditReplayBundleV1,
} from './types.js';

export const BUNDLE_SCHEMA =
  'https://schema.kya-os.org/v1/protocol/audit/bundle-manifest/v1.0.0' as const;
const BUNDLE_SUITE = 'KYA-AUDIT-BUNDLE-JCS-SHA256-JWS-2026' as const;

export type AuditBundleComponentInput =
  | {
      path: string;
      mediaType: string;
      disposition: 'included';
      content: unknown;
    }
  | {
      path: string;
      mediaType: string;
      disposition: Exclude<AuditBundleDisposition, 'included'>;
      reasonCode: string;
    };

export interface AuditReplayBundleExportInput {
  bundleId: string;
  purpose: string;
  verificationPolicyDigest: `sha256:${string}`;
  selections: readonly AuditBundleSelectionV1[];
  components: readonly AuditBundleComponentInput[];
}

export interface AuditReplayBundleExporterOptions {
  hasher: AuditHasher;
  signer: AuditSigner;
  clock: { now(): number };
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== 'object' || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function cloneCanonical<T>(value: T): T {
  return JSON.parse(canonicalizeJson(value)) as T;
}

/** Produces deterministic, signed-inventory evidence bundles. */
export class AuditReplayBundleExporter {
  constructor(private readonly options: AuditReplayBundleExporterOptions) {}

  async export(input: AuditReplayBundleExportInput): Promise<AuditReplayBundleV1> {
    if (!input.bundleId || !input.purpose) {
      throw new TypeError('Bundle ID and export purpose are required');
    }
    const paths = new Set<string>();
    const sortedInputs = [...input.components].sort((left, right) =>
      left.path.localeCompare(right.path));
    const components: AuditBundleComponentV1[] = [];
    for (const item of sortedInputs) {
      assertPath(item.path);
      if (paths.has(item.path)) throw new TypeError(`Duplicate bundle component path: ${item.path}`);
      paths.add(item.path);
      if (item.disposition === 'included') {
        const content = cloneCanonical(item.content);
        const bytes = canonicalizeJsonBytes(content);
        components.push({
          path: item.path,
          mediaType: item.mediaType,
          disposition: 'included',
          digest: await this.options.hasher.sha256(bytes),
          size: String(bytes.length),
          content,
        });
      } else {
        if (!item.reasonCode) throw new TypeError('Excluded bundle items require a reason code');
        components.push({
          path: item.path,
          mediaType: item.mediaType,
          disposition: item.disposition,
          reasonCode: item.reasonCode,
        });
      }
    }

    const inventory = components.map((component) => componentMetadata(component));
    const core = parseAuditBundleManifestCore({
      schema: BUNDLE_SCHEMA,
      bundleId: input.bundleId,
      formatVersion: '1.0.0',
      selections: cloneCanonical([...input.selections]),
      exporter: this.options.signer.ref,
      purpose: input.purpose,
      exportedAt: this.options.clock.now(),
      verificationPolicyDigest: input.verificationPolicyDigest,
      inventory,
      integritySuite: BUNDLE_SUITE,
    });
    const manifestDigest = await hashAuditValue(
      this.options.hasher,
      AUDIT_DIGEST_DOMAINS.bundleManifest,
      core,
    );
    return deepFreeze({
      manifest: {
        core,
        manifestDigest,
        jws: await this.options.signer.sign(canonicalizeJsonBytes(core)),
      },
      components,
    });
  }
}
