/**
 * Replay bundles over the recorded history of `audit-fixtures.ts`, for the tests of the bundle
 * verifier: a policy that trusts the recorder and authorizes it to export, a selection of a whole
 * ledger range, and the exporter and verifier calls with those defaults.
 */

import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { CryptoProviderAuditHasher, hashAuditValue } from '../crypto.js';
import {
  AUDIT_BUNDLE_MEDIA_TYPES,
  AuditReplayBundleExporter,
  verifyAuditBundle,
  type AuditBundleComponentInput,
  type VerifyAuditBundleDependencies,
} from '../replay-bundle.js';
import type {
  AuditBundleSelectionV1,
  AuditLedgerRef,
  AuditReplayBundleV1,
  AuditVerificationPolicyV1,
  AuditVerificationReportV1,
  SignedAuditEntryV1,
} from '../types.js';
import { policy, TestSignatureVerifier, TestSigner } from './audit-fixtures.js';

export const hasher = new CryptoProviderAuditHasher(new NodeCryptoProvider());
export const signer = new TestSigner();
export const LEDGER: AuditLedgerRef = { ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1' };

/** Trusts the recorder of `LEDGER` and authorizes its key to export that ledger. */
export const bundlePolicy: AuditVerificationPolicyV1 = {
  ...policy,
  authorizedExporters: [{
    signerKeys: [{ signer: signer.ref }],
    allowedLedgerIds: [LEDGER.ledgerId],
    allowedPurposes: ['regulatory-review'],
  }],
  acceptedIntegritySuites: [...policy.acceptedIntegritySuites, 'KYA-AUDIT-BUNDLE-JCS-SHA256-JWS-2026'],
};

/** A selection of every entry given, all of one ledger epoch, in sequence order. */
export function selectionOf(
  entries: readonly SignedAuditEntryV1[],
  checkpointTreeSizes: string[] = [],
): AuditBundleSelectionV1 {
  const first = entries[0]!;
  const last = entries.at(-1)!;
  return {
    ledgerId: first.core.ledgerId,
    ledgerEpochId: first.core.ledgerEpochId,
    firstSequence: first.core.sequence,
    lastSequence: last.core.sequence,
    expectedHeadDigest: last.entryDigest,
    checkpointTreeSizes,
  };
}

/** An included component of the given media type. */
export function included(
  mediaType: keyof typeof AUDIT_BUNDLE_MEDIA_TYPES,
  content: readonly unknown[],
): AuditBundleComponentInput {
  return {
    path: `${mediaType}.json`, mediaType: AUDIT_BUNDLE_MEDIA_TYPES[mediaType], disposition: 'included', content,
  };
}

/** A bundle the recorder's key exports under `verificationPolicy`. */
export async function exportBundle(
  selections: readonly AuditBundleSelectionV1[],
  components: readonly AuditBundleComponentInput[],
  verificationPolicy: AuditVerificationPolicyV1 = bundlePolicy,
): Promise<AuditReplayBundleV1> {
  return new AuditReplayBundleExporter({
    hasher, signer, clock: { now: () => 1_750_000_010_000 },
  }).export({
    bundleId: 'bundle', purpose: 'regulatory-review',
    verificationPolicyDigest: await hashAuditValue(
      hasher, 'org.kya-os.audit.verification-policy.v1', verificationPolicy,
    ),
    selections,
    components,
  });
}

/** The verifier's report on `bundle` as it would arrive over the wire. */
export async function verifyBundle(
  bundle: AuditReplayBundleV1,
  verificationPolicy: AuditVerificationPolicyV1 = bundlePolicy,
  dependencies: Partial<VerifyAuditBundleDependencies> = {},
): Promise<AuditVerificationReportV1> {
  return verifyAuditBundle(JSON.parse(JSON.stringify(bundle)) as unknown, verificationPolicy, {
    hasher, signatures: new TestSignatureVerifier(), ...dependencies,
  });
}
