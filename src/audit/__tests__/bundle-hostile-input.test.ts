/**
 * `verifyAuditBundle` is an offline, fail-closed verifier that anyone may hand a bundle: whatever
 * the bundle holds, it answers with a report and never throws.
 */

import { describe, expect, it } from 'vitest';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { CryptoProviderAuditHasher } from '../crypto.js';
import { AUDIT_BUNDLE_MEDIA_TYPES, AuditReplayBundleExporter, verifyAuditBundle } from '../replay-bundle.js';
import type { AuditSigner } from '../crypto.js';
import { policy } from './audit-fixtures.js';

const hasher = new CryptoProviderAuditHasher(new NodeCryptoProvider());

/** A key no policy names, as a stranger's would be. */
const stranger: AuditSigner = {
  ref: { did: 'did:key:zStranger', kid: 'did:key:zStranger#zStranger', alg: 'EdDSA' },
  sign: async () => 'not.a.signature',
};

/** A bundle the shipped exporter wrote, whose every evidence component carries `content`. */
async function bundleCarrying(content: unknown[]): Promise<unknown> {
  const bundle = await new AuditReplayBundleExporter({
    hasher, signer: stranger, clock: { now: () => 1_750_000_010_000 },
  }).export({
    bundleId: 'bundle', purpose: 'any',
    verificationPolicyDigest: `sha256:${'0'.repeat(64)}`,
    selections: [{
      ledgerId: 'ledger', ledgerEpochId: 'epoch_1', firstSequence: '0', lastSequence: '0',
      expectedHeadDigest: `sha256:${'0'.repeat(64)}`, checkpointTreeSizes: [],
    }],
    components: Object.entries(AUDIT_BUNDLE_MEDIA_TYPES).map(([name, mediaType]) => ({
      path: `${name}.json`, mediaType, disposition: 'included' as const, content,
    })),
  });
  return JSON.parse(JSON.stringify(bundle)) as unknown;
}

describe('a bundle verified for whoever sends it', () => {
  it('answers with a report when its components carry more items than a call takes arguments', async () => {
    const received = await bundleCarrying(new Array<number>(300_000).fill(0));

    const report = await verifyAuditBundle(received, policy, {
      hasher, signatures: { verify: async () => false },
    });

    expect(report.cryptographicIntegrity.verdict).toBe('invalid');
    expect(report.checkpointIntegrity.verdict).toBe('invalid');
    expect(report.anchorIntegrity.verdict).toBe('invalid');
  }, 60_000);
});
