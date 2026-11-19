import { exportJWK, generateKeyPair } from 'jose';
import { describe, expect, it } from 'vitest';
import { NodeCryptoProvider } from '../../providers/node-crypto.js';
import { runAuditCli, type AuditCliIo } from '../cli.js';
import { CompactJwsAuditSigner, CryptoProviderAuditHasher, hashAuditValue } from '../crypto.js';
import { MemoryAuditJournal } from '../providers/memory-journal.js';
import { AuditRecorderService } from '../recorder-service.js';
import { AUDIT_BUNDLE_MEDIA_TYPES, AuditReplayBundleExporter } from '../replay-bundle.js';
import type { AuditVerificationPolicyV1 } from '../types.js';
import { producerEvent, tenantRef } from './audit-fixtures.js';

const ledger = { ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1' };
const SIGNED_AT = 1_750_000_001_000;
const DAY = 86_400_000;

type Report = Record<string, { verdict: string; reasonCodes: string[] }>;

/**
 * A bundle of one recorded call, signed at `SIGNED_AT` by one key that records and exports, with
 * the policy that names that key valid until `validUntil` under `keyRevocationMode`.
 */
async function signedBundle(validUntil: number, keyRevocationMode: AuditVerificationPolicyV1['keyRevocationMode']) {
  const hasher = new CryptoProviderAuditHasher(new NodeCryptoProvider());
  const { publicKey, privateKey } = await generateKeyPair('EdDSA', { extractable: true });
  const ref = { did: 'did:web:audit.example', kid: 'did:web:audit.example#recorder', alg: 'EdDSA' as const };
  const signer = new CompactJwsAuditSigner(ref, privateKey);
  const journal = new MemoryAuditJournal();
  await new AuditRecorderService({
    ...ledger, tenantRef, binding: 'urn:kya-os:audit-binding:mcp:2025-11-25', sourceId: 'recorder',
    journal, signer, hasher, clock: { now: () => SIGNED_AT },
  }).submitAuthenticated(
    { ledgerId: ledger.ledgerId, producerEvent: producerEvent('evt_1', 1), encryptedEvidence: [] },
    { producerAuthority: 'did:key:zProducer', tenantAuthority: 'tenant-1', tenantRef },
  );
  const entries = await journal.snapshot(ledger);
  const policy: AuditVerificationPolicyV1 = {
    policyId: 'policy:cli',
    trustedLedgerEpochs: [{ ...ledger, recorderKeys: [{ signer: ref, validUntil }] }],
    trustedObservers: [],
    authorizedExporters: [{
      signerKeys: [{ signer: ref, validUntil }],
      allowedLedgerIds: [ledger.ledgerId],
      allowedPurposes: ['regulatory-review'],
    }],
    acceptedIntegritySuites: ['KYA-AUDIT-JCS-SHA256-JWS-2026', 'KYA-AUDIT-BUNDLE-JCS-SHA256-JWS-2026'],
    acceptedAlgorithms: ['EdDSA'],
    keyRevocationMode,
  };
  const bundle = await new AuditReplayBundleExporter({ hasher, signer, clock: { now: () => SIGNED_AT + 1_000 } })
    .export({
      bundleId: 'bundle', purpose: 'regulatory-review',
      verificationPolicyDigest: await hashAuditValue(hasher, 'org.kya-os.audit.verification-policy.v1', policy),
      selections: [{
        ...ledger, firstSequence: '0', lastSequence: String(entries.length - 1),
        expectedHeadDigest: entries.at(-1)!.entryDigest, checkpointTreeSizes: [],
      }],
      components: [{
        path: 'entries.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.entries, disposition: 'included', content: entries,
      }],
    });
  return {
    'bundle.json': JSON.stringify(bundle),
    'policy.json': JSON.stringify(policy),
    'keys.json': JSON.stringify({ keys: [{ kid: ref.kid, jwk: await exportJWK(publicKey) }] }),
  } as Record<string, string>;
}

async function verify(files: Record<string, string>) {
  const output: string[] = [];
  const errors: string[] = [];
  const io: AuditCliIo = {
    readText: async (path) => files[path]!,
    write: (text) => output.push(text),
    writeError: (text) => errors.push(text),
  };
  const exitCode = await runAuditCli(['verify', 'bundle.json', '--policy', 'policy.json', '--keys', 'keys.json'], io);
  return { exitCode, output: output.join(''), errors: errors.join('') };
}

describe('kya-audit verify: the policy constraints that need the present time', () => {
  it('exits 1 when the policy requires current keys and the signing key ended before now', async () => {
    const { exitCode, output } = await verify(await signedBundle(SIGNED_AT + DAY, 'current'));
    const report = JSON.parse(output) as Report;
    expect(report['cryptographicIntegrity']!.verdict).toBe('valid');
    expect(report['currentAuthorization']).toMatchObject({ verdict: 'invalid' });
    expect(report['currentAuthorization']!.reasonCodes).toContain('AUDIT_KEY_NOT_CURRENT');
    expect(exitCode).toBe(1);
  });

  it('evaluates current keys under keyRevocationMode both as well', async () => {
    const { exitCode, output } = await verify(await signedBundle(SIGNED_AT + DAY, 'both'));
    expect((JSON.parse(output) as Report)['currentAuthorization']!.reasonCodes).toContain('AUDIT_KEY_NOT_CURRENT');
    expect(exitCode).toBe(1);
  });

  it('exits 0 when the signing key is still valid now', async () => {
    const { exitCode, output } = await verify(await signedBundle(Date.now() + DAY, 'current'));
    const report = JSON.parse(output) as Report;
    expect(report['currentAuthorization']!.reasonCodes).not.toContain('AUDIT_KEY_NOT_CURRENT');
    expect(report['currentAuthorization']!.reasonCodes).not.toContain('AUDIT_NOT_EVALUATED');
    expect(exitCode).toBe(0);
  });
});
