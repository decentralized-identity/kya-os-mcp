import { describe, expect, it } from 'vitest';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import type { AuditSignatureVerifier, AuditSigner } from '../crypto.js';
import { CryptoProviderAuditHasher } from '../crypto.js';
import { AuditCheckpointBuilder, MemoryAuditCheckpointStore } from '../checkpoint.js';
import { AuditArtifactVerifier, AUDIT_REASON_CODES } from '../verifier.js';
import { MemoryAuditJournal } from '../providers/memory-journal.js';
import { AuditRecorderService } from '../recorder-service.js';
import { MemoryAuditCheckpointObserver } from '../providers/observer.js';
import type {
  AuditProducerEventCoreV1,
  AuditVerificationPolicyV1,
  PartyRef,
  SignerRef,
} from '../types.js';

const tenantRef: PartyRef = {
  kind: 'keyed_commitment',
  value: `sha256:${'a'.repeat(64)}`,
  keyId: 'tenant-key-1',
};

class TestSigner implements AuditSigner {
  readonly ref = {
    did: 'did:key:zRecorder',
    kid: 'did:key:zRecorder#zRecorder',
    alg: 'EdDSA' as const,
  };
  async sign(payload: Uint8Array): Promise<string> {
    return `test.${Buffer.from(payload).toString('base64url')}.signature`;
  }
}

class TestSignatureVerifier implements AuditSignatureVerifier {
  async verify(payload: Uint8Array, jws: string, signer: SignerRef): Promise<boolean> {
    return signer.kid === 'did:key:zRecorder#zRecorder' &&
      jws === `test.${Buffer.from(payload).toString('base64url')}.signature`;
  }
}

function producerEvent(id: string, sequence: number): AuditProducerEventCoreV1 {
  return {
    schema: 'https://schema.kya-os.org/v1/protocol/audit/event/v1.0.0',
    eventId: id,
    eventType: 'tool.call.completed',
    eventVersion: '1.0.0',
    binding: 'urn:kya-os:audit-binding:mcp:2025-11-25',
    occurredAt: 1_750_000_000_000 + sequence,
    tenantRef,
    source: {
      producer: { kind: 'pairwise_did', did: 'did:key:zProducer' },
      sourceId: 'source-1',
      sourceSequence: String(sequence),
    },
    action: { category: 'tool.call' },
    outcome: 'succeeded',
    evidence: [],
    details: { family: 'tool', phase: 'completed', attempt: '1' },
    privacy: { classification: 'internal', retentionClass: 'audit-365d' },
  };
}

const policy: AuditVerificationPolicyV1 = {
  policyId: 'policy:test',
  trustedLedgerEpochs: [{
    ledgerId: 'kya:tenant:prod:primary',
    ledgerEpochId: 'epoch_1',
    recorderKeys: [{ signer: new TestSigner().ref }],
  }],
  trustedObservers: [],
  authorizedExporters: [],
  acceptedIntegritySuites: [
    'KYA-AUDIT-JCS-SHA256-JWS-2026',
    'KYA-AUDIT-RFC9162-SHA256-JWS-2026',
  ],
  acceptedAlgorithms: ['EdDSA'],
  keyRevocationMode: 'as_observed',
};

async function recordedHistory() {
  const journal = new MemoryAuditJournal();
  const recorder = new AuditRecorderService({
    ledgerId: 'kya:tenant:prod:primary',
    ledgerEpochId: 'epoch_1',
    tenantRef,
    binding: 'urn:kya-os:audit-binding:mcp:2025-11-25',
    sourceId: 'recorder-1',
    journal,
    signer: new TestSigner(),
    hasher: new CryptoProviderAuditHasher(new NodeCryptoProvider()),
    clock: { now: () => 1_750_000_001_000 },
  });
  for (let index = 1; index <= 3; index += 1) {
    await recorder.submitAuthenticated({
      ledgerId: 'kya:tenant:prod:primary',
      producerEvent: producerEvent(`evt_${index}`, index),
      encryptedEvidence: [],
    }, { producerAuthority: 'did:key:zProducer', tenantAuthority: 'tenant-1', tenantRef });
  }
  const ledger = { ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1' };
  return { journal, ledger, entries: await journal.snapshot(ledger) };
}

async function history() {
  return (await recordedHistory()).entries;
}

describe('AuditArtifactVerifier', () => {
  const verifier = new AuditArtifactVerifier({
    hasher: new CryptoProviderAuditHasher(new NodeCryptoProvider()),
    signatures: new TestSignatureVerifier(),
  });

  it('independently verifies entry hashes, receipts, trust, and chain order', async () => {
    const report = await verifier.verifyEntries(await history(), policy);
    expect(report.cryptographicIntegrity).toEqual({ verdict: 'valid', reasonCodes: [] });
    expect(report.chainIntegrity).toEqual({ verdict: 'valid', reasonCodes: [] });
    expect(report.checkpointIntegrity.verdict).toBe('indeterminate');
  });

  it('detects event mutation even if redundant envelope fields are left unchanged', async () => {
    const entries = structuredClone(await history());
    entries[2]!.core.event.action.category = 'mutated';
    const report = await verifier.verifyEntries(entries, policy);
    expect(report.cryptographicIntegrity.verdict).toBe('invalid');
    expect(report.cryptographicIntegrity.reasonCodes).toContain(
      AUDIT_REASON_CODES.EVENT_DIGEST_MISMATCH,
    );
  });

  it('detects deletion and reordering as chain failures', async () => {
    const entries = await history();
    const deleted = await verifier.verifyEntries([entries[0]!, entries[2]!, entries[3]!], policy);
    expect(deleted.chainIntegrity.reasonCodes).toContain(AUDIT_REASON_CODES.SEQUENCE_GAP);

    const reordered = await verifier.verifyEntries(
      [entries[0]!, entries[2]!, entries[1]!, entries[3]!],
      policy,
    );
    expect(reordered.chainIntegrity.verdict).toBe('invalid');
  });

  it('does not trust a cryptographically valid recorder absent from out-of-band policy', async () => {
    const report = await verifier.verifyEntries(await history(), {
      ...policy,
      trustedLedgerEpochs: [],
    });
    expect(report.cryptographicIntegrity.reasonCodes).toContain(
      AUDIT_REASON_CODES.UNTRUSTED_RECORDER,
    );
  });

  it('fails closed without throwing when an entry or checkpoint is hostile input', async () => {
    const malformedEntry = {
      core: {
        schema: 'https://schema.kya-os.org/v1/protocol/audit/entry/v1.0.0',
      },
    };
    const entryReport = await verifier.verifyEntries([malformedEntry], policy);
    expect(entryReport.cryptographicIntegrity).toEqual({
      verdict: 'invalid',
      reasonCodes: [AUDIT_REASON_CODES.SCHEMA_INVALID],
    });

    const checkpointReport = await verifier.verifyCheckpoint(
      { core: null } as never,
      [],
      policy,
    );
    expect(checkpointReport).toEqual({
      verdict: 'invalid',
      reasonCodes: [AUDIT_REASON_CODES.SCHEMA_INVALID],
    });
  });

  it('fails closed for a malformed out-of-band verification policy', async () => {
    const report = await verifier.verifyEntries(await history(), { policyId: 'broken' } as never);
    expect(report.cryptographicIntegrity).toEqual({
      verdict: 'invalid',
      reasonCodes: [AUDIT_REASON_CODES.VERIFICATION_POLICY_INVALID],
    });
  });

  it('keeps historical and current authorization verdicts separate through a policy port', async () => {
    const entries = structuredClone(await history());
    entries[1]!.core.event.authorization = {
      source: 'policy',
      decision: 'allowed',
      policyId: 'policy-at-call-time',
    };
    const authorizationVerifier = new AuditArtifactVerifier({
      hasher: new CryptoProviderAuditHasher(new NodeCryptoProvider()),
      signatures: new TestSignatureVerifier(),
      authorization: {
        verifyAsObserved: async () => ({ verdict: 'valid', reasonCodes: [] }),
        verifyCurrent: async () => ({
          verdict: 'invalid',
          reasonCodes: ['AUDIT_AUTHORIZATION_CURRENTLY_REVOKED'],
        }),
      },
    });
    const report = await authorizationVerifier.verifyEntries(entries, policy);
    expect(report.authorizedAsObserved.verdict).toBe('valid');
    expect(report.currentAuthorization).toEqual({
      verdict: 'invalid',
      reasonCodes: ['AUDIT_AUTHORIZATION_CURRENTLY_REVOKED'],
    });
  });

  it('verifies a checkpoint against the exact journal range and detects a false root', async () => {
    const { journal, ledger, entries } = await recordedHistory();
    const builder = new AuditCheckpointBuilder({
      journal,
      store: new MemoryAuditCheckpointStore(),
      signer: new TestSigner(),
      hasher: new CryptoProviderAuditHasher(new NodeCryptoProvider()),
      clock: { now: () => 1_750_000_002_000 },
    });
    const checkpoint = await builder.createCheckpoint(ledger);

    await expect(verifier.verifyCheckpoint(checkpoint, entries, policy)).resolves.toEqual({
      verdict: 'valid',
      reasonCodes: [],
    });

    const mutated = structuredClone(checkpoint);
    mutated.core.rootDigest = `sha256:${'f'.repeat(64)}`;
    const result = await verifier.verifyCheckpoint(mutated, entries, policy);
    expect(result.verdict).toBe('invalid');
    expect(result.reasonCodes).toContain(AUDIT_REASON_CODES.CHECKPOINT_ROOT_MISMATCH);
  });

  it('requires an out-of-band trusted observer and verifies its chained receipt', async () => {
    const { journal, ledger } = await recordedHistory();
    const checkpoint = await new AuditCheckpointBuilder({
      journal, store: new MemoryAuditCheckpointStore(), signer: new TestSigner(),
      hasher: new CryptoProviderAuditHasher(new NodeCryptoProvider()),
      clock: { now: () => 1_750_000_002_000 },
    }).createCheckpoint(ledger);
    const observer = new MemoryAuditCheckpointObserver({
      observerId: 'observer-1', signer: new TestSigner(),
      hasher: new CryptoProviderAuditHasher(new NodeCryptoProvider()),
      clock: { now: () => 1_750_000_003_000 },
      verifyCheckpoint: async () => true,
      verifyConsistency: async () => true,
    });
    const receipt = await observer.publish(checkpoint);
    expect((await verifier.verifyObservation(checkpoint, receipt, policy)).reasonCodes)
      .toContain(AUDIT_REASON_CODES.UNTRUSTED_OBSERVER);
    await expect(verifier.verifyObservation(checkpoint, receipt, {
      ...policy,
      trustedObservers: [{ signer: new TestSigner().ref }],
    })).resolves.toEqual({ verdict: 'valid', reasonCodes: [] });
  });

  it('reports an empty selection and distinguishes unverified authorization collateral', async () => {
    const empty = await verifier.verifyEntries([], policy);
    expect(empty.chainIntegrity).toEqual({
      verdict: 'invalid',
      reasonCodes: [AUDIT_REASON_CODES.BUNDLE_SELECTION_INCOMPLETE],
    });
    expect(empty.scopeEvidenceCompleteness.verdict).toBe('invalid');

    const entries = structuredClone(await history());
    entries[1]!.core.event.authorization = {
      source: 'policy', decision: 'allowed', policyId: 'policy-at-call-time',
    };
    const report = await verifier.verifyEntries(entries, policy);
    expect(report.authorizedAsObserved.reasonCodes).toContain(
      AUDIT_REASON_CODES.AUTHORIZATION_COLLATERAL_NOT_VERIFIED,
    );
  });

  it('surfaces every independently verifiable entry and chain-integrity failure', async () => {
    const entries = structuredClone(await history());
    entries[0]!.core.event = structuredClone(entries[1]!.core.event);
    entries[1]!.core.evidenceManifestDigest = `sha256:${'1'.repeat(64)}`;
    entries[1]!.entryDigest = `sha256:${'2'.repeat(64)}`;
    entries[1]!.recorderReceipt.core.entryDigest = `sha256:${'3'.repeat(64)}`;
    entries[1]!.recorderReceipt.jws = 'invalid.signature';
    entries[2]!.core.ledgerId = 'kya:tenant:prod:secondary';

    const report = await verifier.verifyEntries(entries, {
      ...policy,
      acceptedIntegritySuites: ['KYA-AUDIT-RFC9162-SHA256-JWS-2026'],
      acceptedAlgorithms: ['ES256'],
      trustedLedgerEpochs: [{
        ...policy.trustedLedgerEpochs[0]!,
        recorderKeys: [{ signer: new TestSigner().ref, validUntil: 1 }],
      }],
    });

    expect(report.cryptographicIntegrity.reasonCodes).toEqual(expect.arrayContaining([
      AUDIT_REASON_CODES.UNSUPPORTED_SUITE,
      AUDIT_REASON_CODES.UNSUPPORTED_ALGORITHM,
      AUDIT_REASON_CODES.UNTRUSTED_RECORDER,
      AUDIT_REASON_CODES.EVIDENCE_MANIFEST_DIGEST_MISMATCH,
      AUDIT_REASON_CODES.ENTRY_DIGEST_MISMATCH,
      AUDIT_REASON_CODES.RECEIPT_MISMATCH,
      AUDIT_REASON_CODES.SIGNATURE_INVALID,
    ]));
    expect(report.chainIntegrity.reasonCodes).toEqual(expect.arrayContaining([
      AUDIT_REASON_CODES.GENESIS_INVALID,
      AUDIT_REASON_CODES.LEDGER_SCOPE_MISMATCH,
      AUDIT_REASON_CODES.PREDECESSOR_MISMATCH,
    ]));

    const orphan = structuredClone((await history())[1]!);
    orphan.core.previousEntryDigest = null;
    expect((await verifier.verifyEntries([orphan], policy)).chainIntegrity.reasonCodes)
      .toContain(AUDIT_REASON_CODES.PREDECESSOR_MISMATCH);
  });

  it('rejects unsupported, untrusted, tampered, and wrong-range checkpoints independently', async () => {
    const { journal, ledger, entries } = await recordedHistory();
    const checkpoint = await new AuditCheckpointBuilder({
      journal, store: new MemoryAuditCheckpointStore(), signer: new TestSigner(),
      hasher: new CryptoProviderAuditHasher(new NodeCryptoProvider()),
      clock: { now: () => 1_750_000_002_000 },
    }).createCheckpoint(ledger);
    const tampered = structuredClone(checkpoint);
    tampered.checkpointDigest = `sha256:${'d'.repeat(64)}`;
    tampered.jws = 'invalid.signature';

    const result = await verifier.verifyCheckpoint(tampered, entries.slice(0, -1), {
      ...policy,
      acceptedIntegritySuites: ['KYA-AUDIT-JCS-SHA256-JWS-2026'],
      acceptedAlgorithms: ['ES256'],
      trustedLedgerEpochs: [{
        ...policy.trustedLedgerEpochs[0]!,
        recorderKeys: [{ signer: new TestSigner().ref, validFrom: 1_750_000_002_001 }],
      }],
    });
    expect(result.reasonCodes).toEqual(expect.arrayContaining([
      AUDIT_REASON_CODES.UNSUPPORTED_SUITE,
      AUDIT_REASON_CODES.UNSUPPORTED_ALGORITHM,
      AUDIT_REASON_CODES.UNTRUSTED_RECORDER,
      AUDIT_REASON_CODES.CHECKPOINT_DIGEST_MISMATCH,
      AUDIT_REASON_CODES.CHECKPOINT_SIGNATURE_INVALID,
      AUDIT_REASON_CODES.CHECKPOINT_RANGE_MISMATCH,
    ]));
    await expect(verifier.verifyCheckpoint(checkpoint, entries, { policyId: 'bad' } as never))
      .resolves.toEqual({
        verdict: 'invalid',
        reasonCodes: [AUDIT_REASON_CODES.VERIFICATION_POLICY_INVALID],
      });
  });

  it('applies observation freshness and reports scope, trust, digest, and signature failures', async () => {
    const { journal, ledger } = await recordedHistory();
    const checkpoint = await new AuditCheckpointBuilder({
      journal, store: new MemoryAuditCheckpointStore(), signer: new TestSigner(),
      hasher: new CryptoProviderAuditHasher(new NodeCryptoProvider()),
      clock: { now: () => 1_750_000_002_000 },
    }).createCheckpoint(ledger);
    const observer = new MemoryAuditCheckpointObserver({
      observerId: 'observer-1', signer: new TestSigner(),
      hasher: new CryptoProviderAuditHasher(new NodeCryptoProvider()),
      clock: { now: () => 1_750_000_003_000 },
      verifyCheckpoint: async () => true,
      verifyConsistency: async () => true,
    });
    const receipt = await observer.publish(checkpoint);
    const trustedPolicy = {
      ...policy,
      trustedObservers: [{ signer: new TestSigner().ref }],
      requiredCheckpointFreshnessMs: 1_000,
    };
    await expect(verifier.verifyObservation(checkpoint, receipt, trustedPolicy))
      .resolves.toEqual({ verdict: 'indeterminate', reasonCodes: [AUDIT_REASON_CODES.NOT_EVALUATED] });

    const timeAware = new AuditArtifactVerifier({
      hasher: new CryptoProviderAuditHasher(new NodeCryptoProvider()),
      signatures: new TestSignatureVerifier(),
      verifiedAt: () => 1_750_000_005_000,
    });
    expect((await timeAware.verifyObservation(checkpoint, receipt, trustedPolicy)).reasonCodes)
      .toContain(AUDIT_REASON_CODES.OBSERVATION_STALE);

    const tampered = structuredClone(receipt);
    tampered.core.ledgerId = 'kya:tenant:prod:secondary';
    tampered.observationDigest = `sha256:${'e'.repeat(64)}`;
    tampered.jws = 'invalid.signature';
    const result = await verifier.verifyObservation(checkpoint, tampered, {
      ...policy,
      acceptedAlgorithms: ['ES256'],
      trustedObservers: [],
    });
    expect(result.reasonCodes).toEqual(expect.arrayContaining([
      AUDIT_REASON_CODES.OBSERVATION_SCOPE_MISMATCH,
      AUDIT_REASON_CODES.UNSUPPORTED_ALGORITHM,
      AUDIT_REASON_CODES.UNTRUSTED_OBSERVER,
      AUDIT_REASON_CODES.OBSERVATION_DIGEST_MISMATCH,
      AUDIT_REASON_CODES.OBSERVATION_SIGNATURE_INVALID,
    ]));
    await expect(verifier.verifyObservation(checkpoint, receipt, { policyId: 'bad' } as never))
      .resolves.toEqual({
        verdict: 'invalid',
        reasonCodes: [AUDIT_REASON_CODES.VERIFICATION_POLICY_INVALID],
      });
  });
});
