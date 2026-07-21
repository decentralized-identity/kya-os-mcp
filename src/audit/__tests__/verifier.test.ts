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
    }, { producerAuthority: 'did:key:zProducer', tenantAuthority: 'tenant-1' });
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
});
