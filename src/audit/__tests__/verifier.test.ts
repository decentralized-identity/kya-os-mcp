import { describe, expect, it } from 'vitest';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import type { AuditSignatureVerifier, AuditSigner } from '../crypto.js';
import { CryptoProviderAuditHasher, hashAuditValue } from '../crypto.js';
import { AuditCheckpointBuilder, MemoryAuditCheckpointStore } from '../checkpoint.js';
import { AUDIT_DIGEST_DOMAINS } from '../integrity.js';
import {
  AuditArtifactVerifier,
  AUDIT_REASON_CODES,
  applyRequiredAuditProfile,
  mergeAuditDimensions,
} from '../verifier.js';
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

  it('bounds recorder trust by checkpoint position and never passes an unresolved bound', async () => {
    const hasher = new CryptoProviderAuditHasher(new NodeCryptoProvider());
    const { journal, ledger } = await recordedHistory();
    const builder = new AuditCheckpointBuilder({
      journal, store: new MemoryAuditCheckpointStore(), signer: new TestSigner(), hasher,
      clock: { now: () => 1_750_000_002_000 },
    });
    const boundary = await builder.createCheckpoint(ledger); // tree size 4
    // The same key keeps signing after the boundary (e.g. after a compromise).
    const recorder = new AuditRecorderService({
      ...ledger, tenantRef, binding: 'urn:kya-os:audit-binding:mcp:2025-11-25',
      sourceId: 'recorder-1', journal, signer: new TestSigner(), hasher,
      clock: { now: () => 1_750_000_003_000 },
    });
    for (let index = 4; index <= 5; index += 1) {
      await recorder.submitAuthenticated({
        ledgerId: ledger.ledgerId,
        producerEvent: producerEvent(`evt_${index}`, index),
        encryptedEvidence: [],
      }, { producerAuthority: 'did:key:zProducer', tenantAuthority: 'tenant-1', tenantRef });
    }
    const later = await builder.createCheckpoint(ledger); // tree size 6
    const entries = await journal.snapshot(ledger);
    const signer = new TestSigner().ref;
    const bounded = (bounds: { validFromCheckpoint?: `sha256:${string}`; validUntilCheckpoint?: `sha256:${string}` }) => ({
      ...policy,
      trustedLedgerEpochs: [{ ...policy.trustedLedgerEpochs[0]!, recorderKeys: [{ signer, ...bounds }] }],
    });
    const until = bounded({ validUntilCheckpoint: boundary.checkpointDigest });
    const context = { checkpoints: [boundary] };

    // Without the named checkpoint the bound cannot be placed: never valid,
    // and never a rejection of the policy.
    expect((await verifier.verifyEntries(entries, until)).cryptographicIntegrity).toEqual({
      verdict: 'indeterminate', reasonCodes: [AUDIT_REASON_CODES.KEY_BOUNDARY_UNRESOLVED],
    });
    expect((await verifier.verifyEntries(entries, until, context)).cryptographicIntegrity)
      .toEqual({ verdict: 'invalid', reasonCodes: [AUDIT_REASON_CODES.UNTRUSTED_RECORDER] });
    expect((await verifier.verifyEntries(entries.slice(0, 4), until, context))
      .cryptographicIntegrity.verdict).toBe('valid');

    const from = bounded({ validFromCheckpoint: boundary.checkpointDigest });
    expect((await verifier.verifyEntries(entries.slice(0, 4), from, context))
      .cryptographicIntegrity.reasonCodes).toEqual([AUDIT_REASON_CODES.UNTRUSTED_RECORDER]);
    expect((await verifier.verifyEntries(entries.slice(4), from, context))
      .cryptographicIntegrity.verdict).toBe('valid');

    const sealedEpoch = {
      ...policy,
      trustedLedgerEpochs: [{
        ...policy.trustedLedgerEpochs[0]!, validUntilCheckpoint: boundary.checkpointDigest,
      }],
    };
    expect((await verifier.verifyEntries(entries, sealedEpoch, context))
      .cryptographicIntegrity.reasonCodes).toEqual([AUDIT_REASON_CODES.UNTRUSTED_RECORDER]);

    // A boundary from another ledger epoch cannot place this epoch's entries.
    const foreign = structuredClone(boundary);
    foreign.core.ledgerEpochId = 'epoch_other';
    const foreignDigest = await hashAuditValue(hasher, AUDIT_DIGEST_DOMAINS.checkpoint, foreign.core);
    expect((await verifier.verifyEntries(
      entries.slice(0, 4),
      bounded({ validUntilCheckpoint: foreignDigest }),
      { checkpoints: [foreign] },
    )).cryptographicIntegrity).toEqual({
      verdict: 'indeterminate', reasonCodes: [AUDIT_REASON_CODES.KEY_BOUNDARY_UNRESOLVED],
    });

    await expect(verifier.verifyCheckpoint(boundary, entries.slice(0, 4), until))
      .resolves.toEqual({ verdict: 'valid', reasonCodes: [] });
    expect((await verifier.verifyCheckpoint(later, entries, until, context)).reasonCodes)
      .toEqual([AUDIT_REASON_CODES.UNTRUSTED_RECORDER]);
    await expect(verifier.verifySignedCheckpoint(later, until)).resolves.toEqual({
      verdict: 'indeterminate', reasonCodes: [AUDIT_REASON_CODES.KEY_BOUNDARY_UNRESOLVED],
    });

    const observer = new MemoryAuditCheckpointObserver({
      observerId: 'observer-1', signer: new TestSigner(), hasher,
      clock: { now: () => 1_750_000_004_000 },
      verifyCheckpoint: async () => true,
      verifyConsistency: async () => true,
    });
    const observerPolicy = {
      ...policy,
      trustedObservers: [{ signer, validUntilCheckpoint: boundary.checkpointDigest }],
    };
    await expect(verifier.verifyObservation(boundary, await observer.publish(boundary), observerPolicy))
      .resolves.toEqual({ verdict: 'valid', reasonCodes: [] });
    expect((await verifier.verifyObservation(
      later, await observer.publish(later), observerPolicy, context,
    )).reasonCodes).toEqual([AUDIT_REASON_CODES.UNTRUSTED_OBSERVER]);
  });

  it('evaluates every key revocation mode instead of rejecting it', async () => {
    const entries = await history(); // recorded at 1_750_000_001_000
    const signer = new TestSigner().ref;
    // Valid when it signed, revoked before verification.
    const revoked = (keyRevocationMode: AuditVerificationPolicyV1['keyRevocationMode']) => ({
      ...policy,
      keyRevocationMode,
      trustedLedgerEpochs: [{
        ...policy.trustedLedgerEpochs[0]!,
        recorderKeys: [{ signer, validUntil: 1_750_000_005_000 }],
      }],
    });
    const at = (now: number) => new AuditArtifactVerifier({
      hasher: new CryptoProviderAuditHasher(new NodeCryptoProvider()),
      signatures: new TestSignatureVerifier(),
      verifiedAt: () => now,
      authorization: {
        verifyAsObserved: async () => ({ verdict: 'valid', reasonCodes: [] }),
        verifyCurrent: async () => ({ verdict: 'valid', reasonCodes: [] }),
      },
    });
    const afterRevocation = at(1_750_000_010_000);
    const valid = { verdict: 'valid', reasonCodes: [] };
    const notCurrent = { verdict: 'invalid', reasonCodes: [AUDIT_REASON_CODES.KEY_NOT_CURRENT] };

    // The as-observed check stays in the integrity dimensions under every mode.
    for (const mode of ['as_observed', 'current', 'both'] as const) {
      const report = await afterRevocation.verifyEntries(entries, revoked(mode));
      expect(report.cryptographicIntegrity).toEqual(valid);
      expect(report.authorizedAsObserved).toEqual(valid);
    }
    // Only current and both hold the key to its status at verification time.
    expect((await afterRevocation.verifyEntries(entries, revoked('as_observed')))
      .currentAuthorization).toEqual(valid);
    expect((await afterRevocation.verifyEntries(entries, revoked('current')))
      .currentAuthorization).toEqual(notCurrent);
    expect((await afterRevocation.verifyEntries(entries, revoked('both')))
      .currentAuthorization).toEqual(notCurrent);
    expect((await at(1_750_000_004_000).verifyEntries(entries, revoked('current')))
      .currentAuthorization).toEqual(valid);

    // A key valid only until a checkpoint has been retired at that checkpoint.
    const retired = {
      ...policy,
      keyRevocationMode: 'current' as const,
      trustedLedgerEpochs: [{
        ...policy.trustedLedgerEpochs[0]!,
        recorderKeys: [{ signer, validUntilCheckpoint: `sha256:${'c'.repeat(64)}` as const }],
      }],
    };
    expect((await afterRevocation.verifyEntries(entries, retired)).currentAuthorization)
      .toEqual({
        verdict: 'invalid',
        reasonCodes: [AUDIT_REASON_CODES.KEY_NOT_CURRENT],
      });

    // Without a clock the current status is undecided, never valid.
    const unclocked = await verifier.verifyEntries(entries, revoked('both'));
    expect(unclocked.cryptographicIntegrity).toEqual(valid);
    expect(unclocked.currentAuthorization).toEqual({
      verdict: 'indeterminate',
      reasonCodes: [
        AUDIT_REASON_CODES.CURRENT_AUTHORIZATION_NOT_EVALUATED,
        AUDIT_REASON_CODES.NOT_EVALUATED,
      ],
    });
  });

  it('checks a checkpoint without its leaves and never trusts an unknown epoch or bound', async () => {
    const hasher = new CryptoProviderAuditHasher(new NodeCryptoProvider());
    const { journal, ledger, entries } = await recordedHistory();
    const checkpoint = await new AuditCheckpointBuilder({
      journal, store: new MemoryAuditCheckpointStore(), signer: new TestSigner(), hasher,
      clock: { now: () => 1_750_000_002_000 },
    }).createCheckpoint(ledger);
    const signer = new TestSigner().ref;
    const unknownBoundary = `sha256:${'c'.repeat(64)}` as const;

    await expect(verifier.verifySignedCheckpoint(checkpoint, policy))
      .resolves.toEqual({ verdict: 'valid', reasonCodes: [] });
    await expect(verifier.verifySignedCheckpoint({} as never, policy))
      .resolves.toEqual({ verdict: 'invalid', reasonCodes: [AUDIT_REASON_CODES.SCHEMA_INVALID] });
    await expect(verifier.verifySignedCheckpoint(checkpoint, { policyId: 'bad' } as never))
      .resolves.toEqual({
        verdict: 'invalid', reasonCodes: [AUDIT_REASON_CODES.VERIFICATION_POLICY_INVALID],
      });
    // A declared range that does not start at genesis is not a tree prefix.
    const offRange = structuredClone(checkpoint);
    offRange.core.firstSequence = '1';
    expect((await verifier.verifySignedCheckpoint(offRange, policy)).reasonCodes)
      .toContain(AUDIT_REASON_CODES.CHECKPOINT_RANGE_MISMATCH);
    // An epoch the policy does not list has no trusted issuer.
    expect((await verifier.verifySignedCheckpoint(checkpoint, { ...policy, trustedLedgerEpochs: [] }))
      .reasonCodes).toEqual([AUDIT_REASON_CODES.UNTRUSTED_RECORDER]);

    // A malformed supporting checkpoint resolves nothing.
    const bounded = {
      ...policy,
      trustedLedgerEpochs: [{
        ...policy.trustedLedgerEpochs[0]!,
        recorderKeys: [{ signer, validUntilCheckpoint: checkpoint.checkpointDigest }],
      }],
    };
    expect((await verifier.verifyEntries(entries, bounded, { checkpoints: [{} as never] }))
      .cryptographicIntegrity).toEqual({
      verdict: 'indeterminate', reasonCodes: [AUDIT_REASON_CODES.KEY_BOUNDARY_UNRESOLVED],
    });

    const observation = await new MemoryAuditCheckpointObserver({
      observerId: 'observer-1', signer: new TestSigner(), hasher,
      clock: { now: () => 1_750_000_004_000 },
      verifyCheckpoint: async () => true,
      verifyConsistency: async () => true,
    }).publish(checkpoint);
    await expect(verifier.verifyObservation(checkpoint, observation, {
      ...policy, trustedObservers: [{ signer, validFromCheckpoint: unknownBoundary }],
    })).resolves.toEqual({
      verdict: 'indeterminate', reasonCodes: [AUDIT_REASON_CODES.KEY_BOUNDARY_UNRESOLVED],
    });

    // Under the current mode, a recorder of an unlisted epoch is not current either.
    const clocked = new AuditArtifactVerifier({
      hasher, signatures: new TestSignatureVerifier(), verifiedAt: () => 1_750_000_010_000,
    });
    expect(clocked.verifyCurrentKeys(
      { ...policy, keyRevocationMode: 'current', trustedLedgerEpochs: [] },
      { entries, checkpoints: [checkpoint], observations: [observation] },
    )).toEqual({ verdict: 'invalid', reasonCodes: [AUDIT_REASON_CODES.KEY_NOT_CURRENT] });
    expect(clocked.verifyCurrentKeys(policy, { entries })).toBeUndefined();
  });

  it('marks every dimension a required audit profile depends on invalid unless valid', async () => {
    const entries = await history();
    const unmet = AUDIT_REASON_CODES.REQUIRED_PROFILE_UNMET;
    const chained = await verifier.verifyEntries(entries, { ...policy, requiredAuditProfile: 'AAP-2' });
    expect(chained.cryptographicIntegrity.verdict).toBe('valid');
    expect(chained.chainIntegrity.verdict).toBe('valid');
    expect(chained.checkpointIntegrity.verdict).toBe('indeterminate');

    const transparent = await verifier.verifyEntries(entries, { ...policy, requiredAuditProfile: 'AAP-3' });
    expect(transparent.checkpointIntegrity).toEqual({
      verdict: 'invalid', reasonCodes: [AUDIT_REASON_CODES.CHECKPOINT_MISSING, unmet],
    });
    expect(transparent.anchorIntegrity.verdict).toBe('indeterminate');

    const observed = await verifier.verifyEntries(entries, { ...policy, requiredAuditProfile: 'AAP-4' });
    expect(observed.anchorIntegrity.reasonCodes).toContain(unmet);

    const allValid = { verdict: 'valid' as const, reasonCodes: [] };
    const report = { ...observed, checkpointIntegrity: allValid, anchorIntegrity: allValid };
    const aap4 = { ...policy, requiredAuditProfile: 'AAP-4' as const };
    expect(applyRequiredAuditProfile(report, aap4).anchorIntegrity)
      .toEqual({ verdict: 'invalid', reasonCodes: [unmet] });
    expect(applyRequiredAuditProfile(report, aap4, { supportingAnchors: true }).anchorIntegrity)
      .toEqual(allValid);
  });

  it('treats an observation dated beyond the clock-skew allowance as invalid, not fresh', async () => {
    const { journal, ledger } = await recordedHistory();
    const hasher = new CryptoProviderAuditHasher(new NodeCryptoProvider());
    const checkpoint = await new AuditCheckpointBuilder({
      journal, store: new MemoryAuditCheckpointStore(), signer: new TestSigner(), hasher,
      clock: { now: () => 1_750_000_002_000 },
    }).createCheckpoint(ledger);
    const now = 1_750_000_010_000;
    const observedAt = async (time: number) => new MemoryAuditCheckpointObserver({
      observerId: 'observer-1', signer: new TestSigner(), hasher,
      clock: { now: () => time },
      verifyCheckpoint: async () => true,
      verifyConsistency: async () => true,
    }).publish(checkpoint);
    const freshness = {
      ...policy,
      trustedObservers: [{ signer: new TestSigner().ref }],
      requiredCheckpointFreshnessMs: 60_000,
    };
    const timeAware = new AuditArtifactVerifier({
      hasher, signatures: new TestSignatureVerifier(), verifiedAt: () => now,
    });

    expect(await timeAware.verifyObservation(
      checkpoint, await observedAt(now + 365 * 24 * 3600 * 1000), freshness,
    )).toEqual({ verdict: 'invalid', reasonCodes: [AUDIT_REASON_CODES.OBSERVATION_FUTURE_DATED] });
    await expect(timeAware.verifyObservation(checkpoint, await observedAt(now + 60_000), freshness))
      .resolves.toEqual({ verdict: 'valid', reasonCodes: [] });
    const strict = new AuditArtifactVerifier({
      hasher, signatures: new TestSignatureVerifier(), verifiedAt: () => now, maxClockSkewMs: 0,
    });
    expect((await strict.verifyObservation(checkpoint, await observedAt(now + 1), freshness))
      .reasonCodes).toEqual([AUDIT_REASON_CODES.OBSERVATION_FUTURE_DATED]);
  });

  it('never lets an empty dimension merge inherit a passing verdict', () => {
    expect(mergeAuditDimensions()).toEqual({
      verdict: 'indeterminate',
      reasonCodes: [AUDIT_REASON_CODES.NOT_EVALUATED],
    });
    expect(mergeAuditDimensions(
      { verdict: 'valid', reasonCodes: [] },
      { verdict: 'valid', reasonCodes: [] },
    )).toEqual({ verdict: 'valid', reasonCodes: [] });
  });
});
