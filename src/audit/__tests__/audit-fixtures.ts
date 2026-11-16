/**
 * A small recorded audit history for the tests of the audit verifiers: three events one recorder
 * signed into one ledger epoch, the signer and signature verifier that stand in for real keys, and
 * the policy that trusts that recorder.
 */

import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import type { AuditSignatureVerifier, AuditSigner } from '../crypto.js';
import { CryptoProviderAuditHasher } from '../crypto.js';
import { MemoryAuditJournal } from '../providers/memory-journal.js';
import { AuditRecorderService } from '../recorder-service.js';
import type {
  AuditProducerEventCoreV1,
  AuditVerificationPolicyV1,
  PartyRef,
  SignerRef,
} from '../types.js';

export const tenantRef: PartyRef = {
  kind: 'keyed_commitment',
  value: `sha256:${'a'.repeat(64)}`,
  keyId: 'tenant-key-1',
};

export class TestSigner implements AuditSigner {
  readonly ref = {
    did: 'did:key:zRecorder',
    kid: 'did:key:zRecorder#zRecorder',
    alg: 'EdDSA' as const,
  };
  async sign(payload: Uint8Array): Promise<string> {
    return `test.${Buffer.from(payload).toString('base64url')}.signature`;
  }
}

export class TestSignatureVerifier implements AuditSignatureVerifier {
  async verify(payload: Uint8Array, jws: string, signer: SignerRef): Promise<boolean> {
    return signer.kid === 'did:key:zRecorder#zRecorder' &&
      jws === `test.${Buffer.from(payload).toString('base64url')}.signature`;
  }
}

export function producerEvent(id: string, sequence: number): AuditProducerEventCoreV1 {
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

export const policy: AuditVerificationPolicyV1 = {
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

export async function recordedHistory() {
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

export async function history() {
  return (await recordedHistory()).entries;
}
