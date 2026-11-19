/**
 * What every provider contract shares: the report shape, the check runner and
 * the fixtures they build. Only `assertAuditProviderContract` and the report
 * types are exported from `@kya-os/mcp/audit/testing`.
 */
import type {
  AuditLedgerRef,
  Digest,
  SignedAuditEntryV1,
} from '../types.js';

export interface AuditProviderContractCheck {
  name: string;
  passed: boolean;
  error?: unknown;
}

export interface AuditProviderContractReport {
  providerKind: 'journal' | 'evidence' | 'observer' | 'anchor' | 'outbox';
  passed: boolean;
  checks: AuditProviderContractCheck[];
}

export function digest(character: string): Digest {
  return `sha256:${character.repeat(64)}`;
}

export function equalJson(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

export function expectContract(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

export async function check(
  checks: AuditProviderContractCheck[],
  name: string,
  execute: () => Promise<void>,
): Promise<void> {
  try {
    await execute();
    checks.push({ name, passed: true });
  } catch (error) {
    checks.push({ name, passed: false, error });
  }
}

export function report(
  providerKind: AuditProviderContractReport['providerKind'],
  checks: AuditProviderContractCheck[],
): AuditProviderContractReport {
  return { providerKind, passed: checks.every((item) => item.passed), checks };
}

export function assertAuditProviderContract(value: AuditProviderContractReport): void {
  const failures = value.checks.filter((item) => !item.passed);
  if (failures.length > 0) {
    throw new AggregateError(
      failures.map((item) => item.error),
      `${value.providerKind} provider contract failed: ${failures.map((item) => item.name).join(', ')}`,
    );
  }
}

/** A distinct digest for each `value`, apart from every {@link digest} of one repeated character. */
export function numberedDigest(value: number): Digest {
  return `sha256:${'f'.repeat(48)}${value.toString(16).padStart(16, '0')}`;
}

/**
 * A well-formed entry for a journal to store. Two entries at one sequence
 * differ only where `variant` names them apart: their entry digest and event ID.
 */
export function contractEntry(
  ledger: AuditLedgerRef,
  sequence: number,
  eventDigest: Digest,
  previousEntryDigest: Digest | null,
  variant?: number,
): SignedAuditEntryV1 {
  const entryDigest = variant === undefined
    ? digest(((sequence + 3) % 10).toString())
    : numberedDigest(variant);
  const eventId = variant === undefined
    ? `contract-event-${sequence}`
    : `contract-event-${sequence}-${variant}`;
  return {
    core: {
      schema: 'https://schema.kya-os.org/v1/protocol/audit/entry/v1.0.0',
      ...ledger,
      sequence: String(sequence),
      previousEntryDigest,
      recordedAt: 1_750_000_000_000 + sequence,
      recorder: {
        did: 'did:key:zContractRecorder',
        kid: 'did:key:zContractRecorder#key',
        alg: 'EdDSA',
      },
      eventDigest,
      event: {
        schema: 'https://schema.kya-os.org/v1/protocol/audit/event/v1.0.0',
        eventId,
        eventType: sequence === 0 ? 'ledger.epoch.started' : 'tool.call.completed',
        eventVersion: '1.0.0',
        binding: 'urn:kya-os:audit-binding:contract:1',
        occurredAt: 1_750_000_000_000 + sequence,
        tenantRef: { kind: 'pairwise_did', did: 'did:key:zContractTenant' },
        source: {
          producer: { kind: 'pairwise_did', did: 'did:key:zContractProducer' },
          sourceId: 'contract-source',
          sourceSequence: String(sequence),
        },
        action: { category: sequence === 0 ? 'ledger.epoch' : 'tool.call' },
        outcome: 'succeeded',
        evidence: [],
        details: sequence === 0
          ? { family: 'ledger', phase: 'epoch_started' }
          : { family: 'tool', phase: 'completed', attempt: '1' },
        privacy: { classification: 'internal', retentionClass: 'contract' },
      },
      evidenceManifestDigest: digest('a'),
      integritySuite: 'KYA-AUDIT-JCS-SHA256-JWS-2026',
    },
    eventDigest,
    entryDigest,
    recorderReceipt: {
      core: {
        schema: 'https://schema.kya-os.org/v1/protocol/audit/receipt/v1.0.0',
        ...ledger,
        sequence: String(sequence),
        eventId,
        entryDigest,
        previousEntryDigest,
        recordedAt: 1_750_000_000_000 + sequence,
        recorder: {
          did: 'did:key:zContractRecorder',
          kid: 'did:key:zContractRecorder#key',
          alg: 'EdDSA',
        },
        integritySuite: 'KYA-AUDIT-JCS-SHA256-JWS-2026',
      },
      jws: `contract-signature-${sequence}`,
    },
  };
}
