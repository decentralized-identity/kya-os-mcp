import { describe, expect, it } from 'vitest';
import {
  AUDIT_ENTRY_SCHEMA_ID,
  AUDIT_EVENT_SCHEMA_ID,
  AUDIT_INTEGRITY_SUITE,
  AUDIT_BUNDLE_INTEGRITY_SUITE,
  AUDIT_BUNDLE_MANIFEST_SCHEMA_ID,
  AUDIT_CHECKPOINT_INTEGRITY_SUITE,
  AUDIT_CHECKPOINT_SCHEMA_ID,
  auditBundleManifestCoreSchema,
  auditCheckpointCoreSchema,
  auditEntryCoreSchema,
  auditProducerEventSchema,
  parseAuditEntryCore,
  parseAuditProducerEvent,
} from '../schemas.js';
import type { AuditProducerEventCoreV1 } from '../types.js';

const digest = (character: string) => `sha256:${character.repeat(64)}` as const;

function makeEvent(): AuditProducerEventCoreV1 {
  return {
    schema: AUDIT_EVENT_SCHEMA_ID,
    eventId: 'evt_01J00000000000000000000000',
    eventType: 'tool.call.completed',
    eventVersion: '1.0.0',
    binding: 'urn:kya-os:audit-binding:mcp:2025-11-25',
    occurredAt: 1_750_000_000_000,
    tenantRef: {
      kind: 'keyed_commitment',
      value: digest('a'),
      keyId: 'tenant-key-2026-01',
    },
    source: {
      producer: { kind: 'pairwise_did', did: 'did:key:zProducer' },
      sourceId: 'mcp-server-1',
      sourceSequence: '42',
    },
    session: {
      ref: { kind: 'keyed_commitment', value: digest('b'), keyId: 'session-key-1' },
    },
    actor: { kind: 'pairwise_did', did: 'did:key:zActor' },
    resource: { kind: 'pairwise_did', did: 'did:key:zServer' },
    action: { category: 'tool.call', name: 'orders.create' },
    outcome: 'succeeded',
    evidence: [],
    details: { family: 'tool', phase: 'completed', attempt: '1' },
    privacy: { classification: 'internal', retentionClass: 'audit-365d' },
  };
}

describe('audit protocol schemas', () => {
  it('accepts the frozen producer core and returns an immutable parsed value', () => {
    const parsed = parseAuditProducerEvent(makeEvent());

    expect(parsed.schema).toBe(AUDIT_EVENT_SCHEMA_ID);
    expect(parsed.eventType).toBe('tool.call.completed');
    expect(Object.isFrozen(parsed)).toBe(true);
  });

  it('rejects unknown integrity-critical fields', () => {
    expect(() =>
      auditProducerEventSchema.parse({ ...makeEvent(), debugPayload: { secret: true } }),
    ).toThrow();
  });

  it('rejects an event detail family that does not match its event type', () => {
    expect(() =>
      parseAuditProducerEvent({
        ...makeEvent(),
        details: { family: 'delegation', phase: 'verified', delegationRef: 'del_1' },
      }),
    ).toThrow(/detail family/i);
  });

  it('requires decimal strings for source and ledger sequences', () => {
    expect(() =>
      parseAuditProducerEvent({
        ...makeEvent(),
        source: { ...makeEvent().source, sourceSequence: '4.2' },
      }),
    ).toThrow();
  });

  it('keeps privacy references separate from resolvable signer references', () => {
    const event = makeEvent();
    expect(() =>
      parseAuditEntryCore({
        schema: AUDIT_ENTRY_SCHEMA_ID,
        ledgerId: 'kya:tenant:prod:primary',
        ledgerEpochId: 'epoch_01J00000000000000000000000',
        sequence: '1',
        previousEntryDigest: null,
        recordedAt: 1_750_000_000_001,
        recorder: event.tenantRef,
        eventDigest: digest('c'),
        event,
        evidenceManifestDigest: digest('d'),
        integritySuite: AUDIT_INTEGRITY_SUITE,
      }),
    ).toThrow();
  });

  it('accepts an epoch-qualified entry with a strict recorder signer', () => {
    const parsed = auditEntryCoreSchema.parse({
      schema: AUDIT_ENTRY_SCHEMA_ID,
      ledgerId: 'kya:tenant:prod:primary',
      ledgerEpochId: 'epoch_01J00000000000000000000000',
      sequence: '1',
      previousEntryDigest: digest('e'),
      recordedAt: 1_750_000_000_001,
      recorder: {
        did: 'did:key:zRecorder',
        kid: 'did:key:zRecorder#zRecorder',
        alg: 'EdDSA',
      },
      eventDigest: digest('c'),
      event: makeEvent(),
      evidenceManifestDigest: digest('d'),
      integritySuite: AUDIT_INTEGRITY_SUITE,
    });

    expect(parsed.ledgerEpochId).toBe('epoch_01J00000000000000000000000');
  });

  it('rejects empty or reversed checkpoint ranges', () => {
    const checkpoint = {
      schema: AUDIT_CHECKPOINT_SCHEMA_ID,
      checkpointId: 'checkpoint:1',
      ledgerId: 'ledger', ledgerEpochId: 'epoch', treeSize: '0',
      firstSequence: '4', lastSequence: '3', rootDigest: digest('a'),
      headEntryDigest: digest('b'), previousCheckpointDigest: null,
      createdAt: 1_750_000_000_000,
      issuer: { did: 'did:key:zRecorder', kid: 'did:key:zRecorder#key', alg: 'EdDSA' },
      integritySuite: AUDIT_CHECKPOINT_INTEGRITY_SUITE,
    };
    expect(() => auditCheckpointCoreSchema.parse(checkpoint)).toThrow(/range/i);
  });

  it('enforces signed bundle inventory disposition rules and unique paths', () => {
    const manifest = {
      schema: AUDIT_BUNDLE_MANIFEST_SCHEMA_ID,
      bundleId: 'bundle_1', formatVersion: '1.0.0',
      selections: [{
        ledgerId: 'ledger', ledgerEpochId: 'epoch', firstSequence: '0',
        lastSequence: '1', expectedHeadDigest: digest('a'), checkpointTreeSizes: [],
      }],
      exporter: { did: 'did:key:zExporter', kid: 'did:key:zExporter#key', alg: 'EdDSA' },
      purpose: 'audit', exportedAt: 1_750_000_000_000,
      verificationPolicyDigest: digest('b'),
      inventory: [
        { path: 'entries.json', mediaType: 'application/json', disposition: 'included', digest: digest('c'), size: '10' },
        { path: 'entries.json', mediaType: 'application/json', disposition: 'redacted', reasonCode: 'MINIMIZED' },
      ],
      integritySuite: AUDIT_BUNDLE_INTEGRITY_SUITE,
    };
    expect(() => auditBundleManifestCoreSchema.parse(manifest)).toThrow(/unique/i);
    expect(() => auditBundleManifestCoreSchema.parse({
      ...manifest,
      inventory: [{ path: 'x', mediaType: 'application/json', disposition: 'included' }],
    })).toThrow(/digest\/size/i);
  });
});
