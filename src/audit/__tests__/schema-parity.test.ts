import { readFileSync } from 'node:fs';
import Ajv2020, { type AnySchema } from 'ajv/dist/2020.js';
import { describe, expect, it } from 'vitest';
import {
  AUDIT_BUNDLE_MANIFEST_SCHEMA_ID,
  AUDIT_CHECKPOINT_SCHEMA_ID,
  AUDIT_ENTRY_SCHEMA_ID,
  AUDIT_EVENT_SCHEMA_ID,
  AUDIT_RECEIPT_SCHEMA_ID,
  auditBundleManifestCoreSchema,
  auditCheckpointCoreSchema,
  auditEntryCoreSchema,
  auditObservationReceiptSchema,
  auditProducerEventSchema,
  auditRecorderReceiptCoreSchema,
  auditVerificationPolicySchema,
} from '../schemas.js';

interface OrderedDecimalRangeKeyword {
  first: string;
  last: string;
}

interface UniquePropertyKeyword {
  array: string;
  property: string;
}

function jsonSchema(name: string): AnySchema {
  return JSON.parse(readFileSync(
    new URL(`../../../schemas/${name}`, import.meta.url),
    'utf8',
  )) as AnySchema;
}

function validator(
  schema: AnySchema,
  refs: Record<string, AnySchema> = {},
): (input: unknown) => boolean {
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  ajv.addKeyword({
    keyword: 'kyaOrderedNumberRange',
    schemaType: 'object',
    type: 'object',
    errors: false,
    validate: (constraint: OrderedDecimalRangeKeyword, data: Record<string, unknown>) => {
      const first = data[constraint.first];
      const last = data[constraint.last];
      if (typeof first !== 'number' || typeof last !== 'number') return true;
      return last >= first;
    },
  });
  ajv.addKeyword({
    keyword: 'kyaOrderedDecimalRange',
    schemaType: 'object',
    type: 'object',
    errors: false,
    validate: (constraint: OrderedDecimalRangeKeyword, data: Record<string, unknown>) => {
      const first = data[constraint.first];
      const last = data[constraint.last];
      if (typeof first !== 'string' || typeof last !== 'string') return true;
      try { return BigInt(last) >= BigInt(first); } catch { return false; }
    },
  });
  ajv.addKeyword({
    keyword: 'kyaUniqueProperty',
    schemaType: 'object',
    type: 'object',
    errors: false,
    validate: (constraint: UniquePropertyKeyword, data: Record<string, unknown>) => {
      const values = data[constraint.array];
      if (!Array.isArray(values)) return true;
      const properties = values.map((value) =>
        typeof value === 'object' && value !== null
          ? (value as Record<string, unknown>)[constraint.property]
          : undefined);
      return new Set(properties).size === properties.length;
    },
  });
  for (const [id, referenced] of Object.entries(refs)) ajv.addSchema(referenced, id);
  return ajv.compile(schema);
}

const digest = (character: string) => `sha256:${character.repeat(64)}`;
const signer = {
  did: 'did:key:zSchemaSigner',
  kid: 'did:key:zSchemaSigner#key',
  alg: 'EdDSA',
};

const event = {
  schema: AUDIT_EVENT_SCHEMA_ID,
  eventId: 'event-1',
  eventType: 'tool.call.completed',
  eventVersion: '1.0.0',
  binding: 'urn:kya-os:audit-binding:mcp:2025-11-25',
  occurredAt: 1_750_000_000_000,
  tenantRef: { kind: 'public_did', did: 'did:example:tenant' },
  source: {
    producer: { kind: 'public_did', did: 'did:example:producer' },
    sourceId: 'source-1',
    sourceSequence: '1',
  },
  action: { category: 'tool.call' },
  outcome: 'succeeded',
  evidence: [],
  details: { family: 'tool', phase: 'completed', attempt: '1' },
  privacy: { classification: 'internal', retentionClass: 'audit-365d' },
};

const checkpoint = {
  schema: AUDIT_CHECKPOINT_SCHEMA_ID,
  checkpointId: 'checkpoint-1',
  ledgerId: 'ledger-1',
  ledgerEpochId: 'epoch-1',
  treeSize: '2',
  firstSequence: '0',
  lastSequence: '1',
  rootDigest: digest('a'),
  headEntryDigest: digest('b'),
  previousCheckpointDigest: null,
  createdAt: 1_750_000_000_000,
  issuer: signer,
  integritySuite: 'KYA-AUDIT-RFC9162-SHA256-JWS-2026',
};

const manifest = {
  schema: AUDIT_BUNDLE_MANIFEST_SCHEMA_ID,
  bundleId: 'bundle-1',
  formatVersion: '1.0.0',
  selections: [{
    ledgerId: 'ledger-1',
    ledgerEpochId: 'epoch-1',
    firstSequence: '0',
    lastSequence: '1',
    expectedHeadDigest: digest('b'),
    checkpointTreeSizes: ['2'],
  }],
  exporter: signer,
  purpose: 'regulatory-review',
  exportedAt: 1_750_000_000_000,
  verificationPolicyDigest: digest('c'),
  inventory: [{
    path: 'entries.json',
    mediaType: 'application/json',
    disposition: 'included',
    digest: digest('d'),
    size: '2',
  }],
  integritySuite: 'KYA-AUDIT-BUNDLE-JCS-SHA256-JWS-2026',
};

const entryCore = {
  schema: AUDIT_ENTRY_SCHEMA_ID,
  ledgerId: 'ledger-1',
  ledgerEpochId: 'epoch-1',
  sequence: '1',
  previousEntryDigest: digest('0'),
  recordedAt: 1_750_000_000_000,
  recorder: signer,
  eventDigest: digest('e'),
  event,
  evidenceManifestDigest: digest('f'),
  integritySuite: 'KYA-AUDIT-JCS-SHA256-JWS-2026',
};

const receiptCore = {
  schema: AUDIT_RECEIPT_SCHEMA_ID,
  ledgerId: 'ledger-1',
  ledgerEpochId: 'epoch-1',
  sequence: '1',
  eventId: 'event-1',
  entryDigest: digest('c'),
  previousEntryDigest: digest('0'),
  recordedAt: 1_750_000_000_000,
  recorder: signer,
  integritySuite: 'KYA-AUDIT-JCS-SHA256-JWS-2026',
};

const observation = {
  core: {
    schema: 'https://schema.kya-os.org/v1/protocol/audit/observation/v1.0.0',
    observerId: 'observer-1',
    observer: signer,
    ledgerId: 'ledger-1',
    ledgerEpochId: 'epoch-1',
    checkpointDigest: digest('c'),
    treeSize: '2',
    observedAt: 1_750_000_000_000,
    previousObservationDigest: null,
  },
  observationDigest: digest('d'),
  jws: 'header.payload.signature',
};

const policy = {
  policyId: 'policy-1',
  trustedLedgerEpochs: [{
    ledgerId: 'ledger-1',
    ledgerEpochId: 'epoch-1',
    recorderKeys: [{ signer }],
  }],
  trustedObservers: [{ signer }],
  authorizedExporters: [{
    signerKeys: [{ signer }],
    allowedLedgerIds: ['ledger-1'],
    allowedPurposes: ['regulatory-review'],
  }],
  acceptedIntegritySuites: ['KYA-AUDIT-JCS-SHA256-JWS-2026'],
  acceptedAlgorithms: ['EdDSA'],
  keyRevocationMode: 'as_observed',
};

describe('audit Zod and JSON Schema parity', () => {
  it('accepts and rejects the same producer-event boundary fixtures', () => {
    const validate = validator(jsonSchema('audit-event.schema.json'));
    const fixtures = [
      event,
      { ...event, eventId: 'x'.repeat(257) },
      { ...event, source: { ...event.source, sourceSequence: '1'.repeat(21) } },
      { ...event, tenantRef: { kind: 'public_did', did: 'did:\ninvalid' } },
      { ...event, occurredAt: 1e21 },
      { ...event, occurredAt: 9_007_199_254_740_991 },
      {
        ...event,
        details: { family: 'delegation', phase: 'rejected', delegationRef: 'x'.repeat(257) },
        eventType: 'delegation.rejected',
      },
    ];
    for (const fixture of fixtures) {
      expect(validate(fixture)).toBe(auditProducerEventSchema.safeParse(fixture).success);
    }
  });

  it('shares decimal limits and ordered checkpoint-range semantics', () => {
    const validate = validator(jsonSchema('audit-checkpoint.schema.json'));
    const fixtures = [
      checkpoint,
      { ...checkpoint, treeSize: '1'.repeat(21) },
      { ...checkpoint, firstSequence: '2', lastSequence: '1' },
      { ...checkpoint, issuer: { ...signer, did: 'did:\ninvalid' } },
      { ...checkpoint, createdAt: 1e21 },
    ];
    for (const fixture of fixtures) {
      expect(validate(fixture)).toBe(auditCheckpointCoreSchema.safeParse(fixture).success);
    }
  });

  it('shares selection ordering and inventory path uniqueness semantics', () => {
    const validate = validator(jsonSchema('audit-bundle-manifest.schema.json'));
    const fixtures = [
      manifest,
      {
        ...manifest,
        selections: [{ ...manifest.selections[0], firstSequence: '2', lastSequence: '1' }],
      },
      { ...manifest, inventory: [manifest.inventory[0], { ...manifest.inventory[0] }] },
      {
        ...manifest,
        selections: [{ ...manifest.selections[0], checkpointTreeSizes: ['1'.repeat(21)] }],
      },
      { ...manifest, exportedAt: 1e21 },
    ];
    for (const fixture of fixtures) {
      expect(validate(fixture)).toBe(auditBundleManifestCoreSchema.safeParse(fixture).success);
    }
  });

  it('shares entry-core semantics including the nested event reference', () => {
    const validate = validator(jsonSchema('audit-entry.schema.json'), {
      'https://schema.kya-os.org/v1/protocol/audit/entry/audit-event.schema.json':
        jsonSchema('audit-event.schema.json'),
    });
    const fixtures = [
      entryCore,
      { ...entryCore, recordedAt: 1e21 },
      { ...entryCore, sequence: '1'.repeat(21) },
      { ...entryCore, recorder: { ...signer, did: 'did:\ninvalid' } },
      { ...entryCore, event: { ...event, occurredAt: 1e21 } },
    ];
    for (const fixture of fixtures) {
      expect(validate(fixture)).toBe(auditEntryCoreSchema.safeParse(fixture).success);
    }
  });

  it('shares recorder-receipt-core semantics', () => {
    const validate = validator(jsonSchema('audit-receipt.schema.json'));
    const fixtures = [
      receiptCore,
      { ...receiptCore, recordedAt: 1e21 },
      { ...receiptCore, eventId: 'x'.repeat(257) },
    ];
    for (const fixture of fixtures) {
      expect(validate(fixture)).toBe(auditRecorderReceiptCoreSchema.safeParse(fixture).success);
    }
  });

  it('shares observation-receipt semantics', () => {
    const validate = validator(jsonSchema('audit-observation.schema.json'));
    const fixtures = [
      observation,
      { ...observation, core: { ...observation.core, observedAt: 1e21 } },
      { ...observation, jws: 'x'.repeat(4097) },
      { ...observation, core: { ...observation.core, treeSize: '1'.repeat(21) } },
    ];
    for (const fixture of fixtures) {
      expect(validate(fixture)).toBe(auditObservationReceiptSchema.safeParse(fixture).success);
    }
  });

  it('shares verification-policy semantics including uniqueness and interval order', () => {
    const validate = validator(jsonSchema('audit-verification-policy.schema.json'));
    const fixtures = [
      policy,
      { ...policy, acceptedIntegritySuites: ['suite-a', 'suite-a'] },
      { ...policy, acceptedAlgorithms: ['EdDSA', 'EdDSA'] },
      { ...policy, trustedObservers: [{ signer, validFrom: 2, validUntil: 1 }] },
      { ...policy, requiredCheckpointFreshnessMs: 1e21 },
    ];
    for (const fixture of fixtures) {
      expect(validate(fixture)).toBe(auditVerificationPolicySchema.safeParse(fixture).success);
    }
  });
});
