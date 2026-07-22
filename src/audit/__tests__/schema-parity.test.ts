import { readFileSync } from 'node:fs';
import Ajv2020, { type AnySchema } from 'ajv/dist/2020.js';
import { describe, expect, it } from 'vitest';
import {
  AUDIT_BUNDLE_MANIFEST_SCHEMA_ID,
  AUDIT_CHECKPOINT_SCHEMA_ID,
  AUDIT_EVENT_SCHEMA_ID,
  auditBundleManifestCoreSchema,
  auditCheckpointCoreSchema,
  auditProducerEventSchema,
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

function validator(schema: AnySchema): (input: unknown) => boolean {
  const ajv = new Ajv2020({ allErrors: true, strict: false });
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

describe('audit Zod and JSON Schema parity', () => {
  it('accepts and rejects the same producer-event boundary fixtures', () => {
    const validate = validator(jsonSchema('audit-event.schema.json'));
    const fixtures = [
      event,
      { ...event, eventId: 'x'.repeat(257) },
      { ...event, source: { ...event.source, sourceSequence: '1'.repeat(21) } },
      { ...event, tenantRef: { kind: 'public_did', did: 'did:\ninvalid' } },
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
    ];
    for (const fixture of fixtures) {
      expect(validate(fixture)).toBe(auditBundleManifestCoreSchema.safeParse(fixture).success);
    }
  });
});
