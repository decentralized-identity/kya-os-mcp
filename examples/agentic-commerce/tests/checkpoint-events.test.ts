/**
 * The Checkpoint event mappers, checked against a strict copy of Checkpoint's
 * ingest schemas (apps/web/lib/api/schemas/kya-os-events.ts). The copy forbids
 * extra keys: Checkpoint would silently strip them, so an extra key here is a
 * field we invented.
 */
import { describe, it, expect } from 'vitest';
import { Ajv } from 'ajv';
import addFormats from 'ajv-formats';
import type { DelegationCredential } from '@kya-os/mcp';
import {
  MAX_REASON_LENGTH,
  grantApprovedEvent,
  grantRevokedEvent,
  orderDecisionEvent,
  refusalReason,
  type EventSource,
  type OrderDecision,
} from '../src/lib/checkpoint-events.js';
import { checkpointReporterFromEnv, eventsEndpoint } from '../src/lib/checkpoint-reporter.js';

const RP_DID = 'did:web:auth.example';
const MERCHANT_DID = 'did:key:z6MkMerchant';
const AGENT_DID = 'did:key:z6MkAgent';
const JTI = 'urn:uuid:agentic-commerce-173-1793284273700';
const source: EventSource = { serverDid: MERCHANT_DID, sdk: { name: 'kya-os-example-agentic-commerce', version: '0.1.0', runtime: 'node' } };

const envelope = {
  specVersion: { type: 'string', minLength: 1, maxLength: 20 },
  ts: { type: 'string', format: 'date-time' },
  source: {
    type: 'object', additionalProperties: false, required: ['serverDid'],
    properties: {
      serverDid: { type: 'string', minLength: 1, maxLength: 500 },
      sdk: { type: 'object', additionalProperties: false, required: ['name'],
        properties: { name: { type: 'string', minLength: 1, maxLength: 200 }, version: { type: 'string', minLength: 1, maxLength: 50 }, runtime: { type: 'string', maxLength: 50 } } },
    },
  },
  session: {
    type: 'object', additionalProperties: false, required: ['id'],
    properties: {
      id: { type: 'string', minLength: 1, maxLength: 100 },
      agent: { type: 'object', additionalProperties: false, properties: { did: { type: 'string', minLength: 1, maxLength: 500 }, label: { type: 'string', maxLength: 255 } } },
    },
  },
};
const jtiOnly = { type: 'object', additionalProperties: false, required: ['jti'], properties: { jti: { type: 'string', minLength: 1, maxLength: 500 } } };
const schemas = {
  'tool.invoked': {
    type: 'object', additionalProperties: false, required: ['specVersion', 'ts', 'source', 'type', 'tool', 'verdict'],
    properties: {
      ...envelope,
      type: { const: 'tool.invoked' },
      tool: { type: 'object', additionalProperties: false, required: ['name'], properties: { name: { type: 'string', minLength: 1, maxLength: 255 }, capability: { type: 'string', maxLength: 200 } } },
      verdict: { enum: ['pass', 'fail'] },
      error: { type: 'object', additionalProperties: false, required: ['excerpt'], properties: { excerpt: { type: 'string', maxLength: 200 } } },
      principal: { type: 'object', additionalProperties: false, properties: { did: { type: 'string', maxLength: 500 }, id: { type: 'string', maxLength: 200 } } },
      delegation: jtiOnly,
    },
  },
  'delegation.observed': {
    type: 'object', additionalProperties: false, required: ['specVersion', 'ts', 'source', 'type', 'delegation'],
    properties: {
      ...envelope,
      type: { const: 'delegation.observed' },
      delegation: {
        type: 'object', additionalProperties: false, required: ['jti', 'issuerDid'],
        properties: {
          jti: { type: 'string', minLength: 1, maxLength: 500 },
          issuerDid: { type: 'string', minLength: 1, maxLength: 500 },
          audience: { type: 'string', maxLength: 500 },
          scopes: { type: 'array', maxItems: 100, items: { type: 'string', minLength: 1, maxLength: 200 } },
          issuedAt: { type: 'string', format: 'date-time' },
          expiresAt: { type: 'string', format: 'date-time' },
        },
      },
    },
  },
  'delegation.revoked': {
    type: 'object', additionalProperties: false, required: ['specVersion', 'ts', 'source', 'type', 'delegation'],
    properties: { ...envelope, type: { const: 'delegation.revoked' }, delegation: jtiOnly, reason: { type: 'string', maxLength: 500 } },
  },
} as const;

const ajv = new Ajv({ allErrors: true, strict: false });
// ajv-formats is CommonJS: its default export arrives wrapped under ESM.
const applyFormats = typeof addFormats === 'function' ? addFormats : addFormats.default;
applyFormats(ajv);
function expectCheckpointAccepts(event: { type: keyof typeof schemas }): void {
  const validate = ajv.compile(schemas[event.type]);
  expect(validate(event), ajv.errorsText(validate.errors)).toBe(true);
}

const vc = {
  id: JTI,
  issuer: RP_DID,
  issuanceDate: '2026-10-29T14:30:13.000Z',
  expirationDate: '2026-10-31T14:31:13.000Z',
  credentialSubject: {
    id: AGENT_DID,
    delegation: {
      id: 'agentic-commerce-173-1793284273700',
      constraints: {
        audience: MERCHANT_DID,
        scopes: ['commerce.order'],
        notBefore: 1793284213,
        notAfter: 1793457073,
        crisp: { scopes: [{ resource: 'https://id.gs1.org/01/09506000134352', matcher: 'prefix', constraints: { maxAmount: '50.00', currency: 'CHF' } }] },
      },
    },
  },
} as unknown as DelegationCredential;

const passed = { signature: 'pass', revocation: 'pass', holder: 'pass' } as const;
const decision = (overrides: Partial<OrderDecision>): OrderDecision => ({
  at: '2026-10-29T18:00:00.000Z',
  allowed: true,
  product: 'risotto',
  quantity: 1,
  gates: passed,
  credential: { jti: JTI, issuerDid: RP_DID },
  verifiedAgentDid: AGENT_DID,
  sessionId: 'sess-1',
  ...overrides,
});

describe('orderDecisionEvent: one tool.invoked per place_order decision', () => {
  it('a permitted order passes, links the grant, names the agent and carries no reason', () => {
    const event = orderDecisionEvent(decision({}), source);
    expectCheckpointAccepts(event);
    expect(event).toEqual({
      specVersion: '0.1', type: 'tool.invoked', ts: '2026-10-29T18:00:00.000Z', source,
      session: { id: 'sess-1', agent: { did: AGENT_DID } },
      tool: { name: 'place_order', capability: 'commerce.order' },
      verdict: 'pass',
      principal: { did: RP_DID },
      delegation: { jti: JTI },
    });
  });

  it('over the spending limit fails with the code and the amounts in plain words', () => {
    const event = orderDecisionEvent(decision({ allowed: false, code: 'SPEND_CAP_EXCEEDED', quantity: 3, total: 'CHF 59.70', cap: 'CHF 50.00' }), source);
    expectCheckpointAccepts(event);
    expect(event.verdict).toBe('fail');
    expect(event.error?.excerpt).toBe('SPEND_CAP_EXCEEDED: Over the spending limit. 3 x risotto = CHF 59.70, the limit is CHF 50.00 per order. Nothing was ordered.');
    // A business refusal under a valid grant still links that grant.
    expect(event.delegation).toEqual({ jti: JTI });
  });

  it('a product outside the grant fails with PRODUCT_OUT_OF_SCOPE', () => {
    const event = orderDecisionEvent(decision({ allowed: false, code: 'PRODUCT_OUT_OF_SCOPE', product: 'olive-oil' }), source);
    expectCheckpointAccepts(event);
    expect(event.error?.excerpt).toBe('PRODUCT_OUT_OF_SCOPE: olive-oil is not a product the shopper approved. Nothing was ordered.');
  });

  it('a revoked grant fails as delegation_revoked and does not claim a verified grant', () => {
    const event = orderDecisionEvent(decision({
      allowed: false, code: 'delegation_invalid', message: 'Delegation verification failed: credential is revoked',
      gates: { signature: 'pass', revocation: 'fail', holder: 'skip' },
    }), source);
    expectCheckpointAccepts(event);
    expect(event.error?.excerpt).toBe('delegation_revoked: This authorization was revoked. Nothing was ordered.');
    expect(event.delegation).toBeUndefined();
    expect(event.principal).toBeUndefined();
    expect(event.session).toEqual({ id: 'sess-1' });
  });

  it('an order before any grant fails as needs_authorization, with the key-bound agent', () => {
    const event = orderDecisionEvent(decision({
      allowed: false, code: 'needs_authorization', credential: null, gates: { signature: 'skip', revocation: 'skip', holder: 'pass' },
    }), source);
    expectCheckpointAccepts(event);
    expect(event.error?.excerpt).toMatch(/^needs_authorization: /);
    expect(event.session).toEqual({ id: 'sess-1', agent: { did: AGENT_DID } });
    expect(event.delegation).toBeUndefined();
  });

  it('a stolen credential (wrong key) names no agent and links no grant', () => {
    const event = orderDecisionEvent(decision({
      allowed: false, code: 'holder_binding_failed', gates: { signature: 'pass', revocation: 'pass', holder: 'fail' },
    }), source);
    expectCheckpointAccepts(event);
    expect(event.error?.excerpt).toMatch(/^holder_binding_failed: /);
    expect(event.session).toEqual({ id: 'sess-1' });
    expect(event.delegation).toBeUndefined();
  });

  it('never echoes an unknown product the caller typed, and keeps any reason within 200 characters', () => {
    const typed = 'x'.repeat(500);
    const reason = refusalReason(decision({ allowed: false, code: 'PRODUCT_OUT_OF_SCOPE', product: typed }));
    expect(reason).not.toContain('xxxx');
    const long = refusalReason(decision({ allowed: false, code: 'SOMETHING_NEW', message: 'm'.repeat(500) }));
    expect(long.length).toBeLessThanOrEqual(MAX_REASON_LENGTH);
    expect(long.startsWith('SOMETHING_NEW: ')).toBe(true);
  });
});

describe('grantApprovedEvent: delegation.observed when the shopper approves', () => {
  it('carries the credential id, issuer, audience, flat scopes and validity window', () => {
    const event = grantApprovedEvent(vc, { serverDid: RP_DID }, '2026-10-29T14:30:14.000Z');
    expectCheckpointAccepts(event);
    expect(event).toEqual({
      specVersion: '0.1', type: 'delegation.observed', ts: '2026-10-29T14:30:14.000Z', source: { serverDid: RP_DID },
      delegation: {
        jti: JTI, issuerDid: RP_DID, audience: MERCHANT_DID, scopes: ['commerce.order'],
        issuedAt: '2026-10-29T14:30:13.000Z', expiresAt: '2026-10-31T14:31:13.000Z',
      },
    });
  });

  it('uses the same id the merchant links orders to', () => {
    const approved = grantApprovedEvent(vc, { serverDid: RP_DID }, '2026-10-29T14:30:14.000Z');
    const ordered = orderDecisionEvent(decision({}), source);
    expect(approved.delegation.jti).toBe(ordered.delegation?.jti);
  });

  it('leaves out an audience that names several parties instead of picking one', () => {
    const many = structuredClone(vc) as unknown as { credentialSubject: { delegation: { constraints: { audience: unknown } } } };
    many.credentialSubject.delegation.constraints.audience = [MERCHANT_DID, 'did:key:z6MkOther'];
    const event = grantApprovedEvent(many as unknown as DelegationCredential, { serverDid: RP_DID }, '2026-10-29T14:30:14.000Z');
    expectCheckpointAccepts(event);
    expect(event.delegation.audience).toBeUndefined();
  });
});

describe('grantRevokedEvent: delegation.revoked when the hub revokes', () => {
  it('names the credential and the reason', () => {
    const event = grantRevokedEvent(vc, { serverDid: RP_DID }, '2026-10-29T18:05:00.000Z', 'Revoked by the shopper.');
    expectCheckpointAccepts(event);
    expect(event).toEqual({
      specVersion: '0.1', type: 'delegation.revoked', ts: '2026-10-29T18:05:00.000Z', source: { serverDid: RP_DID },
      delegation: { jti: JTI }, reason: 'Revoked by the shopper.',
    });
  });
});

describe('reporter configuration', () => {
  const TOKEN = 'kya_test_secret_value';

  it('is off, silently, when neither setting is present', () => {
    const lines: string[] = [];
    expect(checkpointReporterFromEnv({}, (line) => lines.push(line))).toBeNull();
    expect(lines).toEqual([]);
  });

  it('is off with one warning when only one setting is present, and never logs the token', () => {
    const lines: string[] = [];
    expect(checkpointReporterFromEnv({ KYA_OS_EVENTS_TOKEN: TOKEN }, (line) => lines.push(line))).toBeNull();
    expect(lines).toHaveLength(1);
    expect(lines.join('\n')).not.toContain(TOKEN);
  });

  it('refuses plain http off loopback, and a URL carrying credentials, without echoing either', () => {
    const lines: string[] = [];
    expect(checkpointReporterFromEnv({ KYA_OS_EVENTS_URL: 'http://kya.example', KYA_OS_EVENTS_TOKEN: TOKEN }, (line) => lines.push(line))).toBeNull();
    expect(checkpointReporterFromEnv({ KYA_OS_EVENTS_URL: `https://user:${TOKEN}@kya.example`, KYA_OS_EVENTS_TOKEN: TOKEN }, (line) => lines.push(line))).toBeNull();
    expect(lines).toHaveLength(2);
    expect(lines.join('\n')).not.toContain(TOKEN);
  });

  it('takes the full events URL or the bare origin', () => {
    expect(eventsEndpoint('https://kya.example').toString()).toBe('https://kya.example/api/v1/kya-os/events');
    expect(eventsEndpoint('https://kya.example/api/v1/kya-os/events').toString()).toBe('https://kya.example/api/v1/kya-os/events');
    const reporter = checkpointReporterFromEnv({ KYA_OS_EVENTS_URL: 'https://kya.example/api/v1/kya-os/events', KYA_OS_EVENTS_TOKEN: TOKEN });
    expect(reporter?.endpoint).toBe('https://kya.example/api/v1/kya-os/events');
  });
});
