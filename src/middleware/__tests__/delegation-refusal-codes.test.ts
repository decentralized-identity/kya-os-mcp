/**
 * The delegation gate records why it refused a delegation for the operator, and tells the client
 * what it told it before. The refusal code goes into the rejected event's
 * `authorization.verificationCode`, which records what the verification of a delegation came to,
 * as `DELEGATION_CHAIN_VALID` does for one that passed; the event's own `reason.code` stays
 * `DELEGATION_VERIFICATION_FAILED`, and the event has no member it did not have, so it still
 * validates against the published audit event schema. The gate's log line carries the code, and
 * the full reason up to the length a checker's reason may have. What the client receives is
 * unchanged: the same `error`, the same reason cut where it was, and no new member.
 */

import { readFileSync } from 'node:fs';
import Ajv2020, { type AnySchema } from 'ajv/dist/2020.js';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { isTransientRefusal, type RefusalCode } from '../../refusal-codes.js';
import { logger } from '../../logging/index.js';
import { CHECKER_REASON_LENGTH } from '../../utils/revocation-answer.js';
import type { DelegationCredential } from '../../types/protocol.js';
import type { KyaOsDelegationConfig } from '../with-kya-os.js';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { CryptoProviderAuditHasher } from '../../audit/crypto.js';
import { MemoryAuditJournal } from '../../audit/providers/memory-journal.js';
import { LocalAuditRecorderClient } from '../../audit/providers/recorder-client.js';
import { MemoryAuditSourceState } from '../../audit/providers/source-state.js';
import { AuditRecorderService } from '../../audit/recorder-service.js';
import { createAuditTrail, type AuditTrailEventInput } from '../../audit/service.js';
import type { PartyRef } from '../../audit/types.js';
import { failCredentialDigests, makeServer } from './helpers/delegation-gate-server.js';
import { ARGS, CONSENT, TOOL, released } from './helpers/delegated-call.js';
import { delegate, party, type Party } from './helpers/delegating-party.js';

afterEach(() => {
  vi.restoreAllMocks();
});

const validEvent = new Ajv2020({ allErrors: true, strict: false }).compile(
  JSON.parse(readFileSync(new URL('../../../schemas/audit-event.schema.json', import.meta.url), 'utf8')) as AnySchema,
);

/**
 * The event the audit trail service builds of what the gate recorded, as a server whose trail
 * records to a recorder of its own would store it.
 */
async function built(input: AuditTrailEventInput): Promise<unknown> {
  const tenantRef: PartyRef = { kind: 'keyed_commitment', value: `sha256:${'a'.repeat(64)}`, keyId: 'tenant-key-1' };
  const ledger = { ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1' };
  const binding = 'urn:kya-os:audit-binding:mcp:2025-11-25';
  const hasher = new CryptoProviderAuditHasher(new NodeCryptoProvider());
  const clock = { now: () => 1_750_000_000_000 };
  const recorder = new AuditRecorderService({
    ...ledger, tenantRef, binding, sourceId: 'recorder-1', journal: new MemoryAuditJournal(), hasher, clock,
    signer: {
      ref: { did: 'did:key:zRecorder', kid: 'did:key:zRecorder#zRecorder', alg: 'EdDSA' },
      sign: async (payload) => `test.${Buffer.from(payload).toString('base64url')}.signature`,
    },
  });
  const trail = createAuditTrail({
    recorder: new LocalAuditRecorderClient(recorder, () => ({ producerAuthority: 'did:key:zProducer', tenantAuthority: 'tenant-1', tenantRef })),
    delivery: 'best-effort', hasher, ledgerId: ledger.ledgerId, tenantRef,
    producer: { kind: 'pairwise_did', did: 'did:key:zProducer' },
    sourceId: 'mcp-server-1', binding,
    privacy: { classification: 'internal', retentionClass: 'audit-365d' },
    clock, sourceState: new MemoryAuditSourceState(),
  });
  const result = await trail.record(input);
  expect(result.status).toBe('recorded');
  return result.event;
}

/** A dependency that never answers. */
const never = <T>(): Promise<T> => new Promise<T>(() => undefined);

/** What the gate answers, records and logs when it is presented `presented`. */
async function presentedTo(delegation: KyaOsDelegationConfig, presented: (user: Party, agent: Party) => Promise<unknown>) {
  const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
  const { kyaos, events } = await makeServer({ dependencyTimeoutMs: 50, ...delegation });
  const [user, agent] = await Promise.all([party(), party()]);
  const result = await kyaos.wrapWithDelegation(TOOL, CONSENT, released)({ ...ARGS, _kyaos_delegation: await presented(user, agent) });
  const rejected = events.find((event) => event.eventType === 'delegation.rejected');
  const logged = warn.mock.calls.find(([line]) => String(line).startsWith(`[kya-os] Delegation verification failed for "${TOOL}": `));
  return { body: JSON.parse((result.content[0] as { text: string }).text) as Record<string, unknown>, rejected, logged };
}

/** A credential `user` grants `agent`. */
const granted = (user: Party, agent: Party): Promise<DelegationCredential> => delegate(user, agent.did);

describe('a delegation the gate refuses', () => {
  it.each<[string, KyaOsDelegationConfig, (user: Party, agent: Party) => Promise<unknown>, RefusalCode]>([
    ['whose root trustedRootIssuers does not list', { trustedRootIssuers: ['did:web:trusted.example'] }, granted, 'untrusted_root'],
    [
      'whose proof does not verify',
      {},
      async (user, agent) => {
        const credential = await granted(user, agent);
        const proof = credential.proof as unknown as Record<string, unknown>;
        return { ...credential, proof: { ...proof, proofValue: `z${'1'.repeat(86)}` } };
      },
      'invalid_proof',
    ],
    ['that is a string but no VC-JWT', {}, async () => 'not.a.jwt', 'delegation_malformed'],
    [
      'that is not plain data',
      {},
      async (user, agent) => Object.defineProperty({ ...(await granted(user, agent)) }, 'note', { get: () => 'x', enumerable: true }),
      'delegation_malformed',
    ],
    [
      'that holds a value the gate cannot encode',
      {},
      async (user, agent) => {
        const credential = await granted(user, agent);
        return { ...credential, proof: { ...(credential.proof as object), extra: 1n } };
      },
      'delegation_malformed',
    ],
    ['whose issuer DID is not resolved in time', { didResolver: { resolve: never } }, granted, 'deadline_exceeded'],
    [
      'whose chain is not resolved in time',
      { resolveDelegationChain: never },
      async (user, agent) => delegate(agent, user.did, { parent: await granted(user, agent) }),
      'deadline_exceeded',
    ],
    ['that its revocation checker answers revoked', { revocationChecker: { isRevoked: async () => ({ revoked: true }) } }, granted, 'delegation_revoked'],
    ['whose revocation checker throws', { revocationChecker: { isRevoked: async () => { throw new Error('graph down'); } } }, granted, 'status_unavailable'],
  ])('%s, coded for the operator and as before for the client', async (_name, delegation, presented, code) => {
    const { body, rejected, logged } = await presentedTo(delegation, presented);

    expect(Object.keys(body).sort()).toEqual(['error', 'reason']);
    expect(body.error).toBe('delegation_invalid');
    expect(rejected?.reason).toEqual({ code: 'DELEGATION_VERIFICATION_FAILED' });
    expect(rejected?.authorization).toMatchObject({ source: 'delegation', decision: 'denied', verificationCode: code });
    const stored = await built(rejected!);
    expect(validEvent(stored), JSON.stringify(validEvent.errors)).toBe(true);
    expect(logged?.[1]).toEqual({ code, transient: isTransientRefusal(code) });
  });

  it('is refused as runtime_error, transient, when what it verified could not be described', async () => {
    failCredentialDigests(new Error('hash provider down'));
    const { body, rejected, logged } = await presentedTo({}, granted);
    expect(body).toEqual({ error: 'delegation_invalid', reason: 'Delegation credential could not be verified' });
    expect(rejected?.authorization?.verificationCode).toBe('runtime_error');
    expect(logged?.[1]).toEqual({ code: 'runtime_error', transient: true });
  });

  it.each<[string, KyaOsDelegationConfig, string, RefusalCode]>([
    ['a delegation that does not grant the scope', {}, 'Delegation missing required scope', 'insufficient_scope'],
    ['a call with no holder-of-key proof where one is enforced', { holderBinding: 'enforce' }, 'Holder binding:', 'holder_binding_failed'],
  ])('logs the code of %s, and answers the client as before', async (_name, delegation, line, code) => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const { kyaos } = await makeServer(delegation);
    const [user, agent] = await Promise.all([party(), party()]);
    const credential = code === 'insufficient_scope' ? await delegate(user, agent.did, { scopes: ['records:write'] }) : await granted(user, agent);
    const result = await kyaos.wrapWithDelegation(TOOL, CONSENT, released)({ ...ARGS, _kyaos_delegation: credential });
    const body = JSON.parse((result.content[0] as { text: string }).text) as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual(['error', 'reason']);
    expect(body.error).toBe(code);
    expect(warn.mock.calls.find(([text]) => String(text).startsWith(`[kya-os] ${line}`))?.[1]).toEqual({ code, transient: false });
  });

  it('logs the full reason, up to the length a checker reason may have, and tells the client the reason cut as before', async () => {
    const said = 'r'.repeat(CHECKER_REASON_LENGTH);
    const { body, logged } = await presentedTo({ revocationChecker: { isRevoked: async () => ({ revoked: true, reason: said }) } }, granted);
    const line = String(logged?.[0]);
    const reason = line.slice(`[kya-os] Delegation verification failed for "${TOOL}": `.length);
    expect(reason.length).toBeGreaterThan(256);
    expect(reason.length).toBeLessThanOrEqual(CHECKER_REASON_LENGTH + 1);
    // The chain bounds the checker's reason as it did; the gate's log line no longer cuts the whole.
    expect(reason).toMatch(/^Delegation "del-\d+" is revoked: r{256}\u2026$/);
    expect(body.reason).toBe(`${reason.slice(0, 256)}…`);
  });
});
