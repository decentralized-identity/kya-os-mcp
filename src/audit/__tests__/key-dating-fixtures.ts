/**
 * A ledger rotated from one recorder key to the next: epoch_1 under the old key, checkpointed as
 * it grows and sealed by its terminal checkpoint, and epoch_2 under the new key, whose genesis
 * commits that checkpoint. The old key's validity ends at the rotation, and verification runs a
 * year later.
 */

import { canonicalizeJsonBytes } from '../../utils/canonical-json.js';
import { AuditCheckpointBuilder, MemoryAuditCheckpointStore } from '../checkpoint.js';
import type { AuditSignatureVerifier, AuditSigner } from '../crypto.js';
import { hashAuditValue } from '../crypto.js';
import { AUDIT_DIGEST_DOMAINS } from '../integrity.js';
import { MemoryAuditJournal } from '../providers/memory-journal.js';
import { AuditRecorderService } from '../recorder-service.js';
import type {
  AuditLedgerRef,
  AuditVerificationPolicyV1,
  Digest,
  HistoricalAuditKeyPolicy,
  SignedAuditCheckpointV1,
  SignerRef,
} from '../types.js';
import { AuditArtifactVerifier } from '../verifier.js';
import { producerEvent, tenantRef } from './audit-fixtures.js';
import { hasher } from './observer-fixtures.js';

export const RECORDED_AT = 1_750_000_001_000;
export const CHECKPOINTED_AT = 1_750_000_003_000;
export const ROTATED_AT = 1_750_000_004_000;
export const A_YEAR_LATER = ROTATED_AT + 365 * 24 * 60 * 60 * 1000;
export const LEDGER_ID = 'kya:tenant:prod:primary';
export const epoch = (n: number): AuditLedgerRef => ({ ledgerId: LEDGER_ID, ledgerEpochId: `epoch_${n}` });

const submitter = { producerAuthority: 'did:key:zProducer', tenantAuthority: 'tenant-1', tenantRef };

/** A test key named `name`: its signature is the payload and the name, so only it can make one. */
export class NamedKey implements AuditSigner {
  readonly ref: SignerRef;
  constructor(readonly name: string) {
    this.ref = { did: `did:key:z${name}`, kid: `did:key:z${name}#z${name}`, alg: 'EdDSA' };
  }
  async sign(payload: Uint8Array): Promise<string> {
    return `test.${Buffer.from(payload).toString('base64url')}.${this.name}`;
  }
}

export class NamedKeyVerifier implements AuditSignatureVerifier {
  async verify(payload: Uint8Array, jws: string, signer: SignerRef): Promise<boolean> {
    const name = signer.kid.slice(signer.kid.indexOf('#z') + 2);
    return jws === `test.${Buffer.from(payload).toString('base64url')}.${name}`;
  }
}

export const verifierAt = (now: number | undefined): AuditArtifactVerifier =>
  new AuditArtifactVerifier({
    hasher,
    signatures: new NamedKeyVerifier(),
    ...(now === undefined ? {} : { verifiedAt: () => now }),
  });

/**
 * Records `events` into an epoch under `key`, a successor of `previous` when given; `from` is the
 * source sequence of the first.
 */
export async function recordEpoch(
  journal: MemoryAuditJournal,
  ledger: AuditLedgerRef,
  key: NamedKey,
  at: number,
  events: readonly string[],
  previous?: { epochId: string; terminal: Digest },
  from = 1,
): Promise<void> {
  const recorder = new AuditRecorderService({
    ...ledger, tenantRef, binding: 'urn:kya-os:audit-binding:mcp:2025-11-25',
    sourceId: `recorder-${ledger.ledgerEpochId}`, journal, signer: key, hasher, clock: { now: () => at },
    ...(previous === undefined
      ? {}
      : {
          previousEpochId: previous.epochId,
          previousTerminalCheckpointDigest: previous.terminal,
          epochTransitionGuard: { verifyAndSeal: async () => true },
        }),
  });
  for (const [index, id] of events.entries()) {
    await recorder.submitAuthenticated(
      { ledgerId: LEDGER_ID, producerEvent: producerEvent(id, from + index), encryptedEvidence: [] },
      submitter,
    );
  }
}

export async function terminalCheckpoint(
  journal: MemoryAuditJournal,
  ledger: AuditLedgerRef,
  key: NamedKey,
  at: number,
  store = new MemoryAuditCheckpointStore(),
): Promise<SignedAuditCheckpointV1> {
  return new AuditCheckpointBuilder({
    journal, store, signer: key, hasher, clock: { now: () => at },
  }).createCheckpoint(ledger);
}

/** `checkpoint`'s tree, signed by `key` instead, as another key over the same leaves would. */
export async function resigned(
  checkpoint: SignedAuditCheckpointV1,
  key: NamedKey,
): Promise<SignedAuditCheckpointV1> {
  const core = { ...checkpoint.core, issuer: key.ref };
  return {
    core,
    checkpointDigest: await hashAuditValue(hasher, AUDIT_DIGEST_DOMAINS.checkpoint, core),
    jws: await key.sign(canonicalizeJsonBytes(core)),
  };
}

export function rotationPolicy(
  oldKey: HistoricalAuditKeyPolicy,
  newKey: HistoricalAuditKeyPolicy,
  more: Partial<AuditVerificationPolicyV1> = {},
): AuditVerificationPolicyV1 {
  return {
    policyId: 'policy:rotated',
    trustedLedgerEpochs: [
      { ...epoch(1), recorderKeys: [oldKey] },
      { ...epoch(2), recorderKeys: [newKey] },
    ],
    trustedObservers: [],
    authorizedExporters: [{
      signerKeys: [{ signer: newKey.signer }],
      allowedLedgerIds: [LEDGER_ID],
      allowedPurposes: ['regulatory-review'],
    }],
    acceptedIntegritySuites: [
      'KYA-AUDIT-JCS-SHA256-JWS-2026',
      'KYA-AUDIT-RFC9162-SHA256-JWS-2026',
      'KYA-AUDIT-BUNDLE-JCS-SHA256-JWS-2026',
    ],
    acceptedAlgorithms: ['EdDSA'],
    keyRevocationMode: 'as_observed',
    ...more,
  };
}

/**
 * The rotated ledger. `terminal` replaces the digest the new genesis commits to, and `newKey`
 * the new key's policy entry.
 */
export async function rotatedLedger(options: {
  terminal?: Digest;
  newKey?: Omit<HistoricalAuditKeyPolicy, 'signer'>;
} = {}) {
  const journal = new MemoryAuditJournal();
  const store = new MemoryAuditCheckpointStore();
  const oldKey = new NamedKey('Old');
  const newKey = new NamedKey('New');
  await recordEpoch(journal, epoch(1), oldKey, RECORDED_AT, ['evt_1']);
  const first = await terminalCheckpoint(journal, epoch(1), oldKey, CHECKPOINTED_AT - 2_000, store);
  await recordEpoch(journal, epoch(1), oldKey, RECORDED_AT, ['evt_2'], undefined, 2);
  const middle = await terminalCheckpoint(journal, epoch(1), oldKey, CHECKPOINTED_AT - 1_000, store);
  await recordEpoch(journal, epoch(1), oldKey, RECORDED_AT, ['evt_3'], undefined, 3);
  const terminal = await terminalCheckpoint(journal, epoch(1), oldKey, CHECKPOINTED_AT, store);
  await recordEpoch(journal, epoch(2), newKey, ROTATED_AT, ['evt_after'], {
    epochId: 'epoch_1', terminal: options.terminal ?? terminal.checkpointDigest,
  });
  const oldEntries = await journal.snapshot(epoch(1));
  const newEntries = await journal.snapshot(epoch(2));
  return {
    journal,
    oldKey,
    newKey,
    oldEntries,
    newEntries,
    genesis: newEntries[0]!,
    first,
    middle,
    terminal,
    policy: rotationPolicy(
      { signer: oldKey.ref, validUntil: ROTATED_AT },
      { signer: newKey.ref, ...options.newKey },
    ),
  };
}
