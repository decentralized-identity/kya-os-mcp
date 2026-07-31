import { generateKeyPair } from 'jose';
import { WebCryptoProvider } from '../providers/web-crypto.js';
import {
  CompactJwsAuditSignatureVerifier,
  CompactJwsAuditSigner,
  CryptoProviderAuditHasher,
  type AuditVerificationKey,
  type AuditVerificationKeyResolver,
} from './crypto.js';
import { AUDIT_EVENT_SCHEMA_ID } from './schemas.js';
import { AuditRecorderService, type AuditClock } from './recorder-service.js';
import { AuditCheckpointBuilder, MemoryAuditCheckpointStore } from './checkpoint.js';
import { AuditArtifactVerifier } from './verifier.js';
import { MemoryAuditJournal } from './providers/memory-journal.js';
import {
  LocalAuditReadService,
  type AuditCheckpointReadAccess,
  type AuditReadService,
} from './read-service.js';
import type {
  AuditLedgerRef,
  AuditProducerEventCoreV1,
  AuditVerificationPolicyV1,
  PartyRef,
  ProtocolBindingId,
  SignedAuditCheckpointV1,
  SignedAuditEntryV1,
  SignerRef,
} from './types.js';

/**
 * A fully in-memory, self-contained authoritative recorder that produces REAL
 * signed, hash-chained audit entries and serves the {@link AuditReadService}
 * read contract over them.
 *
 * It exists so downstream surfaces (a dashboard viewer, a CLI) and this
 * package's own tests can exercise the produce -> read -> verify loop against
 * genuine cryptographic artifacts without standing up durable storage. The
 * durable recorder is a drop-in for the same contract; anything that verifies
 * here verifies there.
 */
export interface ReferenceRecorder {
  readonly ledger: AuditLedgerRef;
  /** The recorder's signing identity - the key entries are verified against. */
  readonly signerRef: SignerRef;
  /** Operator-facing read surface over the produced ledger. */
  readonly read: AuditReadService;
  /** Checkpoint builder + store, exposed so a client can independently verify proofs. */
  readonly checkpoints: AuditCheckpointReadAccess;
  /** Independent verifier wired to this recorder's key - re-checks any read artifact. */
  readonly verifier: AuditArtifactVerifier;
  /** A trust policy naming this recorder, ready to pass to {@link AuditArtifactVerifier}. */
  readonly verificationPolicy: AuditVerificationPolicyV1;
  /** Append one producer event and return its signed entry. */
  submit(event: AuditProducerEventCoreV1): Promise<SignedAuditEntryV1>;
  /** Seal the current head into a signed RFC-9162 checkpoint (enables inclusion/consistency proofs). */
  checkpoint(): Promise<SignedAuditCheckpointV1>;
}

export interface ReferenceRecorderOptions {
  ledgerId?: string;
  ledgerEpochId?: string;
  /** Override the clock (default: wall clock). Inject a fixed clock for deterministic tests. */
  clock?: AuditClock;
}

const DEFAULT_LEDGER_ID = 'kya:reference:audit:primary';
const DEFAULT_LEDGER_EPOCH_ID = 'epoch_1';
const REFERENCE_BINDING: ProtocolBindingId = 'urn:kya-os:audit-binding:mcp:2025-11-25';
const REFERENCE_PRODUCER_DID = 'did:key:zReferenceProducer';
const REFERENCE_SOURCE_ID = 'reference-recorder';
const REFERENCE_TENANT_AUTHORITY = 'reference-tenant';
const REFERENCE_TENANT_REF: PartyRef = {
  kind: 'keyed_commitment',
  value: `sha256:${'a'.repeat(64)}`,
  keyId: 'reference-tenant-key',
};

/** A minimal, valid tool-call event, so callers can produce history without hand-building the envelope. */
export function sampleAuditEvent(
  sequence: number,
  overrides: Partial<AuditProducerEventCoreV1> = {},
): AuditProducerEventCoreV1 {
  return {
    schema: AUDIT_EVENT_SCHEMA_ID,
    eventId: `evt_${sequence}`,
    eventType: 'tool.call.completed',
    eventVersion: '1.0.0',
    binding: REFERENCE_BINDING,
    occurredAt: 1_750_000_000_000 + sequence,
    tenantRef: REFERENCE_TENANT_REF,
    source: {
      producer: { kind: 'pairwise_did', did: REFERENCE_PRODUCER_DID },
      sourceId: REFERENCE_SOURCE_ID,
      sourceSequence: String(sequence),
    },
    action: { category: 'tool.call', name: 'orders.create' },
    outcome: 'succeeded',
    evidence: [],
    details: { family: 'tool', phase: 'completed', attempt: '1' },
    privacy: { classification: 'internal', retentionClass: 'audit-365d' },
    ...overrides,
  };
}

/** Compose an in-memory reference recorder with a freshly generated Ed25519 signing key. */
export async function createInMemoryReferenceRecorder(
  options: ReferenceRecorderOptions = {},
): Promise<ReferenceRecorder> {
  const ledger: AuditLedgerRef = {
    ledgerId: options.ledgerId ?? DEFAULT_LEDGER_ID,
    ledgerEpochId: options.ledgerEpochId ?? DEFAULT_LEDGER_EPOCH_ID,
  };

  const { publicKey, privateKey } = await generateKeyPair('EdDSA', { extractable: false });
  const signerRef: SignerRef = {
    did: 'did:key:zReferenceRecorder',
    kid: 'did:key:zReferenceRecorder#0',
    alg: 'EdDSA',
  };
  const keyResolver: AuditVerificationKeyResolver = {
    async resolve(candidate): Promise<AuditVerificationKey | null> {
      return candidate.kid === signerRef.kid ? publicKey : null;
    },
  };

  const hasher = new CryptoProviderAuditHasher(new WebCryptoProvider());
  const signer = new CompactJwsAuditSigner(signerRef, privateKey);
  const journal = new MemoryAuditJournal();
  const clock: AuditClock = options.clock ?? { now: () => Date.now() };

  const recorder = new AuditRecorderService({
    ledgerId: ledger.ledgerId,
    ledgerEpochId: ledger.ledgerEpochId,
    tenantRef: REFERENCE_TENANT_REF,
    binding: REFERENCE_BINDING,
    sourceId: REFERENCE_SOURCE_ID,
    journal,
    signer,
    hasher,
    clock,
  });

  const checkpointStore = new MemoryAuditCheckpointStore();
  const checkpointBuilder = new AuditCheckpointBuilder({
    journal,
    store: checkpointStore,
    signer,
    hasher,
    clock,
  });
  const read = new LocalAuditReadService({
    journal,
    checkpoints: { builder: checkpointBuilder, store: checkpointStore },
  });
  const verifier = new AuditArtifactVerifier({
    hasher,
    signatures: new CompactJwsAuditSignatureVerifier(keyResolver),
  });
  const verificationPolicy: AuditVerificationPolicyV1 = {
    policyId: 'policy:reference-recorder',
    trustedLedgerEpochs: [{
      ledgerId: ledger.ledgerId,
      ledgerEpochId: ledger.ledgerEpochId,
      recorderKeys: [{ signer: signerRef }],
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

  return {
    ledger,
    signerRef,
    read,
    checkpoints: { builder: checkpointBuilder, store: checkpointStore },
    verifier,
    verificationPolicy,
    async submit(event: AuditProducerEventCoreV1): Promise<SignedAuditEntryV1> {
      return recorder.submitAuthenticated(
        {
          ledgerId: ledger.ledgerId,
          producerEvent: event,
          encryptedEvidence: [],
        },
        {
          producerAuthority: REFERENCE_PRODUCER_DID,
          tenantAuthority: REFERENCE_TENANT_AUTHORITY,
          tenantRef: REFERENCE_TENANT_REF,
        },
      );
    },
    async checkpoint(): Promise<SignedAuditCheckpointV1> {
      return checkpointBuilder.createCheckpoint(ledger);
    },
  };
}
