/**
 * Shared composition of the published audit SDK: signed entries, hash chains,
 * Merkle checkpoints, optional independent witnessing and replay exports.
 * Each caller supplies its own key and records only its own observations.
 * The in-memory journal advertises AAP-1; exports are snapshots, not a durable
 * transaction log. The RP can replay its retained source events in a new epoch.
 */
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { NodeCryptoProvider, canonicalizeJSON } from '@kya-os/mcp';
import {
  AUDIT_BUNDLE_INTEGRITY_SUITE,
  AUDIT_BUNDLE_MEDIA_TYPES,
  AUDIT_CHECKPOINT_INTEGRITY_SUITE,
  AUDIT_INTEGRITY_SUITE,
  AuditCheckpointBuilder,
  AuditReplayBundleExporter,
  CompactJwsAuditSignatureVerifier,
  CompactJwsAuditSigner,
  CryptoProviderAuditHasher,
  MemoryAuditCheckpointStore,
  MemoryAuditJournal,
  MemoryAuditSourceState,
  Rfc9162MerkleTree,
  buildAuditRecorderReceiptCore,
  createAuditTrail,
  createLocalAuditRecorder,
  digestAuditEntry,
  digestAuditEvent,
  hashAuditValue,
  verifyAuditBundle,
  type AuditCapabilities,
  type AuditObservationReceiptV1,
  type AuditReplayBundleV1,
  type AuditTrailService,
  type AuditVerificationPolicyV1,
  type AuditVerificationReportV1,
  type Digest,
  type PartyRef,
  type SignedAuditCheckpointV1,
  type SignedAuditEntryV1,
  type SignerRef,
} from '@kya-os/mcp/audit';
import type { KyaOsConfig } from '@kya-os/mcp';
import { VAR_DIR, type KeyedIdentity } from './wiring.js';
import { jwkFor, signingKeyFor } from './keys.js';

/** The middleware's `audit` option (not re-exported from the package root). */
export type KyaOsAuditTrail = Exclude<NonNullable<KyaOsConfig['audit']>, false>;

export const AUDIT_BINDING = 'urn:kya-os:audit-binding:mcp:2025-11-25';
export const AUDIT_DIR = path.join(VAR_DIR, 'audit');
export const EXPORT_PURPOSE = 'stage-replay';
const POLICY_DIGEST_DOMAIN = 'org.kya-os.audit.verification-policy.v1';
const encoder = new TextEncoder();

// ---------------------------------------------------------------------------
// Types the console renders
// ---------------------------------------------------------------------------

export interface LedgerRow {
  seq: string;
  at: string;
  eventType: string;
  outcome: string;
  tool: string | null;
  reason: string | null;
  correlationId: string | null;
  entryDigest: string;
  previousEntryDigest: string | null;
  anchored: boolean;
}

export interface TreeRow { depth: number; prefix: string; hash: string; label: string; leafIndex: number | null }

export interface WitnessView {
  observerId: string;
  observer: SignerRef;
  observedAt: number;
  observationDigest: string;
  checkpointDigest: string;
  treeSize: string;
}

export interface AuditReport {
  ledger: { ledgerId: string; ledgerEpochId: string };
  recorder: SignerRef;
  profile: { advertised: string; claim: string; whyNotHigher: string };
  entries: LedgerRow[];
  checkpoint: { treeSize: string; rootDigest: string; checkpointDigest: string; createdAt: number; previousCheckpointDigest: string | null; jws: string } | null;
  witness: WitnessView | null;
  witnessError: string | null;
  tree: TreeRow[];
  inclusions: Array<{ seq: string; leafIndex: number; auditPath: string[]; included: boolean }>;
  allIncluded: boolean;
  chainIntact: boolean;
  unanchored: number;
}

export interface Dimension { verdict: 'valid' | 'invalid' | 'indeterminate'; reasonCodes: string[] }

export interface AuditInsiderEdit {
  sequence: string;
  outcome: SignedAuditEntryV1['core']['event']['outcome'];
  /** The checkpoint the human is viewing, never a silently newer snapshot. */
  checkpointDigest: string;
}

export interface TamperReport {
  target: { seq: string; eventType: string; before: string; after: string; reason: string | null };
  attacker: string;
  anchoredRoot: string;
  tamperedRoot: string;
  rootsMatch: boolean;
  chainBreaksAt: string | null;
  honestInclusion: boolean;
  forgedInclusion: boolean;
  forgedReceiptVerifies: boolean;
  witnessStillBindsAnchoredRoot: boolean;
  reports: { honest: AuditVerificationReportV1; tampered: AuditVerificationReportV1 };
}

export interface ExportResult {
  dir: string;
  files: { bundle: string; tampered: string; policy: string; keys: string };
  command: { honest: string; tampered: string };
  reports: { honest: AuditVerificationReportV1; tampered: AuditVerificationReportV1 };
  bundleId: string;
  manifestDigest: string;
  checkpointDigest: string;
  target: TamperReport['target'];
  components: Array<{ path: string; mediaType: string; size: string; digest: string }>;
}

export interface AnchorResult {
  checkpoint: SignedAuditCheckpointV1;
  created: boolean;
  witness: AuditObservationReceiptV1 | null;
  witnessError: string | null;
}

/** Honest final-run evidence, independent of the selected insider demonstration. */
export interface AuditArchiveSnapshot {
  ledger: { ledgerId: string; ledgerEpochId: string };
  entries: number;
  checkpointDigest: string;
  manifestDigest: string;
  witnessed: boolean;
  witnessError: string | null;
  bundle: AuditReplayBundleV1;
  policy: AuditVerificationPolicyV1;
  keys: { keys: Array<{ kid: string; jwk: Record<string, unknown> }> };
  verification: AuditVerificationReportV1;
}

export interface PartyAudit {
  /** What `createKyaOsMiddleware` takes: record + the honest assurance claim. */
  middlewareAudit: KyaOsAuditTrail;
  /** Record a decision observed by this party on the same ledger. */
  record: AuditTrailService['record'];
  capabilities: AuditCapabilities;
  ledger: { ledgerId: string; ledgerEpochId: string };
  recorder: SignerRef;
  entries(): Promise<SignedAuditEntryV1[]>;
  /** Sign an RFC 9162 checkpoint over the ledger as it stands and have the RP witness it. */
  anchor(): Promise<AnchorResult>;
  report(): Promise<AuditReport>;
  /** An insider WITH the merchant key edits one entry: what still breaks. */
  tamper(edit?: AuditInsiderEdit): Promise<TamperReport>;
  /** Export the demonstrated snapshots, policy, keys, and SDK verification results. */
  exportBundle(): Promise<ExportResult>;
  /** The honest replay bundle (for download). */
  bundle(): Promise<AuditReplayBundleV1>;
  /** Whole current run; leaves the displayed checkpoint and edit unchanged. */
  snapshotForArchive(): Promise<AuditArchiveSnapshot | null>;
}

export interface PartyAuditOptions {
  role?: 'merchant' | 'responsible-party';
  ledgerId?: string;
  epochId?: string;
  /** POST endpoint of the Responsible Party's witness (observer). Omit for none. */
  witnessUrl?: string;
  /** Resolve the public key (standard base64) of a witness/observer signer, for keys.json. */
  resolvePublicKeyBase64?: (signer: SignerRef) => Promise<string | null>;
  auditDir?: string;
  clock?: { now(): number };
}

interface AuditMaterial {
  all: SignedAuditEntryV1[];
  anchor: AnchorResult;
  policy: AuditVerificationPolicyV1;
  keys: { keys: Array<{ kid: string; jwk: Record<string, unknown> }> };
  honest: AuditReplayBundleV1;
}

// ---------------------------------------------------------------------------

export async function createPartyAudit(identity: KeyedIdentity, options: PartyAuditOptions = {}): Promise<PartyAudit> {
  const clock = options.clock ?? Date;
  const role = options.role ?? 'merchant';
  const binding = role === 'merchant' ? AUDIT_BINDING : 'urn:kya-os:audit-binding:example-consent:v1';
  const cryptoProvider = new NodeCryptoProvider();
  const hasher = new CryptoProviderAuditHasher(cryptoProvider);
  const tree = new Rfc9162MerkleTree(hasher);
  const recorderRef: SignerRef = { did: identity.did, kid: identity.kid, alg: 'EdDSA' };
  const signer = new CompactJwsAuditSigner(recorderRef, await signingKeyFor(identity));
  const ledger = {
    ledgerId: options.ledgerId ?? `kya:${role}:${shortId(identity.did)}:${role === 'merchant' ? 'orders' : 'consent'}`,
    ledgerEpochId: options.epochId ?? `epoch-${new Date(clock.now()).toISOString().slice(0, 10)}`,
  };
  const tenantRef: PartyRef = { kind: 'keyed_commitment', value: `sha256:${createHash('sha256').update(identity.did).digest('hex')}`, keyId: `${role}-tenant-v1` };
  const journal = new MemoryAuditJournal();
  const store = new MemoryAuditCheckpointStore();
  const auditDir = options.auditDir ?? AUDIT_DIR;

  // The honest claim. `assertAuditCapabilities` (inside createAuditTrail and
  // createKyaOsMiddleware) throws if we advertise more than the mechanics
  // support: an in-memory journal caps us at AAP-1.
  const capabilities: AuditCapabilities = {
    profile: 'AAP-1',
    recorderTopology: 'self-hosted',
    delivery: 'required',
    journalDurability: 'ephemeral',
    atomicAppend: true,
    sourceHighWater: false,
    merkleCheckpoints: true,
    independentObservation: Boolean(options.witnessUrl),
    supportingAnchors: [],
    evidenceRetention: 'none',
  };

  const recorder = createLocalAuditRecorder({
    ...ledger,
    tenantRef,
    binding,
    sourceId: `${role}-edge`,
    journal,
    signer,
    hasher,
    clock,
  }, () => ({ producerAuthority: identity.did, tenantAuthority: role, tenantRef }));

  const trail = createAuditTrail({
    recorder,
    delivery: 'required', // no receipt without a record — a failed record fails the call
    hasher,
    ledgerId: ledger.ledgerId,
    expectedLedgerEpochId: ledger.ledgerEpochId,
    tenantRef,
    producer: { kind: identity.did.startsWith('did:web:') ? 'public_did' : 'pairwise_did', did: identity.did },
    sourceId: `${role}-edge`,
    binding,
    privacy: { classification: 'internal', retentionClass: 'audit-365d' },
    clock,
    sourceState: new MemoryAuditSourceState(),
    capabilities,
  });

  const middlewareAudit: KyaOsAuditTrail = {
    record: (input, recordOptions) => trail.record(input, recordOptions),
    auditProfile: capabilities.profile,
    capabilities,
    includeToolNames: true,
  };

  const builder = new AuditCheckpointBuilder({ journal, store, signer, hasher, clock });
  let latest: AnchorResult | null = null;
  let lastWitnessed: SignedAuditCheckpointV1 | null = null;
  let materialCache: { key: string; value: Promise<AuditMaterial> } | null = null;
  let lastDemonstration: { material: AuditMaterial; tampered: AuditReplayBundleV1; report: TamperReport } | null = null;

  const entries = () => journal.snapshot(ledger);

  async function checkpointSnapshot(): Promise<AnchorResult> {
    const all = await entries();
    if (all.length === 0) throw new Error('nothing to anchor yet — run a beat first');
    const checkpoint = await builder.createCheckpoint(ledger); // idempotent at the same tree size
    const created = latest?.checkpoint.checkpointDigest !== checkpoint.checkpointDigest;
    let witness: AuditObservationReceiptV1 | null = created ? null : (latest?.witness ?? null);
    let witnessError: string | null = null;
    if (options.witnessUrl && !witness) {
      try {
        const consistency = lastWitnessed && lastWitnessed.core.treeSize !== checkpoint.core.treeSize
          ? { oldTreeSize: lastWitnessed.core.treeSize, oldRoot: lastWitnessed.core.rootDigest, proof: await builder.consistencyProof(ledger, lastWitnessed.core.treeSize, checkpoint) }
          : null;
        const res = await fetch(options.witnessUrl, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ checkpoint, consistency }),
          signal: AbortSignal.timeout(2500),
        });
        const body = (await res.json()) as { receipt?: AuditObservationReceiptV1; error?: string };
        if (!res.ok || !body.receipt) throw new Error(body.error ?? `witness returned HTTP ${res.status}`);
        witness = body.receipt;
        lastWitnessed = checkpoint;
      } catch (err) {
        witnessError = err instanceof Error ? err.message : String(err);
      }
    }
    return { checkpoint, created, witness, witnessError };
  }

  async function anchor(): Promise<AnchorResult> {
    const snapshot = await checkpointSnapshot();
    // A new displayed anchor starts a new demonstration. Archiving a run
    // separately must not change the screen if Start over later fails.
    if (snapshot.created) lastDemonstration = null;
    latest = snapshot;
    return latest;
  }

  async function report(): Promise<AuditReport> {
    // Pin all anchor evidence before yielding. A concurrent Show audit may
    // publish another checkpoint while the inclusion proofs are computing.
    const anchorSnapshot = structuredClone(latest);
    const all = await entries();
    // Each report is one immutable snapshot. The SDK still constructs and
    // verifies every proof; shared subtree roots avoid hashing the ledger
    // again for every leaf. The cache is discarded after this report.
    const reportTree = new SnapshotMerkleTree(hasher);
    const leaves = all.map((e) => e.entryDigest);
    const cp = anchorSnapshot?.checkpoint ?? null;
    const anchoredSize = cp ? Number(cp.core.treeSize) : 0;
    const anchoredLeaves = leaves.slice(0, anchoredSize);
    const root = cp?.core.rootDigest ?? null;
    const inclusions = [];
    for (let i = 0; i < anchoredLeaves.length; i++) {
      const auditPath = await reportTree.inclusionProof(anchoredLeaves, i);
      inclusions.push({
        seq: all[i]!.core.sequence,
        leafIndex: i,
        auditPath: auditPath.map(String),
        included: root ? await reportTree.verifyInclusion({ leaf: anchoredLeaves[i]!, leafIndex: i, treeSize: anchoredLeaves.length, root, auditPath }) : false,
      });
    }
    let chainIntact = all.length > 0;
    for (let i = 1; i < all.length; i++) if (all[i]!.core.previousEntryDigest !== all[i - 1]!.entryDigest) chainIntact = false;
    const w = anchorSnapshot?.witness ?? null;
    return {
      ledger,
      recorder: recorderRef,
      profile: {
        advertised: capabilities.profile,
        claim: 'Recorded — structured capture of delivered instrumented events',
        whyNotHigher: 'journal is in-memory for the stage; the SDK refuses AAP-2+ without a durable journal (same code on Postgres/WORM → AAP-3, plus this witness → AAP-4)',
      },
      entries: all.map((e, i) => row(e, i < anchoredSize)),
      checkpoint: cp ? { treeSize: cp.core.treeSize, rootDigest: cp.core.rootDigest, checkpointDigest: cp.checkpointDigest, createdAt: cp.core.createdAt, previousCheckpointDigest: cp.core.previousCheckpointDigest, jws: cp.jws } : null,
      witness: w ? { observerId: w.core.observerId, observer: w.core.observer, observedAt: w.core.observedAt, observationDigest: w.observationDigest, checkpointDigest: w.core.checkpointDigest, treeSize: w.core.treeSize } : null,
      witnessError: anchorSnapshot?.witnessError ?? null,
      tree: anchoredLeaves.length ? await renderTree(reportTree, anchoredLeaves) : [],
      inclusions,
      allIncluded: inclusions.length > 0 && inclusions.every((i) => i.included),
      chainIntact,
      unanchored: all.length - anchoredSize,
    };
  }

  // ---- bundle + policy + keys ---------------------------------------------------

  async function policyFor(witness: AuditObservationReceiptV1 | null): Promise<AuditVerificationPolicyV1> {
    return {
      policyId: `urn:kya-os:example:agentic-commerce:policy:${ledger.ledgerEpochId}`,
      trustedLedgerEpochs: [{ ...ledger, recorderKeys: [{ signer: recorderRef }] }],
      trustedObservers: witness ? [{ signer: witness.core.observer }] : [],
      authorizedExporters: [{ signerKeys: [{ signer: recorderRef }], allowedLedgerIds: [ledger.ledgerId], allowedPurposes: [EXPORT_PURPOSE] }],
      acceptedIntegritySuites: [AUDIT_INTEGRITY_SUITE, AUDIT_CHECKPOINT_INTEGRITY_SUITE, AUDIT_BUNDLE_INTEGRITY_SUITE],
      acceptedAlgorithms: ['EdDSA'],
      keyRevocationMode: 'as_observed',
    };
  }

  async function keysFor(witness: AuditObservationReceiptV1 | null): Promise<{ keys: Array<{ kid: string; jwk: Record<string, unknown> }> }> {
    const keys = [{ kid: recorderRef.kid, jwk: jwkFor(identity.publicKeyBase64, recorderRef.kid) }];
    if (witness && options.resolvePublicKeyBase64) {
      const pub = await options.resolvePublicKeyBase64(witness.core.observer).catch(() => null);
      if (pub) keys.push({ kid: witness.core.observer.kid, jwk: jwkFor(pub, witness.core.observer.kid) });
    }
    return { keys };
  }

  async function buildBundle(input: { entries: SignedAuditEntryV1[]; checkpoint: SignedAuditCheckpointV1; witness: AuditObservationReceiptV1 | null; policy: AuditVerificationPolicyV1; bundleId: string }): Promise<AuditReplayBundleV1> {
    const { checkpoint } = input;
    const size = Number(checkpoint.core.treeSize);
    const covered = input.entries.slice(0, size);
    const leaves = covered.map((e) => e.entryDigest);
    // All proofs belong to this immutable bundle snapshot. The SDK computes
    // each path; sharing its subtree roots avoids quadratic ledger hashing.
    const bundleTree = new SnapshotMerkleTree(hasher);
    const inclusionProofs = [];
    for (let i = 0; i < covered.length; i++) {
      inclusionProofs.push({
        ...ledger,
        sequence: covered[i]!.core.sequence,
        entryDigest: covered[i]!.entryDigest,
        checkpointDigest: checkpoint.checkpointDigest,
        proof: { leafIndex: String(i), treeSize: checkpoint.core.treeSize, auditPath: (await bundleTree.inclusionProof(leaves, i)).map(String) },
      });
    }
    const exporter = new AuditReplayBundleExporter({ hasher, signer, clock });
    const last = covered[covered.length - 1]!;
    return exporter.export({
      bundleId: input.bundleId,
      purpose: EXPORT_PURPOSE,
      verificationPolicyDigest: await hashAuditValue(hasher, POLICY_DIGEST_DOMAIN, input.policy),
      selections: [{ ...ledger, firstSequence: covered[0]!.core.sequence, lastSequence: last.core.sequence, expectedHeadDigest: last.entryDigest, checkpointTreeSizes: [checkpoint.core.treeSize] }],
      components: [
        { path: 'entries.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.entries, disposition: 'included', content: covered },
        { path: 'checkpoints.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.checkpoints, disposition: 'included', content: [checkpoint] },
        { path: 'inclusion-proofs.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.inclusionProofs, disposition: 'included', content: inclusionProofs },
        ...(input.witness ? [{ path: 'observations.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.observations, disposition: 'included' as const, content: [input.witness] }] : []),
      ],
    });
  }

  async function verify(bundle: AuditReplayBundleV1 | unknown, policy: AuditVerificationPolicyV1, keys: { keys: Array<{ kid: string; jwk: Record<string, unknown> }> }): Promise<AuditVerificationReportV1> {
    const byKid = new Map(keys.keys.map((k) => [k.kid, k.jwk]));
    const signatures = new CompactJwsAuditSignatureVerifier({ resolve: async (signer) => (byKid.get(signer.kid) as never) ?? null });
    return verifyAuditBundle(bundle, policy, { hasher, signatures });
  }

  /** Anchor if needed, then everything a verifier needs, honest and forged. */
  async function materialize(pinned?: AnchorResult): Promise<AuditMaterial> {
    const all = await entries();
    const current = pinned ?? (latest && latest.checkpoint.core.treeSize === String(all.length) ? latest : await anchor());
    const key = `${current.checkpoint.checkpointDigest}:${current.witness?.observationDigest ?? ''}`;
    if (materialCache?.key === key) return materialCache.value;
    const a = structuredClone(current);
    // Recording may have continued while anchor() contacted its witness.
    // Read the immutable checkpoint prefix after choosing that checkpoint.
    const covered = structuredClone((await entries()).slice(0, Number(a.checkpoint.core.treeSize)));
    const value = (async (): Promise<AuditMaterial> => {
      const [policy, keys] = await Promise.all([policyFor(a.witness), keysFor(a.witness)]);
      const stamp = a.checkpoint.core.treeSize;
      const honest = await buildBundle({ entries: covered, checkpoint: a.checkpoint, witness: a.witness, policy, bundleId: `urn:kya-os:example:agentic-commerce:bundle:${ledger.ledgerEpochId}:${stamp}` });
      return { all: covered, anchor: a, policy, keys, honest };
    })();
    materialCache = { key, value };
    try { return await value; }
    catch (error) { if (materialCache?.value === value) materialCache = null; throw error; }
  }

  /**
   * The insider: has the merchant's signing key and write access to the journal.
   * Edits the selected line (or the latest refusal), recomputes the event
   * and entry digests, re-signs the receipt, and re-exports a bundle with a
   * fresh manifest signature. Everything under their control is consistent —
   * and it is still caught, because the NEXT entry's `previousEntryDigest`, the
   * checkpoint root the room saw, and the RP's witness receipt all commit to the
   * honest digest. A final entry has no successor to break; the checkpoint
   * still detects its changed digest.
   */
  async function forge(all: SignedAuditEntryV1[], edit?: AuditInsiderEdit): Promise<{ entries: SignedAuditEntryV1[]; index: number; forged: SignedAuditEntryV1; original: SignedAuditEntryV1 }> {
    // The most incriminating line: the LATEST refused tool call (after the kill,
    // that is the revoked agent's order) — the one an insider would want gone.
    const refused = (e: SignedAuditEntryV1) => e.core.event.eventType.startsWith('tool.call.') && (e.core.event.outcome === 'denied' || e.core.event.outcome === 'failed');
    let index = edit ? all.findIndex(entry => entry.core.sequence === edit.sequence) : all.length - 1;
    if (!edit) {
      while (index >= 0 && !refused(all[index]!)) index -= 1;
      if (index < 0) index = all.length - 1;
    }
    if (index < 0) throw new Error('Select an entry included in the displayed checkpoint. This sequence is unknown or unanchored.');
    const original = all[index]!;
    if (edit?.outcome === original.core.event.outcome) throw new Error('Choose a different outcome to demonstrate an edit.');
    const core = structuredClone(original.core) as SignedAuditEntryV1['core'];
    const event = core.event;
    event.outcome = edit?.outcome ?? (event.outcome === 'succeeded' ? 'failed' : 'succeeded');
    core.eventDigest = await digestAuditEvent(hasher, core.event);
    const entryDigest = await digestAuditEntry(hasher, core);
    const receiptCore = buildAuditRecorderReceiptCore(core, entryDigest);
    const forged: SignedAuditEntryV1 = {
      core,
      eventDigest: core.eventDigest,
      entryDigest,
      recorderReceipt: { core: receiptCore, jws: await signer.sign(encoder.encode(canonicalizeJSON(receiptCore))) },
    };
    const entries = all.slice();
    entries[index] = forged;
    return { entries, index, forged, original };
  }

  async function tamper(edit?: AuditInsiderEdit): Promise<TamperReport> {
    if (edit !== undefined) {
      if (!edit || typeof edit !== 'object' || Array.isArray(edit) ||
          typeof edit.sequence !== 'string' || !/^(0|[1-9]\d*)$/.test(edit.sequence) ||
          !['succeeded', 'failed', 'denied', 'challenged', 'unknown'].includes(edit.outcome) ||
          typeof edit.checkpointDigest !== 'string') throw new Error('Provide a sequence, supported outcome, and checkpoint digest.');
      if (!latest || latest.checkpoint.checkpointDigest !== edit.checkpointDigest) {
        throw new Error('The displayed checkpoint is missing or has changed. Show audit again before editing.');
      }
    }
    const m = await materialize(edit ? latest! : undefined);
    const { entries: forgedEntries, index, forged, original } = await forge(m.all, edit);
    const tampered = await buildBundle({ entries: forgedEntries, checkpoint: m.anchor.checkpoint, witness: m.anchor.witness, policy: m.policy, bundleId: `urn:kya-os:example:agentic-commerce:bundle:${ledger.ledgerEpochId}:${m.anchor.checkpoint.core.treeSize}:edited` });
    const [honestReport, tamperedReport] = await Promise.all([verify(m.honest, m.policy, m.keys), verify(tampered, m.policy, m.keys)]);
    const leaves = m.all.map((e) => e.entryDigest);
    const forgedLeaves = forgedEntries.map((e) => e.entryDigest);
    const root = m.anchor.checkpoint.core.rootDigest;
    const tamperedRoot = await tree.root(forgedLeaves);
    const auditPath = await tree.inclusionProof(leaves, index);
    const next = m.all[index + 1];
    const byKid = new Map(m.keys.keys.map((k) => [k.kid, k.jwk]));
    const verifier = new CompactJwsAuditSignatureVerifier({ resolve: async (s) => (byKid.get(s.kid) as never) ?? null });
    const report: TamperReport = {
      target: { seq: original.core.sequence, eventType: original.core.event.eventType, before: original.core.event.outcome, after: forged.core.event.outcome, reason: original.core.event.reason?.code ?? null },
      attacker: 'insider with the recorder signing key and write access to the journal',
      anchoredRoot: root,
      tamperedRoot,
      rootsMatch: root === tamperedRoot,
      chainBreaksAt: next ? (next.core.previousEntryDigest === forged.entryDigest ? null : next.core.sequence) : null,
      honestInclusion: await tree.verifyInclusion({ leaf: leaves[index]!, leafIndex: index, treeSize: leaves.length, root, auditPath }),
      forgedInclusion: await tree.verifyInclusion({ leaf: forged.entryDigest, leafIndex: index, treeSize: leaves.length, root, auditPath }),
      forgedReceiptVerifies: await verifier.verify(encoder.encode(canonicalizeJSON(forged.recorderReceipt.core)), forged.recorderReceipt.jws, recorderRef),
      witnessStillBindsAnchoredRoot: m.anchor.witness ? m.anchor.witness.core.checkpointDigest === m.anchor.checkpoint.checkpointDigest : false,
      reports: { honest: honestReport, tampered: tamperedReport },
    };
    if (latest?.checkpoint.checkpointDigest !== m.anchor.checkpoint.checkpointDigest) {
      throw new Error('The checkpoint changed while verifying the edit. Show audit again before editing.');
    }
    lastDemonstration = { material: m, tampered, report };
    return structuredClone(report);
  }

  async function exportBundle(): Promise<ExportResult> {
    if (!lastDemonstration) await tamper();
    const { material: m, tampered, report } = lastDemonstration!;
    fs.mkdirSync(auditDir, { recursive: true });
    const files = {
      bundle: path.join(auditDir, 'bundle.json'),
      tampered: path.join(auditDir, 'bundle.tampered.json'),
      policy: path.join(auditDir, 'policy.json'),
      keys: path.join(auditDir, 'keys.json'),
    };
    fs.writeFileSync(files.bundle, JSON.stringify(m.honest, null, 2));
    fs.writeFileSync(files.tampered, JSON.stringify(tampered, null, 2));
    fs.writeFileSync(files.policy, JSON.stringify(m.policy, null, 2));
    fs.writeFileSync(files.keys, JSON.stringify(m.keys, null, 2));
    const rel = (p: string) => path.relative(process.cwd(), p) || p;
    // The package's `kya-audit` bin only runs when argv[1] ends in /audit/cli.js,
    // which the npm bin shim does not satisfy (fix pending upstream); call the
    // file directly. `npm run verify:ledger` wraps the same line.
    const cli = 'node node_modules/@kya-os/mcp/dist/audit/cli.js verify';
    return {
      dir: auditDir,
      files,
      command: {
        honest: `${cli} ${rel(files.bundle)} --policy ${rel(files.policy)} --keys ${rel(files.keys)}`,
        tampered: `${cli} ${rel(files.tampered)} --policy ${rel(files.policy)} --keys ${rel(files.keys)}`,
      },
      reports: structuredClone(report.reports),
      bundleId: m.honest.manifest.core.bundleId,
      manifestDigest: m.honest.manifest.manifestDigest,
      checkpointDigest: m.anchor.checkpoint.checkpointDigest,
      target: { ...report.target },
      components: m.honest.manifest.core.inventory.map((i) => ({ path: i.path, mediaType: i.mediaType, size: i.size ?? '0', digest: i.digest ?? '' })),
    };
  }

  async function bundle(): Promise<AuditReplayBundleV1> {
    return structuredClone((lastDemonstration?.material ?? await materialize()).honest);
  }

  async function snapshotForArchive(): Promise<AuditArchiveSnapshot | null> {
    if ((await entries()).length === 0) return null;
    const m = await materialize(await checkpointSnapshot());
    const verification = await verify(m.honest, m.policy, m.keys);
    if ([verification.cryptographicIntegrity, verification.chainIntegrity, verification.checkpointIntegrity]
      .some(dimension => dimension.verdict !== 'valid')) throw new Error('AUDIT_ARCHIVE_INVALID: the complete run did not verify; the current run remains active.');
    if (m.anchor.witness && verification.anchorIntegrity.verdict !== 'valid') {
      throw new Error('AUDIT_ARCHIVE_INVALID: the returned witness evidence did not verify; the current run remains active.');
    }
    return structuredClone({ ledger, entries: m.all.length,
      checkpointDigest: m.anchor.checkpoint.checkpointDigest, manifestDigest: m.honest.manifest.manifestDigest,
      witnessed: m.anchor.witness !== null, witnessError: m.anchor.witnessError,
      bundle: m.honest, policy: m.policy, keys: m.keys, verification });
  }

  return { middlewareAudit, record: (input, recordOptions) => trail.record(input, recordOptions), capabilities, ledger, recorder: recorderRef, entries, anchor, report, tamper, exportBundle, bundle, snapshotForArchive };
}

// ---------------------------------------------------------------------------

function shortId(did: string): string {
  return did.replace(/^did:key:/, '').slice(-8).toLowerCase();
}

function row(e: SignedAuditEntryV1, anchored: boolean): LedgerRow {
  const ev = e.core.event;
  return {
    seq: e.core.sequence,
    at: new Date(e.core.recordedAt).toISOString(),
    eventType: ev.eventType,
    outcome: ev.outcome,
    tool: ev.action.name ?? null,
    reason: ev.reason?.code ?? null,
    correlationId: ev.correlationId ?? null,
    entryDigest: e.entryDigest,
    previousEntryDigest: e.core.previousEntryDigest,
    anchored,
  };
}

/** Share SDK-computed roots within a single immutable report or bundle snapshot. */
class SnapshotMerkleTree extends Rfc9162MerkleTree {
  private readonly roots = new Map<string, Promise<Digest>>();

  override root(leaves: readonly Digest[]): Promise<Digest> {
    // Include every digest in the key, so neither a changed interior leaf nor
    // a differently sized subtree can reuse another root.
    const key = leaves.join(',');
    const cached = this.roots.get(key);
    if (cached) return cached;
    const root = super.root(leaves);
    this.roots.set(key, root);
    return root;
  }
}

/**
 * The RFC 9162 tree over the leaves, flattened into render-ready rows.
 * Faithful to the spec's split rule (§2.1: k = the largest power of two
 * STRICTLY less than n), so the shape is the real one, not a padded balanced
 * tree. The root row's hash equals `Rfc9162MerkleTree.root()`.
 */
async function renderTree(tree: Rfc9162MerkleTree, leaves: readonly Digest[]): Promise<TreeRow[]> {
  const rows: TreeRow[] = [];
  const splitAt = (n: number) => { let p = 1; while (p * 2 < n) p *= 2; return p; };
  async function walk(lo: number, hi: number, depth: number, pad: string, connector: string): Promise<void> {
    const hash = await tree.root(leaves.slice(lo, hi));
    const prefix = pad + connector;
    if (hi - lo === 1) { rows.push({ depth, prefix, hash, label: `seq ${lo}`, leafIndex: lo }); return; }
    rows.push({ depth, prefix, hash, label: `[${lo}..${hi - 1}]`, leafIndex: null });
    const childPad = pad + (connector === '' ? '' : connector.startsWith('├') ? '│  ' : '   ');
    const s = lo + splitAt(hi - lo);
    await walk(lo, s, depth + 1, childPad, '├─ ');
    await walk(s, hi, depth + 1, childPad, '└─ ');
  }
  await walk(0, leaves.length, 0, '', '');
  return rows;
}
