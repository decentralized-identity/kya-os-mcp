/**
 * Test helper: `StatusList2021Manager`s over one in-memory store, as the replicas of one issuing
 * service run them, with a signer whose proof tells what it covers, and the clock and randomness
 * that make a run of retried writes take the same course every time.
 */
import { createHash } from 'node:crypto';
import { gunzipSync, gzipSync } from 'node:zlib';
import type { CompressionFunction, DecompressionFunction } from '../../bitstring.js';
import { StatusList2021Manager, type StatusList2021ManagerOptions } from '../../statuslist-manager.js';
import type { MemoryStatusListStorage } from '../../storage/memory-statuslist-storage.js';
import { canonicalizeJSON } from '../../utils.js';
import type { VCSigningFunction } from '../../vc-issuer.js';
import type { CredentialStatus, Proof } from '../../../types/protocol.js';
import { statusListGzipCodec } from '../../../utils/statuslist-gzip.js';

export const identity = { getDid: () => 'did:web:issuer.example', getKeyId: () => 'did:web:issuer.example#key-1' };

const LIST_OPTIONS = { statusListBaseUrl: 'https://status.example', defaultListSize: 1024 };

/** A proof whose value is the SHA-256 of what was signed, so a test can tell what a stored list's proof covers. */
export function proofOver(canonical: string): Proof {
  return { type: 'Ed25519Signature2020', proofValue: createHash('sha256').update(canonical).digest('base64url') };
}

export const sign: VCSigningFunction = async (canonical) => proofOver(canonical);

/** GZIP done synchronously, so a write runs in microtasks alone and only a sleep waits on a clock. */
export const synchronousGzip: CompressionFunction & DecompressionFunction = {
  compress: async (data) => new Uint8Array(gzipSync(data)),
  decompress: async (data) => new Uint8Array(gunzipSync(data)),
};

/** What a replica is built with beside its store: its signer, its codec and its options. */
export interface ReplicaSetup {
  sign?: VCSigningFunction;
  codec?: CompressionFunction & DecompressionFunction;
  options?: StatusList2021ManagerOptions;
}

/** A manager over `storage`, as one replica of the issuing service builds it. */
export function replica(storage: MemoryStatusListStorage, setup: ReplicaSetup = {}): StatusList2021Manager {
  const codec = setup.codec ?? statusListGzipCodec;
  return new StatusList2021Manager(storage, identity, setup.sign ?? sign, codec, codec, {
    ...LIST_OPTIONS,
    ...setup.options,
  });
}

/** `count` entries on one revocation list in `storage`, allocated by the issuing service. */
export async function allocated(storage: MemoryStatusListStorage, count: number): Promise<CredentialStatus[]> {
  const issuer = replica(storage);
  const entries: CredentialStatus[] = [];
  for (let i = 0; i < count; i++) entries.push(await issuer.allocateStatusEntry('revocation'));
  return entries;
}

/** Whether the list stored under `statusListId` carries a proof over what it says. */
export async function signedOverItself(storage: MemoryStatusListStorage, statusListId: string): Promise<boolean> {
  const list = await storage.getStatusList(statusListId);
  if (!list?.proof) return false;
  const { proof, ...unsigned } = list;
  return proof.proofValue === proofOver(canonicalizeJSON(unsigned)).proofValue;
}

/** A repeatable stream of numbers from 0 up to 1, from `seed` (mulberry32). */
export function seededRandom(seed: number): () => number {
  let state = seed | 0;
  return () => {
    state = (state + 0x6d2b79f5) | 0;
    let mixed = Math.imul(state ^ (state >>> 15), 1 | state);
    mixed = (mixed + Math.imul(mixed ^ (mixed >>> 7), 61 | mixed)) ^ mixed;
    return ((mixed ^ (mixed >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Time that moves only when all other work has run: then the earliest sleep wakes, sleeps with one
 * deadline in the order they began. Work that waits on nothing but this clock and microtasks takes
 * the same course on every run.
 */
export class VirtualClock {
  private now = 0;
  private begun = 0;
  private timers: { at: number; order: number; wake: () => void }[] = [];

  readonly sleep = (ms: number): Promise<void> =>
    new Promise((wake) => {
      this.timers.push({ at: this.now + ms, order: this.begun++, wake });
    });

  /** Run the clock until `work` settles, and settle as it did. */
  async run<T>(work: Promise<T>): Promise<T> {
    let outcome: { value: T } | { error: unknown } | undefined;
    work.then(
      (value) => (outcome = { value }),
      (error: unknown) => (outcome = { error }),
    );
    for (;;) {
      await new Promise((resolve) => setImmediate(resolve));
      if (outcome !== undefined) break;
      this.timers.sort((a, b) => a.at - b.at || a.order - b.order);
      const timer = this.timers.shift();
      if (timer === undefined) throw new Error('the work waits on something other than this clock');
      this.now = timer.at;
      timer.wake();
    }
    if ('error' in outcome) throw outcome.error;
    return outcome.value;
  }
}
