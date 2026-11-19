/**
 * Several `StatusList2021Manager`s over one status-list store, as the replicas of one issuing
 * service run them, or a process that builds a manager per request. Each manager serialises only
 * its own writes, so these tests interleave the writes of different managers and check that every
 * change a manager reported is on the list the store keeps, signed over what the list says.
 */

import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { StatusList2021Manager, StatusListWriteConflictError } from '../statuslist-manager.js';
import { STATUS_LIST_WRITE_ATTEMPTS } from '../statuslist-storage.js';
import { MemoryStatusListStorage } from '../storage/memory-statuslist-storage.js';
import { canonicalizeJSON } from '../utils.js';
import type { VCSigningFunction } from '../vc-issuer.js';
import type { CredentialStatus, Proof, StatusList2021Credential } from '../../types/protocol.js';
import { statusListGzipCodec } from '../../utils/statuslist-gzip.js';

const identity = { getDid: () => 'did:web:issuer.example', getKeyId: () => 'did:web:issuer.example#key-1' };
const options = { statusListBaseUrl: 'https://status.example', defaultListSize: 1024 };

/** A proof whose value is the SHA-256 of what was signed, so a test can tell what a stored list's proof covers. */
function proofOver(canonical: string): Proof {
  return { type: 'Ed25519Signature2020', proofValue: createHash('sha256').update(canonical).digest('base64url') };
}

const sign: VCSigningFunction = async (canonical) => proofOver(canonical);

/**
 * A signer that holds every signature until `writers` are waiting, and none after that, so each of
 * `writers` managers has read the list before any of them writes it.
 */
function signerHeldFor(writers: number): VCSigningFunction {
  let waiting = 0;
  let release!: () => void;
  const everyoneRead = new Promise<void>((resolve) => {
    release = resolve;
  });
  return async (canonical) => {
    if (++waiting === writers) release();
    await everyoneRead;
    return proofOver(canonical);
  };
}

/** A manager over `storage`, as one replica of the issuing service builds it. */
function replica(storage: MemoryStatusListStorage, signingFunction: VCSigningFunction = sign): StatusList2021Manager {
  return new StatusList2021Manager(storage, identity, signingFunction, statusListGzipCodec, statusListGzipCodec, options);
}

/** `count` entries on one revocation list in `storage`, allocated by the issuing service. */
async function allocated(storage: MemoryStatusListStorage, count: number): Promise<CredentialStatus[]> {
  const issuer = replica(storage);
  const entries: CredentialStatus[] = [];
  for (let i = 0; i < count; i++) entries.push(await issuer.allocateStatusEntry('revocation'));
  return entries;
}

/**
 * A store where, while `contending` is on, another writer stores the list again just before each
 * conditional write a manager makes, so every such write is over a list that has since changed.
 */
class ContendedStore extends MemoryStatusListStorage {
  contending = true;
  conditionalWrites = 0;

  override async setStatusListIfMatch(
    statusListId: string,
    credential: StatusList2021Credential,
    etag: string | null,
  ): Promise<boolean> {
    this.conditionalWrites++;
    const current = await this.getStatusList(statusListId);
    if (this.contending && current) await this.setStatusList(statusListId, current);
    return super.setStatusListIfMatch(statusListId, credential, etag);
  }
}

/** Whether the list stored under `statusListId` carries a proof over what it says. */
async function signedOverItself(storage: MemoryStatusListStorage, statusListId: string): Promise<boolean> {
  const list = await storage.getStatusList(statusListId);
  if (!list?.proof) return false;
  const { proof, ...unsigned } = list;
  return proof.proofValue === proofOver(canonicalizeJSON(unsigned)).proofValue;
}

describe('StatusList2021Manager writers over one store', () => {
  it('keeps both revocations when two managers revoke on one list at once', async () => {
    const storage = new MemoryStatusListStorage();
    const [first, second] = await allocated(storage, 2);
    const held = signerHeldFor(2);

    await Promise.all([
      replica(storage, held).updateStatus(first!, true),
      replica(storage, held).updateStatus(second!, true),
    ]);

    const verifier = replica(storage);
    expect({ first: await verifier.checkStatus(first!), second: await verifier.checkStatus(second!) })
      .toEqual({ first: true, second: true });
    expect(await signedOverItself(storage, first!.statusListCredential)).toBe(true);
  });

  it('keeps every change, revocations and a restoration, when five managers write one list at once', async () => {
    const storage = new MemoryStatusListStorage();
    const entries = await allocated(storage, 5);
    await replica(storage).updateStatus(entries[0]!, true);
    const held = signerHeldFor(5);

    await Promise.all([
      replica(storage, held).updateStatus(entries[0]!, false),
      ...entries.slice(1).map((entry) => replica(storage, held).updateStatus(entry, true)),
    ]);

    expect(await replica(storage).getRevokedIndices(entries[0]!.statusListCredential)).toEqual([1, 2, 3, 4]);
    expect(await signedOverItself(storage, entries[0]!.statusListCredential)).toBe(true);
  });

  it('creates a list once when two managers create it at once', async () => {
    const storage = new MemoryStatusListStorage();
    const held = signerHeldFor(2);

    const [first, second] = await Promise.all([
      replica(storage, held).allocateStatusEntry('revocation'),
      replica(storage, held).allocateStatusEntry('revocation'),
    ]);

    expect(first.statusListCredential).toBe(second.statusListCredential);
    expect(await storage.getStatusListVersionCount(first.statusListCredential)).toBe(1);
  });

  it('does not let a creation that lost the race replace a list that has since recorded a revocation', async () => {
    const storage = new MemoryStatusListStorage();
    let signing!: () => void;
    const lateCreatorSigns = new Promise<void>((resolve) => {
      signing = resolve;
    });
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const lateCreator = replica(storage, async (canonical) => {
      signing();
      await held;
      return proofOver(canonical);
    });

    // The late creator has read no list and is signing a fresh, empty one.
    const lateEntry = lateCreator.allocateStatusEntry('revocation');
    await lateCreatorSigns;
    const other = replica(storage);
    const entry = await other.allocateStatusEntry('revocation');
    await other.updateStatus(entry, true);

    release();
    await lateEntry;
    expect(await other.checkStatus(entry)).toBe(true);
    expect(await storage.getStatusListVersionCount(entry.statusListCredential)).toBe(2);
  });

  it('throws a coded error after a bounded number of refused writes, and never stores a stale list', async () => {
    const storage = new ContendedStore();
    const [entry] = await allocated(storage, 1);
    const id = entry!.statusListCredential;
    const created = await storage.getStatusList(id);
    const before = storage.conditionalWrites;
    const manager = replica(storage);

    const error = await manager.updateStatus(entry!, true).catch((thrown: unknown) => thrown);

    expect(error).toBeInstanceOf(StatusListWriteConflictError);
    expect(error).toMatchObject({
      name: 'StatusListWriteConflictError',
      code: 'STATUS_LIST_WRITE_CONFLICT',
      statusListId: id,
      attempts: STATUS_LIST_WRITE_ATTEMPTS,
    });
    expect((error as Error).message).toMatch(/was not written.*Make the change again\.$/);
    expect(storage.conditionalWrites - before).toBe(STATUS_LIST_WRITE_ATTEMPTS);
    // Every list the store kept is the one the other writer stored, so nothing this manager signed
    // over a list it read was stored.
    const versions = await storage.getStatusListVersionCount(id);
    expect(versions).toBe(1 + STATUS_LIST_WRITE_ATTEMPTS);
    for (let version = 1; version <= versions; version++) {
      expect(await storage.getStatusListVersion(id, version)).toEqual(created);
    }

    // Made again once the other writer stops, the change is stored.
    storage.contending = false;
    await manager.updateStatus(entry!, true);
    expect(await manager.checkStatus(entry!)).toBe(true);
  });
});
