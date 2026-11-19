/**
 * StatusList2021 Manager
 *
 * Manages StatusList2021 credentials for efficient delegation revocation.
 *
 * Related Spec: W3C StatusList2021
 */

import type {
  StatusList2021Credential,
  CredentialStatus,
} from '../types/protocol.js';
import { BitstringManager, type CompressionFunction, type DecompressionFunction } from './bitstring.js';
import { parseStatusListIndex } from '../utils/statuslist-bits.js';
import type { VCSigningFunction } from './vc-issuer.js';
import { canonicalizeJSON } from './utils.js';
import { acceptEntrySize, acceptStatusPurpose } from '../utils/statuslist-acceptance.js';
import { assertStatusListValidity } from '../utils/statuslist-validity.js';
import { clockSkewOption } from '../utils/validity-window.js';
import { RefusalError } from '../utils/refusal.js';
import { describeValue } from '../utils/describe-value.js';
import {
  entryOwnerRecorder,
  readEntryOwner,
  retireEntryOwner,
  type StatusEntryAllocationOptions,
  type StatusEntryOwner,
  type StatusEntryOwners,
} from './status-entry-owner.js';
import { KeyedLock } from '../utils/keyed-lock.js';
import type { StatusListStorageProvider } from './statuslist-storage.js';
import {
  commitStatusListChange,
  writeRetryOf,
  type StatusListChange,
  type StatusListWriteRetry,
  type StatusListWriteRetryOptions,
} from './statuslist-write.js';

export type {
  ConditionalStatusListStorageProvider,
  HistoricalStatusListStorageProvider,
  StatusListStorageProvider,
  StoredStatusList,
} from './statuslist-storage.js';
export {
  StatusListWriteConflictError,
  isStatusListWriteConflict,
  type StatusListWriteRetryOptions,
} from './statuslist-write.js';

export interface StatusListIdentityProvider {
  getDid(): string;
  getKeyId(): string;
}

/** The options of a {@link StatusList2021Manager}, and how it retries a refused write. */
export interface StatusList2021ManagerOptions extends StatusListWriteRetryOptions {
  statusListBaseUrl?: string;
  defaultListSize?: number;
  maxClockSkewMs?: number;
}

export class StatusList2021Manager implements StatusEntryOwners {
  private statusListBaseUrl: string;
  private defaultListSize: number;
  /** The clock tolerance each bound of a list's validity window is held with, in milliseconds. */
  private skewMs: number;
  /** How a write a conditional store refused is tried again. */
  private retry: StatusListWriteRetry;
  /**
   * Per-status-list mutex for this manager's own writes. Every read-modify-write
   * of a list this manager makes (status updates and first creation) runs inside
   * it, so none of them overwrites another of them with a stale copy. It cannot
   * see another manager's writes: those are kept only by a store with the
   * conditional write, as the constructor's `storage` says.
   */
  private updateLocks = new KeyedLock();

  /**
   * @param storage - Where the manager keeps its lists. More than one manager
   *   may write to one store, as replicas, serverless instances, or a manager
   *   built per request do, only when the store implements
   *   `ConditionalStatusListStorageProvider`, as `MemoryStatusListStorage`
   *   does: a write another writer got in before is then made again over the
   *   list now stored, after a short random wait, up to
   *   `options.maxWriteConflicts` times. Over any other store the last write
   *   wins, so write through one manager only; the first write a manager
   *   makes to one warns once per process.
   * @param compressor - GZIP-compresses the bitstring of every list this
   *   manager publishes. Defaults to `statusListGzipCodec` (through
   *   {@link BitstringManager}). Status-list readers accept only GZIP, so a
   *   list published without it would read as revoked everywhere; publishing
   *   throws instead.
   * @param decompressor - Inflates the GZIP lists this manager reads. Defaults
   *   to `statusListGzipCodec` (through {@link BitstringManager}). Reading
   *   throws on a list that is not GZIP and on a decompressor that returns its
   *   input unchanged.
   * @param options.maxClockSkewMs - The clock tolerance, in milliseconds, each
   *   bound of a kept list's validity window is held with when the list is
   *   read: a number from 0 to 600,000. Default 120,000, the proof verifier's
   *   default skew. Any other value throws a `TypeError` naming the option.
   * @param options.maxWriteConflicts - How many times a conditional store may
   *   refuse the write of one change before it throws
   *   `StatusListWriteConflictError`: a whole number, 0 or more. Default 32.
   *   Between tries the manager waits a random part of a delay that doubles
   *   from 2 ms, under a ceiling of 100 ms or, where it is longer, the length
   *   of the try just refused doubled every four refusals, and never waits
   *   more than 10 s at once. Any other value throws a `TypeError` naming the
   *   option.
   */
  constructor(
    private storage: StatusListStorageProvider,
    private identity: StatusListIdentityProvider,
    private signingFunction: VCSigningFunction,
    private compressor?: CompressionFunction,
    private decompressor?: DecompressionFunction,
    options?: StatusList2021ManagerOptions
  ) {
    this.statusListBaseUrl = options?.statusListBaseUrl || 'https://status.example.com';
    this.defaultListSize = options?.defaultListSize || 131072;
    this.skewMs = clockSkewOption(options?.maxClockSkewMs);
    this.retry = writeRetryOf(options);
  }

  /**
   * Allocate the next entry of the `purpose` list for one delegation, creating the list on first
   * use. Give each delegation an entry of its own, and register the delegation with it. Pass
   * `options.delegationId`, the id the delegation is registered under, to record the entry as that
   * delegation's: a delegation graph built with this manager as `statusEntryOwners` then registers
   * it for no other, and `CascadingRevocationManager` sets and clears it for no other. It needs a
   * storage provider that implements `StatusEntryOwnerStorageProvider`, and throws a `TypeError`
   * before taking an index for one that does not.
   *
   * The owner is recorded last, once the list holds the entry's index: an allocation that throws
   * records none, and its index is registered for no delegation by a graph that reads owners.
   * Allocate again.
   *
   * @throws {Error} when the index the store allocated is outside the list.
   * @throws {StatusListWriteConflictError} when the list had to be created and
   *   a conditional store refused every write of it; nothing was stored.
   */
  async allocateStatusEntry(
    purpose: 'revocation' | 'suspension',
    options?: StatusEntryAllocationOptions
  ): Promise<CredentialStatus> {
    const recordOwner = entryOwnerRecorder(this.storage, options);
    const statusListId = `${this.statusListBaseUrl}/${purpose}/v1`;

    // The order: take the index, write the list (a conditional write, tried again over the list now
    // stored when another writer got in first), check the list holds the index, and only then
    // record the owner, under that same index. An index with no owner recorded is registered for
    // no delegation by a graph that reads owners, and `allocateIndex` never gives it out again, so
    // an allocation that stops before the record, as for a `StatusListWriteConflictError`, a store
    // that cannot be reached, or a crash, leaves an index nobody can take. Recording first would
    // leave an owner for an index the allocation then gave up.
    const index = await this.storage.allocateIndex(statusListId);

    const capacity = await this.ensureStatusListExists(statusListId, purpose);
    // An index past the end of the list can never be read or set, so refuse
    // it (SPEC.md §6.7) rather than mint a credential that cannot be revoked.
    if (index >= capacity) {
      throw new Error(
        `Status list ${statusListId} is full: index ${index} is outside its ${capacity} entries`
      );
    }

    await recordOwner(statusListId, index);

    const credentialStatus: CredentialStatus = {
      id: `${statusListId}#${index}`,
      type: 'StatusList2021Entry',
      statusPurpose: purpose,
      statusListIndex: index.toString(),
      statusListCredential: statusListId,
    };

    return credentialStatus;
  }

  /**
   * The owner `allocateStatusEntry` recorded for `credentialStatus`, by its list's id exactly as
   * written, or `undefined` when it recorded none.
   */
  getStatusEntryOwner(credentialStatus: CredentialStatus): Promise<StatusEntryOwner | undefined> {
    return readEntryOwner(this.storage, credentialStatus);
  }

  /**
   * Retire `credentialStatus`, keeping its owner, so a delegation graph built with this manager as
   * `statusEntryOwners` registers no delegation with it again. The graph calls this when it removes
   * the delegation the entry was allocated to.
   */
  retireStatusEntry(credentialStatus: CredentialStatus): Promise<void> {
    return retireEntryOwner(this.storage, credentialStatus);
  }

  /**
   * Set the bit of `credentialStatus` when `revoked` is true, or clear it, then
   * sign the list again and store it. An entry whose `statusListCredential` is
   * not the id the stored list was created with, which a storage provider that
   * reads two spellings of a URL as one list would hand back, throws a
   * `RefusalError` of code `delegation_malformed`, and changes nothing.
   *
   * @throws {StatusListWriteConflictError} when a conditional store refused
   *   every write of the list, because another writer stored it first each
   *   time; nothing was stored, so make the change again.
   */
  async updateStatus(credentialStatus: CredentialStatus, revoked: boolean): Promise<void> {
    assertOneBitEntry(credentialStatus);
    const { statusListCredential } = credentialStatus;
    await this.updateLocks.run(statusListCredential, () =>
      commitStatusListChange(
        this.storage,
        statusListCredential,
        (statusList) => this.withStatusBit(statusList, credentialStatus, revoked),
        this.retry
      )
    );
  }

  /**
   * `statusList` with the bit of `credentialStatus` set to `revoked`, signed
   * again. Applied to each list the store holds until one is written, so only
   * this change is added to whatever other writers stored.
   */
  private async withStatusBit(
    statusList: StatusList2021Credential | null,
    credentialStatus: CredentialStatus,
    revoked: boolean
  ): Promise<StatusListChange<void>> {
    const { statusListCredential, statusListIndex } = credentialStatus;

    if (!statusList) {
      throw new Error(`Status list not found: ${statusListCredential}`);
    }
    if (statusList.id !== statusListCredential) {
      throw new RefusalError(
        'delegation_malformed',
        `Status list ${describeValue(statusListCredential)} reads as the list ${describeValue(statusList.id)}, so no ` +
          'entry of it is set or cleared: an entry names its list by the id the list was created with'
      );
    }

    const manager = await BitstringManager.decode(
      statusList.credentialSubject.encodedList,
      this.compressor,
      this.decompressor
    );

    // The parse checkStatus uses, which reads "5abc" as no index rather than as 5, so it never flips
    // another credential's bit. It also takes a non-negative safe integer: the entry is this
    // manager's own record, which a storage layer may hand back with the index as a number, and
    // refusing it would leave a revoked credential's bit clear.
    const index = parseStatusListIndex(statusListIndex, { acceptNumber: true });
    manager.setBit(index, revoked);

    const encodedList = await manager.encode();

    const updatedCredential: StatusList2021Credential = {
      ...statusList,
      credentialSubject: {
        ...statusList.credentialSubject,
        encodedList,
      },
    };

    return { write: await this.signed(updatedCredential), result: undefined };
  }

  /** `credential` with a new proof by this manager's identity over all of it but its old proof. */
  private async signed(credential: StatusList2021Credential): Promise<StatusList2021Credential> {
    const unsignedCredential = { ...credential };
    delete (unsignedCredential as Record<string, unknown>)['proof'];

    const canonicalVC = canonicalizeJSON(unsignedCredential);
    const proof = await this.signingFunction(
      canonicalVC,
      this.identity.getDid(),
      this.identity.getKeyId()
    );

    return { ...credential, proof };
  }

  async checkStatus(credentialStatus: CredentialStatus): Promise<boolean> {
    assertOneBitEntry(credentialStatus);
    const { statusListCredential, statusListIndex } = credentialStatus;

    const statusList = await this.storage.getStatusList(statusListCredential);
    if (!statusList) {
      throw new RefusalError(
        'status_unavailable',
        `Status list not found: ${statusListCredential} — cannot determine revocation status`
      );
    }

    // Fail-CLOSED on statusPurpose parity via the shared acceptance rule: the resolved list MUST be
    // the SAME KIND the credential points at, else its clear bit would report "not revoked" from the
    // wrong list, a fail-OPEN revocation bypass. The list is this manager's own, read from its
    // storage with no proof checked, so only the purpose part of the rule applies.
    const purpose = acceptStatusPurpose(statusList, credentialStatus.statusPurpose);
    if (!purpose.valid) {
      throw new RefusalError('status_signer_untrusted', purpose.reason);
    }
    // A list outside the validity window it states says nothing of now, whatever its bits say. The
    // lists this manager writes state no end.
    assertStatusListValidity(statusList, Date.now(), this.skewMs);

    const manager = await BitstringManager.decode(
      statusList.credentialSubject.encodedList,
      this.compressor,
      this.decompressor
    );

    // Strict canonical-decimal parse, fail-closed (shared primitive — a lenient parse would read a
    // DIFFERENT, often clear, bit than the credential names: a revocation bypass).
    const index = parseStatusListIndex(statusListIndex);
    return manager.getBit(index);
  }

  async getRevokedIndices(statusListId: string): Promise<number[]> {
    const statusList = await this.storage.getStatusList(statusListId);
    if (!statusList) {
      return [];
    }

    const manager = await BitstringManager.decode(
      statusList.credentialSubject.encodedList,
      this.compressor,
      this.decompressor
    );

    return manager.getSetBits();
  }

  /**
   * Create the status list on first use and return its capacity in entries.
   * Runs inside the list's lock and re-reads the list there, and over a
   * conditional store creates it only where none is stored: a creation that
   * raced past another, this manager's or another manager's, must not replace
   * a list that has since recorded a revocation with a fresh, empty one. Over
   * any other store that holds for this manager's own creations only.
   */
  private ensureStatusListExists(
    statusListId: string,
    purpose: 'revocation' | 'suspension'
  ): Promise<number> {
    return this.updateLocks.run(statusListId, () =>
      commitStatusListChange(
        this.storage,
        statusListId,
        (existing) => this.createdIfMissing(existing, statusListId, purpose),
        this.retry
      )
    );
  }

  /** No write and the capacity of `existing` when there is one, else a fresh signed list and its capacity. */
  private async createdIfMissing(
    existing: StatusList2021Credential | null,
    statusListId: string,
    purpose: 'revocation' | 'suspension'
  ): Promise<StatusListChange<number>> {
    if (existing) {
      const decoded = await BitstringManager.decode(
        existing.credentialSubject.encodedList,
        this.compressor,
        this.decompressor
      );
      return { result: decoded.getSize() };
    }

    const manager = new BitstringManager(
      this.defaultListSize,
      this.compressor,
      this.decompressor
    );
    const encodedList = await manager.encode();

    const unsignedCredential = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://w3id.org/vc/status-list/2021/v1',
      ] as [string, string],
      id: statusListId,
      type: ['VerifiableCredential', 'StatusList2021Credential'] as [string, string],
      issuer: this.identity.getDid(),
      issuanceDate: new Date().toISOString(),
      credentialSubject: {
        id: `${statusListId}#list`,
        type: 'StatusList2021' as const,
        statusPurpose: purpose,
        encodedList,
      },
    };

    return {
      write: await this.signed(unsignedCredential),
      // Capacity as a reader decodes it: whole bytes of the encoded bitstring.
      result: manager.getRawBits().length * 8,
    };
  }

  getStatusListBaseUrl(): string {
    return this.statusListBaseUrl;
  }

  getDefaultListSize(): number {
    return this.defaultListSize;
  }
}

/**
 * Throw unless `credentialStatus` is one bit wide, as the shared rule decides it
 * ({@link acceptEntrySize}). The manager reads and writes the bit at an entry's index, and an entry
 * of another `statusSize` keeps its status in other bits, so the bit at its index is another
 * entry's. It throws before any list is read from storage.
 */
function assertOneBitEntry(credentialStatus: CredentialStatus): void {
  const size = acceptEntrySize(credentialStatus.statusSize);
  if (!size.valid) {
    throw new RefusalError('delegation_malformed', size.reason);
  }
}

/**
 * Build a {@link StatusList2021Manager}. `compressor` and `decompressor`
 * default to `statusListGzipCodec`; when supplied they MUST GZIP and
 * inflate GZIP, as the manager's constructor documents. More than one manager
 * may write to `storage` only when it implements
 * `ConditionalStatusListStorageProvider`; over any other store, write
 * through one manager only, and its first write warns once per process.
 */
export function createStatusListManager(
  storage: StatusListStorageProvider,
  identity: StatusListIdentityProvider,
  signingFunction: VCSigningFunction,
  compressor?: CompressionFunction,
  decompressor?: DecompressionFunction,
  options?: StatusList2021ManagerOptions
): StatusList2021Manager {
  return new StatusList2021Manager(
    storage,
    identity,
    signingFunction,
    compressor,
    decompressor,
    options
  );
}
