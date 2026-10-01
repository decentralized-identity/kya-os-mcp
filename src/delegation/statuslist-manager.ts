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
import { assertStatusPurpose } from '../utils/statuslist-purpose.js';

export interface StatusListStorageProvider {
  getStatusList(statusListId: string): Promise<StatusList2021Credential | null>;
  setStatusList(statusListId: string, credential: StatusList2021Credential): Promise<void>;
  allocateIndex(statusListId: string): Promise<number>;
}

/** Optional immutable-history extension used by audit replay/export adapters. */
export interface HistoricalStatusListStorageProvider extends StatusListStorageProvider {
  getStatusListVersion(
    statusListId: string,
    version: number,
  ): Promise<StatusList2021Credential | null>;
  getStatusListVersionCount(statusListId: string): Promise<number>;
}

export interface StatusListIdentityProvider {
  getDid(): string;
  getKeyId(): string;
}

export class StatusList2021Manager {
  private statusListBaseUrl: string;
  private defaultListSize: number;
  /**
   * Per-status-list mutex. Every read-modify-write of a list (status updates
   * and first creation) runs inside it, so no writer can overwrite another's
   * bit with a stale copy.
   */
  private updateLocks = new Map<string, Promise<void>>();

  constructor(
    private storage: StatusListStorageProvider,
    private identity: StatusListIdentityProvider,
    private signingFunction: VCSigningFunction,
    private compressor: CompressionFunction,
    private decompressor: DecompressionFunction,
    options?: {
      statusListBaseUrl?: string;
      defaultListSize?: number;
    }
  ) {
    this.statusListBaseUrl = options?.statusListBaseUrl || 'https://status.example.com';
    this.defaultListSize = options?.defaultListSize || 131072;
  }

  async allocateStatusEntry(purpose: 'revocation' | 'suspension'): Promise<CredentialStatus> {
    const statusListId = `${this.statusListBaseUrl}/${purpose}/v1`;

    const index = await this.storage.allocateIndex(statusListId);

    const capacity = await this.ensureStatusListExists(statusListId, purpose);
    // An index past the end of the list can never be read or set, so refuse
    // it (SPEC.md §6.7) rather than mint a credential that cannot be revoked.
    if (index >= capacity) {
      throw new Error(
        `Status list ${statusListId} is full: index ${index} is outside its ${capacity} entries`
      );
    }

    const credentialStatus: CredentialStatus = {
      id: `${statusListId}#${index}`,
      type: 'StatusList2021Entry',
      statusPurpose: purpose,
      statusListIndex: index.toString(),
      statusListCredential: statusListId,
    };

    return credentialStatus;
  }

  async updateStatus(credentialStatus: CredentialStatus, revoked: boolean): Promise<void> {
    await this.withListLock(credentialStatus.statusListCredential, () =>
      this.doUpdateStatus(credentialStatus, revoked)
    );
  }

  /**
   * Run `task` once every earlier task on the same status list has settled,
   * serializing read-modify-write per list. The task's own error reaches the
   * caller; the chain stores a non-rejecting copy so later tasks still run.
   */
  private withListLock<T>(statusListId: string, task: () => Promise<T>): Promise<T> {
    const previous = this.updateLocks.get(statusListId) ?? Promise.resolve();
    const operation = previous.then(task);
    this.updateLocks.set(
      statusListId,
      operation.then(
        () => undefined,
        () => undefined
      )
    );
    return operation;
  }

  private async doUpdateStatus(credentialStatus: CredentialStatus, revoked: boolean): Promise<void> {
    const { statusListCredential, statusListIndex } = credentialStatus;

    const statusList = await this.storage.getStatusList(statusListCredential);
    if (!statusList) {
      throw new Error(`Status list not found: ${statusListCredential}`);
    }

    const manager = await BitstringManager.decode(
      statusList.credentialSubject.encodedList,
      this.compressor,
      this.decompressor
    );

    // Same strict parse as checkStatus: a lenient one reads "5abc" as 5 and
    // would flip another credential's bit.
    const index = parseStatusListIndex(statusListIndex);
    manager.setBit(index, revoked);

    const encodedList = await manager.encode();

    const updatedCredential: StatusList2021Credential = {
      ...statusList,
      credentialSubject: {
        ...statusList.credentialSubject,
        encodedList,
      },
    };

    const unsignedCredential = { ...updatedCredential };
    delete (unsignedCredential as Record<string, unknown>)['proof'];

    const canonicalVC = canonicalizeJSON(unsignedCredential);
    const proof = await this.signingFunction(
      canonicalVC,
      this.identity.getDid(),
      this.identity.getKeyId()
    );

    const signedCredential: StatusList2021Credential = {
      ...updatedCredential,
      proof,
    };

    await this.storage.setStatusList(statusListCredential, signedCredential);
  }

  async checkStatus(credentialStatus: CredentialStatus): Promise<boolean> {
    const { statusListCredential, statusListIndex } = credentialStatus;

    const statusList = await this.storage.getStatusList(statusListCredential);
    if (!statusList) {
      throw new Error(
        `Status list not found: ${statusListCredential} — cannot determine revocation status`
      );
    }

    // Fail-CLOSED on statusPurpose parity via the shared validator: the resolved list MUST be the
    // SAME KIND the credential points at, else its clear bit would report "not revoked" from the
    // wrong list — a fail-OPEN revocation bypass.
    assertStatusPurpose(statusList.credentialSubject.statusPurpose, credentialStatus.statusPurpose);

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
   * Runs inside the list's lock and re-reads the list there: a creation that
   * raced past another must not replace a list that has since recorded a
   * revocation with a fresh, empty one.
   */
  private ensureStatusListExists(
    statusListId: string,
    purpose: 'revocation' | 'suspension'
  ): Promise<number> {
    return this.withListLock(statusListId, () =>
      this.createStatusListIfMissing(statusListId, purpose)
    );
  }

  private async createStatusListIfMissing(
    statusListId: string,
    purpose: 'revocation' | 'suspension'
  ): Promise<number> {
    const existing = await this.storage.getStatusList(statusListId);
    if (existing) {
      const decoded = await BitstringManager.decode(
        existing.credentialSubject.encodedList,
        this.compressor,
        this.decompressor
      );
      return decoded.getSize();
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

    const canonicalVC = canonicalizeJSON(unsignedCredential);
    const proof = await this.signingFunction(
      canonicalVC,
      this.identity.getDid(),
      this.identity.getKeyId()
    );

    const signedCredential: StatusList2021Credential = {
      ...unsignedCredential,
      proof,
    };

    await this.storage.setStatusList(statusListId, signedCredential);
    // Capacity as a reader decodes it: whole bytes of the encoded bitstring.
    return manager.getRawBits().length * 8;
  }

  getStatusListBaseUrl(): string {
    return this.statusListBaseUrl;
  }

  getDefaultListSize(): number {
    return this.defaultListSize;
  }
}

export function createStatusListManager(
  storage: StatusListStorageProvider,
  identity: StatusListIdentityProvider,
  signingFunction: VCSigningFunction,
  compressor: CompressionFunction,
  decompressor: DecompressionFunction,
  options?: {
    statusListBaseUrl?: string;
    defaultListSize?: number;
  }
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
