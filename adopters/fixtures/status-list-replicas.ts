/**
 * An adopter runs its issuing service as two replicas, each with its own `StatusList2021Manager`,
 * over one status-list store of its own: a table whose rows carry a version, as a database row
 * does, read and written after a moment's latency. Both replicas revoke credentials on one list at
 * the same moment, so each reads the list before the other has written it. The table implements
 * the optional conditional write, `ConditionalStatusListStorageProvider`, with the row version as
 * the etag, so a write over a row that has since changed is refused and the replica makes its
 * change again over the row now stored. A verifier that reads the published list finds every
 * revocation either replica reported, on a list the issuer signed, and the library warns about
 * nothing. A replica whose every write is refused throws `StatusListWriteConflictError` and
 * stores nothing.
 *
 * The control builds the same replicas over the same table without the conditional write: one
 * revocation is lost, which shows the replicas really did read before each other wrote, and the
 * library says so once.
 */
import assert from 'node:assert/strict';
import { setTimeout as sleep } from 'node:timers/promises';
import {
  StatusList2021Manager,
  StatusListWriteConflictError,
  base64urlDecodeToBytes,
  canonicalizeJSON,
  statusListGzipCodec,
  type ConditionalStatusListStorageProvider,
  type CredentialStatus,
  type StatusList2021Credential,
  type StatusListStorageProvider,
  type StoredStatusList,
} from '@kya-os/mcp';
import { createRevocationChecker } from '@kya-os/mcp/card';
import { runCases } from './shared/cases.js';
import { signingFunctionOf } from './shared/credentials.js';
import { crypto, didKeyParty } from './shared/keys.js';

const BASE_URL = 'https://status.issuer.example';
const issuer = await didKeyParty();

/** The adopter's status-list table: one row per list, the list as JSON and a version every write of the row raises. */
class StatusListTable implements ConditionalStatusListStorageProvider {
  readonly #rows = new Map<string, { json: string; version: number }>();
  readonly #nextIndex = new Map<string, number>();
  /** While on, another writer updates the row just before each conditional write. */
  busy = false;

  async getStatusList(statusListId: string): Promise<StatusList2021Credential | null> {
    return (await this.getStatusListWithEtag(statusListId))?.credential ?? null;
  }

  async getStatusListWithEtag(statusListId: string): Promise<StoredStatusList | null> {
    await sleep(1);
    const row = this.#rows.get(statusListId);
    if (row === undefined) return null;
    return { credential: JSON.parse(row.json) as StatusList2021Credential, etag: String(row.version) };
  }

  async setStatusList(statusListId: string, credential: StatusList2021Credential): Promise<void> {
    await sleep(1);
    this.#write(statusListId, credential);
  }

  /** `UPDATE ... SET json = ?, version = version + 1 WHERE id = ? AND version = ?`, or an `INSERT` that fails on a row already there. */
  async setStatusListIfMatch(
    statusListId: string,
    credential: StatusList2021Credential,
    etag: string | null,
  ): Promise<boolean> {
    await sleep(1);
    const row = this.#rows.get(statusListId);
    if (this.busy && row !== undefined) row.version++;
    if ((row === undefined ? null : String(row.version)) !== etag) return false;
    this.#write(statusListId, credential);
    return true;
  }

  async allocateIndex(statusListId: string): Promise<number> {
    const index = this.#nextIndex.get(statusListId) ?? 0;
    this.#nextIndex.set(statusListId, index + 1);
    return index;
  }

  /** How many times the row of `statusListId` was written. */
  version(statusListId: string): number {
    return this.#rows.get(statusListId)?.version ?? 0;
  }

  #write(statusListId: string, credential: StatusList2021Credential): void {
    const version = this.version(statusListId) + 1;
    this.#rows.set(statusListId, { json: JSON.stringify(credential), version });
  }
}

/** The same table as a store with only the three methods every store has: no conditional write. */
function withoutConditionalWrite(table: StatusListTable): StatusListStorageProvider {
  return {
    getStatusList: (statusListId) => table.getStatusList(statusListId),
    setStatusList: (statusListId, credential) => table.setStatusList(statusListId, credential),
    allocateIndex: (statusListId) => table.allocateIndex(statusListId),
  };
}

/** One replica of the issuing service: its own manager over `store`, signing as the issuer. */
function replica(store: StatusListStorageProvider): StatusList2021Manager {
  return new StatusList2021Manager(
    store,
    { getDid: () => issuer.did, getKeyId: () => issuer.kid },
    signingFunctionOf(issuer),
    statusListGzipCodec,
    statusListGzipCodec,
    { statusListBaseUrl: BASE_URL },
  );
}

/** Two entries on one revocation list, then each revoked by its own replica at the same moment. */
async function revokeFromTwoReplicas(store: StatusListStorageProvider): Promise<CredentialStatus[]> {
  const [one, two] = [replica(store), replica(store)];
  const entries = [await one.allocateStatusEntry('revocation'), await one.allocateStatusEntry('revocation')];
  await Promise.all([one.updateStatus(entries[0]!, true), two.updateStatus(entries[1]!, true)]);
  return entries;
}

/** Whether a verifier that reads the list `table` publishes finds each of `entries` revoked. */
async function revokedAsPublished(table: StatusListTable, entries: readonly CredentialStatus[]): Promise<boolean[]> {
  const check = createRevocationChecker({
    fetch: async (url) => {
      const list = await table.getStatusList(url);
      return { ok: list !== null, status: list === null ? 404 : 200, json: async () => list };
    },
  });
  return Promise.all(entries.map(async (entry) => (await check(entry)).revoked));
}

/** Whether the list `table` holds under `statusListId` carries the issuer's signature over what it says. */
async function signedByIssuer(table: StatusListTable, statusListId: string): Promise<boolean> {
  const list = await table.getStatusList(statusListId);
  const proofValue = list?.proof?.proofValue;
  if (list === null || typeof proofValue !== 'string') return false;
  const { proof: _proof, ...unsigned } = list;
  const data = new TextEncoder().encode(canonicalizeJSON(unsigned));
  return crypto.verify(data, base64urlDecodeToBytes(proofValue), issuer.publicKey);
}

/** Run `work`, and return what it returned with the console warnings about status-list stores it caused. */
async function watchingWarnings<T>(work: () => Promise<T>): Promise<{ value: T; warnings: string[] }> {
  const warnings: string[] = [];
  const original = console.warn;
  console.warn = (...args: unknown[]) => {
    const text = args.map(String).join(' ');
    if (text.includes('status-list store')) warnings.push(text);
  };
  try {
    return { value: await work(), warnings };
  } finally {
    console.warn = original;
  }
}

await runCases('status-list-replicas', 'two replicas over a store with the conditional write lose no revocation, a write refused every time throws StatusListWriteConflictError, and a store without it warns once', [
  {
    name: 'two replicas over the table with the conditional write keep both revocations, signed, with no warning',
    run: async () => {
      const table = new StatusListTable();
      const { value: entries, warnings } = await watchingWarnings(() => revokeFromTwoReplicas(table));
      assert.deepEqual(await revokedAsPublished(table, entries), [true, true]);
      assert.equal(await signedByIssuer(table, entries[0]!.statusListCredential), true);
      assert.deepEqual(warnings, []);
    },
  },
  {
    name: 'a replica whose every write is refused throws StatusListWriteConflictError and stores nothing',
    run: async () => {
      const table = new StatusListTable();
      const manager = replica(table);
      const entry = await manager.allocateStatusEntry('revocation');
      table.busy = true;
      const error: unknown = await manager.updateStatus(entry, true).catch((thrown: unknown) => thrown);
      table.busy = false;
      assert.ok(error instanceof StatusListWriteConflictError, String(error));
      assert.equal(error.code, 'STATUS_LIST_WRITE_CONFLICT');
      assert.equal(error.statusListId, entry.statusListCredential);
      assert.deepEqual(await revokedAsPublished(table, [entry]), [false]);
      await manager.updateStatus(entry, true);
      assert.deepEqual(await revokedAsPublished(table, [entry]), [true]);
    },
  },
  {
    name: 'control: the same replicas over the same table without the conditional write lose one revocation, and the library warns once',
    run: async () => {
      const table = new StatusListTable();
      const { value: entries, warnings } = await watchingWarnings(() => revokeFromTwoReplicas(withoutConditionalWrite(table)));
      const revoked = await revokedAsPublished(table, entries);
      assert.equal(revoked.filter(Boolean).length, 1, `revoked as published: ${revoked.join(', ')}`);
      assert.equal(table.version(entries[0]!.statusListCredential), 3);
      assert.equal(warnings.length, 1, warnings.join('\n'));
      assert.match(warnings[0] ?? '', /Implement getStatusListWithEtag and setStatusListIfMatch/);
    },
  },
]);
