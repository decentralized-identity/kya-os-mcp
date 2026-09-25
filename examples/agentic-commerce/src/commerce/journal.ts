import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { lock } from 'proper-lockfile';

export interface CommerceState {
  version: 1;
  records: Record<string, Record<string, unknown>>;
  requests: Record<string, { digest: string; result: unknown; at: number }>;
  payments: Record<string, string>;
}
const writers = new Map<string, Promise<unknown>>();
const isObject = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);

/** All adapter instances share a writer queue and all processes sharing this
 * volume use the same atomic-directory lock, including throughout settlement.
 * A killed worker's lease becomes stale after 15 seconds; recovery preserves its
 * fsynced settlement intent, which remains unresolved and is never auto-retried.
 * Keep the lease policy identical across deployments sharing a volume. */
export class CommerceJournal {
  readonly file: string;
  constructor(file: string) { this.file = path.resolve(file); }

  read(): CommerceState {
    if (!fs.existsSync(this.file)) return { version: 1, records: {}, requests: {}, payments: {} };
    try {
      const value: unknown = JSON.parse(fs.readFileSync(this.file, 'utf8'));
      if (!isObject(value) || value['version'] !== 1 || !isObject(value['records']) || !isObject(value['requests']) || !isObject(value['payments'])) throw new Error('invalid schema');
      return value as unknown as CommerceState;
    } catch { throw new Error('COMMERCE_STORAGE_INVALID: refusing to forget previous payment attempts'); }
  }

  write(state: CommerceState): void {
    fs.mkdirSync(path.dirname(this.file), { recursive: true, mode: 0o700 });
    const temporary = `${this.file}.${randomUUID()}.tmp`;
    let descriptor: number | undefined;
    try {
      descriptor = fs.openSync(temporary, 'wx', 0o600);
      fs.writeFileSync(descriptor, JSON.stringify(state));
      fs.fsyncSync(descriptor);
      fs.closeSync(descriptor);
      descriptor = undefined;
      fs.renameSync(temporary, this.file);
      // Windows does not support directory fsync; file data is still flushed.
      if (process.platform !== 'win32') {
        const directory = fs.openSync(path.dirname(this.file), 'r');
        try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
      }
    } finally {
      if (descriptor !== undefined) fs.closeSync(descriptor);
      fs.rmSync(temporary, { force: true });
    }
  }

  async exclusive<T>(operation: () => T | Promise<T>): Promise<T> {
    const result = (writers.get(this.file) ?? Promise.resolve()).then(async () => {
      fs.mkdirSync(path.dirname(this.file), { recursive: true, mode: 0o700 });
      let release: () => Promise<void>;
      try {
        release = await lock(this.file, {
          realpath: false,
          stale: 15_000,
          update: 2_000,
          retries: { retries: 80, factor: 1, minTimeout: 250, maxTimeout: 250, maxRetryTime: 20_000 },
          // Continuing an in-flight payment after losing mutual exclusion is
          // unsafe. This deliberately throws outside the request's promise and
          // terminates the worker, preserving any durable unresolved intent.
          onCompromised(error) {
            throw new Error('COMMERCE_LOCK_COMPROMISED: worker cannot safely continue payment processing', { cause: error });
          },
        });
      } catch (error) {
        throw new Error('COMMERCE_STORAGE_BUSY: could not acquire the transaction lock; no payment submitted', { cause: error });
      }
      try { return await operation(); }
      finally { await release(); }
    });
    const tail = result.catch(() => {});
    writers.set(this.file, tail);
    try { return await result; }
    finally { if (writers.get(this.file) === tail) writers.delete(this.file); }
  }
}
