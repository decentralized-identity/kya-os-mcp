/**
 * FilePendingFlowStore — a durable {@link PendingFlowStore} backed by a JSON
 * file, the OAuth/OIDC counterpart to {@link FileGrantStore}.
 *
 * It persists the PKCE `codeVerifier` (keyed by the resume token) to the same
 * kind of process-external backing, so an authorization callback that lands on a
 * DIFFERENT instance — or after a restart — can still complete the token
 * exchange. Holding that state in a per-process Map is exactly what breaks the
 * OAuth half of consent persistence.
 *
 * `get` is non-consuming; `delete` consumes after a successful exchange. A
 * production Redis/Durable-Object backing should make delete-after-exchange
 * atomic (GETDEL / CAS) to close the one-time-use replay window.
 */

import fs from 'node:fs';
import path from 'node:path';
import { PendingFlowStore, type PendingFlow } from '@kya-os/mcp';

interface Entry {
  flow: PendingFlow;
  expiresAt: number;
}

export class FilePendingFlowStore extends PendingFlowStore {
  constructor(
    private readonly filePath: string,
    private readonly now: () => number = () => Date.now(),
  ) {
    super();
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  }

  private read(): Record<string, Entry> {
    try {
      if (!fs.existsSync(this.filePath)) return {};
      return JSON.parse(fs.readFileSync(this.filePath, 'utf-8')) as Record<string, Entry>;
    } catch {
      return {};
    }
  }

  private write(data: Record<string, Entry>): void {
    fs.writeFileSync(this.filePath, JSON.stringify(data, null, 2) + '\n');
  }

  async put(token: string, flow: PendingFlow, ttlMs: number): Promise<void> {
    const data = this.read();
    data[token] = { flow, expiresAt: this.now() + ttlMs };
    this.write(data);
  }

  async get(token: string): Promise<PendingFlow | undefined> {
    const data = this.read();
    const entry = data[token];
    if (!entry) return undefined;
    if (entry.expiresAt <= this.now()) {
      delete data[token];
      this.write(data);
      return undefined;
    }
    return entry.flow;
  }

  async consume(token: string): Promise<PendingFlow | undefined> {
    // Atomic read+remove within a process (fs read/write are synchronous). A
    // production backing should use a real atomic op (Redis GETDEL / CAS) so the
    // one-time-use guard holds across processes too.
    const data = this.read();
    const entry = data[token];
    if (!entry) return undefined;
    delete data[token];
    this.write(data);
    if (entry.expiresAt <= this.now()) return undefined;
    return entry.flow;
  }

  async delete(token: string): Promise<void> {
    const data = this.read();
    if (token in data) {
      delete data[token];
      this.write(data);
    }
  }

  async cleanup(): Promise<void> {
    const data = this.read();
    const now = this.now();
    let changed = false;
    for (const [token, entry] of Object.entries(data)) {
      if (entry.expiresAt <= now) {
        delete data[token];
        changed = true;
      }
    }
    if (changed) this.write(data);
  }
}
