/**
 * FileGrantStore — a durable {@link GrantStore} backed by a single JSON file.
 *
 * The simplest swappable process-external backing (no Redis dependency in CI):
 * every operation reads the JSON file fresh and writes it back, so two server
 * instances — or the same instance after a restart — see each other's grants.
 * This is what makes the no-paste retry work across instances: the grant is in a
 * store both instances read, not in a per-process Map.
 *
 * The confused-deputy guard is preserved exactly as in MemoryGrantStore:
 * `getBySession` only returns grants bound to the asked session, and a grant
 * bound to one session is never returned to another.
 *
 * Production would swap this for Redis / a Durable Object / Postgres behind the
 * same `GrantStore` interface — the server code does not change.
 */

import fs from 'node:fs';
import path from 'node:path';
import { GrantStore, type Grant } from '@kya-os/mcp';

export class FileGrantStore extends GrantStore {
  constructor(
    private readonly filePath: string,
    private readonly now: () => number = () => Date.now(),
  ) {
    super();
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  }

  private read(): Grant[] {
    try {
      if (!fs.existsSync(this.filePath)) return [];
      return JSON.parse(fs.readFileSync(this.filePath, 'utf-8')) as Grant[];
    } catch {
      return [];
    }
  }

  private write(grants: Grant[]): void {
    fs.writeFileSync(this.filePath, JSON.stringify(grants, null, 2) + '\n');
  }

  private active(grants: Grant[]): Grant[] {
    const now = this.now();
    return grants.filter(
      (g) => g.status !== 'revoked' && (g.expiresAt === undefined || g.expiresAt > now),
    );
  }

  private covers(grant: Grant, required?: string[]): boolean {
    if (!required || required.length === 0) return true;
    return required.every((s) => grant.scopes.includes(s));
  }

  async bind(grant: Grant): Promise<void> {
    const grants = this.read().filter((g) => g.id !== grant.id);
    grants.push({ ...grant });
    this.write(grants);
  }

  async getByAgent(agentDid: string, requiredScopes?: string[]): Promise<Grant[]> {
    return this.active(this.read()).filter(
      (g) => g.agentDid === agentDid && this.covers(g, requiredScopes),
    );
  }

  async getBySession(sessionId: string, requiredScopes?: string[]): Promise<Grant[]> {
    return this.active(this.read()).filter(
      (g) => g.sessionId === sessionId && this.covers(g, requiredScopes),
    );
  }

  async getById(id: string): Promise<Grant | undefined> {
    return this.read().find((g) => g.id === id);
  }

  async revoke(id: string, reason?: string): Promise<void> {
    const grants = this.read();
    const grant = grants.find((g) => g.id === id);
    if (!grant) return;
    grant.status = 'revoked';
    if (reason !== undefined) grant.revocationReason = reason;
    this.write(grants);
  }

  async cleanup(): Promise<void> {
    const now = this.now();
    this.write(this.read().filter((g) => g.expiresAt === undefined || g.expiresAt > now));
  }
}
