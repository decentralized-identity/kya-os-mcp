import { AsyncLocalStorage } from 'node:async_hooks';

type Mode = 'operation' | 'exclusive';
interface Lease {
  mode: Mode;
  active: boolean;
  references: number;
  release(): void;
}

/** Concurrent merchant work shares a run; reset waits for it to finish, then
 * excludes later work until the new run is ready. Nested work retains its
 * original lease, including when an exclusive reset is already waiting.
 *
 * This is a process-local boundary. Acquire the agent wallet queue before
 * exclusive access, and never hold a lease while waiting for that queue or
 * calling the gateway through HTTP: async context does not cross HTTP hops.
 */
export class RunBoundary {
  private readonly context = new AsyncLocalStorage<Lease>();
  private readonly waiters: Array<{ mode: Mode; resolve(lease: Lease): void }> = [];
  private operations = 0;
  private exclusiveActive = false;

  async operation<T>(work: () => T | Promise<T>): Promise<T> {
    const current = this.context.getStore();
    return this.invoke(current?.active ? current : await this.acquire('operation'), work);
  }

  async exclusive<T>(work: () => T | Promise<T>): Promise<T> {
    const current = this.context.getStore();
    if (current?.active && current.mode === 'operation') {
      throw new Error('RUN_BOUNDARY_UPGRADE_FORBIDDEN: acquire exclusive access outside an active operation');
    }
    return this.invoke(current?.active ? current : await this.acquire('exclusive'), work);
  }

  private invoke<T>(lease: Lease, work: () => T | Promise<T>): Promise<T> {
    lease.references += 1;
    return this.context.run(lease, async () => {
      try { return await work(); }
      finally {
        lease.references -= 1;
        if (lease.references === 0) {
          lease.active = false;
          lease.release();
        }
      }
    });
  }

  private acquire(mode: Mode): Promise<Lease> {
    return new Promise(resolve => {
      this.waiters.push({ mode, resolve });
      this.drain();
    });
  }

  private drain(): void {
    if (this.exclusiveActive) return;
    while (this.waiters.length) {
      const next = this.waiters[0]!;
      if (next.mode === 'exclusive' && this.operations !== 0) return;
      this.waiters.shift();
      if (next.mode === 'exclusive') this.exclusiveActive = true;
      else this.operations += 1;
      next.resolve({
        mode: next.mode,
        active: true,
        references: 0,
        release: () => {
          if (next.mode === 'exclusive') this.exclusiveActive = false;
          else this.operations -= 1;
          this.drain();
        },
      });
      // A queued writer prevents new readers from overtaking it.
      if (this.exclusiveActive) return;
    }
  }
}
