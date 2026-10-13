import { afterEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { CommerceJournal } from '../src/commerce/journal.js';

const directories: string[] = [];
const children: ChildProcessWithoutNullStreams[] = [];
const exampleDirectory = fileURLToPath(new URL('..', import.meta.url));
const journalModule = new URL('../src/commerce/journal.ts', import.meta.url).href;
const fixture = () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'commerce-journal-'));
  directories.push(directory);
  return path.join(directory, 'transactions.json');
};
afterEach(async () => {
  await Promise.all(children.splice(0).map(child => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    return new Promise<void>(resolve => {
      child.once('close', () => resolve());
      child.kill('SIGKILL');
    });
  }));
  directories.splice(0).forEach(directory => fs.rmSync(directory, { recursive: true, force: true }));
});

function worker(file: string, source: string) {
  const child = spawn(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', `
    import fs from 'node:fs';
    import { CommerceJournal } from ${JSON.stringify(journalModule)};
    const file = ${JSON.stringify(file)};
    const journal = new CommerceJournal(file);
    const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
    ${source}
  `], { cwd: exampleDirectory, stdio: ['pipe', 'pipe', 'pipe'] });
  children.push(child);
  let output = '', error = '';
  child.stdout.on('data', data => { output += String(data); });
  child.stderr.on('data', data => { error += String(data); });
  const done = new Promise<{ code: number | null; signal: NodeJS.Signals | null; error: string }>((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => resolve({ code, signal, error }));
  });
  return {
    child, done,
    async waitFor(marker: string) {
      await expect.poll(() => output.includes(marker), { timeout: 8_000, interval: 20 }).toBe(true);
    },
  };
}

describe('durable payment transaction journal', () => {
  it('serializes competing instances so a lost response cannot run the same effect twice', async () => {
    const file = fixture();
    const one = new CommerceJournal(file), two = new CommerceJournal(file);
    let effects = 0;
    const perform = (journal: CommerceJournal) => journal.exclusive(async () => {
      const state = journal.read();
      if (state.records['checkout']) return state.records['checkout'];
      effects++;
      await new Promise(resolve => setTimeout(resolve, 10));
      state.records['checkout'] = { state: 'settled', orderId: 'order-1' };
      journal.write(state);
      return state.records['checkout'];
    });
    const results = await Promise.all([perform(one), perform(two)]);
    expect(effects).toBe(1);
    expect(results[0]).toEqual(results[1]);
    expect(new CommerceJournal(file).read().records['checkout']).toEqual(results[0]);
  });

  it('holds the shared-volume lock across the entire effect and persistence in two real processes', async () => {
    const file = fixture();
    const source = `
      process.stdout.write('READY\\n');
      await new Promise(resolve => process.stdin.once('data', resolve));
      await journal.exclusive(async () => {
        const state = journal.read();
        if (state.records.checkout) return;
        // Both workers would read the empty state before either persists without a process-shared lock.
        await delay(400);
        fs.appendFileSync(file + '.effects', 'payment-submitted\\n');
        state.records.checkout = { state: 'settled', orderId: 'order-1' };
        journal.write(state);
      });
      process.stdin.destroy();
    `;
    const one = worker(file, source), two = worker(file, source);
    await Promise.all([one.waitFor('READY'), two.waitFor('READY')]);
    one.child.stdin.write('GO');
    two.child.stdin.write('GO');
    expect(await Promise.all([one.done, two.done])).toEqual([
      { code: 0, signal: null, error: '' }, { code: 0, signal: null, error: '' },
    ]);
    expect(fs.readFileSync(`${file}.effects`, 'utf8')).toBe('payment-submitted\n');
    expect(new CommerceJournal(file).read().records['checkout']).toEqual({ state: 'settled', orderId: 'order-1' });
    expect(fs.existsSync(`${file}.lock`)).toBe(false);
  }, 12_000);

  it('creates the first journal in a new directory without requiring an existing realpath', async () => {
    const file = path.join(path.dirname(fixture()), 'first-run', 'transactions.json');
    const journal = new CommerceJournal(file);
    await journal.exclusive(() => journal.write(journal.read()));
    expect(fs.existsSync(file)).toBe(true);
    expect(fs.existsSync(`${file}.lock`)).toBe(false);
  });

  it('heartbeats a live transaction and terminates a worker whose lock is compromised before an effect', async () => {
    const file = fixture();
    const running = worker(file, `
      await journal.exclusive(async () => {
        process.stdout.write('LOCKED\\n');
        await delay(10_000);
        fs.appendFileSync(file + '.effects', 'must-not-run\\n');
      });
    `);
    await running.waitFor('LOCKED');
    const initialMtime = fs.statSync(`${file}.lock`).mtimeMs;
    await expect.poll(() => fs.statSync(`${file}.lock`).mtimeMs, { timeout: 5_000, interval: 50 }).toBeGreaterThan(initialMtime);
    fs.rmdirSync(`${file}.lock`);
    const result = await running.done;
    expect(result.code).not.toBe(0);
    expect(result.error).toContain('COMMERCE_LOCK_COMPROMISED');
    expect(fs.existsSync(`${file}.effects`)).toBe(false);
  }, 12_000);

  it('recovers a stale lock after a process crash without forgetting the unresolved settlement', async () => {
    const file = fixture();
    const running = worker(file, `
      await journal.exclusive(async () => {
        const state = journal.read();
        state.records.checkout = { state: 'settling', paymentIdentity: 'nonce-1' };
        state.payments['nonce-1'] = 'checkout';
        journal.write(state);
        process.stdout.write('PERSISTED\\n');
        await delay(60_000);
      });
    `);
    await running.waitFor('PERSISTED');
    running.child.kill('SIGKILL');
    expect((await running.done).signal).toBe('SIGKILL');
    expect(fs.existsSync(`${file}.lock`)).toBe(true);
    // Model elapsed downtime without sleeping through the fixed 15-second stale lease.
    const stale = new Date(Date.now() - 30_000);
    fs.utimesSync(`${file}.lock`, stale, stale);
    const recovered = new CommerceJournal(file);
    await recovered.exclusive(() => {
      const state = recovered.read();
      expect(state.records['checkout']).toEqual({ state: 'settling', paymentIdentity: 'nonce-1' });
      expect(state.payments['nonce-1']).toBe('checkout');
    });
    expect(fs.existsSync(`${file}.lock`)).toBe(false);
  }, 12_000);

  it('retains a settlement intent across restart before any external effect can occur', async () => {
    const file = fixture();
    const journal = new CommerceJournal(file);
    await journal.exclusive(() => {
      const state = journal.read();
      state.records['checkout'] = { state: 'settling', paymentIdentity: 'nonce-1' };
      state.payments['nonce-1'] = 'checkout';
      journal.write(state);
    });
    const restarted = new CommerceJournal(file).read();
    expect(restarted.records['checkout']).toMatchObject({ state: 'settling' });
    expect(restarted.payments['nonce-1']).toBe('checkout');
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);
  });

  it('fails closed on corrupted or unsupported journal data rather than forgetting settled orders', () => {
    const file = fixture();
    for (const content of ['{', '{}', '{"version":2,"records":{},"requests":{},"payments":{}}']) {
      fs.writeFileSync(file, content);
      expect(() => new CommerceJournal(file).read()).toThrow(/COMMERCE_STORAGE_INVALID/);
    }
  });

  it('does not poison the writer queue when a request fails', async () => {
    const journal = new CommerceJournal(fixture());
    await expect(journal.exclusive(() => { throw new Error('refused'); })).rejects.toThrow('refused');
    expect(await journal.exclusive(() => 7)).toBe(7);
  });
});
