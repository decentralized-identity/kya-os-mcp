/**
 * The bounded reader against a real HTTP server on 127.0.0.1: a body that stalls after its first
 * bytes, or trickles one byte at a time, is refused at the deadline with the deadline's own reason,
 * never the runtime's `AbortError`. The provider opts out of the private-network rule, which would
 * otherwise refuse 127.0.0.1 before any request.
 */

import { createServer, type Server } from 'node:http';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { RuntimeFetchProvider } from '../../providers/runtime-fetch.js';
import { fetchDidJson } from '../read-did-json.js';
import { fetchStatusListJson } from '../status-list-fetch.js';

let server: Server;
let base: string;
const provider = new RuntimeFetchProvider({ allowPrivateNetworkHosts: true });
const timers = new Set<ReturnType<typeof setInterval>>();

beforeAll(async () => {
  server = createServer((request, response) => {
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.write('{"id":');
    if (request.url === '/trickle') {
      const timer = setInterval(() => response.write(' '), 200);
      timers.add(timer);
      response.on('close', () => { clearInterval(timer); timers.delete(timer); });
    }
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('missing test listener');
  base = `http://127.0.0.1:${address.port}`;
});

afterAll(async () => {
  for (const timer of timers) clearInterval(timer);
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
});

/** How `reading` settles, and after how many milliseconds. */
async function outcome(reading: Promise<unknown>): Promise<{ name: string; message: string; ms: number }> {
  const start = Date.now();
  try {
    await reading;
    return { name: 'resolved', message: '', ms: Date.now() - start };
  } catch (error) {
    const { name, message } = error as Error;
    return { name, message, ms: Date.now() - start };
  }
}

/**
 * The deadline's own reason, which only the 5,000 ms timer gives, and not before it. A loaded
 * machine can only delay the timer, so no upper bound on wall time is asserted; the fake-timer tests
 * pin the deadline to 5,000 ms.
 */
function atTheDeadline(settled: { name: string; message: string; ms: number }, message: string): void {
  expect(settled).toMatchObject({ name: 'Error', message });
  expect(settled.ms).toBeGreaterThanOrEqual(4_900);
}

describe.concurrent('a real server that stops sending', () => {
  it('ends a DID document whose body stalls after its first bytes', async () => {
    atTheDeadline(await outcome(fetchDidJson(provider, `${base}/stall`)), 'DID resolution deadline exceeded');
  }, 15_000);

  it('ends a status list whose body trickles one byte at a time', async () => {
    atTheDeadline(await outcome(fetchStatusListJson(provider, `${base}/trickle`)), 'Status list fetch deadline exceeded');
  }, 15_000);
});
