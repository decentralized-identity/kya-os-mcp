/**
 * Node's own `EnvHttpProxyAgent`, which Node installs as the global dispatcher under
 * `NODE_USE_ENV_PROXY=1`, asked in a child process. A server and a proxy listen on loopback and
 * count every connection made to them. The provider reads a host the agent sends through the proxy
 * through `fetch`, and pins a host `NO_PROXY` names. Composed with an interceptor that dispatches
 * later, as undici's `interceptors.dns()` does once it has resolved the host, the agent is one the
 * provider cannot read: it pins both, and connects to neither the host nor the proxy to decide. Nor
 * does it where a library patched the agent's class to dispatch later, as instrumentation may.
 * Node 20 installs no dispatcher of its own until the first fetch, so there each case is skipped.
 */

import { spawn } from 'node:child_process';
import net from 'node:net';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

const PROXIED = 'https://lists.proxied.example/list';

/** How the child changes the agent Node installed before the provider is asked. */
type Change = 'none' | 'composed' | 'patched';

/** What the child installs, whether the provider pins each URL there, after waiting out anything put off. */
const CHILD = (index: string, notProxied: string, change: Change) => `
const { RuntimeFetchProvider } = await import(${JSON.stringify(index)});
const key = Symbol.for('undici.globalDispatcher.1');
const dispatcher = globalThis[key]?.constructor?.name;
const later = (dispatch) => function (options, handler) {
  setTimeout(() => dispatch.call(this, options, handler), 0);
  return true;
};
if (dispatcher === 'EnvHttpProxyAgent' && ${JSON.stringify(change)} === 'composed') {
  globalThis[key] = globalThis[key].compose(later);
}
if (dispatcher === 'EnvHttpProxyAgent' && ${JSON.stringify(change)} === 'patched') {
  const prototype = Object.getPrototypeOf(globalThis[key]);
  prototype.dispatch = later(prototype.dispatch);
}
const pinning = new RuntimeFetchProvider()[Symbol.for('@kya-os/mcp/address-pinning')];
const proxied = (await pinning(${JSON.stringify(PROXIED)})) !== undefined;
const noProxy = (await pinning(${JSON.stringify(notProxied)})) !== undefined;
await new Promise((resolve) => setTimeout(resolve, 300));
process.stdout.write(JSON.stringify({ dispatcher, proxied, noProxy }));
`;

/** A loopback server that counts and drops every connection made to it. */
function counting(): { server: net.Server; connections: { count: number } } {
  const connections = { count: 0 };
  const server = net.createServer((socket) => {
    connections.count += 1;
    socket.destroy();
  });
  return { server, connections };
}

const host = counting();
const proxy = counting();
let hostPort: number;
let proxyPort: number;

beforeAll(async () => {
  [hostPort, proxyPort] = await Promise.all(
    [host.server, proxy.server].map(
      (server) => new Promise<number>((resolve) => server.listen(0, '127.0.0.1', () => resolve((server.address() as net.AddressInfo).port))),
    ),
  );
});
beforeEach(() => {
  host.connections.count = 0;
  proxy.connections.count = 0;
});
afterAll(async () => {
  await Promise.all([host.server, proxy.server].map((server) => new Promise((resolve) => server.close(resolve))));
});

/** The child's report, with the event loop left free meanwhile, so each server takes the connections made to it. */
function runChild(change: Change): Promise<{ status: number | null; stdout: string; stderr: string }> {
  const root = fileURLToPath(new URL('../../..', import.meta.url));
  const index = pathToFileURL(fileURLToPath(new URL('../../index.ts', import.meta.url))).href;
  const notProxied = `https://127.0.0.1:${hostPort}/list`;
  const child = spawn(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', CHILD(index, notProxied, change)], {
    cwd: root,
    env: {
      ...process.env,
      NODE_USE_ENV_PROXY: '1',
      HTTPS_PROXY: `http://127.0.0.1:${proxyPort}`,
      NO_PROXY: '127.0.0.1',
      NODE_NO_WARNINGS: '1',
    },
  });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (chunk: Buffer) => (stdout += chunk.toString('utf8')));
  child.stderr.on('data', (chunk: Buffer) => (stderr += chunk.toString('utf8')));
  return new Promise((resolve) => child.on('close', (status) => resolve({ status, stdout, stderr })));
}

describe("Node's own EnvHttpProxyAgent, under NODE_USE_ENV_PROXY=1", () => {
  it('reads a host it sends through the proxy through fetch, and pins a host NO_PROXY names', { timeout: 30_000 }, async (test) => {
    const child = await runChild('none');
    expect(child.status, child.stderr).toBe(0);
    const seen = JSON.parse(child.stdout) as { dispatcher?: string };
    if (seen.dispatcher !== 'EnvHttpProxyAgent') test.skip();
    expect({ ...seen, host: host.connections.count, proxy: proxy.connections.count }).toEqual({
      dispatcher: 'EnvHttpProxyAgent',
      proxied: false,
      noProxy: true,
      host: 0,
      proxy: 0,
    });
  });

  it.for<[string, Change]>([
    ['composed with an interceptor that dispatches later', 'composed'],
    ['whose class a library patched to dispatch later', 'patched'],
  ])('pins every host under one %s, and connects nowhere to decide', { timeout: 30_000 }, async ([, change], test) => {
    const child = await runChild(change);
    expect(child.status, child.stderr).toBe(0);
    const seen = JSON.parse(child.stdout) as { dispatcher?: string };
    if (seen.dispatcher !== 'EnvHttpProxyAgent') test.skip();
    expect({ ...seen, host: host.connections.count, proxy: proxy.connections.count }).toEqual({
      dispatcher: 'EnvHttpProxyAgent',
      proxied: true,
      noProxy: true,
      host: 0,
      proxy: 0,
    });
  });
});
