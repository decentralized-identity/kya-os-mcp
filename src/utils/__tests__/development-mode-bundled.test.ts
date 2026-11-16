/**
 * `development: true` must never run in production, and a Worker build is production too. A bundler
 * that defines `process.env.NODE_ENV` writes `"production"` in place of that expression and leaves
 * no `process` behind, as a Worker has none. The guard reads the expression as such a bundler finds
 * it, so a production build still refuses the setting, and a runtime with no `process` and nothing
 * inlined is not production. Each test bundles the public `createDidWebResolver` with esbuild and
 * runs it where there is no `process`, with the web globals a Worker has.
 */

import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { build } from 'esbuild';
import { describe, expect, it } from 'vitest';

/** `createDidWebResolver`, bundled for a browser or Worker with `define`, as `kya.createDidWebResolver`. */
async function bundled(define: Record<string, string>): Promise<string> {
  // The module that defines it, which the package's entries export it from.
  const entry = JSON.stringify(fileURLToPath(new URL('../../delegation/did-web-resolver.ts', import.meta.url)));
  const result = await build({
    stdin: { contents: `export { createDidWebResolver } from ${entry};`, resolveDir: process.cwd(), loader: 'ts' },
    bundle: true,
    platform: 'browser',
    format: 'iife',
    globalName: 'kya',
    define,
    write: false,
    logLevel: 'silent',
  });
  return result.outputFiles[0]!.text;
}

/** What building a did:web resolver with `development: true` comes to in `code`, run where there is no `process`. */
function developmentIn(code: string): string {
  const quiet = { warn: () => undefined, error: () => undefined, info: () => undefined, debug: () => undefined, log: () => undefined };
  const worker = vm.createContext({
    console: quiet, URL, TextEncoder, TextDecoder, crypto: globalThis.crypto, setTimeout, clearTimeout, AbortController, Response, Headers,
  });
  vm.runInContext(code, worker);
  expect(vm.runInContext('typeof process', worker)).toBe('undefined');
  try {
    vm.runInContext('kya.createDidWebResolver({ fetch: async () => { throw new Error("no request expected"); } }, { development: true })', worker);
    return 'built';
  } catch (error) {
    return (error as Error).message;
  }
}

describe('development: true in a bundled Worker build', () => {
  it('is refused when the bundler inlined NODE_ENV as "production"', async () => {
    const code = await bundled({ 'process.env.NODE_ENV': '"production"' });
    expect(developmentIn(code)).toBe(
      'DidWebResolverOptions.development is true while NODE_ENV is "production": development: true reads private and local ' +
        'hosts and must never run in production. Remove it; to read private hosts in production, give the fetch provider ' +
        'allowPrivateNetworkHosts: true.',
    );
  });

  it('is admitted when the bundler inlined NODE_ENV as "development"', async () => {
    expect(developmentIn(await bundled({ 'process.env.NODE_ENV': '"development"' }))).toBe('built');
  });

  it('is admitted where there is no process and nothing was inlined, which is not production', async () => {
    expect(developmentIn(await bundled({}))).toBe('built');
  });
});
