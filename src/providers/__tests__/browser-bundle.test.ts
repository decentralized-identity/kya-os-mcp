/**
 * `@kya-os/mcp/providers` is the documented import path for `WebCryptoProvider`
 * in browsers and Workers. The same entry exports `NodeCryptoProvider`, so a
 * top-level `node:crypto` import there broke every browser bundle of the
 * entry. Node built-ins are loaded lazily instead; this holds that in place.
 */
import { describe, it, expect } from 'vitest';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

describe('@kya-os/mcp/providers in a browser bundle', () => {
  it.each(['WebCryptoProvider', '*'])('bundles `export %s` for platform=browser', async (name) => {
    const entry = JSON.stringify(fileURLToPath(new URL('../index.ts', import.meta.url)));
    const contents = name === '*' ? `export * from ${entry};` : `export { ${name} } from ${entry};`;
    const result = await build({
      stdin: { contents, resolveDir: process.cwd(), loader: 'ts' },
      bundle: true,
      platform: 'browser',
      format: 'esm',
      write: false,
      logLevel: 'silent',
    }).then(
      () => 'ok',
      (e: { errors?: Array<{ text: string }> }) => (e.errors ?? []).map((x) => x.text).join('\n'),
    );
    expect(result).toBe('ok');
  });
});
