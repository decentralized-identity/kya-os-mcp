/**
 * Every public entry must keep its exported values when a consumer bundles it.
 *
 * esbuild wraps a module in a lazy `__esm` initialiser when it is reached through
 * a dynamic import (Cloudflare Worker templates do this). A consumer that also
 * statically imports a value re-exported by an entry barrel then needs that
 * barrel's initialiser call; with `"sideEffects": false` covering the barrel,
 * esbuild drops the call and the value reads as `undefined`. The card proof meta
 * key and TTL did exactly this, so a bundled verifier treated signed calls as
 * unsigned; three `delegation` values were affected the same way. `package.json`
 * marks the entry barrels as having side effects; this test holds that in place
 * for every entry, built as published (`dist/`).
 */
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';
import { afterAll, describe, expect, it } from 'vitest';
import { BUILT, consumerDir, ENTRIES, PACKAGE } from './bundling.js';

type Snapshot = Record<string, { type: string; value?: unknown }>;

/** What a value must look like after bundling: primitives by value, objects by type. */
function snapshot(module: Record<string, unknown>, names: readonly string[]): Snapshot {
  return Object.fromEntries(
    names.map((name) => {
      const value = module[name];
      const primitive = value === null || typeof value !== 'object';
      return [name, primitive ? { type: typeof value, value } : { type: typeof value }];
    }),
  );
}

/** The exported values (not functions or classes) a consumer can read from a module. */
function valueExports(module: Record<string, unknown>): string[] {
  return Object.keys(module).filter(
    (name) => name !== 'default' && module[name] !== undefined && typeof module[name] !== 'function',
  );
}

describe.skipIf(!BUILT)('public entries keep their values when bundled with esbuild', () => {
  // A consumer resolves the package through node_modules, so esbuild reads the
  // real package.json (exports map and sideEffects).
  const { dir: workDir, remove } = consumerDir('kya-os-bundle-');
  afterAll(remove);

  it('covers every code entry in the exports map', () => {
    const specifiers = ENTRIES.map(({ specifier }) => specifier);
    expect(specifiers).toEqual(
      expect.arrayContaining([PACKAGE.name, `${PACKAGE.name}/card`, `${PACKAGE.name}/delegation`]),
    );
  });

  it.each(ENTRIES)('$specifier', async ({ specifier: entry, file }) => {
    // Read the expected values from the built entry itself, as Node loads it.
    const expected = (await import(/* @vite-ignore */ pathToFileURL(file).href)) as Record<string, unknown>;
    const names = valueExports(expected);
    if (names.length === 0) return; // functions and types only: nothing to lose

    // The shape that triggers the lazy wrapping: a static import of the entry's
    // values next to a dynamic import of another entry that reaches the same modules.
    const lazyEntry = entry === PACKAGE.name ? `${PACKAGE.name}/card` : PACKAGE.name;
    const imports = names.map((name) => `${name} as v_${name}`).join(', ');
    const values = names.map((name) => `${JSON.stringify(name)}: v_${name}`).join(', ');
    const outfile = join(workDir, `${entry.replace(/\W/g, '_')}.mjs`);
    await build({
      stdin: {
        contents: [
          `import { ${imports} } from ${JSON.stringify(entry)};`,
          `export const lazy = () => import(${JSON.stringify(lazyEntry)});`,
          `export const values = { ${values} };`,
        ].join('\n'),
        resolveDir: workDir,
        loader: 'js',
      },
      outfile,
      bundle: true,
      format: 'esm',
      platform: 'browser',
      target: 'es2022',
      external: ['node:*'],
      logLevel: 'silent',
    });

    const bundled = (await import(/* @vite-ignore */ pathToFileURL(outfile).href)) as {
      values: Record<string, unknown>;
    };
    expect(snapshot(bundled.values, names)).toEqual(snapshot(expected, names));
  }, 30_000);
});
