/**
 * A consumer's bundle carries the zod the library uses, and not every locale zod ships.
 *
 * zod 4's named export `z` is an object holding the whole of zod, its error messages in every
 * locale among it, about 260 kB minified. A bundler cannot leave out a member of an object the code
 * is handed, so `import { z } from 'zod'` in any module a consumer reached put all of them in the
 * bundle: a card verifier of 13 kB came to 485 kB. Imported as a namespace, `import * as z from
 * 'zod'`, the bundler keeps only the members the code names, English messages among them. ESLint
 * refuses the named import in the library's source; this holds each entry, bundled as published
 * (`dist/`), to it.
 */
import { build } from 'esbuild';
import { describe, expect, it } from 'vitest';
import { BUILT, ENTRIES, useConsumerDir } from './bundling.js';

/**
 * The locale modules of zod a bundle holds, by file name: those that put any bytes into the output.
 * The metafile's own `inputs` also lists every module the bundler read and then left out.
 */
function zodLocales(inputs: Record<string, { bytesInOutput: number }>): string[] {
  return Object.entries(inputs)
    .filter(([, input]) => input.bytesInOutput > 0)
    .map(([path]) => /node_modules\/zod\/(?:.*\/)?locales\/([^/]+)$/.exec(path.replaceAll('\\', '/'))?.[1])
    .filter((name): name is string => name !== undefined && name !== 'index.js')
    .sort();
}

describe.skipIf(!BUILT)('a bundle of any entry holds no zod locale but English', () => {
  const consumerDir = useConsumerDir('kya-os-bundle-zod-');

  it.each(ENTRIES)('every export of $specifier', async ({ specifier }) => {
    const result = await build({
      stdin: { contents: `export * from ${JSON.stringify(specifier)};`, resolveDir: consumerDir(), loader: 'js' },
      bundle: true,
      write: false,
      metafile: true,
      format: 'esm',
      platform: 'browser',
      target: 'es2022',
      external: ['node:*'],
      logLevel: 'silent',
    });

    const [output] = Object.values(result.metafile.outputs);
    const locales = zodLocales(output?.inputs ?? {});
    expect(locales.filter((name) => name !== 'en.js')).toEqual([]);
  }, 30_000);
});
