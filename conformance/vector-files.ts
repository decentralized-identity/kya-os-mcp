/**
 * What every vector generator writes: the suite version each vector file carries, and the file
 * itself, as JSON with two-space indentation and a final newline, in the text `vectorFileText`
 * (./numbers-as-written.ts) gives it. `suite-hash.mjs` hashes the files and `SUITE-MANIFEST.json`
 * names the same version.
 */

import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { VECTORS_DIR } from './loader.js';
import { vectorFileText, type NumberAsWritten } from './numbers-as-written.js';
import type { VectorFile } from './types.js';

/** The suite version of every vector file the generators write. */
export const SUITE_VERSION = '1.12.0';

/** Write `file` to the vectors directory as `name`, with each of `numbersAsWritten` as its text, and say so. */
export function writeVectorFile(file: VectorFile, name: string, numbersAsWritten: readonly NumberAsWritten[] = []): void {
  writeFileSync(join(VECTORS_DIR, name), vectorFileText(file, name, numbersAsWritten), 'utf8');
  console.log(`wrote ${name} (${file.vectors.length} vectors)`);
}
