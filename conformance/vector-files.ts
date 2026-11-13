/**
 * What every vector generator writes: the suite version each vector file carries, and the file
 * itself, as JSON with two-space indentation and a final newline. `suite-hash.mjs` hashes the files
 * and `SUITE-MANIFEST.json` names the same version.
 */

import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { VECTORS_DIR } from './loader.js';
import type { VectorFile } from './types.js';

/** The suite version of every vector file the generators write. */
export const SUITE_VERSION = '1.4.0';

/** Write `file` to the vectors directory as `name`, and say so. */
export function writeVectorFile(file: VectorFile, name: string): void {
  writeFileSync(join(VECTORS_DIR, name), JSON.stringify(file, null, 2) + '\n', 'utf8');
  console.log(`wrote ${name} (${file.vectors.length} vectors)`);
}
