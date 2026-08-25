/**
 * Vector-set immutability invariant.
 *
 * The committed conformance vectors are pinned by conformance/SUITE-MANIFEST.json:
 * per-file SHA-256 over the raw committed bytes, [filename, hex] pairs sorted by
 * filename, RFC 8785 (JCS) canonicalization of the array, SHA-256 of that,
 * "sha256:" prefix. This test recomputes the hash from disk through the
 * library's real `canonicalizeJSON` (the standalone `conformance/suite-hash.mjs`
 * uses a JCS-equivalent JSON.stringify shortcut, so this doubles as a guard on
 * that equivalence) and fails on ANY drift: a changed byte, an added file, or a
 * deleted file. `pnpm run conformance:generate` mints fresh keys, so its output
 * must never be committed over an existing suiteVersion.
 */

import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, expect } from 'vitest';
import { canonicalizeJSON } from '../../src/delegation/utils.js';
import { VECTORS_DIR } from '../loader.js';

const INVARIANT =
  'conformance vectors are immutable at a suiteVersion; bump suiteVersion in ' +
  'SUITE-MANIFEST.json (and regenerate the manifest with suite-hash.mjs --json) ' +
  'if this change is intentional.';

interface SuiteManifest {
  suiteVersion: string;
  vectorSetHash: string;
  vectorCount: number;
  files: [string, string][];
  pinnedAt: { package: string; packageVersion: string };
}

const sha256 = (bytes: Buffer | string): string =>
  createHash('sha256').update(bytes).digest('hex');

const manifest = JSON.parse(
  readFileSync(join(VECTORS_DIR, '..', 'SUITE-MANIFEST.json'), 'utf8'),
) as SuiteManifest;

const committedNames = readdirSync(VECTORS_DIR)
  .filter((name) => name.endsWith('.json'))
  .sort();
const committedFiles: [string, string][] = committedNames.map((name) => [
  name,
  sha256(readFileSync(join(VECTORS_DIR, name))),
]);

describe('conformance vector-set immutability (SUITE-MANIFEST.json)', () => {
  it('recomputed vectorSetHash matches the committed manifest', () => {
    const recomputed = `sha256:${sha256(canonicalizeJSON(committedFiles))}`;
    expect(recomputed, INVARIANT).toBe(manifest.vectorSetHash);
  });

  it('every committed vector file appears in the manifest (no untracked additions)', () => {
    const pinned = new Set(manifest.files.map(([name]) => name));
    const added = committedNames.filter((name) => !pinned.has(name));
    expect(added, INVARIANT).toEqual([]);
  });

  it('every manifest file exists in vectors/ (no untracked deletions)', () => {
    const onDisk = new Set(committedNames);
    const deleted = manifest.files.map(([name]) => name).filter((name) => !onDisk.has(name));
    expect(deleted, INVARIANT).toEqual([]);
  });

  it('per-file hashes match the manifest', () => {
    expect(committedFiles, INVARIANT).toEqual(manifest.files);
  });

  it('vectorCount matches the vectors committed on disk', () => {
    const count = committedNames.reduce((total, name) => {
      const parsed = JSON.parse(readFileSync(join(VECTORS_DIR, name), 'utf8')) as {
        vectors: unknown[];
      };
      return total + parsed.vectors.length;
    }, 0);
    expect(count, INVARIANT).toBe(manifest.vectorCount);
  });

  it('every vector file carries the manifest suiteVersion', () => {
    for (const name of committedNames) {
      const parsed = JSON.parse(readFileSync(join(VECTORS_DIR, name), 'utf8')) as {
        version: string;
      };
      expect(parsed.version, `${name}: ${INVARIANT}`).toBe(manifest.suiteVersion);
    }
  });
});
