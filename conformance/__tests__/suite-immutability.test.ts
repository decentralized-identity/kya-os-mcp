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

/**
 * Prose counts drift silently. The manifest's own `vectorCount` was guarded
 * above from the day it was introduced, but the vector count QUOTED in the DIF
 * submission was not, and it sat at 44 after the suite grew to 48. That is the
 * document a standards body reads, so an unguarded number there is the most
 * expensive kind to leave stale.
 *
 * Any document that states a vector total must state the manifest's.
 */
describe('documented vector counts', () => {
  const REPO_ROOT = join(VECTORS_DIR, '..', '..');
  const DOCUMENTS = ['submission/0000-decentralized-authority.md'];

  it.each(DOCUMENTS)('%s quotes the manifest vector count', (relativePath) => {
    const text = readFileSync(join(REPO_ROOT, relativePath), 'utf8');
    const quoted = [
      ...text.matchAll(/(\d+)[- ]vector\b/gi),
    ].map((match) => Number(match[1]));

    expect(
      quoted.length,
      `${relativePath} states no vector count; drop it from DOCUMENTS if that is intended`,
    ).toBeGreaterThan(0);

    const wrong = quoted.filter((count) => count !== manifest.vectorCount);
    expect(
      wrong,
      `${relativePath} claims ${wrong.join(', ')} vectors; the suite has ${manifest.vectorCount}`,
    ).toEqual([]);
  });
});

/**
 * CONFORMANCE.md prints what `conformance/verify.py` reports, and a reader
 * holds a run of their own against it. A check added to the verifier and not
 * to the document leaves that reader with output the document does not show.
 *
 * The document lists every check the verifier makes, by the name the verifier
 * reports it under, in the order it makes them. Of the checks it makes of the
 * status-list vectors, one under each vector's id, it shows the first by name
 * and then one line that stands for every one.
 */
describe('the verifier output CONFORMANCE.md shows', () => {
  const REPO_ROOT = join(VECTORS_DIR, '..', '..');
  /** The line that stands for the check of each status-list vector. */
  const EACH_STATUS_LIST_VECTOR = '... one result for every status-list vector ...';

  it('lists the checks conformance/verify.py makes, in the order it makes them', () => {
    const verifier = readFileSync(join(REPO_ROOT, 'conformance', 'verify.py'), 'utf8');
    const made = [...verifier.matchAll(/results\.append\(\(\s*(?:"((?:[^"\\]|\\.)*)"|item\["id"\],)/g)]
      .map((match) => match[1] ?? EACH_STATUS_LIST_VECTOR);
    const calls = verifier.match(/results\.append\(/g) ?? [];
    expect(made.length, 'no check was read from conformance/verify.py').toBeGreaterThan(0);
    expect(made.length, 'a check in conformance/verify.py is named in a way this test does not read').toBe(calls.length);

    const document = readFileSync(join(REPO_ROOT, 'CONFORMANCE.md'), 'utf8');
    const output = /Expected output:\n\n```\n(KYA-OS cross-language verifier[^]*?)```/.exec(document)?.[1];
    expect(output, 'CONFORMANCE.md shows no output of the cross-language verifier').toBeDefined();
    const shown = output!.split('\n').flatMap((line) => {
      if (line.startsWith('  [PASS] ')) return [line.slice('  [PASS] '.length)];
      return line.trim() === EACH_STATUS_LIST_VECTOR ? [EACH_STATUS_LIST_VECTOR] : [];
    });

    // The status-list checks shown by name are the first the verifier makes,
    // in the order of the files it reads, just before the line for them all.
    const statusListIds = committedNames.flatMap((name) => {
      const parsed = JSON.parse(readFileSync(join(VECTORS_DIR, name), 'utf8')) as {
        category?: string;
        vectors: { id: string }[];
      };
      return parsed.category === 'status-list' ? parsed.vectors.map(({ id }) => id) : [];
    });
    const named = shown.filter((name) => statusListIds.includes(name));
    const standing = shown.indexOf(EACH_STATUS_LIST_VECTOR);
    expect(named).toEqual(statusListIds.slice(0, named.length));
    expect(shown.slice(standing - named.length, standing)).toEqual(named);

    expect(shown.filter((name) => !statusListIds.includes(name))).toEqual(made);
  });
});
