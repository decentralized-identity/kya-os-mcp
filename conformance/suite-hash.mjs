#!/usr/bin/env node
/**
 * Suite-hash tool for the KYA-OS conformance vector set.
 *
 * Recipe (KYA-OS Conformance Attestation Program):
 *   1. SHA-256 of each vector file's raw committed bytes.
 *   2. Array of [filename, hex] pairs, sorted by filename.
 *   3. RFC 8785 (JCS) canonicalization of that array.
 *   4. vectorSetHash = "sha256:" + SHA-256 hex of the canonical form.
 *
 * JCS note: this script must run under plain `node` in CI, so it cannot import
 * the repo's TypeScript `canonicalizeJSON`. For an array of [string, string]
 * pairs, `JSON.stringify` IS the JCS serialization: RFC 8785 preserves array
 * order and defines string serialization exactly as ECMAScript
 * `JSON.stringify` (RFC 8785 section 3.2.2.2), and the only constructs where
 * JCS can differ from a naive serializer (object member sorting, number
 * formatting) cannot occur in this shape. The vitest immutability test
 * recomputes the hash through the library's real `canonicalizeJSON`, so any
 * divergence here would fail CI.
 *
 * Usage:
 *   node conformance/suite-hash.mjs           # print the vectorSetHash
 *   node conformance/suite-hash.mjs --json    # print {suiteVersion, vectorSetHash, vectorCount, files}
 *   node conformance/suite-hash.mjs --check   # exit non-zero if SUITE-MANIFEST.json does not match
 */
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const MANIFEST_PATH = join(HERE, 'SUITE-MANIFEST.json');

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

export function computeSuite(vectorsDir = join(HERE, 'vectors')) {
  const names = readdirSync(vectorsDir)
    .filter((name) => name.endsWith('.json'))
    .sort();
  let vectorCount = 0;
  const versions = new Set();
  const files = names.map((name) => {
    const bytes = readFileSync(join(vectorsDir, name));
    const parsed = JSON.parse(bytes.toString('utf8'));
    vectorCount += parsed.vectors.length;
    versions.add(parsed.version);
    return [name, sha256(bytes)];
  });
  if (versions.size !== 1) {
    throw new Error(`vector files disagree on version: ${[...versions].join(', ')}`);
  }
  // JCS-equivalent for an array of string pairs; see header comment.
  const vectorSetHash = `sha256:${sha256(JSON.stringify(files))}`;
  return { suiteVersion: [...versions][0], vectorSetHash, vectorCount, files };
}

const mode = process.argv[2] ?? '';
const computed = computeSuite();
if (mode === '--json') {
  console.log(JSON.stringify(computed, null, 2));
} else if (mode === '--check') {
  const manifest = JSON.parse(readFileSync(MANIFEST_PATH, 'utf8'));
  const mismatched = ['suiteVersion', 'vectorSetHash', 'vectorCount', 'files'].filter(
    (key) => JSON.stringify(manifest[key]) !== JSON.stringify(computed[key]),
  );
  if (mismatched.length > 0) {
    console.error(`suite-hash: MISMATCH with SUITE-MANIFEST.json on: ${mismatched.join(', ')}`);
    console.error(`  committed: ${manifest.vectorSetHash} (${manifest.vectorCount} vectors)`);
    console.error(`  computed:  ${computed.vectorSetHash} (${computed.vectorCount} vectors)`);
    console.error(
      'Conformance vectors are immutable at a suiteVersion. If this change is intentional,',
    );
    console.error(
      'bump suiteVersion and regenerate the manifest with `node conformance/suite-hash.mjs --json`.',
    );
    process.exit(1);
  }
  console.log(
    `suite-hash: OK ${computed.vectorSetHash} matches SUITE-MANIFEST.json ` +
      `(suiteVersion ${computed.suiteVersion}, ${computed.vectorCount} vectors)`,
  );
} else if (mode === '') {
  console.log(computed.vectorSetHash);
} else {
  console.error(`suite-hash: unknown flag "${mode}" (expected --json or --check)`);
  process.exit(2);
}
