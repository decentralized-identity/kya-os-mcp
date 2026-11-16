/**
 * Vector loader for the KYA-OS conformance harness.
 *
 * Reads every `*.json` under `conformance/vectors/`, validates each file's shape
 * (version + category + vectors), and returns a flat, deduplicated list of
 * {@link ConformanceVector}. Fails loudly on a malformed vector file so a typo in
 * a vector never silently weakens the suite.
 *
 * This file, `types.ts` and `runner.ts` are what an implementer of another library copies beside
 * the vectors, so the three import only Node.js built-ins and each other, never the package's
 * source: whatever the loader checks, it checks with code of its own
 * (`__tests__/standalone-harness.test.ts`).
 */

import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import type { ConformanceVector, VectorCategory, VectorFile } from './types.js';

const HERE = dirname(fileURLToPath(import.meta.url));

/** Absolute path to the bundled `conformance/vectors/` directory. */
export const VECTORS_DIR = join(HERE, 'vectors');

const VALID_CATEGORIES: readonly VectorCategory[] = [
  'signed-proof',
  'delegation-chain',
  'status-list',
  'did-key-resolution',
  'did-web-resolution',
  'card-proof',
  'entity-card',
  'audit-integrity',
  'negotiation',
];

/** A JSON object, or one built in code as an object literal: not an array, a `Map` or a class instance. */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/**
 * Throw a `TypeError` unless the verifier configuration a status-list input states (SPEC.md §6.6)
 * is well formed: a `trustedRootIssuer` and a `trustedRootStatusList`, when present, are non-empty
 * strings, and a `statusListIssuers`, when present, is a plain object that maps each status-list
 * issuer, a non-empty key, to an array of the status-list URLs and `https:` origins it keeps, each
 * a string that starts with `https://` or `http://`, none of them under two issuers.
 * `conformance/status_list.py` refuses the same inputs in the same words, so the suite's two
 * readers refuse the same malformed vector, and the reference adapter calls this too.
 */
export function assertStatusListConfiguration(input: unknown): void {
  const fields: Record<string, unknown> = isPlainObject(input) ? input : {};
  for (const member of ['trustedRootIssuer', 'trustedRootStatusList']) {
    const value = fields[member];
    if (value !== undefined && (typeof value !== 'string' || value.length === 0)) {
      throw new TypeError(`${member} is not a non-empty string`);
    }
  }
  const issuers = fields['statusListIssuers'];
  if (issuers === undefined) return;
  if (!isPlainObject(issuers)) {
    throw new TypeError('statusListIssuers does not map issuers to lists of URLs');
  }
  const keeperOf = new Map<string, string>();
  for (const [keeper, bindings] of Object.entries(issuers)) {
    if (keeper === '' || !Array.isArray(bindings)) {
      throw new TypeError('statusListIssuers does not map issuers to lists of URLs');
    }
    for (const binding of bindings as unknown[]) {
      if (typeof binding !== 'string' || !/^https?:\/\//.test(binding)) {
        throw new TypeError('statusListIssuers does not map issuers to lists of URLs');
      }
      if ((keeperOf.get(binding) ?? keeper) !== keeper) {
        throw new TypeError('statusListIssuers binds one URL to two issuers');
      }
      keeperOf.set(binding, keeper);
    }
  }
}

function assertVectorFile(file: unknown, source: string): asserts file is VectorFile {
  if (typeof file !== 'object' || file === null) {
    throw new Error(`Vector file ${source} is not an object`);
  }
  const f = file as Record<string, unknown>;
  if (typeof f['version'] !== 'string') {
    throw new Error(`Vector file ${source} is missing a string "version"`);
  }
  if (!VALID_CATEGORIES.includes(f['category'] as VectorCategory)) {
    throw new Error(
      `Vector file ${source} has invalid "category": ${String(f['category'])}`,
    );
  }
  if (!Array.isArray(f['vectors'])) {
    throw new Error(`Vector file ${source} is missing a "vectors" array`);
  }
  for (const v of f['vectors'] as unknown[]) {
    assertVector(v, f['category'] as VectorCategory, source);
  }
}

function assertVector(
  vector: unknown,
  fileCategory: VectorCategory,
  source: string,
): asserts vector is ConformanceVector {
  if (typeof vector !== 'object' || vector === null) {
    throw new Error(`A vector in ${source} is not an object`);
  }
  const v = vector as Record<string, unknown>;
  for (const field of ['id', 'description', 'reason'] as const) {
    if (typeof v[field] !== 'string' || (v[field] as string).length === 0) {
      throw new Error(`Vector in ${source} is missing string "${field}"`);
    }
  }
  if (v['expected'] !== 'pass' && v['expected'] !== 'fail') {
    throw new Error(
      `Vector ${String(v['id'])} in ${source} has invalid "expected": ${String(v['expected'])}`,
    );
  }
  // A vector may omit category and inherit the file's; if present it must match.
  const category = (v['category'] as VectorCategory | undefined) ?? fileCategory;
  if (category !== fileCategory) {
    throw new Error(
      `Vector ${String(v['id'])} category "${category}" does not match file category "${fileCategory}" in ${source}`,
    );
  }
  if (!('input' in v)) {
    throw new Error(`Vector ${String(v['id'])} in ${source} is missing "input"`);
  }
  if (category === 'status-list') {
    try {
      assertStatusListConfiguration(v['input']);
    } catch (error) {
      throw new Error(
        `Vector ${String(v['id'])} in ${source}: ${error instanceof Error ? error.message : String(error)}`,
        { cause: error },
      );
    }
  }
}

/**
 * Load and validate all conformance vectors from {@link VECTORS_DIR}.
 *
 * @returns Flat list of vectors with `category` always populated.
 * @throws if a vector file is malformed or two vectors share an id.
 */
export function loadVectors(dir: string = VECTORS_DIR): ConformanceVector[] {
  const files = readdirSync(dir).filter((f) => f.endsWith('.json')).sort();
  const vectors: ConformanceVector[] = [];
  const seenIds = new Set<string>();

  for (const fileName of files) {
    const source = join(dir, fileName);
    const raw = readFileSync(source, 'utf8');
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (error) {
      throw new Error(
        `Vector file ${source} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`,
        { cause: error },
      );
    }
    assertVectorFile(parsed, source);

    for (const vector of parsed.vectors) {
      const normalized: ConformanceVector = {
        ...vector,
        category: vector.category ?? parsed.category,
      };
      if (seenIds.has(normalized.id)) {
        throw new Error(`Duplicate vector id "${normalized.id}" (in ${source})`);
      }
      seenIds.add(normalized.id);
      vectors.push(normalized);
    }
  }

  if (vectors.length === 0) {
    throw new Error(`No conformance vectors found in ${dir}`);
  }

  return vectors;
}
