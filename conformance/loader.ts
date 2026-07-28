/**
 * Vector loader for the KYA-OS conformance harness.
 *
 * Reads every `*.json` under `conformance/vectors/`, validates each file's shape
 * (version + category + vectors), and returns a flat, deduplicated list of
 * {@link ConformanceVector}. Fails loudly on a malformed vector file so a typo in
 * a vector never silently weakens the suite.
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
