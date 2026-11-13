/**
 * A status-list vector may state the verifier configuration it is checked with, `trustedRootIssuer`
 * and `statusListIssuers` (SPEC.md §6.6). The two readers of the suite refuse the same malformed
 * configuration: the TypeScript loader refuses the vector, and the reference adapter fails it when
 * handed it directly, while `conformance/status_list.py` reads it as refused. A well-formed
 * configuration leaves the vector's verdict as the vector states it.
 */

import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { loadVectors } from '../loader.js';
import { ReferenceConformanceAdapter } from '../reference-adapter.js';
import { requirePython } from './python.js';
import type { ConformanceVector } from '../types.js';

const HERE = fileURLToPath(new URL('..', import.meta.url));
const VERSION = (JSON.parse(readFileSync(join(HERE, 'vectors', 'status-list.json'), 'utf8')) as { version: string }).version;
const vectors = loadVectors().filter((vector) => vector.category === 'status-list');

/** A configuration by name, given the DID of the vector credential's issuer. */
type Variant = [name: string, configuration: (owner: string) => Record<string, unknown>];

/** The vector `id` names, with the members `configuration` returns set on its input. */
function configured(id: string, configuration: Variant[1]): ConformanceVector {
  const vector = structuredClone(vectors.find((item) => item.id === id)!);
  const input = vector.input as Record<string, unknown> & { credential: { issuer: string } };
  Object.assign(input, configuration(input.credential.issuer));
  return vector;
}

const MALFORMED: Variant[] = [
  ...[null, 7, '', ['did:x'], { id: 'did:x' }].map((root): Variant => [
    `trustedRootIssuer ${JSON.stringify(root)}`, () => ({ trustedRootIssuer: root }),
  ]),
  ...[null, 'did:x', [], { 'did:x': 'did:y' }].map((map): Variant => [
    `statusListIssuers ${JSON.stringify(map)}`, () => ({ statusListIssuers: map }),
  ]),
  ['statusListIssuers naming a number for the issuer', (owner) => ({ statusListIssuers: { [owner]: [7] } })],
  ['statusListIssuers naming one DID for the issuer, not an array', (owner) => ({ statusListIssuers: { [owner]: 'did:z' } })],
];

const WELL_FORMED: Variant[] = [
  ['the credential issuer pinned as the root', (owner) => ({ trustedRootIssuer: owner })],
  ['an empty statusListIssuers', () => ({ statusListIssuers: {} })],
  ['statusListIssuers accepting no one for the issuer', (owner) => ({ statusListIssuers: { [owner]: [] } })],
];

/** Whether the loader reads `vector` from a vector file of its own, or the error it refuses it with. */
function load(vector: ConformanceVector): true | string {
  const dir = mkdtempSync(join(tmpdir(), 'kya-os-vectors-'));
  try {
    writeFileSync(join(dir, 'status-list.json'), JSON.stringify({ version: VERSION, category: 'status-list', vectors: [vector] }));
    loadVectors(dir);
    return true;
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** What `conformance/status_list.py` reads each vector's input as, with the suite's own JCS and Ed25519. */
function python(interpreter: readonly string[], cases: readonly ConformanceVector[]): boolean[] {
  const [command, ...args] = interpreter;
  const reader = [
    'import json, sys', 'sys.path.insert(0, sys.argv[1])', 'import verify', 'from status_list import verify_input',
    'for line in sys.stdin:', '    print(json.dumps(verify_input(json.loads(line), verify.jcs, verify.ed25519_verify)))',
  ].join('\n');
  const output = execFileSync(command!, [...args, '-I', '-B', '-c', reader, HERE], {
    input: cases.map((vector) => JSON.stringify(vector.input)).join('\n') + '\n', encoding: 'utf8',
  });
  return output.trim().split('\n').map((line) => JSON.parse(line) as boolean);
}

const adapter = new ReferenceConformanceAdapter();
const IDS = ['status-list/no-id-list', 'status-list/active-credential'];

/** Each of `variants` on each vector of {@link IDS}, and what the loader, the adapter and Python make of it. */
async function verdicts(interpreter: readonly string[], variants: readonly Variant[]) {
  const cases = IDS.flatMap((id) => variants.map(([name, configuration]) => ({ name: `${id}, ${name}`, vector: configured(id, configuration) })));
  const read = python(interpreter, cases.map(({ vector }) => vector));
  return Promise.all(cases.map(async ({ name, vector }, i) => ({
    name,
    expected: vector.expected,
    loader: load(vector) === true ? 'read' : 'refused',
    adapter: (await adapter.verifyStatusList(vector.input as never)).outcome,
    python: read[i],
  })));
}

describe('a status-list vector that states its verifier configuration', () => {
  it('is refused by the loader, the reference adapter and the Python reader alike when the configuration is malformed', async (context) => {
    const read = await verdicts(requirePython(context), MALFORMED);
    expect(read).toEqual(read.map(({ name, expected }) => ({ name, expected, loader: 'refused', adapter: 'fail', python: false })));
  });

  it('names the malformed member when the loader refuses it', () => {
    expect(load(configured(IDS[0]!, () => ({ trustedRootIssuer: 7 })))).toMatch(
      /^Vector status-list\/no-id-list in .*status-list\.json: trustedRootIssuer of type number is not a non-empty string$/,
    );
    expect(load(configured(IDS[0]!, () => ({ statusListIssuers: null })))).toMatch(
      /: statusListIssuers must be a plain object mapping credential issuer DIDs to arrays of status-list issuer DIDs$/,
    );
  });

  it('keeps the verdict the vector states when the configuration is well formed', async (context) => {
    const read = await verdicts(requirePython(context), WELL_FORMED);
    expect(read).toEqual(read.map(({ name, expected }) => ({ name, expected, loader: 'read', adapter: expected, python: expected === 'pass' })));
  });
});
