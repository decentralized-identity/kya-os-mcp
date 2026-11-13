/**
 * A status-list vector may state the verifier configuration it is checked with, `trustedRootIssuer`,
 * `trustedRootStatusList` and `statusListIssuers` (SPEC.md §6.6). The two readers of the suite refuse the same malformed
 * configuration: the TypeScript loader refuses the vector, and the reference adapter fails it when
 * handed it directly, while `conformance/status_list.py` reads it as refused. A well-formed
 * configuration leaves the vector's verdict as the vector states it. Both read a proof's key and
 * signature alike too: the key's `x` as SPEC.md §7.4 reads it, and the `proofValue` as §7.8 does.
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
  ...[null, 7, '', ['https://x.example'], { id: 'https://x.example' }].map((url): Variant => [
    `trustedRootStatusList ${JSON.stringify(url)}`, (owner) => ({ trustedRootIssuer: owner, trustedRootStatusList: url }),
  ]),
  ...[null, 'did:x', [], { 'did:x': 'https://x.example' }, { '': ['https://x.example'] }].map((map): Variant => [
    `statusListIssuers ${JSON.stringify(map)}`, () => ({ statusListIssuers: map }),
  ]),
  ['statusListIssuers naming a number for the issuer', (owner) => ({ statusListIssuers: { [owner]: [7] } })],
  ['statusListIssuers naming one URL for the issuer, not an array', (owner) => ({ statusListIssuers: { [owner]: 'https://z.example' } })],
  ['statusListIssuers naming a DID for the issuer, as a map of accepted issuers would', (owner) => ({ statusListIssuers: { [owner]: ['did:z'] } })],
  ['statusListIssuers naming an array that holds a URL', (owner) => ({ statusListIssuers: { [owner]: [['https://z.example']] } })],
  ['statusListIssuers naming a URL of another scheme', (owner) => ({ statusListIssuers: { [owner]: ['ftp://z.example/1'] } })],
  ['statusListIssuers binding one URL to two issuers', (owner) => ({ statusListIssuers: { [owner]: ['https://z.example'], 'did:z': ['https://z.example'] } })],
];

const WELL_FORMED: Variant[] = [
  ['the credential issuer pinned as the root', (owner) => ({ trustedRootIssuer: owner })],
  ['an empty statusListIssuers', () => ({ statusListIssuers: {} })],
  ['statusListIssuers binding nothing to the issuer', (owner) => ({ statusListIssuers: { [owner]: [] } })],
  ['statusListIssuers binding another URL, an origin and an http URL to the issuer, one of them twice', (owner) => ({
    statusListIssuers: { [owner]: ['https://z.example/1', 'https://z.example', 'http://z.example/1', 'https://z.example/1'] },
  })],
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
    'for line in sys.stdin.buffer:', '    print(json.dumps(verify_input(json.loads(line), verify.jcs, verify.ed25519_verify)))',
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
      /^Vector status-list\/no-id-list in .*status-list\.json: trustedRootIssuer is not a non-empty string$/,
    );
    expect(load(configured(IDS[0]!, () => ({ trustedRootStatusList: '' })))).toMatch(/: trustedRootStatusList is not a non-empty string$/);
    expect(load(configured(IDS[0]!, () => ({ statusListIssuers: null })))).toMatch(
      /: statusListIssuers does not map issuers to lists of URLs$/,
    );
    expect(load(configured(IDS[0]!, () => ({ statusListIssuers: { 'did:a': ['https://z.example'], 'did:b': ['https://z.example'] } })))).toMatch(
      /: statusListIssuers binds one URL to two issuers$/,
    );
  });

  it('keeps the verdict the vector states when the configuration is well formed', async (context) => {
    const read = await verdicts(requirePython(context), WELL_FORMED);
    expect(read).toEqual(read.map(({ name, expected }) => ({ name, expected, loader: 'read', adapter: expected, python: expected === 'pass' })));
  });
});

/** An edit of a status-list vector's input: of every proof's `proofValue`, or of every key's `x`. */
type Rewrite = [name: string, edit: (input: Record<string, unknown>) => void, verdict: 'pass' | 'fail'];

/** Each proof the input carries, the credential's and its status list's. */
const proofsOf = (input: Record<string, unknown>): { proofValue: string }[] => [
  (input.credential as { proof: { proofValue: string } }).proof,
  ...Object.values(input.statusLists as Record<string, { proof: { proofValue: string } }>).map(({ proof }) => proof),
];
/** Each Ed25519 key the input's DID documents carry. */
const keysOf = (input: Record<string, unknown>): { x: string }[] =>
  Object.values(input.didDocuments as Record<string, { verificationMethod: { publicKeyJwk: { x: string } }[] }>)
    .flatMap(({ verificationMethod }) => verificationMethod.map(({ publicKeyJwk }) => publicKeyJwk));
const everyProof = (rewrite: (value: string) => string) => (input: Record<string, unknown>) => {
  for (const proof of proofsOf(input)) proof.proofValue = rewrite(proof.proofValue);
};
const everyKey = (rewrite: (value: string) => string) => (input: Record<string, unknown>) => {
  for (const key of keysOf(input)) key.x = rewrite(key.x);
};

const REWRITES: Rewrite[] = [
  ['proofValue in the base64 alphabet', everyProof((value) => value.replaceAll('-', '+').replaceAll('_', '/')), 'pass'],
  ['proofValue padded with =', everyProof((value) => `${value}==`), 'pass'],
  ['proofValue broken across lines', everyProof((value) => `${value.slice(0, 40)}\n${value.slice(40)}`), 'pass'],
  ['proofValue with a character outside base64', everyProof((value) => `${value.slice(0, 10)}!${value.slice(10)}`), 'fail'],
  ['x padded with =', everyKey((value) => `${value}=`), 'fail'],
  ['x with a space at its end', everyKey((value) => `${value} `), 'fail'],
];

describe('a status-list vector whose proofs or keys are written another way', () => {
  it('has the same verdict from the reference adapter and the Python reader', async (context) => {
    const interpreter = requirePython(context);
    const cases = REWRITES.map(([name, edit, verdict]) => {
      const vector = structuredClone(vectors.find((item) => item.id === 'status-list/active-credential')!);
      edit(vector.input as Record<string, unknown>);
      return { name, vector, verdict };
    });
    const read = python(interpreter, cases.map(({ vector }) => vector));
    const verdicts = await Promise.all(cases.map(async ({ name, vector }, i) => ({
      name,
      adapter: (await adapter.verifyStatusList(vector.input as never)).outcome,
      python: read[i] ? 'pass' : 'fail',
    })));
    expect(verdicts).toEqual(cases.map(({ name, verdict }) => ({ name, adapter: verdict, python: verdict })));
  });
});
