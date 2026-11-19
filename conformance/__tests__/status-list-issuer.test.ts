/**
 * What the reference issuer writes is what the suite's readers read. A `StatusList2021Manager`
 * issues a list and an entry in each of its two formats, a `BitstringStatusListCredential` that
 * states `validFrom`, `validUntil` and `ttl` with a `BitstringStatusListEntry`, and a
 * `StatusList2021Credential` that states `expirationDate` with a `StatusList2021Entry`, signed in
 * the vectors' own proof profile. The reference adapter and `conformance/status_list.py` each read
 * the credential on it as active, and as revoked once the manager sets its bit.
 *
 * The `ttl` vectors of `status-list-validity.json` (suite 1.13.0) hold a verifier to what Bitstring
 * Status List v1.0 §2.2 says of that member, "The value does not override or replace the validity
 * period": a list inside its window is read whatever its `ttl`, and one past its `validUntil` is
 * refused whatever its `ttl`. The list of `status-list/ttl-list` has the members the reference
 * issuer writes, and no others.
 */

import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  MemoryStatusListStorage,
  StatusList2021Manager,
  statusListGzipCodec,
  type StatusList2021ManagerOptions,
  type StatusListCredential,
} from '../../src/index.js';
import { signVC } from '../crypto-kit.js';
import { statusListVectorDeps } from '../generate-vectors.js';
import { loadVectors } from '../loader.js';
import { ReferenceConformanceAdapter } from '../reference-adapter.js';
import type { ConformanceVector, StatusListInput } from '../types.js';
import { PYTHON_TEST_TIMEOUT_MS, requirePython, type Interpreter } from './python.js';

const HERE = fileURLToPath(new URL('..', import.meta.url));
const DAY_MS = 24 * 60 * 60 * 1000;
const deps = statusListVectorDeps;

/** What `conformance/status_list.py` reads each input as, with the suite's own JCS and Ed25519. */
function python([command, ...args]: Interpreter, inputs: readonly StatusListInput[]): boolean[] {
  const reader = [
    'import json, sys', 'sys.path.insert(0, sys.argv[1])', 'import verify', 'from status_list import verify_input',
    'for line in sys.stdin.buffer:', '    print(json.dumps(verify_input(json.loads(line), verify.jcs, verify.ed25519_verify)))',
  ].join('\n');
  const output = execFileSync(command, [...args, '-I', '-B', '-c', reader, HERE], {
    input: inputs.map((input) => JSON.stringify(input)).join('\n') + '\n', encoding: 'utf8',
  });
  return output.trim().split('\n').map((line) => JSON.parse(line) as boolean);
}

/**
 * A manager built with `options` that signs as a new party in the vectors' proof profile, an
 * `Ed25519Signature2020` over the list's canonical JSON, with one entry allocated, and the input a
 * verifier is given for a delegation that states that entry, with the list as the store now holds it.
 */
async function issued(options: StatusList2021ManagerOptions) {
  const [issuer, holder] = await Promise.all([deps.mintParty(), deps.mintParty()]);
  const storage = new MemoryStatusListStorage<StatusListCredential>();
  const manager = new StatusList2021Manager(
    storage,
    { getDid: () => issuer.did, getKeyId: () => issuer.kid },
    (canonicalList) => signVC(deps.crypto, JSON.parse(canonicalList) as Record<string, unknown>, issuer.privateKey, issuer.kid),
    statusListGzipCodec,
    statusListGzipCodec,
    { statusListBaseUrl: 'https://status.example.com/issued', ...options },
  );
  const entry = await manager.allocateStatusEntry('revocation');
  const credential = await deps.signDelegation(issuer, holder.did, 'issued', entry);
  const input = async (): Promise<StatusListInput> => ({
    credential,
    statusLists: { [entry.statusListCredential]: await storage.getStatusList(entry.statusListCredential) },
    didDocuments: { [issuer.did]: deps.didDocumentFor(issuer) },
    serverDid: deps.serverDid,
  });
  return { manager, entry, input };
}

const FORMATS: readonly [string, StatusList2021ManagerOptions][] = [
  ['BitstringStatusList', { format: 'BitstringStatusList', validityPeriodMs: 7 * DAY_MS, ttl: 300_000 }],
  ['StatusList2021', { validityPeriodMs: 7 * DAY_MS }],
];

describe('a status list the reference issuer writes', () => {
  it.for(FORMATS)('is read by the reference adapter and by the Python reader, clear and then set: %s', { timeout: PYTHON_TEST_TIMEOUT_MS }, async ([, options], context) => {
    const { manager, entry, input } = await issued(options);
    const clear = await input();
    await manager.updateStatus(entry, true);
    const set = await input();

    const adapter = new ReferenceConformanceAdapter();
    expect(await adapter.verifyStatusList(clear)).toMatchObject({ outcome: 'pass' });
    expect(await adapter.verifyStatusList(set)).toMatchObject({ outcome: 'fail' });
    expect(python(requirePython(context), [clear, set])).toEqual([true, false]);
  });
});

describe('the ttl vectors', () => {
  const vectors = loadVectors();
  const byId = (id: string): ConformanceVector => {
    const vector = vectors.find((item) => item.id === id);
    if (!vector) throw new Error(`missing vector ${id}`);
    return vector;
  };
  /** The list and the status entry a vector carries. */
  const partsOf = (id: string) => {
    const input = byId(id).input as StatusListInput;
    const entry = (input.credential as { credentialStatus: Record<string, unknown> }).credentialStatus;
    const list = input.statusLists[entry.statusListCredential as string] as Record<string, unknown>;
    return { input, entry, list, subject: list.credentialSubject as Record<string, unknown> };
  };

  it.each([
    ['status-list/ttl-list', 'pass', { validUntil: '2999-01-01T00:00:00.000Z' }, 300_000],
    ['status-list/ttl-past-end-list', 'fail', { validUntil: '2026-02-01T00:00:00.000Z' }, 3_155_760_000_000],
    ['status-list/ttl-run-out-list', 'pass', {}, 1],
  ] as const)('%s is a %s vector whose list states the window and the ttl it is named for', async (id, expected, end, ttl) => {
    const { input, list, subject } = partsOf(id);
    expect(byId(id).expected).toBe(expected);
    expect(list).toMatchObject({ validFrom: '2026-01-01T00:00:00.000Z', ...end });
    expect('validUntil' in list).toBe('validUntil' in end);
    expect(subject.ttl).toBe(ttl);
    expect(await new ReferenceConformanceAdapter().verifyStatusList(input)).toMatchObject({ outcome: expected });
  });

  it('refuses the list past its end for its window, and for nothing else', async () => {
    const result = await new ReferenceConformanceAdapter().verifyStatusList(partsOf('status-list/ttl-past-end-list').input);
    expect(result.detail).toMatch(/expired at "2026-02-01T00:00:00\.000Z" \(its validUntil\)/);
  });

  it('carries, in status-list/ttl-list, a list and an entry with the members the reference issuer writes', async () => {
    const vector = partsOf('status-list/ttl-list');
    const { entry, input } = await issued({ format: 'BitstringStatusList', validityPeriodMs: 7 * DAY_MS, ttl: 300_000 });
    const list = (await input()).statusLists[entry.statusListCredential] as Record<string, unknown>;
    const membersOf = (value: object) => Object.keys(value).sort();

    expect(membersOf(vector.list)).toEqual(membersOf(list));
    expect(membersOf(vector.subject)).toEqual(membersOf(list.credentialSubject as object));
    expect(membersOf(vector.entry)).toEqual(membersOf(entry));
    expect(vector.list).toMatchObject({ '@context': list['@context'], type: list.type });
    expect(vector.subject).toMatchObject({ type: 'BitstringStatusList', statusPurpose: 'revocation', ttl: 300_000 });
    expect(vector.entry.type).toBe(entry.type);
  });
});
