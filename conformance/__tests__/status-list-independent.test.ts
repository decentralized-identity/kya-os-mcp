import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { BitstringManager, statusListGzipCodec } from '../../src/index.js';
import { revocationEntriesOf, type DelegationChain } from '../../src/card/delegation.js';
import { acceptEntrySize, acceptStatusList, statusListExpectationFor, type StatusListIssuers } from '../../src/utils/statuslist-acceptance.js';
import { parseStatusListIndex } from '../../src/utils/statuslist-bits.js';
import { loadVectors } from '../loader.js';
import { requirePython } from './python.js';
import type { StatusListInput } from '../types.js';

const url = 'https://status.example/list?version=1#bits';
const entry = { type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: '7', statusListCredential: url };

/** The chains, each by its hops' issuers. Raw identities deliberately collide across roles. */
const CHAINS = [['did:r', 'did:i', 'did:l'], ['did:r', 'did:i', 'did:r'], ['did:r', 'did:r', 'did:l']].map((issuers) => ({ issuers }));

/** The URL the root's own credential names when it is not the list the cases read. */
const ROOT_OWN = 'https://status.example/root-own';
/** What a verifier's configuration binds: nothing, the list's URL or its origin to a service, another URL, or the URL to a party of the chain. */
const SERVICES: StatusListIssuers[] = [
  {},
  { 'did:s': [url] },
  { 'did:s': ['https://status.example'] },
  { 'did:s': ['https://status.example.evil.example', 'https://status.example/list'], 'did:l': ['https://lists.elsewhere.example'] },
  { 'did:r': ['https://status.example/other', url] },
  { 'did:i': [], 'did:l': [url] },
];

/** Every case on one chain whose root's own credential names `rootList`; there is no signer-row verdict. */
function cases(issuers: readonly string[], rootList: string) {
  const rows = [];
  const chain = issuers.map((issuer, index) => ({
    issuer: index === 1 ? { id: issuer } : issuer,
    credentialStatus: index === 0 ? { ...entry, statusListCredential: rootList } : entry,
  }));
  for (const pin of [undefined, 'did:r', 'did:wrong']) {
    for (const services of SERVICES) {
      for (const hop of [0, 1, 2]) {
        for (const issuer of ['did:r', 'did:i', 'did:l', 'did:s', 'did:wrong', { id: 'did:l' }, { id: 7 }]) {
          for (const id of [{}, { id: url }, { id: 'https://status.example/list' }, { id: null }]) {
            for (const shape of [
              { type: ['StatusList2021Credential'], credentialSubject: { type: 'StatusList2021', statusPurpose: 'revocation' } },
              { type: ['BitstringStatusListCredential'], credentialSubject: { type: 'BitstringStatusList', statusPurpose: ['suspension', 'revocation'] } },
              { type: ['StatusList2021Credential'], credentialSubject: { type: 'StatusList2021', statusPurpose: ['revocation'] } },
              { type: ['BitstringStatusListCredential'], credentialSubject: { type: 'BitstringStatusList', statusPurpose: ['revocation', null] } },
              { credentialSubject: { statusPurpose: 'suspension' } },
              { credentialSubject: { statusPurpose: null } },
            ]) rows.push({ chain, hop, pin, services, url, rootList, list: { issuer, ...id, ...shape } });
          }
        }
      }
    }
  }
  return rows;
}

describe('independent status authority derivation', () => {
  it('reads UTF-8 JSONL even when Python stdin uses a Windows code page', (test) => {
    const [python, ...args] = requirePython(test);
    const script = fileURLToPath(new URL('../status_list.py', import.meta.url));
    // U+0141 contains a UTF-8 byte undefined in cp1252, so a locale-decoded read fails.
    const listUrl = 'https://status.example/Łódź';
    const row = {
      chain: [{ issuer: 'did:i' }], hop: 0, url: listUrl,
      list: { issuer: 'did:i', id: listUrl, credentialSubject: { statusPurpose: 'revocation' } },
    };
    const reader = 'import runpy, sys; sys.stdin.reconfigure(encoding="cp1252"); runpy.run_path(sys.argv[1], run_name="__main__")';
    const output = execFileSync(python, [...args, '-I', '-B', '-c', reader, script], {
      input: JSON.stringify(row) + '\n', encoding: 'utf8',
    });
    expect(JSON.parse(output)).toBe(true);
  });

  // One chain and one root URL per test, 9,072 cases each, keeps each run of the Python port well inside a test's time.
  const ROOTED = CHAINS.flatMap((chain) => [url, ROOT_OWN].map((rootList) => ({ ...chain, rootList })));
  it.for(ROOTED)('agrees with Python on the raw chain $issuers, its root on $rootList: the keeper of the URL, role aliases, bindings and hostile lists', ({ issuers, rootList }, test) => {
    const [python, ...args] = requirePython(test);
    const rows = cases(issuers, rootList);
    const script = fileURLToPath(new URL('../status_list.py', import.meta.url));
    // The Python port reads no hop but its issuer, so it is sent each hop's issuer, and the URL the
    // root's own entry names beside them, not the status entries.
    const output = execFileSync(python, [...args, '-B', script], {
      input: rows.map((row) => JSON.stringify({ ...row, chain: row.chain.map(({ issuer }) => ({ issuer })) })).join('\n') + '\n',
      encoding: 'utf8', maxBuffer: 32 * 1024 * 1024,
    });
    const expected = output.trim().split('\n').map((line) => JSON.parse(line) as boolean);
    expect(expected).toHaveLength(rows.length);
    expect(expected).toContain(true);
    expect(expected).toContain(false);
    const mismatches = rows.flatMap((row, i) => {
      const contexts = revocationEntriesOf(row.chain as unknown as DelegationChain, row.pin);
      const context = contexts[row.hop]!;
      const observed = acceptStatusList(row.list, statusListExpectationFor(entry, {
        credentialIssuer: context.credentialIssuer!,
        ...(context.trustedRootIssuer === undefined ? {} : { trustedRootIssuer: context.trustedRootIssuer }),
        ...(context.trustedRootStatusList === undefined ? {} : { trustedRootStatusList: context.trustedRootStatusList }),
      }, row.services)).valid;
      return observed === expected[i] ? [] : [{ row, observed, expected: expected[i] }];
    });
    expect(mismatches.slice(0, 5)).toEqual([]);
  });
});

/**
 * Whether the Python port reads the active-credential vector as not revoked with each of `changes`
 * made to its status entry, over a list with every bit clear, so an entry is read (true) exactly
 * when it is one the port takes. Signatures are stubbed in Python: only the entry differs between
 * the inputs.
 */
async function readByPython(python: readonly string[], changes: readonly Record<string, unknown>[]): Promise<boolean[]> {
  const clear = await new BitstringManager(131072, statusListGzipCodec, statusListGzipCodec).encode();
  const vector = loadVectors().find((item) => item.id === 'status-list/active-credential')!;
  const inputs = changes.map((change) => {
    const input = structuredClone(vector.input) as StatusListInput & { credential: { credentialStatus: Record<string, unknown> } };
    Object.assign(input.credential.credentialStatus, change);
    (input.statusLists[input.credential.credentialStatus.statusListCredential as string] as { credentialSubject: { encodedList: string } })
      .credentialSubject.encodedList = clear;
    return JSON.stringify(input);
  });
  const reader = [
    'import json, sys', 'sys.path.insert(0, sys.argv[1])', 'from status_list import verify_input',
    'for line in sys.stdin.buffer:', '    print(json.dumps(verify_input(json.loads(line), lambda document: b"", lambda *proof: True)))',
  ].join('\n');
  const [command, ...args] = python;
  const output = execFileSync(command!, [...args, '-I', '-B', '-c', reader, fileURLToPath(new URL('..', import.meta.url))], {
    input: inputs.join('\n') + '\n', encoding: 'utf8',
  });
  return output.trim().split('\n').map((line) => JSON.parse(line) as boolean);
}

describe('independent statusListIndex reading', () => {
  it('reads every index form, string or not, as the TypeScript parser does', async (context) => {
    const python = requirePython(context);
    const forms = ['7', '0', '007', '131071', '131072', '', ' 7', '7 ', '7\n', '+7', '-7', '-0', '7junk', '7.5', '1e1',
      '0x7', '7_0', '\u0667', '\uff17', '\u{1D7D5}', '\u096D', '9007199254740991', '9007199254740992', 7, 0, ['7'], null,
      `${'0'.repeat(4300)}7`, `${'0'.repeat(4300)}9007199254740992`, '9'.repeat(4301)];
    const read = await readByPython(python, forms.map((statusListIndex) => ({ statusListIndex })));
    const parsed = forms.map((form) => {
      try {
        return parseStatusListIndex(form) < 131072;
      } catch {
        return false;
      }
    });
    expect(forms.map((form, i) => [form, read[i]])).toEqual(forms.map((form, i) => [form, parsed[i]]));
    expect(read).toContain(true);
  });
});

describe('independent statusSize reading', () => {
  it('reads an entry of every stated size, or of none, as the shared TypeScript rule does', async (context) => {
    const python = requirePython(context);
    const sizes = [1, 2, 3, 0, -1, 1.5, '1', '2', '', null, true, false, [1], [], { size: 1 }, 2 ** 53];
    const read = await readByPython(python, [{}, ...sizes.map((statusSize) => ({ statusSize }))]);
    const accepted = [acceptEntrySize(undefined), ...sizes.map(acceptEntrySize)].map((verdict) => verdict.valid);
    expect(['none', ...sizes].map((size, i) => [size, read[i]])).toEqual(['none', ...sizes].map((size, i) => [size, accepted[i]]));
    expect(read.slice(0, 3)).toEqual([true, true, false]);
  });
});
