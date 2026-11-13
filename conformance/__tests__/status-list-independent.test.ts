import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { BitstringManager, statusListGzipCodec } from '../../src/index.js';
import { revocationEntriesOf, type DelegationChain } from '../../src/card/delegation.js';
import { acceptStatusList, statusListExpectationFor, type StatusListIssuers } from '../../src/utils/statuslist-acceptance.js';
import { parseStatusListIndex } from '../../src/utils/statuslist-bits.js';
import { loadVectors } from '../loader.js';
import { requirePython } from './python.js';
import type { StatusListInput } from '../types.js';

const url = 'https://status.example/list?version=1#bits';
const entry = { type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: '7', statusListCredential: url };

/** The chains, each by its hops' issuers. Raw identities deliberately collide across roles. */
const CHAINS = [['did:r', 'did:i', 'did:l'], ['did:r', 'did:i', 'did:r'], ['did:r', 'did:r', 'did:l']].map((issuers) => ({ issuers }));

/** Every case on one chain; there is no signer-row verdict. */
function cases(issuers: readonly string[]) {
  const rows = [];
  const chain = issuers.map((issuer, index) => ({
    issuer: index === 1 ? { id: issuer } : issuer,
    credentialStatus: entry,
  }));
  for (const pin of [undefined, 'did:r', 'did:wrong']) {
    for (const services of [{}, { 'did:l': ['did:s'] }, { 'did:i': ['did:r', 'did:l'] }] as StatusListIssuers[]) {
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
            ]) rows.push({ chain, hop, pin, services, url, list: { issuer, ...id, ...shape } });
          }
        }
      }
    }
  }
  return rows;
}

describe('independent status authority derivation', () => {
  // One chain per test, 4,536 cases each, keeps each run of the Python port well inside a test's time.
  it.for(CHAINS)('agrees with Python on the raw chain $issuers: root admission, role aliases, mapping direction and hostile lists', ({ issuers }, test) => {
    const [python, ...args] = requirePython(test);
    const rows = cases(issuers);
    const script = fileURLToPath(new URL('../status_list.py', import.meta.url));
    // The Python port reads no hop but its issuer, so it is sent each hop's issuer, not its status entry.
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
      }, row.services)).valid;
      return observed === expected[i] ? [] : [{ row, observed, expected: expected[i] }];
    });
    expect(mismatches.slice(0, 5)).toEqual([]);
  });
});

describe('independent statusListIndex reading', () => {
  it('reads every index form, string or not, as the TypeScript parser does', async (context) => {
    const [python, ...args] = requirePython(context);
    const forms = ['7', '0', '007', '131071', '131072', '', ' 7', '7 ', '7\n', '+7', '-7', '-0', '7junk', '7.5', '1e1',
      '0x7', '7_0', '\u0667', '\uff17', '\u{1D7D5}', '\u096D', '9007199254740991', '9007199254740992', 7, 0, ['7'], null,
      `${'0'.repeat(4300)}7`, `${'0'.repeat(4300)}9007199254740992`, '9'.repeat(4301)];
    // Every bit clear, so an index is read (true) exactly when it parses and is in range. Signatures are
    // stubbed in Python: only the index differs between these inputs and the active-credential vector.
    const clear = await new BitstringManager(131072, statusListGzipCodec, statusListGzipCodec).encode();
    const vector = loadVectors().find((item) => item.id === 'status-list/active-credential')!;
    const inputs = forms.map((index) => {
      const input = structuredClone(vector.input) as StatusListInput & { credential: { credentialStatus: Record<string, unknown> } };
      input.credential.credentialStatus.statusListIndex = index;
      (input.statusLists[input.credential.credentialStatus.statusListCredential as string] as { credentialSubject: { encodedList: string } })
        .credentialSubject.encodedList = clear;
      return JSON.stringify(input);
    });
    const reader = [
      'import json, sys', 'sys.path.insert(0, sys.argv[1])', 'from status_list import verify_input',
      'for line in sys.stdin:', '    print(json.dumps(verify_input(json.loads(line), lambda document: b"", lambda *proof: True)))',
    ].join('\n');
    const output = execFileSync(python, [...args, '-I', '-B', '-c', reader, fileURLToPath(new URL('..', import.meta.url))], {
      input: inputs.join('\n') + '\n', encoding: 'utf8',
    });
    const read = output.trim().split('\n').map((line) => JSON.parse(line) as boolean);
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
