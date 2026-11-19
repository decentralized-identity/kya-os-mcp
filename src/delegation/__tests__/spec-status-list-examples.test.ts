/**
 * SPEC.md §6.6 shows a status list in each format and the entry that names one. Each example is
 * what the reference issuer writes: a list of the format `statusListFormatOf` reads it as, with the
 * members `StatusList2021Manager` gives a list of that format and no others but its proof, holding
 * the 131,072 clear entries of a new list, inside the window it states on a day of that window.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { statusListIssuer } from '../../__tests__/utils/status-list-manager.js';
import { DelegationCredentialStatusSchema } from '../../card/delegation.js';
import { statusListFormatOf, type StatusListFormat } from '../../utils/statuslist-format.js';
import { statusListGzipCodec } from '../../utils/statuslist-gzip.js';
import { acceptStatusListValidity } from '../../utils/statuslist-validity.js';
import { BitstringManager } from '../bitstring.js';

// A Windows checkout may write the file with CRLF line endings; the patterns below read LF.
const spec = readFileSync(fileURLToPath(new URL('../../../SPEC.md', import.meta.url)), 'utf8').replace(/\r\n/g, '\n');
const section = /\n### 6\.6 [^]*?\n### 6\.7 /.exec(spec)![0];
const examples = [...section.matchAll(/```json\n([^]*?)```/g)].map((match) => JSON.parse(match[1]!) as Record<string, unknown>);
const membersOf = (value: unknown) => Object.keys(value as object).sort();
const DAY_MS = 24 * 60 * 60 * 1000;

describe('the status lists of SPEC.md §6.6', () => {
  it('are a list of each format and an entry, the W3C format first', () => {
    expect(examples.map((example) => statusListFormatOf(example) ?? example.type)).toEqual([
      'BitstringStatusList',
      'BitstringStatusListEntry',
      'StatusList2021',
    ]);
  });

  it.each([
    [0, { format: 'BitstringStatusList', validityPeriodMs: 7 * DAY_MS, ttl: 300_000 }],
    [2, { format: 'StatusList2021', validityPeriodMs: 7 * DAY_MS }],
  ] as const)('show, as example %i, the list the reference issuer writes with %j', async (at, options) => {
    const example = examples[at]!;
    const subject = example.credentialSubject as Record<string, unknown>;
    const { manager, storage } = await statusListIssuer({ ...options, format: options.format as StatusListFormat });
    const entry = await manager.allocateStatusEntry('revocation');
    const { proof: _proof, ...written } = (await storage.getStatusList(entry.statusListCredential)) as Record<string, unknown>;

    expect(membersOf(example)).toEqual(membersOf(written));
    expect(membersOf(subject)).toEqual(membersOf(written.credentialSubject));
    expect(example).toMatchObject({ '@context': written['@context'], type: written.type });
    expect(subject.id).toBe(`${String(example.id)}#list`);
    // The bits, not the text: a GZIP header names the system that wrote it, so two encodings of one list differ.
    const bits = await BitstringManager.decode(subject.encodedList as string, statusListGzipCodec, statusListGzipCodec);
    expect([bits.getRawBits().length * 8, bits.getSetBits()]).toEqual([131_072, []]);
    expect(acceptStatusListValidity(example, Date.parse('2024-03-04T00:00:00Z'))).toEqual({ valid: true });
    expect(acceptStatusListValidity(example, Date.parse('2024-03-09T00:00:00Z'))).toMatchObject({ valid: false });
  });

  it('show an entry of the first list as the reference issuer writes one', async () => {
    const [list, example] = examples as [Record<string, unknown>, Record<string, unknown>];
    const entry = await (await statusListIssuer({ format: 'BitstringStatusList' })).manager.allocateStatusEntry('revocation');
    expect(membersOf(example)).toEqual(membersOf(entry));
    expect(example).toMatchObject({
      id: `${String(list.id)}#${String(example.statusListIndex)}`,
      type: entry.type,
      statusPurpose: (list.credentialSubject as Record<string, unknown>).statusPurpose,
      statusListCredential: list.id,
    });
    expect(DelegationCredentialStatusSchema.safeParse(example).success).toBe(true);
  });
});
