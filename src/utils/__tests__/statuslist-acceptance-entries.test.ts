/**
 * The status-list acceptance API, `acceptStatusList`, `acceptedStatusListIssuers` and
 * `statusListExpectationFor` with their types, is exported from the entries a user needs:
 * `@kya-os/mcp`, `@kya-os/mcp/delegation` for a custom `StatusListResolver`, and `@kya-os/mcp/card`
 * for a custom revocation checker. Each exports the module's own values and types, and no other
 * module re-exports them.
 */

import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import * as rule from '../statuslist-acceptance.js';
import * as cardEntry from '../../card/index.js';
import * as delegationEntry from '../../delegation/index.js';
import * as rootEntry from '../../index.js';
import { typeErrors } from '../../__tests__/utils/type-errors.js';

const ENTRIES = { root: rootEntry, delegation: delegationEntry, card: cardEntry };
const VALUES = ['acceptStatusList', 'acceptedStatusListIssuers', 'statusListExpectationFor'] as const;
const TYPES = ['StatusCheckContext', 'StatusListIssuers', 'StatusListExpectation', 'StatusListVerdict'];

const REPO = fileURLToPath(new URL('../../../', import.meta.url));

/** Every TypeScript source file under `dir`, tests aside, relative to the repository. */
function sources(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((item) => {
    const path = join(dir, item.name);
    if (item.isDirectory()) return item.name === '__tests__' ? [] : sources(path);
    return item.name.endsWith('.ts') ? [relative(REPO, path).split('\\').join('/')] : [];
  });
}

describe('the rule on the public entries', () => {
  it('exports each value from @kya-os/mcp, @kya-os/mcp/delegation and @kya-os/mcp/card', () => {
    for (const [name, entry] of Object.entries(ENTRIES)) {
      for (const value of VALUES) {
        expect(rule[value], value).toBeTypeOf('function');
        expect((entry as Record<string, unknown>)[value], `${name}.${value}`).toBe(rule[value]);
      }
    }
  });

  // The types have no value to compare, so a consumer module is compiled that holds each type, and the
  // type of statusListExpectationFor, from each entry, to be the module's own, and one pair that is
  // not, which must be the only error: the check can fail, and fails for nothing else.
  it('exports its types and the type of statusListExpectationFor from each entry, as the same types', () => {
    const same = Object.keys(ENTRIES).flatMap((entry) => [
      ...TYPES.map((type) => `Same<rule.${type}, ${entry}.${type}>`),
      `Same<typeof rule.statusListExpectationFor, typeof ${entry}.statusListExpectationFor>`,
    ]);
    const source = `
      import type * as rule from '../statuslist-acceptance.js';
      import type * as root from '../../index.js';
      import type * as delegation from '../../delegation/index.js';
      import type * as card from '../../card/index.js';
      type Same<A, B> = (<T>() => T extends A ? 1 : 2) extends (<T>() => T extends B ? 1 : 2) ? true : false;
      export const same: [${same.join(', ')}] = [${same.map(() => 'true').join(', ')}];
      export const differ: Same<root.StatusListIssuers, card.StatusCheckContext> = true;
    `;
    const errors = typeErrors(source, new URL('./consumer.ts', import.meta.url));

    const differLine = source.split('\n').findIndex((line) => line.includes('const differ')) + 1;
    expect(errors.match(/error TS\d+/g)).toHaveLength(1);
    expect(errors).toMatch(new RegExp(`consumer\\.ts\\(${differLine},\\d+\\): error TS2322`));
  }, 60_000);

  // A refusal carries its reason and an acceptance none, so a caller reads `reason` as a string once
  // it knows the list was refused. The consumer below must fail on a refusal without a reason and on
  // an acceptance with one, and nowhere else.
  it('types a verdict as an acceptance, or a refusal with its reason', () => {
    const source = `
      import type { StatusListVerdict } from '../statuslist-acceptance.js';
      declare const verdict: StatusListVerdict;
      export const reason: string = verdict.valid ? 'read' : verdict.reason;
      export const accepted: StatusListVerdict = { valid: true };
      export const refused: StatusListVerdict = { valid: false };
      export const explained: StatusListVerdict = { valid: true, reason: 'read' };
    `;
    const errors = typeErrors(source, new URL('./verdict-consumer.ts', import.meta.url));

    const lineOf = (name: string) => source.split('\n').findIndex((line) => line.includes(`const ${name}`)) + 1;
    expect(errors.match(/error TS\d+/g)).toHaveLength(2);
    expect(errors).toMatch(new RegExp(`verdict-consumer\\.ts\\(${lineOf('refused')},\\d+\\): error TS2322`));
    expect(errors).toMatch(new RegExp(`verdict-consumer\\.ts\\(${lineOf('explained')},\\d+\\): error TS2353`));
  }, 60_000);

  it('is re-exported by those three entries alone', () => {
    const reexport = /^export\b[^;]*?\bfrom\s+['"][^'"]*\/statuslist-acceptance\.js['"]/m;
    const reexporters = sources(join(REPO, 'src')).filter((file) => reexport.test(readFileSync(join(REPO, file), 'utf8')));
    expect(reexporters.sort()).toEqual(['src/card/revocation.ts', 'src/delegation/index.ts', 'src/index.ts']);
  });
});
