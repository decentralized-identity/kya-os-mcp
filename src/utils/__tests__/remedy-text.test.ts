/**
 * A reason cut for length carries a `statusListIssuers` remedy whole or not at all: wherever the
 * cut falls, `sanitizeForMessage` cuts before a remedy it would split, and takes nothing else away.
 */

import { describe, expect, it } from 'vitest';
import { sanitizeForMessage } from '../message-text.js';
import { exactRemedy, GENERAL_REMEDY, withoutPartialRemedy } from '../remedy-text.js';

const HEAD = 'status list issuer "did:web:signer.example" does not keep this list\'s URL: "did:web:issuer.example" does';
const REMEDIES = [
  ['an exact remedy that names the signer', exactRemedy('did:web:signer.example', 'https://issuer.example/lists/1', 'name')],
  ["an exact remedy that moves the URL's binding", exactRemedy('did:web:signer.example', 'https://issuer.example/lists/1', 'move')],
  ['the general remedy', GENERAL_REMEDY],
] as const;

describe('a reason that ends with a statusListIssuers remedy, cut for length', () => {
  it.each(REMEDIES)('holds %s whole or none of it, wherever the cut falls', (_name, remedy) => {
    const words = `wrapper: ${HEAD}`;
    const reason = `${words}${remedy}`;
    for (let length = 1; length <= reason.length + 1; length++) {
      const cut = sanitizeForMessage(reason, length);
      if (length >= reason.length) {
        expect(cut).toBe(reason);
      } else if (length >= words.length + '; if '.length) {
        expect(cut, `cut at ${length}`).toBe(`${words}…`);
      } else {
        // Before the remedy, or within the "; if " that opens it and may open other words.
        expect(cut, `cut at ${length}`).toBe(`${reason.slice(0, length)}…`);
      }
    }
  });

  it('keeps a whole remedy that words after it are cut from', () => {
    const reason = `${HEAD}${GENERAL_REMEDY} (seen by the wrapper)`;
    expect(sanitizeForMessage(reason, reason.length - 5)).toBe(`${reason.slice(0, -5)}…`);
  });

  it('takes away an opening a cut fell in, and nothing that does not open a remedy', () => {
    expect(withoutPartialRemedy(`${HEAD}; if "did:web:sig`)).toBe(HEAD);
    expect(withoutPartialRemedy(`${HEAD}; if the list's iss`)).toBe(HEAD);
    expect(withoutPartialRemedy(`${HEAD}; if `)).toBe(HEAD);
    expect(withoutPartialRemedy(`${HEAD}; i`)).toBe(`${HEAD}; i`);
    expect(withoutPartialRemedy(`${HEAD}; if you retry, it may pass`)).toBe(`${HEAD}; if you retry, it may pass`);
  });

  it('takes away a remedy whose configuration names a value cut short', () => {
    const remedy = exactRemedy('did:web:signer.example', 'https://issuer.example/lists/1', 'name');
    expect(withoutPartialRemedy(`${HEAD}${remedy.slice(0, -4)}`)).toBe(HEAD);
    expect(withoutPartialRemedy(`${HEAD}${remedy}`)).toBe(`${HEAD}${remedy}`);
  });
});
