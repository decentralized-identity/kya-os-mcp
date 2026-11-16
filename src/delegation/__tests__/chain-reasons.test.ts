/**
 * The reasons chain enforcement gives when its chain resolver or revocation checker fails or
 * refuses: each quotes the delegation ids it names as `describeValue` quotes any value the other
 * party chose, writes the text it did not write, an error's message or the checker's reason,
 * through `sanitizeForMessage`, cut after 256 UTF-16 code units, with every character
 * `describeValue` escapes and every lone surrogate read as U+FFFD, and names a thrown value that is
 * not an `Error` as an unknown error.
 */
import { describe, it, expect } from 'vitest';
import { chainResolutionFailure, revocationCheckFailure, revokedReason } from '../chain-reasons.js';

/** Text no verifier wrote: a line break, an escape sequence, a lone surrogate, and 300 more units. */
const HOSTILE = `gone\n\u001b[31m\uD800${'x'.repeat(300)}`;
/** HOSTILE as `sanitizeForMessage` writes it: its first 256 units, each unsafe one as U+FFFD, and a mark. */
const SANITIZED = `gone��[31m�${'x'.repeat(256 - 11)}…`;

describe('chain enforcement reasons', () => {
  it('quotes the message of the error the chain resolver threw, sanitized', () => {
    expect(chainResolutionFailure(new Error(HOSTILE))).toBe(`Failed to resolve delegation chain: ${SANITIZED}`);
    expect(chainResolutionFailure(new Error('timeout'))).toBe('Failed to resolve delegation chain: timeout');
  });

  it('quotes the message of the error the revocation checker threw, sanitized, for the delegation it checked', () => {
    expect(revocationCheckFailure('del-1', new Error(HOSTILE))).toBe(`Revocation check failed for delegation "del-1": ${SANITIZED}`);
  });

  it('reads a bidirectional control, a line or paragraph separator and a character that renders as nothing in the text as U+FFFD', () => {
    // describeValue escapes each of these, so neither a quoted value nor the text around it can
    // reorder a reason, break its line or hide a character.
    const hidden = ['\u202e', '\u2066', '\u2028', '\u2029', '\u200b', '\u00ad', '\u0600', '\u{E0041}', '\u3164', '\ufe0f'];
    const message = `gone${hidden.join('x')}`;
    const read = `gone${hidden.map(() => '\ufffd').join('x')}`;
    expect(chainResolutionFailure(new Error(message))).toBe(`Failed to resolve delegation chain: ${read}`);
    expect(revokedReason('leaf', undefined, message)).toBe(`Delegation "leaf" is revoked: ${read}`);
  });

  it('quotes each delegation id it names as describeValue does, cut after 64 characters and escaped', () => {
    const long = 'd'.repeat(100);
    const quotedLong = `"${'d'.repeat(64)}"...`;
    expect(revocationCheckFailure('del"1\u202e', new Error('x'))).toBe('Revocation check failed for delegation "del\\"1\\u202e": x');
    expect(revokedReason(long, 'root\u2028x', undefined)).toBe(`Delegation ${quotedLong} is revoked via ancestor "root\\u2028x"`);
    expect(revokedReason(long, undefined, 'by its issuer')).toBe(`Delegation ${quotedLong} is revoked: by its issuer`);
  });

  it('names a thrown value that is not an Error as an unknown error, never converting it', () => {
    const thrown: unknown[] = [HOSTILE, undefined, null, 7, { message: HOSTILE }, { toString: () => HOSTILE }];
    for (const value of thrown) {
      expect(chainResolutionFailure(value)).toBe('Failed to resolve delegation chain: Unknown error');
      expect(revocationCheckFailure('del-1', value)).toBe('Revocation check failed for delegation "del-1": Unknown error');
    }
  });

  it('says a delegation is revoked, with the reason the revocation checker gave, sanitized', () => {
    expect(revokedReason('leaf', undefined, HOSTILE)).toBe(`Delegation "leaf" is revoked: ${SANITIZED}`);
    expect(revokedReason('leaf', undefined, 'by its issuer')).toBe('Delegation "leaf" is revoked: by its issuer');
  });

  it('says a delegation is revoked, and nothing more, when the checker gave no reason', () => {
    expect(revokedReason('leaf', undefined, undefined)).toBe('Delegation "leaf" is revoked');
    expect(revokedReason('leaf', undefined, '')).toBe('Delegation "leaf" is revoked');
  });

  it('names the revoked ancestor instead of any reason the checker gave', () => {
    expect(revokedReason('leaf', 'root', HOSTILE)).toBe('Delegation "leaf" is revoked via ancestor "root"');
    expect(revokedReason('leaf', 'root', undefined)).toBe('Delegation "leaf" is revoked via ancestor "root"');
  });
});
