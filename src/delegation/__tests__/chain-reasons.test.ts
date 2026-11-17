/**
 * The reasons chain enforcement gives when its chain resolver or revocation checker fails or
 * refuses: each quotes the delegation ids it names as `describeValue` quotes any value the other
 * party chose, writes the text it did not write, the words of a `RefusalError` one of them threw or
 * the checker's reason, through `sanitizeForMessage`, cut after 256 UTF-16 code units, with every
 * character `describeValue` escapes and every lone surrogate read as U+FFFD. What else either
 * throws, an `Error` of its own or a value that is no `Error`, is logged, and the reason says only
 * which of them failed.
 */
import { afterEach, describe, it, expect, vi } from 'vitest';
import { chainResolutionFailure, revocationCheckFailure, revokedReason } from '../chain-reasons.js';
import { logger } from '../../logging/index.js';
import { RefusalError } from '../../utils/refusal.js';

afterEach(() => {
  vi.restoreAllMocks();
});

/** A refusal of the host's in `words`. */
const refused = (words: string) => new RefusalError('status_unavailable', words);

/** Text no verifier wrote: a line break, an escape sequence, a lone surrogate, and 300 more units. */
const HOSTILE = `gone\n\u001b[31m\uD800${'x'.repeat(300)}`;
/** HOSTILE as `sanitizeForMessage` writes it: its first 256 units, each unsafe one as U+FFFD, and a mark. */
const SANITIZED = `gone��[31m�${'x'.repeat(256 - 11)}…`;

describe('chain enforcement reasons', () => {
  it('quotes the words of a RefusalError the chain resolver threw, sanitized', () => {
    expect(chainResolutionFailure(refused(HOSTILE))).toBe(`Failed to resolve delegation chain: ${SANITIZED}`);
    expect(chainResolutionFailure(refused('timeout'))).toBe('Failed to resolve delegation chain: timeout');
  });

  it('quotes the words of a RefusalError the revocation checker threw, sanitized, for the delegation it checked', () => {
    expect(revocationCheckFailure('del-1', refused(HOSTILE))).toBe(`Revocation check failed for delegation "del-1": ${SANITIZED}`);
  });

  it('says only which failed, for any other error either threw, and logs its words', () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    expect(chainResolutionFailure(new Error('connect ECONNREFUSED 10.1.2.3:5432'))).toBe('Failed to resolve delegation chain: the chain resolver failed');
    expect(revocationCheckFailure('del-1', new Error('connect ECONNREFUSED 10.1.2.3:6379'))).toBe(
      'Revocation check failed for delegation "del-1": the revocation checker failed',
    );
    expect(warn.mock.calls.map(String)).toEqual([
      '[kya-os] Failed to resolve delegation chain: the chain resolver failed: connect ECONNREFUSED 10.1.2.3:5432',
      '[kya-os] Revocation check failed for delegation "del-1": the revocation checker failed: connect ECONNREFUSED 10.1.2.3:6379',
    ]);
  });

  it('reads a bidirectional control, a line or paragraph separator and a character that renders as nothing in the text as U+FFFD', () => {
    // describeValue escapes each of these, so neither a quoted value nor the text around it can
    // reorder a reason, break its line or hide a character.
    const hidden = ['\u202e', '\u2066', '\u2028', '\u2029', '\u200b', '\u00ad', '\u0600', '\u{E0041}', '\u3164', '\ufe0f'];
    const message = `gone${hidden.join('x')}`;
    const read = `gone${hidden.map(() => '\ufffd').join('x')}`;
    expect(chainResolutionFailure(refused(message))).toBe(`Failed to resolve delegation chain: ${read}`);
    expect(revokedReason('leaf', undefined, message)).toBe(`Delegation "leaf" is revoked: ${read}`);
  });

  it('quotes each delegation id it names as describeValue does, cut after 64 characters and escaped', () => {
    const long = 'd'.repeat(100);
    const quotedLong = `"${'d'.repeat(64)}"...`;
    expect(revocationCheckFailure('del"1\u202e', refused('x'))).toBe('Revocation check failed for delegation "del\\"1\\u202e": x');
    expect(revokedReason(long, 'root\u2028x', undefined)).toBe(`Delegation ${quotedLong} is revoked via ancestor "root\\u2028x"`);
    expect(revokedReason(long, undefined, 'by its issuer')).toBe(`Delegation ${quotedLong} is revoked: by its issuer`);
  });

  it('says only which failed for a thrown value that is not an Error, never converting it', () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const thrown: unknown[] = [HOSTILE, undefined, null, 7, { message: HOSTILE }, { toString: () => HOSTILE }];
    for (const value of thrown) {
      expect(chainResolutionFailure(value)).toBe('Failed to resolve delegation chain: the chain resolver failed');
      expect(revocationCheckFailure('del-1', value)).toBe('Revocation check failed for delegation "del-1": the revocation checker failed');
    }
    expect(warn.mock.calls.map(String).join('\n')).not.toContain('gone');
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
