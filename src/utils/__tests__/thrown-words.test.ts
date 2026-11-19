import { afterEach, describe, expect, it, vi } from 'vitest';
import { logger } from '../../logging/index.js';
import { RefusalError } from '../refusal.js';
import { thrownReason, unreadStatusList, WITHHELD_SUFFIX } from '../thrown-words.js';

describe('thrownReason', () => {
  afterEach(() => vi.restoreAllMocks());

  it("ends a withheld reason by saying the verifier's log has the detail, and logs the words without saying so", () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);

    const reason = thrownReason(new Error('connect ECONNREFUSED 10.0.0.7:443'), { withheld: 'proof did not verify', tag: '[kya-os]' });

    expect(reason).toBe("proof did not verify; the verifier's log says why");
    expect(warn.mock.calls).toEqual([['[kya-os] proof did not verify: connect ECONNREFUSED 10.0.0.7:443']]);
  });

  it('says so only where the log was given the words: a reason that shows them logs nothing and points nowhere', () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);

    const reason = thrownReason(new RefusalError('did_invalid', 'the DID names a private host'), {
      withheld: 'proof did not verify',
      shown: (words) => `DID refused: ${words}`,
      tag: '[kya-os]',
    });

    expect(reason).toBe('DID refused: the DID names a private host');
    expect(reason).not.toContain(WITHHELD_SUFFIX);
    expect(warn).not.toHaveBeenCalled();
  });

  it('tells whoever presented a status list it could not read the URL they chose, and where the detail went, and nothing the network answered', () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);

    const reason = thrownReason(new Error('HTTP 503 from 10.1.2.3'), {
      withheld: unreadStatusList('https://issuer.example/lists/1'),
      tag: '[revocation]',
    });

    expect(reason).toBe(`the status list at "https://issuer.example/lists/1" could not be read or checked; the verifier's log says why`);
    expect(reason).not.toMatch(/503|10\.1\.2\.3/);
    expect(warn.mock.calls).toEqual([['[revocation] the status list at "https://issuer.example/lists/1" could not be read or checked: HTTP 503 from 10.1.2.3']]);
  });
});
