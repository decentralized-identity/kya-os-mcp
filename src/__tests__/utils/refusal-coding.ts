/**
 * The `code` and `transient` a test expects beside a refusal it checks for something else, such as
 * its reason: the code a set status bit carries, the codes of a status that could not be proven
 * clear, and any code at all where the test is about the reason alone. The codes themselves are
 * pinned by the refusal-code tests of each family.
 */

import { expect } from 'vitest';
import { isTransientRefusal, type RefusalCode } from '../../refusal-codes.js';

/** The code and transient flag of `code`. */
export function codedAs(code: RefusalCode): { code: RefusalCode; transient: boolean } {
  return { code, transient: isTransientRefusal(code) };
}

/** What a status read from a set bit carries. */
export const BIT_SET = codedAs('delegation_revoked');

/** Any code and transient flag, for a refusal a test checks only by its reason. */
export const ANY_CODE = { code: expect.any(String) as string, transient: expect.any(Boolean) as boolean };
