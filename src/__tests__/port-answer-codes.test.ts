/**
 * A host's seam may state the code of its refusal, and the library reads only the codes of its
 * catalog from it, so the code a seam answers is typed `string`: an answer whose code comes from a
 * variable, a configuration or JSON compiles, as one written as a literal of the catalog does. The
 * seams are a `RevocationChecker`, a `SignatureVerificationFunction` and a `DelegationVerifier`. The
 * test compiles code that uses the package's public entry points, with strict options, and expects
 * no type error.
 */

import { describe, expect, it } from 'vitest';
import { typeErrors } from './utils/type-errors.js';

/** Where the in-memory module sits, so it imports the entry points as `../index.js` and the like. */
const AT = new URL('./port-answer-codes.usage.ts', import.meta.url);

/** How long compiling a module against the whole package may take. */
const COMPILE_MS = 60_000;

describe("the code a host's seam answers", () => {
  it(
    'compiles as a string, read from a variable, and as a literal of the catalog',
    () => {
      expect(
        typeErrors(
          `
          import type { DelegationVerifier, SignatureVerificationFunction } from '../index.js';
          import type { RevocationChecker } from '../delegation/index.js';

          declare const configured: { code: string; reason: string };

          export const revocationChecker: RevocationChecker = {
            isRevoked: async () => ({ revoked: true, reason: configured.reason, code: configured.code }),
          };
          export const literalChecker: RevocationChecker = {
            isRevoked: async () => ({ revoked: true, code: 'delegation_revoked' }),
          };
          export const signatureVerifier: SignatureVerificationFunction = async () => ({
            valid: false,
            reason: configured.reason,
            code: configured.code,
          });
          export const delegationVerifier: DelegationVerifier = {
            verify: async () => ({ valid: false, reason: configured.reason, code: configured.code }),
          };
          `,
          AT,
        ),
      ).toBe('');
    },
    COMPILE_MS,
  );
});
