/**
 * The types an enforcement point and a client compile against. `verifyDelegatedCallProof` takes what
 * the call presented as a required input, so the comparison cannot be left out by leaving out an
 * argument, and `generateRequestProof` takes the delegation by itself, never a chain. Each test
 * compiles code that uses the package's public entry point, with strict options.
 */
import { describe, expect, it } from 'vitest';
import { typeErrors } from '../../__tests__/utils/type-errors.js';

/** Where the in-memory module sits, so it imports the entry point as `../../index.js`. */
const AT = new URL('./delegated-call-proof.usage.ts', import.meta.url);
const COMPILE_MS = 60_000;

const PREAMBLE = `
  import {
    generateRequestProof,
    verifyDelegatedCallProof,
    admitsRetainedDelegation,
    type DelegatedCallProofResult,
    type GenerateRequestProofInput,
    type HeldDelegation,
    type KyaOsConfig,
    type VerifyDelegatedCallProofInput,
  } from '../../index.js';
  declare const base: Omit<VerifyDelegatedCallProofInput, 'presented'>;
  declare const client: Omit<GenerateRequestProofInput, 'delegation'>;
  declare const credential: object;
  declare const jwt: string;
  declare const held: HeldDelegation;
`;

describe('the types of a delegated call proof', () => {
  it(
    'compile for a verifier that says what was presented, and a client that names its delegation',
    () => {
      expect(
        typeErrors(
          `${PREAMBLE}
          export async function verified(): Promise<DelegatedCallProofResult[]> {
            return [
              await verifyDelegatedCallProof({ ...base, presented: credential }),
              await verifyDelegatedCallProof({ ...base, presented: jwt, ancestors: [credential], mode: 'require' }),
              await verifyDelegatedCallProof({ ...base, presented: null, mode: 'prefer' }),
            ];
          }
          export async function retained(result: DelegatedCallProofResult): Promise<boolean> {
            return result.status === 'bound' && result.claims !== undefined && admitsRetainedDelegation(result.claims, held);
          }
          export const proofs = [
            generateRequestProof(client),
            generateRequestProof({ ...client, delegation: credential }),
            generateRequestProof({ ...client, delegation: jwt }),
            generateRequestProof({ ...client, delegation: 'none' }),
          ];
          export const config: Pick<KyaOsConfig, 'delegation'> = {
            delegation: { holderBinding: 'enforce', requestBinding: 'require' },
          };
          `,
          AT,
        ),
      ).toBe('');
    },
    COMPILE_MS,
  );

  it(
    'do not compile for a verifier that leaves out what was presented',
    () => {
      const errors = typeErrors(`${PREAMBLE} export const result = verifyDelegatedCallProof(base);`, AT);
      expect(errors).toMatch(/Property 'presented' is missing/);
    },
    COMPILE_MS,
  );

  it(
    'do not compile for a client that passes a chain, or a mode the middleware does not have',
    () => {
      const chain = typeErrors(`${PREAMBLE} export const proof = generateRequestProof({ ...client, delegationChain: [credential] });`, AT);
      expect(chain).toMatch(/'delegationChain' does not exist/);
      const mode = typeErrors(
        `${PREAMBLE} export const config: Pick<KyaOsConfig, 'delegation'> = { delegation: { requestBinding: 'required' } };`,
        AT,
      );
      expect(mode).toMatch(/'"required"' is not assignable/);
    },
    COMPILE_MS,
  );
});
