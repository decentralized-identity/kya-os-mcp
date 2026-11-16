/**
 * Code written against 1.22.0 still compiles. Since then the public results gained a refusal code
 * and whether it is transient, each optional, beside the members they had: a result is read as it
 * was, a double of a public function returns what it returned, and a host's seam answers as it
 * answered. Each test compiles code that uses the package's public entry points, with strict
 * options, and expects no type error.
 */

import { describe, expect, it } from 'vitest';
import { typeErrors } from './utils/type-errors.js';

/** Where the in-memory module sits, so it imports the entry points as `../index.js` and the like. */
const AT = new URL('./public-result-types.usage.ts', import.meta.url);

/** How long compiling a module against the whole package may take. */
const COMPILE_MS = 60_000;

describe('the public results changed since 1.22.0', () => {
  it(
    'compile as 1.22.0 code reads, builds and doubles them',
    () => {
      expect(
        typeErrors(
          `
          import type { DelegationVCVerificationResult, DIDResolver } from '../index.js';
          import {
            validateScopeAttenuation,
            verifyVcJwtSignature,
            type ChainValidationResult,
            type DelegationCredentialVerifierPort,
            type RevocationChecker,
            type SignatureVerificationResult,
            type StatusCheckResult,
            type VcJwtSignatureResult,
          } from '../delegation/index.js';
          import {
            CHECKER_REASON_LENGTH,
            evaluateRevocationChain,
            type BitstringRevocationChecker,
            type DelegationChainResult,
            type DelegationGateResult,
            type RequestDelegationResult,
            type RevocationChainResult,
            type RevocationStatus,
            type VerifyCardResult,
          } from '../card/index.js';
          import type { DelegationCredential } from '../types/protocol.js';

          declare const parent: DelegationCredential;
          declare const child: DelegationCredential;
          declare const level: VerifyCardResult['conformanceLevel'];

          // validateScopeAttenuation: its reason read without narrowing, and a double of it.
          const attenuation = validateScopeAttenuation(parent, child);
          export const summary: { ok: boolean; why?: string } = { ok: attenuation.valid, why: attenuation.reason };
          export const attenuationDouble: typeof validateScopeAttenuation = () => ({ valid: false, reason: 'wider' });

          // verifyVcJwtSignature: its result read and changed, and a double of it.
          export async function signatureOf(jwt: string, resolver: DIDResolver): Promise<VcJwtSignatureResult> {
            const result = await verifyVcJwtSignature(jwt, 'did:web:issuer.example', undefined, resolver);
            if (!result.valid) result.reason = 'refused: ' + (result.reason ?? '');
            return result;
          }
          export const signatureDouble: typeof verifyVcJwtSignature = async () => ({ valid: false, reason: 'bad', durationMs: 1 });

          // The results a host's double or seam builds, as 1.22.0 built them.
          export const verified: DelegationVCVerificationResult = { valid: false, reason: 'expired', stage: 'basic' };
          export const signature: SignatureVerificationResult = { valid: false, reason: 'bad', durationMs: 1 };
          export const status: StatusCheckResult = { valid: false, reason: 'revoked', outcome: 'revoked' };
          export const chain: ChainValidationResult = { valid: false, reason: 'too deep' };
          export const port: DelegationCredentialVerifierPort = {
            verifyDelegationCredential: async () => ({ valid: false, reason: 'no' }),
          };
          export const ancestors: RevocationChecker = { isRevoked: async () => ({ revoked: true, reason: 'revoked' }) };
          export const resolver: DIDResolver = { resolve: async () => null };
          export const revocation: RevocationStatus = { revoked: true, fresh: false, reason: 'unreadable' };
          export const check: BitstringRevocationChecker = async () => ({ revoked: false, fresh: true });
          export const walk: RevocationChainResult = { ok: false, fresh: false, reasons: ['revoked'] };
          export const walked: Promise<RevocationChainResult> = evaluateRevocationChain([], check);
          export const cardChain: DelegationChainResult = { ok: false, reasons: ['x'], allowedAction: [], depth: 0 };
          export const card: VerifyCardResult = {
            ok: true, entityType: 'agent', conformanceLevel: level, verifiedCapabilities: [], attestations: [],
            revocation: { revoked: false, fresh: true },
          };
          export const rejected: RequestDelegationResult = { ok: false, code: 'delegation_missing', reasons: [] };
          export const gate: DelegationGateResult = {
            ok: false, status: 401, error: { code: 'delegation_missing', message: 'none', reasons: [] },
          };
          export const length: number = CHECKER_REASON_LENGTH;
          `,
          AT,
        ),
      ).toBe('');
    },
    COMPILE_MS,
  );
});

describe("the delegation RevocationChecker port's answer", () => {
  it(
    'lets a host state the code of a revocation, and whether it is transient, without a cast',
    () => {
      expect(
        typeErrors(
          `
          import type { RefusalCode } from '../index.js';
          import type { RevocationChecker } from '../delegation/index.js';

          declare const suspended: RefusalCode;
          export const checker: RevocationChecker = {
            isRevoked: async () => ({ revoked: true, reason: 'suspended', code: suspended, transient: false }),
          };
          export class Registry implements RevocationChecker {
            async isRevoked(delegationId: string) {
              if (delegationId === 'urn:suspended') return { revoked: true, code: suspended, transient: false };
              return { revoked: false };
            }
          }
          export const stated: Awaited<ReturnType<RevocationChecker['isRevoked']>> = {
            revoked: true, reason: 'revoked', code: 'delegation_revoked', transient: false,
          };
          `,
          AT,
        ),
      ).toBe('');
    },
    COMPILE_MS,
  );
});
