/**
 * What a verifier needs to hold a proof against a delegation chain is
 * exported from the package root and from the entry point of the module it
 * lives in. The two are one surface: code written against either imports the
 * same thing under the same name.
 */
import { describe, expect, it } from 'vitest';
import * as root from '../index.js';
import * as delegation from '../delegation/index.js';
import * as proof from '../proof/index.js';
import * as chainDigest from '../delegation/chain-digest.js';
import * as delegationRef from '../delegation/delegation-ref.js';
import * as signedForm from '../delegation/signed-form.js';
import { typeErrors } from './utils/type-errors.js';

type Module = Record<string, unknown>;

describe('the exports for binding a proof to a delegation chain', () => {
  it.each([
    ['the chain digest', chainDigest as Module],
    ['the delegation reference', delegationRef as Module],
  ])('are all of %s module, from the root and from ./delegation alike', (_name, module) => {
    const names = Object.keys(module);
    expect(names.length).toBeGreaterThan(0);
    for (const name of names) {
      expect((root as Module)[name], `${name} from the root`).toBe(module[name]);
      expect((delegation as Module)[name], `${name} from ./delegation`).toBe(module[name]);
    }
  });

  it('are the signed form a digest is taken over, and none of how a credential is read to get it', () => {
    const exported = ['MAX_CREDENTIAL_NESTING_DEPTH', 'NoSignedFormError', 'signedForm', 'signingInput'];
    for (const entry of [root as Module, delegation as Module]) {
      expect(Object.keys(signedForm).filter((name) => name in entry).sort()).toEqual(exported);
      for (const name of exported) expect(entry[name]).toBe((signedForm as Module)[name]);
    }
  });

  it('are the bound on how deep a credential nests, from the root and from ./delegation alike', () => {
    expect(root.MAX_CREDENTIAL_NESTING_DEPTH).toBe(64);
    expect(delegation.MAX_CREDENTIAL_NESTING_DEPTH).toBe(root.MAX_CREDENTIAL_NESTING_DEPTH);
  });

  it('are the codes a verifier reports a binding by, from the root and from ./proof alike', () => {
    expect(proof.PROOF_VERIFICATION_ERROR_CODES).toBe(root.PROOF_VERIFICATION_ERROR_CODES);
    expect(root.PROOF_VERIFICATION_ERROR_CODES).toMatchObject({
      CONTENT_BINDING_MISMATCH: 'CONTENT_BINDING_MISMATCH',
      OUTCOME_MISMATCH: 'OUTCOME_MISMATCH',
      DELEGATION_BINDING_MISMATCH: 'DELEGATION_BINDING_MISMATCH',
    });
  });

  // The types have no value to compare, so a consumer module is compiled that
  // holds each pair to be one type, and one pair that is not, which must be
  // the only error: the check can fail, and fails for nothing else.
  it('are the same types from each entry point', () => {
    const source = `
      import type * as root from '../index.js';
      import type * as delegation from '../delegation/index.js';
      import type * as proof from '../proof/index.js';
      type Same<A, B> = (<T>() => T extends A ? 1 : 2) extends (<T>() => T extends B ? 1 : 2) ? true : false;
      export const same: [
        Same<root.ReceivedCredential, delegation.ReceivedCredential>,
        Same<root.DelegationChainDigests, delegation.DelegationChainDigests>,
        Same<root.SignedForm, delegation.SignedForm>,
        Same<root.SignedCredential, delegation.SignedCredential>,
        Same<root.SignedJwt, delegation.SignedJwt>,
        Same<root.Sha256, delegation.Sha256>,
        Same<root.ExpectedContent, proof.ExpectedContent>,
        Same<root.ProofBindingMismatch, proof.ProofBindingMismatch>,
      ] = [true, true, true, true, true, true, true, true];
      export const differ: Same<root.SignedCredential, delegation.SignedJwt> = true;
    `;
    const errors = typeErrors(source, new URL('./consumer.ts', import.meta.url));

    const differLine = source.split('\n').findIndex((line) => line.includes('const differ')) + 1;
    expect(errors.match(/error TS\d+/g)).toHaveLength(1);
    expect(errors).toMatch(new RegExp(`consumer\\.ts\\(${differLine},\\d+\\): error TS2322`));
  });

  // `Sha256` is the type of the hash every digest and reference function
  // takes, so a caller can name what it passes them. Code that binds a
  // `CryptoProvider` to it compiles, and code that passes something else
  // in its place does not, which must be the only error.
  it.each([
    ['the root', '../index.js'],
    ['./delegation', '../delegation/index.js'],
  ])('are the type of the hash the digests take, from %s, which a bound CryptoProvider is', (_name, entry) => {
    const source = `
      import { delegationCredentialDigest, delegationRefOf, type Sha256 } from '${entry}';
      import type { CryptoProvider } from '../index.js';
      export const bind = (provider: CryptoProvider): Sha256 => (bytes) => provider.hash(bytes);
      export const digest = (provider: CryptoProvider) => delegationCredentialDigest('a.b.c', bind(provider));
      export const reference = (hash: Sha256) => delegationRefOf('a.b.c', hash);
      export const wrong: Sha256 = (text: string) => Promise.resolve(text);
    `;
    const errors = typeErrors(source, new URL('./consumer.ts', import.meta.url));

    const wrongLine = source.split('\n').findIndex((line) => line.includes('const wrong')) + 1;
    expect(errors.match(/error TS\d+/g)).toHaveLength(1);
    expect(errors).toMatch(new RegExp(`consumer\\.ts\\(${wrongLine},\\d+\\): error TS2322`));
  });
});
