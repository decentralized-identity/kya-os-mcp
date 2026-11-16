/**
 * Each refusal of a delegation chain carries a stable code and whether it is transient, beside its
 * reason: the walk's own configuration, the resolver's answer, the chain's linkage and root, each
 * credential's verdict, its audience and scope, and the revocation of every credential of the
 * chain. Every case goes through `validateDelegationChain` as `@kya-os/mcp/delegation` exports it.
 */

import { describe, expect, it } from 'vitest';
import {
  isTransientRefusal,
  validateDelegationChain,
  validateScopeAttenuation,
  type ChainEnforcementDeps,
  type ChainValidationResult,
  type DelegationCredential,
  type RefusalCode,
} from '../index.js';
import { SERVER, baseDeps, chainOfThree, cred, resolving } from './helpers/chain-fixtures.js';

/** A dependency that never answers. */
const never = <T>(): Promise<T> => new Promise<T>(() => undefined);

/** Expect `result` refused with `code`, transient exactly when the code is. */
function expectRefused(result: ChainValidationResult, code: RefusalCode, transient = isTransientRefusal(code)): void {
  expect({ valid: result.valid, code: result.code, transient: result.transient }, result.reason).toEqual({
    valid: false,
    code,
    transient,
  });
}

const { root, middle, leaf } = chainOfThree();

/** The chain of three resolved, with `overrides` on the deps. */
const chainDeps = (overrides: Partial<ChainEnforcementDeps> = {}): ChainEnforcementDeps => ({
  ...resolving([root, middle]),
  ...overrides,
});

/** A per-credential verifier that refuses the credential whose delegation is `id` with `answer`. */
const refusingAt = (id: string, answer: unknown): ChainEnforcementDeps['verifier'] => ({
  verifyDelegationCredential: async (credential) =>
    (credential.credentialSubject.delegation.id === id ? answer : { valid: true }) as { valid: boolean },
});

describe('a chain refused before any credential of it is verified', () => {
  it.each<[string, () => Promise<ChainValidationResult>, RefusalCode, boolean]>([
    ['a leaf that is not a delegation credential', () => validateDelegationChain({} as DelegationCredential, baseDeps), 'delegation_malformed', false],
    ['under a dependencyTimeoutMs it cannot use', () => validateDelegationChain(leaf, chainDeps({ dependencyTimeoutMs: 0 })), 'configuration_error', false],
    [
      'a re-delegated leaf with no resolveDelegationChain configured',
      () => validateDelegationChain(leaf, { ...baseDeps }),
      'configuration_error',
      false,
    ],
    [
      'whose resolver throws',
      () => validateDelegationChain(leaf, chainDeps({ resolveDelegationChain: async () => { throw new Error('store down'); } })),
      'runtime_error',
      true,
    ],
    [
      'whose resolver never answers',
      () => validateDelegationChain(leaf, chainDeps({ resolveDelegationChain: never, dependencyTimeoutMs: 20 })),
      'deadline_exceeded',
      true,
    ],
    ['whose resolver returns no credential', () => validateDelegationChain(leaf, resolving([])), 'chain_invalid', false],
    [
      'whose resolver returns more values than maxChainLength',
      () => validateDelegationChain(leaf, chainDeps({ resolveDelegationChain: async () => [root, middle, leaf], maxChainLength: 2 })),
      'chain_invalid',
      false,
    ],
    [
      'whose resolver returns a value that cannot be copied',
      () => validateDelegationChain(leaf, chainDeps({ snapshotAncestor: () => { throw new Error('not data'); } })),
      'delegation_malformed',
      false,
    ],
    ['whose resolver returns the leaf before an ancestor', () => validateDelegationChain(leaf, resolving([root, leaf, middle])), 'chain_invalid', false],
    [
      'whose resolver returns a value that is not a credential',
      () => validateDelegationChain(leaf, resolving([{} as DelegationCredential, middle])),
      'delegation_malformed',
      false,
    ],
    ['under a maxChainLength that is not a positive integer', () => validateDelegationChain(leaf, chainDeps({ maxChainLength: 0 })), 'configuration_error', false],
    ['longer than maxChainLength', () => validateDelegationChain(leaf, chainDeps({ maxChainLength: 2 })), 'chain_invalid', false],
    [
      'whose credentials do not descend one from another',
      () => validateDelegationChain(leaf, resolving([root, cred({ id: 'middle', issuerDid: 'did:agent', subjectDid: 'did:else', parentId: 'root', audience: SERVER })])),
      'chain_invalid',
      false,
    ],
    ['whose root repeats', () => validateDelegationChain(leaf, resolving([root, root, middle])), 'chain_invalid', false],
    [
      'whose root is issued by a DID trustedRootIssuers does not list',
      () => validateDelegationChain(leaf, chainDeps({ trustedRootIssuers: ['did:web:trusted.example'] })),
      'untrusted_root',
      false,
    ],
    [
      'under a trustedRootIssuers that is not a list of DIDs',
      () => validateDelegationChain(leaf, chainDeps({ trustedRootIssuers: ['trusted'] })),
      'configuration_error',
      false,
    ],
    [
      'whose root names no issuer, under trustedRootIssuers',
      () => validateDelegationChain(leaf, chainDeps({
        resolveDelegationChain: async () => [{ ...root, issuer: 5 } as unknown as DelegationCredential, middle],
        trustedRootIssuers: ['did:user'],
      })),
      'delegation_malformed',
      false,
    ],
  ])('%s', async (_name, validate, code, transient) => {
    expectRefused(await validate(), code, transient);
  });
});

describe('a chain refused as its credentials are verified', () => {
  it.each<[string, Partial<ChainEnforcementDeps>, RefusalCode, boolean]>([
    ['whose credential has a status and no status list is configured', {
      resolveDelegationChain: async () => [cred({ id: 'root', issuerDid: 'did:user', subjectDid: 'did:agent', scopes: ['read', 'list'], withStatus: true }), middle],
      statusListConfigured: false,
    }, 'configuration_error', false],
    ['whose credential the verifier refuses with a code', { verifier: refusingAt('middle', { valid: false, reason: 'gone', code: 'delegation_revoked' }) }, 'delegation_revoked', false],
    ['whose credential the verifier could not decide on', { verifier: refusingAt('root', { valid: false, reason: 'no DID', code: 'did_unavailable' }) }, 'did_unavailable', true],
    ['whose credential the verifier refuses with no code', { verifier: refusingAt('root', { valid: false, reason: 'no' }) }, 'delegation_invalid', false],
    ['whose credential the verifier answers what is not a verdict', { verifier: refusingAt('root', { valid: 'no' }) }, 'runtime_error', true],
    ['whose server is not in the audience of a credential', { serverDid: 'did:web:other.example' }, 'chain_invalid', false],
    [
      'whose re-delegation names no audience',
      { resolveDelegationChain: async () => [root, cred({ id: 'middle', issuerDid: 'did:agent', subjectDid: 'did:sub', parentId: 'root', scopes: ['read'] })] },
      'chain_invalid',
      false,
    ],
    [
      'whose re-delegation is wider than its parent',
      { resolveDelegationChain: async () => [root, cred({ id: 'middle', issuerDid: 'did:agent', subjectDid: 'did:sub', parentId: 'root', scopes: ['admin'], audience: SERVER })] },
      'chain_invalid',
      false,
    ],
  ])('%s', async (_name, overrides, code, transient) => {
    expectRefused(await validateDelegationChain(leaf, chainDeps(overrides)), code, transient);
  });
});

describe('a chain whose leaf is not stable data', () => {
  it('is refused as chain_invalid when the walk ends at another delegation than the leaf it was given', async () => {
    const root = cred({ id: 'root', issuerDid: 'did:user', subjectDid: 'did:agent', scopes: ['read'], audience: SERVER });
    const delegation = { ...root.credentialSubject.delegation };
    let verified = false;
    // The leaf's delegation id reads as `root` until the verifier has passed it, and as another after.
    Object.defineProperty(delegation, 'id', { enumerable: true, get: () => (verified ? 'swapped' : 'root') });
    const shifting = { ...root, credentialSubject: { ...root.credentialSubject, delegation } } as DelegationCredential;
    const verifier: ChainEnforcementDeps['verifier'] = {
      verifyDelegationCredential: async () => {
        verified = true;
        return { valid: true };
      },
    };

    const result = await validateDelegationChain(shifting, { ...baseDeps, verifier });
    expectRefused(result, 'chain_invalid');
    expect(result.reason).toMatch(/ended at .* instead of leaf/);
  });
});

describe('a chain refused by its revocation checker', () => {
  const checking = (isRevoked: (id: string) => Promise<unknown>): Partial<ChainEnforcementDeps> => ({
    revocationChecker: { isRevoked: isRevoked as never },
    dependencyTimeoutMs: 20,
  });

  it.each<[string, Partial<ChainEnforcementDeps>, RefusalCode, boolean]>([
    ['that answers its leaf is revoked', checking(async (id) => ({ revoked: id === 'leaf' })), 'delegation_revoked', false],
    ['that answers an ancestor is revoked', checking(async (id) => ({ revoked: id === 'root' })), 'delegation_revoked', false],
    ['that throws', checking(async () => { throw new Error('graph down'); }), 'status_unavailable', true],
    ['that never answers', checking(never), 'deadline_exceeded', true],
    ['that answers what is not an answer', checking(async () => ({ revoked: 'no' })), 'status_unavailable', true],
  ])('%s', async (_name, overrides, code, transient) => {
    expectRefused(await validateDelegationChain(leaf, chainDeps(overrides)), code, transient);
  });
});

describe('a chain that validates', () => {
  it('carries no code', async () => {
    const result = await validateDelegationChain(leaf, chainDeps({ revocationChecker: { isRevoked: async () => ({ revoked: false }) } }));
    expect(result.valid).toBe(true);
    expect(result).not.toHaveProperty('code');
    expect(result).not.toHaveProperty('transient');
  });
});

describe('validateScopeAttenuation', () => {
  it('refuses a child wider than its parent as chain_invalid, and passes a narrower one with no code', () => {
    expect(validateScopeAttenuation(root, cred({ id: 'c', issuerDid: 'did:agent', subjectDid: 'did:c', scopes: ['admin'] }))).toMatchObject({
      valid: false,
      code: 'chain_invalid',
      transient: false,
    });
    expect(validateScopeAttenuation(root, cred({ id: 'c', issuerDid: 'did:agent', subjectDid: 'did:c' }))).toMatchObject({
      valid: false,
      code: 'chain_invalid',
    });
    expect(validateScopeAttenuation(root, middle)).toEqual({ valid: true });
  });
});
