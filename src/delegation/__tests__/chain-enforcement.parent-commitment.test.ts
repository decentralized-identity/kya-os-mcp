/**
 * A re-delegation's commitment to its parent in the base profile (SPEC.md §6.2):
 * `credentialSubject.delegation.parentCredentialDigest`, the digest §7.8 gives the parent credential.
 * A credential is otherwise tied to its parent by names alone, the parent's delegation id and its
 * subject, so a parent issued again under the same id would carry every credential issued under the
 * first. The issuer writes the digest when it is handed the parent; the chain walk checks it whenever
 * a credential states it, before any credential is verified, and tells the presenter of a refusal
 * only what the presented credential states.
 */
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { delegationCredentialDigest } from '../chain-digest.js';
import { validateDelegationChain, type ChainEnforcementDeps, type DelegationCredentialVerifierPort } from '../chain-enforcement.js';
import { commitsTo } from '../parent-commitment.js';
import { logger } from '../../logging/index.js';
import { WebCryptoProvider } from '../../providers/web-crypto.js';
import type { DelegationCredential } from '../../types/protocol.js';
import { nodeCrypto } from '../../__tests__/utils/node-crypto-provider.js';
import { delegate, party, reissued, type Party } from '../../middleware/__tests__/helpers/delegating-party.js';
import { WITHHELD_SUFFIX } from '../../utils/thrown-words.js';

const SERVER = 'did:web:server.example';
const hash = (bytes: Uint8Array): Promise<string> => nodeCrypto.hash(bytes);
const SCOPES = ['payments:send'];

/** Deps that resolve `ancestors`, and record each credential the verifier port is asked about. */
function resolving(ancestors: DelegationCredential[]): ChainEnforcementDeps & { asked: string[] } {
  const asked: string[] = [];
  const verifier: DelegationCredentialVerifierPort = {
    verifyDelegationCredential: async (credential) => {
      asked.push(credential.credentialSubject.delegation.id);
      return { valid: true };
    },
  };
  return { serverDid: SERVER, verifier, statusListConfigured: true, resolveDelegationChain: async () => ancestors, asked };
}

/** `credential` stating `stated` as its `parentCredentialDigest`, whatever it stated before. */
const stating = (credential: DelegationCredential, stated: unknown): DelegationCredential => ({
  ...credential,
  credentialSubject: {
    ...credential.credentialSubject,
    delegation: { ...credential.credentialSubject.delegation, parentCredentialDigest: stated as string },
  },
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('a parent commitment in a base profile chain', () => {
  let user: Party;
  let agent: Party;
  let subAgent: Party;
  let tool: Party;
  let root: DelegationCredential;
  let middle: DelegationCredential;
  let leaf: DelegationCredential;

  beforeAll(async () => {
    [user, agent, subAgent, tool] = await Promise.all([party(), party(), party(), party()]);
    root = await delegate(user, agent.did, { id: 'root', scopes: SCOPES });
    middle = await delegate(agent, subAgent.did, { id: 'middle', parent: root, commits: true, audience: SERVER, scopes: SCOPES });
    leaf = await delegate(subAgent, tool.did, { id: 'leaf', parent: middle, commits: true, audience: SERVER, scopes: SCOPES });
  });

  it('is written by the issuer handed the parent: the digest SPEC §7.8 gives that credential', async () => {
    expect(middle.credentialSubject.delegation.parentCredentialDigest).toBe(await delegationCredentialDigest(root, hash));
    expect(leaf.credentialSubject.delegation.parentCredentialDigest).toBe(await delegationCredentialDigest(middle, hash));
    expect(root.credentialSubject.delegation).not.toHaveProperty('parentCredentialDigest');
  });

  it('is not written without the parent, as before', async () => {
    const plain = await delegate(agent, subAgent.did, { parent: root, audience: SERVER, scopes: SCOPES });
    expect(plain.credentialSubject.delegation).not.toHaveProperty('parentCredentialDigest');
  });

  it('is not written for a parent the delegation does not name, or one delegated to another', async () => {
    const record = { id: 'onward', issuerDid: agent.did, subjectDid: subAgent.did, constraints: { scopes: SCOPES } };
    const elsewhere = await delegate(user, agent.did, { id: 'elsewhere', scopes: SCOPES });
    await expect(agent.issuer.createAndIssueDelegation({ ...record, parentId: 'root' }, { parent: elsewhere })).rejects.toThrow(TypeError);
    await expect(agent.issuer.createAndIssueDelegation(record, { parent: root })).rejects.toThrow(/parentId/);
    await expect(subAgent.issuer.createAndIssueDelegation({ ...record, issuerDid: subAgent.did, parentId: 'root' }, { parent: root })).rejects.toThrow(
      /not delegated to this issuer/,
    );
  });

  it('holds for a chain whose every re-delegation states its parent', async () => {
    expect(await validateDelegationChain(leaf, resolving([root, middle]))).toMatchObject({ valid: true });
  });

  it('is not asked of a chain that states none, which validates as before', async () => {
    const plainMiddle = await delegate(agent, subAgent.did, { id: 'middle', parent: root, audience: SERVER, scopes: SCOPES });
    const plainLeaf = await delegate(subAgent, tool.did, { id: 'leaf', parent: plainMiddle, audience: SERVER, scopes: SCOPES });
    expect(await validateDelegationChain(plainLeaf, resolving([root, plainMiddle]))).toMatchObject({ valid: true });
    // The residual: with no commitment, a parent issued again under the same id carries the credential.
    const again = { ...(await reissued(agent, plainMiddle, { scopes: SCOPES })), issuanceDate: '2026-01-01T00:00:00.000Z' };
    expect(await delegationCredentialDigest(again, hash)).not.toBe(await delegationCredentialDigest(plainMiddle, hash));
    expect(await validateDelegationChain(plainLeaf, resolving([root, again]))).toMatchObject({ valid: true });
  });

  it('refuses the presented credential under a parent issued again under the same id, before any credential is verified', async () => {
    const again = await reissued(agent, middle, { scopes: [...SCOPES, 'payments:refund'] });
    expect(again.credentialSubject.delegation.id).toBe('middle');
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const deps = resolving([root, again]);

    expect(await validateDelegationChain(leaf, deps)).toEqual({
      valid: false,
      reason: `Delegation "leaf" states a parentCredentialDigest that is not the digest of the parent its chain resolves to${WITHHELD_SUFFIX}`,
      code: 'chain_invalid',
      transient: false,
    });
    expect(deps.asked).toEqual([]);
    expect(warn.mock.calls.flat().join('\n')).toContain('is not the digest of its parent middle as resolved');
  });

  it('tells the presenter only that its chain is broken when an ancestor commits to another parent', async () => {
    const again = await reissued(user, root, { scopes: [...SCOPES, 'payments:refund'] });
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);

    expect(await validateDelegationChain(leaf, resolving([again, middle]))).toMatchObject({
      valid: false,
      reason: `Delegation "leaf" does not descend from a root through the chain its parent resolves to${WITHHELD_SUFFIX}`,
      code: 'chain_invalid',
    });
    expect(warn.mock.calls.flat().join('\n')).toContain('Delegation middle states a parentCredentialDigest that is not the digest of its parent root as resolved');
  });

  it.each([
    ['null', null],
    ['a digest of another form', 'sha256:abc'],
    ['an empty string', ''],
    ['a number', 7],
  ])('refuses a credential that states %s: it states the member, and it is not its parent digest', async (_form, stated) => {
    expect(await validateDelegationChain(stating(leaf, stated), resolving([root, middle]))).toMatchObject({
      valid: false,
      code: 'chain_invalid',
      reason: `Delegation "leaf" states a parentCredentialDigest that is not the digest of the parent its chain resolves to${WITHHELD_SUFFIX}`,
    });
  });

  it('refuses a commitment to a parent that has no signed form, which has no digest', async () => {
    const { proof: _proof, ...unsigned } = middle;
    expect(await validateDelegationChain(leaf, resolving([root, unsigned as DelegationCredential]))).toMatchObject({
      valid: false,
      code: 'chain_invalid',
    });
  });

  it('reports a hash that fails as that failure, never as a commitment that does not hold', async () => {
    const digest = await delegationCredentialDigest(root, hash);
    expect(await commitsTo(digest, root, hash)).toBe(true);
    const failing = (): Promise<string> => Promise.reject(new Error('no hash'));
    await expect(commitsTo(digest, root, failing)).rejects.toThrow('no hash');
  });

  it('refuses a chain whose parent cannot be digested as a fault, before any credential is verified', async () => {
    vi.spyOn(WebCryptoProvider.prototype, 'hash').mockRejectedValue(new Error('no hash'));
    const deps = resolving([root, middle]);
    expect(await validateDelegationChain(leaf, deps)).toMatchObject({
      valid: false,
      code: 'runtime_error',
      reason: 'Delegation chain could not be checked: a parent credential could not be digested',
    });
    expect(deps.asked).toEqual([]);
  });

  it('refuses a root that states one, presented or resolved, since it has no parent credential', async () => {
    const digest = await delegationCredentialDigest(root, hash);
    expect(await validateDelegationChain(stating(root, digest), resolving([]))).toMatchObject({
      valid: false,
      code: 'chain_invalid',
      reason: 'Delegation "root" has no parent credential, so it states no parentCredentialDigest',
    });

    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const statingRoot = stating(root, digest);
    const under = await delegate(agent, subAgent.did, { id: 'under', parent: statingRoot, audience: SERVER, scopes: SCOPES });
    expect(await validateDelegationChain(under, resolving([statingRoot]))).toMatchObject({
      valid: false,
      code: 'chain_invalid',
      reason: `Delegation "under" does not descend from a root through the chain its parent resolves to${WITHHELD_SUFFIX}`,
    });
    expect(warn.mock.calls.flat().join('\n')).toContain('Root delegation root has no parent credential');
  });
});
