/**
 * A revocation answer is read strictly, wherever one is read. A custom `StatusListResolver` and a
 * `RevocationChecker` are code the host supplies, and a JavaScript one can answer anything. Only a
 * literal `false` (the status check) or an object whose `revoked` is the literal `false` (the
 * revocation check) lets a credential pass, only a literal `true` revokes it, and every other
 * answer is refused as a status that could not be read. No answer is converted, and none throws.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { createRealSignatureVerifier } from '../../__tests__/audit/helpers/crypto-helpers.js';
import { delegationRecord, keyOf, signedCredential } from '../../__tests__/utils/delegation-credentials.js';
import { issuerDidDocument, methodOf } from '../../__tests__/utils/did-documents.js';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import {
  countingAnswer,
  NOT_BOOLEANS,
  PASSING_WITH_THROWING_CODE,
  THROWING_ANSWERS,
  throwingMember,
} from '../../__tests__/utils/revocation-answers.js';
import type { AgentIdentity } from '../../providers/base.js';
import { isTransientRefusal, type RefusalCode } from '../../refusal-codes.js';
import type { CredentialStatus, DelegationCredential } from '../../types/protocol.js';
import { validateDelegationChain, type RevocationChecker } from '../chain-enforcement.js';
import { withStatusCache } from '../status-cache.js';
import { DelegationCredentialVerifier, type StatusListResolver } from '../vc-verifier.js';

const SERVER = 'did:web:server.example';
const STATUS: CredentialStatus = {
  id: 'https://status.example/1#7',
  type: 'BitstringStatusListEntry',
  statusPurpose: 'revocation',
  statusListIndex: '7',
  statusListCredential: 'https://status.example/1',
};

let issuer: AgentIdentity;
beforeAll(async () => {
  issuer = await keyOf('did:web:root.example', 'key');
});

/** A verifier that resolves the issuer's DID document and reads statuses from `statusListResolver`. */
function verifierWith(statusListResolver?: StatusListResolver): DelegationCredentialVerifier {
  return new DelegationCredentialVerifier({
    didResolver: { resolve: async (did) => (did === issuer.did ? issuerDidDocument(methodOf(issuer)) : null) },
    signatureVerifier: createRealSignatureVerifier(new NodeCryptoProvider()),
    statusListResolver,
  });
}

/** A resolver whose every answer is `answer`, typed as the boolean it claims to be. */
const answering = (answer: unknown): StatusListResolver => ({ checkStatus: async () => answer as boolean });

describe('the delegation status check', () => {
  const verify = async (answer: unknown) =>
    verifierWith(answering(answer)).verifyDelegationCredential(
      await signedCredential(issuer, { credentialStatus: STATUS }),
      { skipCache: true },
    );

  it('passes a credential only on a literal false', async () => {
    expect(await verify(false)).toMatchObject({ valid: true, stage: 'complete' });
  });

  it('refuses a credential as revoked only on a literal true', async () => {
    expect(await verify(true)).toMatchObject({
      valid: false,
      stage: 'status',
      statusOutcome: 'revoked',
      reason: 'Credential revoked via "BitstringStatusListEntry" ("revocation")',
    });
  });

  it.each(NOT_BOOLEANS)('refuses a credential as status_unresolvable when the resolver answers %s', async (_label, answer, named) => {
    expect(await verify(answer)).toMatchObject({
      valid: false,
      stage: 'status',
      statusOutcome: 'status_unresolvable',
      reason: `Credential status could not be read: the status list resolver's answer (${named}) is neither true nor false`,
    });
  });

  it.each([throwingMember('revoked'), throwingMember('reason', { revoked: true })])(
    'refuses a credential on an object with %s, which it does not read',
    async (_label, answer) => {
      expect(await verify(answer)).toMatchObject({
        valid: false,
        stage: 'status',
        statusOutcome: 'status_unresolvable',
        reason: "Credential status could not be read: the status list resolver's answer (of type object) is neither true nor false",
      });
    },
  );

  it('does not keep an unreadable answer in the status cache, so the next check asks again', async () => {
    const answers: unknown[] = [null, false];
    let asked = 0;
    const cached = withStatusCache({ checkStatus: async () => answers[asked++] as boolean }, { maxStalenessMs: 60_000 });
    const verifier = verifierWith(cached);
    const credential = await signedCredential(issuer, { credentialStatus: STATUS });
    expect(await verifier.verifyDelegationCredential(credential, { skipCache: true })).toMatchObject({
      valid: false,
      statusOutcome: 'status_unresolvable',
    });
    expect(await verifier.verifyDelegationCredential(credential, { skipCache: true })).toMatchObject({ valid: true });
    expect(await verifier.verifyDelegationCredential(credential, { skipCache: true })).toMatchObject({ valid: true });
    expect(asked).toBe(2);
  });
});

describe("validateDelegationChain's revocation check", () => {
  const ID = 'del-leaf';
  const REVOKED: RefusalCode = 'delegation_revoked';
  let leaf: DelegationCredential;
  beforeAll(async () => {
    leaf = await signedCredential(issuer, {
      record: delegationRecord(issuer.did, {
        id: ID,
        constraints: { scopes: ['orders:place'], audience: SERVER, notAfter: Math.floor(Date.now() / 1000) + 3600 },
      }),
    });
  });
  const validate = async (answer: unknown) =>
    validateDelegationChain(leaf, {
      serverDid: SERVER,
      verifier: verifierWith(),
      statusListConfigured: false,
      revocationChecker: { isRevoked: async () => answer } as RevocationChecker,
    });
  /** A refusal at the revocation check, which comes after the chain was evaluated: by default, of a status not read. */
  const refused = (reason: string, code: RefusalCode = 'status_unavailable') =>
    ({ valid: false, reason, code, transient: isTransientRefusal(code), evaluated: [leaf] });

  /** Why the chain is refused when the checker's answer is not an object. */
  const notAnObject = (named: string) =>
    `Revocation status of delegation "${ID}" could not be read: the revocation checker's answer (${named}) is not an object`;
  /** Why the chain is refused when the answer's `revoked` member is not a boolean. */
  const notABoolean = (named: string) =>
    `Revocation status of delegation "${ID}" could not be read: the revoked member of the revocation checker's answer (${named}) is neither true nor false`;

  it('passes a chain only on an answer whose revoked is a literal false', async () => {
    expect(await validate({ revoked: false })).toMatchObject({ valid: true });
    expect(await validate({ revoked: false, reason: 'never revoked' })).toMatchObject({ valid: true });
  });

  it('refuses a chain as revoked only on an answer whose revoked is a literal true', async () => {
    expect(await validate({ revoked: true })).toEqual(refused(`Delegation "${ID}" is revoked`, REVOKED));
    expect(await validate({ revoked: true, reason: 'key compromise' })).toEqual(refused(`Delegation "${ID}" is revoked: key compromise`, REVOKED));
    expect(await validate({ revoked: true, revokedAncestor: 'del-root' })).toEqual(refused(`Delegation "${ID}" is revoked via ancestor "del-root"`, REVOKED));
  });

  it('names a revoked chain without a reason or an ancestor that is not a string', async () => {
    expect(await validate({ revoked: true, reason: 5, revokedAncestor: { id: 'del-root' } })).toEqual(refused(`Delegation "${ID}" is revoked`, REVOKED));
  });

  it.each(NOT_BOOLEANS)('refuses a chain when the answer has %s as its revoked member', async (_label, revoked, named) => {
    expect(await validate({ revoked })).toEqual(refused(notABoolean(named)));
  });

  it('refuses a chain when the answer has no revoked member', async () => {
    expect(await validate({})).toEqual(refused(notABoolean('of type undefined')));
    expect(await validate({ reason: 'not revoked' })).toEqual(refused(notABoolean('of type undefined')));
  });

  it.each([
    ['undefined', undefined, 'of type undefined'],
    ['null', null, 'of type null'],
    ['false', false, 'of type boolean'],
    ['true', true, 'of type boolean'],
    ['0', 0, 'of type number'],
    ['an empty string', '', '""'],
    ['the string "false"', 'false', '"false"'],
    ['an array', [{ revoked: false }], 'of type array'],
  ] as const)('refuses a chain when the checker answers %s, not an object', async (_label, answer, named) => {
    expect(await validate(answer)).toEqual(refused(notAnObject(named)));
  });

  it.each(THROWING_ANSWERS)('refuses a chain, and does not reject, on an answer with %s', async (_label, answer, why) => {
    expect(await validate(answer)).toEqual(refused(`Revocation status of delegation "${ID}" could not be read: ${why}`));
  });

  it('passes a chain on an answer that does not revoke, whatever its code getter would do', async () => {
    expect((await validate(PASSING_WITH_THROWING_CODE)).valid).toBe(true);
  });

  it('reads each member of an answer once', async () => {
    for (const members of [{ revoked: false }, { revoked: true, reason: 'key compromise' }]) {
      const { answer, reads } = countingAnswer(members);
      const result = await validate(answer);
      expect(result.valid).toBe(members.revoked === false);
      expect(reads.revoked).toBe(1);
      expect(reads.reason).toBe(1);
      expect(reads.revokedAncestor).toBe(1);
    }
  });
});
