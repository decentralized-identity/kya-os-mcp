/**
 * A custom signature verifier is code the host supplies, and one written in JavaScript, or one with
 * a fault, can answer anything. Its verdict counts only as an object whose `valid` is the literal
 * `true`: any other answer leaves the signature unverified with a reason that says the verdict
 * could not be read, and nothing throws. Each credential here carries a tampered `proofValue`, so
 * a verdict read by its truthiness would verify a signature that does not hold. The per-credential
 * verifier of `validateDelegationChain` answers in the same shape and is read by the same rule.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import { delegationRecord, keyOf, signedCredential } from '../../__tests__/utils/delegation-credentials.js';
import { issuerDidDocument, methodOf } from '../../__tests__/utils/did-documents.js';
import { revokedProxy } from '../../__tests__/utils/verdict-answers.js';
import type { AgentIdentity } from '../../providers/base.js';
import type { DelegationCredential } from '../../types/protocol.js';
import { validateDelegationChain } from '../chain-enforcement.js';
import { DelegationCredentialVerifier, type SignatureVerificationFunction } from '../vc-verifier.js';

const SERVER = 'did:web:server.example';
const UNREADABLE = "The verdict of the signature verifier could not be read: ";

let issuer: AgentIdentity;
let tampered: DelegationCredential;
beforeAll(async () => {
  issuer = await keyOf('did:web:root.example', 'key');
  const credential = await signedCredential(issuer);
  tampered = { ...credential, proof: { ...credential.proof!, proofValue: 'AAAA' } };
});

/** What the verifier makes of `tampered` when its signature verifier answers `answer`. */
function verdictOn(answer: unknown) {
  const verifier = new DelegationCredentialVerifier({
    didResolver: { resolve: async (did) => (did === issuer.did ? issuerDidDocument(methodOf(issuer)) : null) },
    signatureVerifier: (async () => answer) as SignatureVerificationFunction,
  });
  return verifier.verifyDelegationCredential(tampered, { skipCache: true });
}

/** An object whose `member` throws when read, and that counts how often it was read. */
function throwingOn(member: string, rest: Record<string, unknown>, reads: { count: number }): object {
  return Object.defineProperty({ ...rest }, member, {
    enumerable: true,
    get() {
      reads.count += 1;
      throw new Error('getter boom');
    },
  });
}

describe('a signature verifier whose answer is not a verdict', () => {
  const notAnObject: [string, unknown, string][] = [
    ['undefined', undefined, 'of type undefined'],
    ['null', null, 'of type null'],
    ['true', true, 'of type boolean'],
    ['a string', 'valid', '"valid"'],
    ['an array', [true], 'of type array'],
  ];
  it.each(notAnObject)('leaves the signature unverified when it answers %s', async (_label, answer, described) => {
    expect(await verdictOn(answer)).toMatchObject({
      valid: false,
      stage: 'signature',
      reason: `${UNREADABLE}its answer (${described}) is not an object`,
      checks: { signatureValid: false },
    });
  });

  const notABoolean: [string, unknown, string][] = [
    ['{ valid: "false" }', { valid: 'false' }, '"false"'],
    ['{ valid: "true" }', { valid: 'true' }, '"true"'],
    ['{ valid: 1 }', { valid: 1 }, 'of type number'],
    ['{ valid: {} }', { valid: {} }, 'of type object'],
    ['{ valid: new Boolean(true) }', { valid: new Boolean(true) }, 'of type object'],
    ['{}', {}, 'of type undefined'],
    ['{ valid: null, reason: "x" }', { valid: null, reason: 'x' }, 'of type null'],
  ];
  it.each(notABoolean)('leaves the signature unverified when it answers %s', async (_label, answer, described) => {
    expect(await verdictOn(answer)).toMatchObject({
      valid: false,
      stage: 'signature',
      reason: `${UNREADABLE}the valid member of its answer (${described}) is neither true nor false`,
      checks: { signatureValid: false },
    });
  });

  it('quotes at most the first 64 characters of a valid member that is a string', async () => {
    const result = await verdictOn({ valid: 'y'.repeat(500) });
    expect(result.reason).toBe(`${UNREADABLE}the valid member of its answer ("${'y'.repeat(64)}"...) is neither true nor false`);
  });

  it('reads each member once, and refuses an answer whose valid or reason member throws', async () => {
    for (const [member, rest] of [['valid', { reason: 'x' }], ['reason', { valid: true }], ['reason', { valid: false }]] as const) {
      const reads = { count: 0 };
      expect(await verdictOn(throwingOn(member, rest, reads))).toMatchObject({
        valid: false,
        stage: 'signature',
        reason: `${UNREADABLE}reading its answer threw`,
      });
      expect(reads.count).toBe(1);
    }
  });

  it('refuses, and does not throw on, an answer whose valid member throws when it is looked at', async () => {
    expect(await verdictOn({ valid: revokedProxy() })).toMatchObject({
      valid: false,
      stage: 'signature',
      reason: `${UNREADABLE}reading its answer threw`,
    });
  });

  it('reads valid and reason once each on an answer it accepts', async () => {
    const reads = { valid: 0, reason: 0 };
    const answer = {
      get valid() {
        reads.valid += 1;
        return reads.valid === 1 ? false : true;
      },
      get reason() {
        reads.reason += 1;
        return 'bad signature';
      },
    };
    expect(await verdictOn(answer)).toMatchObject({ valid: false, stage: 'signature', reason: 'bad signature' });
    expect(reads).toEqual({ valid: 1, reason: 1 });
  });
});

describe('a signature verifier that answers a verdict', () => {
  it('verifies on the literal true, and carries no reason', async () => {
    expect(await verdictOn({ valid: true, reason: 'ignored' })).toMatchObject({ valid: true, stage: 'complete', reason: undefined });
  });

  it('refuses on the literal false with the reason the verifier gave, as bounded text', async () => {
    expect(await verdictOn({ valid: false, reason: 'Signature verification failed' })).toMatchObject({
      valid: false,
      stage: 'signature',
      reason: 'Signature verification failed',
    });
    const long = await verdictOn({ valid: false, reason: `line one\n${'z'.repeat(400)}` });
    expect(long.reason).toBe(`line one�${'z'.repeat(247)}…`);
  });

  it('refuses on the literal false with a reason that is not a string as one with no reason', async () => {
    expect(await verdictOn({ valid: false, reason: 7 })).toMatchObject({ valid: false, stage: 'signature', reason: 'Unknown failure' });
    expect(await verdictOn({ valid: false })).toMatchObject({ valid: false, stage: 'signature', reason: 'Unknown failure' });
  });
});

describe("validateDelegationChain's credential verifier", () => {
  const validate = async (answer: unknown) => {
    const leaf = await signedCredential(issuer, {
      record: delegationRecord(issuer.did, {
        id: 'del-leaf',
        constraints: { scopes: ['orders:place'], audience: SERVER, notAfter: Math.floor(Date.now() / 1000) + 3600 },
      }),
    });
    return validateDelegationChain(leaf, {
      serverDid: SERVER,
      verifier: { verifyDelegationCredential: (async () => answer) as never },
      statusListConfigured: false,
    });
  };
  const unreadable = 'Delegation del-leaf invalid: The verdict of the credential verifier could not be read: ';

  it('passes a credential only on the literal true', async () => {
    expect(await validate({ valid: true })).toMatchObject({ valid: true });
  });

  it('refuses the chain, and does not throw, on any other answer', async () => {
    expect(await validate({ valid: 'false' })).toEqual({
      valid: false,
      reason: `${unreadable}the valid member of its answer ("false") is neither true nor false`,
    });
    expect(await validate({ valid: 1 })).toEqual({
      valid: false,
      reason: `${unreadable}the valid member of its answer (of type number) is neither true nor false`,
    });
    expect(await validate(undefined)).toEqual({
      valid: false,
      reason: `${unreadable}its answer (of type undefined) is not an object`,
    });
    expect(await validate(null)).toEqual({ valid: false, reason: `${unreadable}its answer (of type null) is not an object` });
    const reads = { count: 0 };
    expect(await validate(throwingOn('valid', {}, reads))).toEqual({ valid: false, reason: `${unreadable}reading its answer threw` });
    expect(reads.count).toBe(1);
    expect(await validate({ valid: revokedProxy() })).toEqual({ valid: false, reason: `${unreadable}reading its answer threw` });
  });

  it('refuses on the literal false with the reason the verifier gave', async () => {
    expect(await validate({ valid: false, reason: 'expired' })).toEqual({ valid: false, reason: 'Delegation del-leaf invalid: expired' });
  });
});
