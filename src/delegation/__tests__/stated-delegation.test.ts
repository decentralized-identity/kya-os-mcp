/**
 * The delegation a request proof states in its JWS protected header (SPEC §7.8): what a holder
 * writes for the credential it presents, how a verifier reads the parameter back, and what each
 * reading comes to beside the credential a call presented.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import { delegationCredentialDigest } from '../chain-digest.js';
import { NoSignedFormError } from '../signed-form.js';
import {
  DELEGATION_HEADER_PARAMETER,
  NO_DELEGATION,
  delegationStatement,
  requestBindingMode,
  statedDelegationOf,
  statementParameters,
  statementRefusal,
  unnamedStatementRefusal,
  type RequestBindingMode,
  type StatedDelegation,
  type StatementRefusal,
  type UnnamedStatement,
} from '../stated-delegation.js';
import type { DelegationCredential } from '../../types/protocol.js';
import { nodeCrypto as crypto } from '../../__tests__/utils/node-crypto-provider.js';
import { delegate, party } from '../../middleware/__tests__/helpers/delegating-party.js';

const hash = (bytes: Uint8Array): Promise<string> => crypto.hash(bytes);
const DIGEST = `sha256:${'ab'.repeat(32)}`;
const OTHER = `sha256:${'cd'.repeat(32)}`;
const header = (value: unknown) => ({ alg: 'EdDSA', kid: 'did:key:z6Mk#z6Mk', [DELEGATION_HEADER_PARAMETER]: value });

describe('the statement a holder writes', () => {
  let credential: DelegationCredential;

  beforeAll(async () => {
    const [issuer, agent] = await Promise.all([party(), party()]);
    credential = await delegate(issuer, agent.did);
  });

  it('is the SPEC §7.8 digest of the credential presented, in the form it is sent', async () => {
    expect(await delegationStatement(credential, hash)).toBe(await delegationCredentialDigest(credential, hash));
  });

  it('is "none" for a call that presents no delegation', async () => {
    expect(NO_DELEGATION).toBe('none');
    expect(await delegationStatement(NO_DELEGATION, hash)).toBe('none');
  });

  it('is not made for a value with no signed form', async () => {
    await expect(delegationStatement({ not: 'a credential' }, hash)).rejects.toThrow(NoSignedFormError);
    await expect(delegationStatement('not-a-jwt', hash)).rejects.toThrow(NoSignedFormError);
  });
});

describe("the header parameters a holder's proof states its delegation with", () => {
  let sent: DelegationCredential;
  let named: DelegationCredential;
  const parameter = (value: string) => ({ [DELEGATION_HEADER_PARAMETER]: value });

  beforeAll(async () => {
    const [issuer, agent] = await Promise.all([party(), party()]);
    [sent, named] = await Promise.all([delegate(issuer, agent.did), delegate(issuer, agent.did, { scopes: ['other:scope'] })]);
  });

  it('state the delegation the request sends, with no word from the holder', async () => {
    expect(await statementParameters(undefined, sent, hash)).toEqual(parameter(await delegationCredentialDigest(sent, hash)));
  });

  it('state "none" for a request that sends no delegation, left out or null', async () => {
    expect(await statementParameters(undefined, undefined, hash)).toEqual(parameter('none'));
    expect(await statementParameters(undefined, null, hash)).toEqual(parameter('none'));
  });

  it("state the holder's own word over what the request sends", async () => {
    const digest = await delegationCredentialDigest(named, hash);
    expect(await statementParameters(named, sent, hash)).toEqual(parameter(digest));
    expect(await statementParameters(named, undefined, hash)).toEqual(parameter(digest));
    expect(await statementParameters(NO_DELEGATION, sent, hash)).toEqual(parameter('none'));
  });

  it('state nothing for a delegation the request sends that has no signed form', async () => {
    for (const unsigned of [{ not: 'a credential' }, 'not-a-jwt', 7, false, []]) {
      expect(await statementParameters(undefined, unsigned, hash)).toEqual({});
    }
  });

  it("throw for the holder's own word when it has no signed form", async () => {
    await expect(statementParameters('not-a-jwt', sent, hash)).rejects.toThrow(NoSignedFormError);
  });

  it('pass on a failure of the hash, which is no statement about the delegation', async () => {
    const failing = (): Promise<string> => Promise.reject(new Error('no hash'));
    await expect(statementParameters(undefined, sent, failing)).rejects.toThrow('no hash');
  });
});

describe('the statement a verifier reads from a protected header', () => {
  it.each<[string, unknown, StatedDelegation]>([
    ['a credential digest', DIGEST, { kind: 'credential', digest: DIGEST }],
    ['"none"', 'none', { kind: 'none' }],
    ['a digest in upper case', DIGEST.toUpperCase(), { kind: 'malformed' }],
    ['a digest of another length', `${DIGEST}00`, { kind: 'malformed' }],
    ['an empty string', '', { kind: 'malformed' }],
    ['null', null, { kind: 'malformed' }],
    ['a number', 7, { kind: 'malformed' }],
    ['an array holding a digest', [DIGEST], { kind: 'malformed' }],
    ['"None"', 'None', { kind: 'malformed' }],
  ])('reads %s', (_name, value, expected) => {
    expect(statedDelegationOf(header(value))).toEqual(expected);
  });

  it('reads a header without the parameter, or no header at all, as stating nothing', () => {
    expect(statedDelegationOf({ alg: 'EdDSA', kid: 'k' })).toEqual({ kind: 'absent' });
    expect(statedDelegationOf(undefined)).toEqual({ kind: 'absent' });
  });

  it('reads only a member the header holds itself', () => {
    const inherited = Object.create({ [DELEGATION_HEADER_PARAMETER]: DIGEST }) as Record<string, unknown>;
    expect(statedDelegationOf(inherited)).toEqual({ kind: 'absent' });
  });
});

describe('a statement beside the credential a call presented', () => {
  const stated = (digest: string): StatedDelegation => ({ kind: 'credential', digest });

  it('holds when it is that credential, under either mode', () => {
    expect(statementRefusal(stated(DIGEST), DIGEST, 'prefer')).toBeUndefined();
    expect(statementRefusal(stated(DIGEST), DIGEST, 'require')).toBeUndefined();
  });

  it('is refused under either mode when it is another credential', () => {
    expect(statementRefusal(stated(OTHER), DIGEST, 'prefer')?.cause).toBe('delegation_mismatch');
    expect(statementRefusal(stated(OTHER), DIGEST, 'require')?.cause).toBe('delegation_mismatch');
  });

  it('is refused under either mode when it is malformed, whatever was presented', () => {
    for (const presented of [DIGEST, null]) {
      expect(statementRefusal({ kind: 'malformed' }, presented, 'prefer')?.cause).toBe('delegation_statement_malformed');
      expect(statementRefusal({ kind: 'malformed' }, presented, 'require')?.cause).toBe('delegation_statement_malformed');
    }
  });

  it('that says "none" is refused under require, and taken under prefer', () => {
    expect(statementRefusal({ kind: 'none' }, DIGEST, 'require')?.cause).toBe('delegation_stated_none');
    expect(statementRefusal({ kind: 'none' }, DIGEST, 'prefer')).toBeUndefined();
  });

  it('that is absent is refused under require, and taken under prefer', () => {
    expect(statementRefusal({ kind: 'absent' }, DIGEST, 'require')?.cause).toBe('delegation_unnamed');
    expect(statementRefusal({ kind: 'absent' }, DIGEST, 'prefer')).toBeUndefined();
    expect(statementRefusal({ kind: 'absent' }, null, 'require')?.cause).toBe('delegation_unnamed');
    expect(statementRefusal({ kind: 'absent' }, null, 'prefer')).toBeUndefined();
  });

  it('holds beside no credential when it says "none" or names one, which the caller then selects by', () => {
    expect(statementRefusal({ kind: 'none' }, null, 'require')).toBeUndefined();
    expect(statementRefusal(stated(DIGEST), null, 'require')).toBeUndefined();
  });
});

describe('a statement that names no credential', () => {
  type Cause = StatementRefusal['cause'] | undefined;
  it.each<[UnnamedStatement['kind'], boolean, RequestBindingMode, Cause]>([
    ['malformed', true, 'prefer', 'delegation_statement_malformed'],
    ['malformed', false, 'prefer', 'delegation_statement_malformed'],
    ['malformed', true, 'require', 'delegation_statement_malformed'],
    ['malformed', false, 'require', 'delegation_statement_malformed'],
    ['none', true, 'prefer', undefined],
    ['none', false, 'prefer', undefined],
    ['none', true, 'require', 'delegation_stated_none'],
    ['none', false, 'require', undefined],
    ['absent', true, 'prefer', undefined],
    ['absent', false, 'prefer', undefined],
    ['absent', true, 'require', 'delegation_unnamed'],
    ['absent', false, 'require', 'delegation_unnamed'],
  ])('%s, beside a presented credential: %s, under %s', (kind, presented, mode, cause) => {
    expect(unnamedStatementRefusal({ kind }, presented, mode)?.cause).toBe(cause);
  });

  it('gives each refusal a reason that shows no credential, digest or key', () => {
    for (const kind of ['malformed', 'none', 'absent'] as const) {
      const reason = unnamedStatementRefusal({ kind }, true, 'require')?.reason;
      expect(reason).toMatch(/^Request proof /);
      expect(reason).not.toMatch(/sha256:|did:|urn:/);
    }
  });
});

describe('the requestBinding option', () => {
  it('defaults to prefer, and takes prefer and require as written', () => {
    expect(requestBindingMode(undefined, 'requestBinding')).toBe('prefer');
    expect(requestBindingMode('prefer', 'requestBinding')).toBe('prefer');
    expect(requestBindingMode('require', 'requestBinding')).toBe('require');
  });

  it('throws a TypeError naming the option for any other value', () => {
    for (const value of ['required', 'off', '', true, null, 1]) {
      expect(() => requestBindingMode(value, 'delegation.requestBinding')).toThrow(TypeError);
      expect(() => requestBindingMode(value, 'delegation.requestBinding')).toThrow(/delegation\.requestBinding/);
    }
  });
});
