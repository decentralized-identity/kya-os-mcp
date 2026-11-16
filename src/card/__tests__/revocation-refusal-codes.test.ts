/**
 * Each status a revocation checker cannot prove clear carries a stable code and whether it is
 * transient, beside its reason: a set bit, an entry the checker does not read, a list that could not
 * be read, one whose host the reader refused, one that may not answer for the credential, and a read
 * that ran out of time. The chain walk keeps the code of the hop that refused. Every case goes
 * through `@kya-os/mcp/card` as an adopter calls it, over a real signed list.
 */

import { beforeAll, describe, expect, it } from 'vitest';
import {
  createRevocationChecker,
  createSafeFetch,
  createStatusListProofVerifier,
  evaluateRevocationChain,
  isTransientRefusal,
  type BitstringRevocationChecker,
  type RefusalCode,
  type RevocationCheckerDeps,
  type RevocationStatus,
  type RevocationStatusEntry,
  type SafeFetch,
} from '../index.js';
import { documentsOf, servingFromMemory, signedStatusList, webParty, type WebParty } from '../../__tests__/utils/adopter-issuers.js';

const LIST = 'https://issuer.example/status/1';
const SET = 7;
const CLEAR = 3;
const CONTEXT = { credentialIssuer: 'did:web:issuer.example' };

let issuer: WebParty;
let other: WebParty;
let list: Record<string, unknown>;
beforeAll(async () => {
  [issuer, other] = await Promise.all([webParty('did:web:issuer.example'), webParty('did:web:other.example')]);
  list = await signedStatusList(issuer, LIST, [SET]);
});

/** The entry at `index` of {@link LIST}, with `members` over it. */
const entryAt = (index: number, members: Record<string, unknown> = {}): RevocationStatusEntry =>
  ({ id: `${LIST}#${index}`, type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: String(index), statusListCredential: LIST, ...members }) as RevocationStatusEntry;

/** A checker over `fetch`, holding each list to its issuer's proof unless `deps` says otherwise. */
const checkerOver = (fetch: SafeFetch, deps: Partial<RevocationCheckerDeps> = {}): BitstringRevocationChecker =>
  createRevocationChecker({ fetch, verifyStatusList: createStatusListProofVerifier({ didResolver: documentsOf(issuer, other) }), ...deps });

/** A dependency that never answers. */
const never = <T>(): Promise<T> => new Promise<T>(() => undefined);

/** Expect `status` failed closed with `code`, transient exactly when the code is. */
function expectCoded(status: RevocationStatus, code: RefusalCode): void {
  expect({ revoked: status.revoked, code: status.code, transient: status.transient }, status.reason).toEqual({
    revoked: true,
    code,
    transient: isTransientRefusal(code),
  });
}

describe('createRevocationChecker', () => {
  it('codes a set bit delegation_revoked, and a clear one not at all', async () => {
    const check = checkerOver(servingFromMemory({ [LIST]: list }));
    expectCoded(await check(entryAt(SET), CONTEXT), 'delegation_revoked');
    const clear = await check(entryAt(CLEAR), CONTEXT);
    expect(clear).toEqual({ revoked: false, fresh: true });
  });

  it.each<[string, () => Promise<RevocationStatus>, RefusalCode]>([
    ['an entry of another purpose', () => checkerOver(servingFromMemory({ [LIST]: list }))(entryAt(SET, { statusPurpose: 'suspension' }), CONTEXT), 'delegation_malformed'],
    ['an entry two bits wide', () => checkerOver(servingFromMemory({ [LIST]: list }))(entryAt(SET, { statusSize: 2 }), CONTEXT), 'delegation_malformed'],
    ['an entry that is not an object', () => checkerOver(servingFromMemory({ [LIST]: list }))(null as never, CONTEXT), 'delegation_malformed'],
    ['an entry whose index is not a decimal string', () => checkerOver(servingFromMemory({ [LIST]: list }))(entryAt(SET, { statusListIndex: '0x7' }), CONTEXT), 'delegation_malformed'],
    ['a call that names no credential issuer', () => checkerOver(servingFromMemory({ [LIST]: list }))(entryAt(SET)), 'configuration_error'],
    ['a list that is not served', () => checkerOver(servingFromMemory({}))(entryAt(SET), CONTEXT), 'status_unavailable'],
    ['a list whose read throws', () => checkerOver(async () => { throw new Error('connection reset'); })(entryAt(SET), CONTEXT), 'status_unavailable'],
    ['a list on a host the reader refuses', () => checkerOver(createSafeFetch())(entryAt(SET, { statusListCredential: 'http://issuer.example/status/1' }), CONTEXT), 'host_refused'],
    [
      'a list another issuer signed',
      async () => checkerOver(servingFromMemory({ [LIST]: await signedStatusList(other, LIST, [SET]) }))(entryAt(CLEAR), CONTEXT),
      'status_signer_untrusted',
    ],
    ['a list whose proof does not verify', () => checkerOver(servingFromMemory({ [LIST]: list }), { verifyStatusList: () => false })(entryAt(CLEAR), CONTEXT), 'status_signer_untrusted'],
    [
      'a list of another purpose, read with no proof check',
      () => createRevocationChecker({ fetch: servingFromMemory({ [LIST]: list }), statusPurpose: 'suspension' })(entryAt(CLEAR, { statusPurpose: 'suspension' })),
      'status_signer_untrusted',
    ],
    [
      'a list with no bitstring, read with no proof check',
      () => createRevocationChecker({ fetch: servingFromMemory({ [LIST]: { ...list, credentialSubject: { statusPurpose: 'revocation' } } }) })(entryAt(CLEAR)),
      'status_unavailable',
    ],
    ['a list that does not arrive in time', () => checkerOver(never, { dependencyTimeoutMs: 20 })(entryAt(CLEAR), CONTEXT), 'deadline_exceeded'],
  ])('codes %s', async (_name, check, code) => {
    expectCoded(await check(), code);
  });
});

describe('evaluateRevocationChain', () => {
  const hop = (index: number) => ({ entry: entryAt(index), credentialIssuer: issuer.did });

  it.each<[string, BitstringRevocationChecker, RefusalCode]>([
    ['a hop its checker answers revoked, with no code', async () => ({ revoked: true, fresh: true }), 'delegation_revoked'],
    ['a hop its checker could not prove clear, with the code it gave', async () => ({ revoked: true, fresh: false, code: 'status_signer_untrusted', reason: 'not the keeper' }), 'status_signer_untrusted'],
    ['a hop its checker answers with a code outside the catalog', async () => ({ revoked: true, fresh: false, code: 'nope' as never }), 'delegation_revoked'],
    ['a hop whose answer cannot be read', async () => ({ revoked: 'yes' }) as never, 'status_unavailable'],
    ['a hop its checker has not answered in time', never, 'deadline_exceeded'],
  ])('codes %s', async (_name, check, code) => {
    const result = await evaluateRevocationChain([hop(CLEAR), hop(SET)], check, { dependencyTimeoutMs: 20 });
    expect({ ok: result.ok, code: result.code, transient: result.transient }, result.reasons.join()).toEqual({
      ok: false,
      code,
      transient: isTransientRefusal(code),
    });
  });

  it('codes a hop the shipped checker refused with the code of that checker, and a chain that passes not at all', async () => {
    const refused = await evaluateRevocationChain([hop(SET)], checkerOver(servingFromMemory({})));
    expect(refused).toMatchObject({ ok: false, code: 'status_unavailable', transient: true });
    const passed = await evaluateRevocationChain([hop(CLEAR)], checkerOver(servingFromMemory({ [LIST]: list })));
    expect(passed).toEqual({ ok: true, fresh: true, reasons: [] });
  });
});
