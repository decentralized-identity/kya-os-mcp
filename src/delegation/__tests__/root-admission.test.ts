/**
 * With `trustedRootIssuers` set, a chain's root is admitted by the issuer the credential names
 * before anything about it is verified, and refused, with a reason that quotes that issuer as a
 * reason quotes any value its sender chose, when the list does not hold it.
 */

import { describe, it, expect } from 'vitest';
import { rootAdmissionRefusal, trustedRootIssuersRefusal } from '../root-admission.js';
import type { DelegationCredential } from '../../types/protocol.js';

const ACME = 'did:web:acme.example';
const OTHER = 'did:web:other.example';

/** A root credential reduced to the members admission reads. */
const root = (issuer: unknown, issuerDid = ACME): DelegationCredential =>
  ({ issuer, credentialSubject: { delegation: { id: 'del-1', issuerDid } } }) as unknown as DelegationCredential;

/** What a trustedRootIssuers list must be, as a refusal of one says. */
const TRUSTED_ROOT_ISSUERS_RULE = 'trustedRootIssuers must be an array of DIDs, each a string that starts with "did:" and has no white space around it';

const untrusted = (quoted: string) => `Root delegation del-1 is issued by ${quoted}, which is not a trusted root issuer`;

describe('rootAdmissionRefusal', () => {
  it('admits every root when no list is set', () => {
    for (const issuer of [OTHER, { id: OTHER }, 5, undefined]) {
      expect(rootAdmissionRefusal(root(issuer), undefined)).toBeUndefined();
    }
  });

  it('refuses every root under a list that is not an array of DIDs without surrounding white space, null and a string included', () => {
    const invalid: [unknown, string][] = [
      [null, 'a value of type null'], [ACME, 'a string'], [`${ACME} ${OTHER}`, 'a string'], [{}, 'a value of type object'],
      [[ACME, ''], 'an array with an entry ""'], [['acme'], 'an array with an entry "acme"'],
      [['DID:web:acme.example'], 'an array with an entry "DID:web:acme.example"'],
      [[`${ACME} `], `an array with an entry "${ACME} "`], [[` ${ACME}`], `an array with an entry " ${ACME}"`],
      [[`${ACME}\n`], `an array with an entry "${ACME}\\n"`], [[`${ACME}\u00a0`], `an array with an entry "${ACME}\u00a0"`],
      [[ACME, 5], 'an array with an entry of type number'], [[[ACME]], 'an array with an entry of type array'],
    ];
    for (const [list, got] of invalid) {
      expect(trustedRootIssuersRefusal(list)).toBe(`${TRUSTED_ROOT_ISSUERS_RULE} (got ${got})`);
      expect(rootAdmissionRefusal(root(ACME), list as readonly string[])).toBe(trustedRootIssuersRefusal(list));
    }
    for (const list of [[], [ACME], [ACME, OTHER], ['did:x']]) expect(trustedRootIssuersRefusal(list)).toBeUndefined();
  });

  it('admits a root whose issuer, as a string or as the id of an issuer object, is listed', () => {
    expect(rootAdmissionRefusal(root(ACME), [ACME])).toBeUndefined();
    expect(rootAdmissionRefusal(root({ id: ACME, name: 'Acme' }), [OTHER, ACME])).toBeUndefined();
  });

  it('refuses a root whose issuer is not listed, and every root under an empty list', () => {
    expect(rootAdmissionRefusal(root(OTHER), [ACME])).toBe(untrusted(`"${OTHER}"`));
    expect(rootAdmissionRefusal(root({ id: OTHER }), [ACME])).toBe(untrusted(`"${OTHER}"`));
    expect(rootAdmissionRefusal(root(ACME), [])).toBe(untrusted(`"${ACME}"`));
  });

  it("reads the credential's issuer, never the issuerDid its delegation claims", () => {
    expect(rootAdmissionRefusal(root(OTHER, ACME), [ACME])).toBe(untrusted(`"${OTHER}"`));
    expect(rootAdmissionRefusal(root(ACME, OTHER), [ACME])).toBeUndefined();
  });

  it('compares each listed issuer whole, so an issuer that starts with one, or that one starts with, is not admitted', () => {
    for (const nearMiss of [`${ACME}.evil`, `${ACME}:x`, `${ACME}#key-1`, 'did:web:acme']) {
      expect(rootAdmissionRefusal(root(nearMiss), [ACME])).toBe(untrusted(`"${nearMiss}"`));
    }
  });

  it('refuses a root that names no issuer string with the reason its verification would give', () => {
    expect(rootAdmissionRefusal(root(5), [ACME])).toBe('Delegation del-1 invalid: Credential issuer of type number is not a URL');
    expect(rootAdmissionRefusal(root({ id: [ACME] }), [ACME])).toBe(
      'Delegation del-1 invalid: Credential issuer id of type array is not a URL',
    );
  });

  it('quotes at most the first 64 characters of an issuer, as well-formed text with a lone surrogate escaped', () => {
    const long = `did:web:long.example:${'a'.repeat(400_000)}`;
    expect(rootAdmissionRefusal(root(long), [ACME])).toBe(untrusted(`"${long.slice(0, 64)}"...`));
    expect(rootAdmissionRefusal(root(`${OTHER}:\uD800`), [ACME])).toBe(untrusted(`"${OTHER}:\\ud800"`));
  });
});
