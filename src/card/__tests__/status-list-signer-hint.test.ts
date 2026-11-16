/**
 * An issuer whose status lists a separate DID signs. The keeper rule refuses such a list until the
 * verifier names that DID in `statusListIssuers`, and the refusal ends with the configuration that
 * would accept it, as a condition the operator judges, since anyone can sign a list. Applying exactly
 * that configuration, read back out of the refusal, then accepts the list. Every test uses the
 * package's public exports, as an adopter would.
 */

import { beforeAll, describe, expect, it } from 'vitest';
import { DelegationCredentialVerifier, type CredentialStatus, type StatusListResolver } from '../../index.js';
import {
  CHECKER_REASON_LENGTH,
  createRevocationChecker,
  createStatusListProofVerifier,
  evaluateRevocationChain,
  type BitstringStatusListEntry,
  type StatusCheckContext,
  type StatusListIssuers,
} from '../index.js';
import { documentsOf, servingFromMemory, signedStatusList, webParty, type WebParty } from '../../__tests__/utils/adopter-issuers.js';
import { credentialJwt, delegationRecord, signedCredential } from '../../__tests__/utils/delegation-credentials.js';

const LIST_URL = 'https://issuer.example/lists/1';
const ENTRY = { statusListCredential: LIST_URL, statusListIndex: '3', statusPurpose: 'revocation' as const };

let issuer: WebParty;
let signer: WebParty;
let root: WebParty;
let list: Record<string, unknown>;
beforeAll(async () => {
  [issuer, signer, root] = await Promise.all([
    webParty('did:web:issuer.example'),
    webParty('did:web:issuer.example:status'),
    webParty('did:web:root.example'),
  ]);
  list = await signedStatusList(signer, LIST_URL);
});

/** The library's checker over `list` served at {@link LIST_URL}, with `statusListIssuers` if given. */
function checkerWith(statusListIssuers?: StatusListIssuers, served: Record<string, unknown> = list) {
  return createRevocationChecker({
    fetch: servingFromMemory({ [LIST_URL]: served }),
    verifyStatusList: createStatusListProofVerifier({ didResolver: documentsOf(issuer, signer, root) }),
    ...(statusListIssuers === undefined ? {} : { statusListIssuers }),
  });
}

/** The `statusListIssuers` value a refusal ends with, read back as an operator would copy it. */
function hintedConfiguration(reason: string | undefined): StatusListIssuers {
  const written = /statusListIssuers: (\{ .* \})$/.exec(reason ?? '')?.[1];
  if (written === undefined) throw new Error(`no configuration at the end of ${JSON.stringify(reason)}`);
  return JSON.parse(written) as StatusListIssuers;
}

const KEEPER_REFUSAL = `status list issuer "did:web:issuer.example:status" does not keep this list's URL: "did:web:issuer.example" does`;
const ORIGIN_HINT =
  '; if "did:web:issuer.example:status" signs this issuer\'s lists, name it in statusListIssuers: ' +
  '{ "did:web:issuer.example:status": ["https://issuer.example"] }';

describe("a list signed by a DID other than the credential's issuer", () => {
  it('is refused with the configuration that would accept it, which then accepts it', async () => {
    const refused = await checkerWith()(ENTRY, { credentialIssuer: issuer.did });
    expect(refused).toEqual({
      revoked: true,
      fresh: false,
      reason: `${KEEPER_REFUSAL}, as the issuer of the credential${ORIGIN_HINT}`,
    });
    const configured = hintedConfiguration(refused.reason);
    expect(configured).toEqual({ [signer.did]: ['https://issuer.example'] });
    expect(await checkerWith(configured)(ENTRY, { credentialIssuer: issuer.did })).toEqual({ revoked: false, fresh: true });
  });

  it('names the pinned root as the keeper when its own credential names the URL, and the same remedy accepts it', async () => {
    const context: StatusCheckContext = { credentialIssuer: issuer.did, trustedRootIssuer: root.did, trustedRootStatusList: LIST_URL };
    const refused = await checkerWith()(ENTRY, context);
    expect(refused.reason).toBe(
      `status list issuer "${signer.did}" does not keep this list's URL: "${root.did}" does, as the pinned root whose own credential names it` +
        ORIGIN_HINT,
    );
    expect(await checkerWith(hintedConfiguration(refused.reason))(ENTRY, context)).toEqual({ revoked: false, fresh: true });
  });

  it("binds the list's own URL where the configuration binds its origin to another issuer", async () => {
    const configured = { [root.did]: ['https://issuer.example'] };
    const refused = await checkerWith(configured)(ENTRY, { credentialIssuer: issuer.did });
    expect(refused.reason).toBe(
      `status list issuer "${signer.did}" does not keep this list's URL: "${root.did}" does, as the issuer statusListIssuers binds this URL's origin to; ` +
        `if "${signer.did}" signs the list at this URL, name it in statusListIssuers: { "${signer.did}": ["${LIST_URL}"] }`,
    );
    const hinted = hintedConfiguration(refused.reason);
    expect(await checkerWith({ ...configured, ...hinted })(ENTRY, { credentialIssuer: issuer.did })).toEqual({ revoked: false, fresh: true });
  });

  it('moves the binding of the URL where the configuration binds the URL itself to another issuer', async () => {
    const configured = { [root.did]: [LIST_URL] };
    const refused = await checkerWith(configured)(ENTRY, { credentialIssuer: issuer.did });
    expect(refused.reason).toBe(
      `status list issuer "${signer.did}" does not keep this list's URL: "${root.did}" does, as the issuer statusListIssuers binds this URL to; ` +
        `if "${signer.did}" signs the list at this URL, move the URL's binding to it in statusListIssuers: { "${signer.did}": ["${LIST_URL}"] }`,
    );
    expect(await checkerWith(hintedConfiguration(refused.reason))(ENTRY, { credentialIssuer: issuer.did })).toEqual({
      revoked: false,
      fresh: true,
    });
  });

  it('binds the exact URL of a list at no https origin the map can bind, such as an http: one', async () => {
    const url = 'http://issuer.example/lists/1';
    const plain = await signedStatusList(signer, url);
    const checker = createRevocationChecker({
      fetch: servingFromMemory({ [url]: plain }),
      verifyStatusList: createStatusListProofVerifier({ didResolver: documentsOf(issuer, signer) }),
    });
    const refused = await checker({ ...ENTRY, statusListCredential: url }, { credentialIssuer: issuer.did });
    expect(refused.reason).toMatch(/name it in statusListIssuers: \{ "did:web:issuer\.example:status": \["http:\/\/issuer\.example\/lists\/1"\] \}$/);
  });

  it('says only where to name the signer when it cannot print the configuration whole', async () => {
    const longSigner = await webParty(`did:web:issuer.example:${'s'.repeat(300)}`);
    const longList = await signedStatusList(longSigner, LIST_URL);
    const refused = await checkerWith(undefined, longList)(ENTRY, { credentialIssuer: issuer.did });
    expect(refused.reason).toMatch(
      /, as the issuer of the credential; if the list's issuer signs this issuer's lists, name it in statusListIssuers with this list's https origin or URL$/,
    );
    expect(refused.reason!.length).toBeLessThanOrEqual(CHECKER_REASON_LENGTH);
  });

  it('binds the exact URL of a list whose host has an upper-case letter, which no origin binding holds', async () => {
    const url = 'https://Issuer.example/lists/1';
    const served = { fetch: servingFromMemory({ [url]: await signedStatusList(signer, url) }) };
    const verifyStatusList = createStatusListProofVerifier({ didResolver: documentsOf(issuer, signer) });
    const entry = { ...ENTRY, statusListCredential: url };
    const refused = await createRevocationChecker({ ...served, verifyStatusList })(entry, { credentialIssuer: issuer.did });
    expect(refused.reason).toBe(
      `${KEEPER_REFUSAL}, as the issuer of the credential; if "${signer.did}" signs this issuer's lists, ` +
        `name it in statusListIssuers: { "${signer.did}": ["${url}"] }`,
    );
    const statusListIssuers = hintedConfiguration(refused.reason);
    expect(await createRevocationChecker({ ...served, verifyStatusList, statusListIssuers })(entry, { credentialIssuer: issuer.did }))
      .toEqual({ revoked: false, fresh: true });
  });

  it('adds nothing where no binding could accept the list: a URL that ends in "/" at no https origin', async () => {
    const url = 'http://issuer.example/lists/';
    const checker = createRevocationChecker({
      fetch: servingFromMemory({ [url]: await signedStatusList(signer, url) }),
      verifyStatusList: createStatusListProofVerifier({ didResolver: documentsOf(issuer, signer) }),
    });
    const refused = await checker({ ...ENTRY, statusListCredential: url }, { credentialIssuer: issuer.did });
    expect(refused.reason).toBe(`${KEEPER_REFUSAL}, as the issuer of the credential`);
  });

  it('adds nothing to a refusal of a list whose issuer is no DID, or names no issuer', async () => {
    for (const [issuerValue, reason] of [
      ['https://issuer.example/', `status list issuer "https://issuer.example/" does not keep this list's URL: "${issuer.did}" does, as the issuer of the credential`],
      [undefined, 'status list names no issuer'],
    ] as const) {
      const unsigned = { ...list, issuer: issuerValue };
      const refused = await checkerWith(undefined, unsigned)(ENTRY, { credentialIssuer: issuer.did });
      expect(refused.reason).toBe(reason);
    }
  });

  it('carries the whole remedy through the chain walk, after the hop it names', async () => {
    const walked = await evaluateRevocationChain([{ entry: ENTRY, credentialIssuer: issuer.did }], checkerWith());
    expect(walked.ok).toBe(false);
    expect(walked.reasons[0]).toMatch(new RegExp(`${ORIGIN_HINT.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`));
  });

  it("carries the whole remedy through the delegation verifier, from an adopter's resolver that throws it", async () => {
    const checker = checkerWith();
    const resolver: StatusListResolver = {
      async checkStatus(status, context) {
        const verdict = await checker(status as unknown as BitstringStatusListEntry, context);
        if (verdict.revoked && !verdict.fresh) throw new Error(verdict.reason);
        return verdict.revoked;
      },
    };
    const credentialStatus: CredentialStatus = { id: `${LIST_URL}#3`, type: 'BitstringStatusListEntry', ...ENTRY };
    const credential = await signedCredential(issuer.key, { record: delegationRecord(issuer.did), credentialStatus });
    const result = await new DelegationCredentialVerifier({ didResolver: documentsOf(issuer) }).verifyDelegationJwt(
      await credentialJwt(credential, issuer.key),
      { statusListResolver: resolver, skipCache: true },
    );
    expect(result).toMatchObject({
      valid: false,
      statusOutcome: 'status_unresolvable',
      reason: `Status check error: ${KEEPER_REFUSAL}, as the issuer of the credential${ORIGIN_HINT}`,
    });
  });
});

describe('statusListIssuers bindings, as an operator writes them', () => {
  it('takes an origin with nothing after it, and an exact URL, whatever the case of its host', async () => {
    for (const binding of ['https://issuer.example', LIST_URL]) {
      expect(await checkerWith({ [signer.did]: [binding] })(ENTRY, { credentialIssuer: issuer.did }), binding).toEqual({
        revoked: false,
        fresh: true,
      });
    }
    for (const binding of ['https://ISSUER.example/lists/1', 'https://issuer example/lists/1']) {
      expect(() => checkerWith({ [signer.did]: [binding] }), binding).not.toThrow();
    }
  });

  it.each([
    [
      'an origin followed by "/"',
      'https://issuer.example/',
      'an origin followed by "/", which binds only itself, as an exact URL, and no other URL at that origin: ' +
        'write it as "https://issuer.example"',
    ],
    [
      'an origin whose host has an upper-case letter',
      'https://Issuer.example',
      'an origin whose host is not in lower case, which binds only itself, as an exact URL, and no URL at that origin: ' +
        'write the host in lower case, as "https://issuer.example"',
    ],
    [
      'a path that ends in "/", which reads as a prefix',
      'https://issuer.example/lists/',
      'which ends in "/" as a path prefix would, but a binding is an https origin or a list\'s exact URL, never a prefix: ' +
        'bind the origin, "https://issuer.example", or each list URL',
    ],
    [
      'an http: origin, which no origin binding is',
      'http://issuer.example/',
      'which ends in "/" as a path prefix would, but a binding is an https origin or a list\'s exact URL, never a prefix: ' +
        'bind each list URL',
    ],
  ])('refuses %s when the checker is created, naming the fix', (_label, binding, why) => {
    expect(() => checkerWith({ [signer.did]: [binding] })).toThrow(
      new TypeError(`statusListIssuers["${signer.did}"] holds "${binding}", ${why}`),
    );
  });
});
