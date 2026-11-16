/**
 * The key-relationship vectors (suite ≥ 1.3.0). The issuer's DID document
 * lists `#login-1` under `authentication` and `#assert-1` under
 * `assertionMethod`. Each negative fails for one thing alone: the reference
 * adapter rejects it with the reason SPEC.md §6.2 gives, and accepts it once
 * that one thing is undone. Each differs from its file's positive vector in
 * that thing, except the lists whose key another DID controls or the document
 * defines twice: they are signed with `#login-1`, which their document also
 * lists under `assertionMethod`. The delegation also travels as a VC-JWT,
 * whose negatives differ from the VC-JWT that verifies in their header alone;
 * one whose signature cannot be redone without the issuer's key is shown to
 * verify with the key its document lists first under `assertionMethod`.
 */

import { createPublicKey, verify as verifySignature } from 'node:crypto';
import { describe, it, expect } from 'vitest';
import { anotherDidReason } from '../../src/__tests__/utils/did-documents.js';
import { loadVectors } from '../loader.js';
import { ReferenceConformanceAdapter } from '../reference-adapter.js';
import type {
  AdapterResult,
  DelegationChainInput,
  ExpectedOutcome,
  StatusListInput,
} from '../types.js';

interface Signed {
  proof: { verificationMethod: string; proofPurpose: string; proofValue: string };
}
interface Method {
  id: string;
  type?: string;
  controller?: string;
  publicKeyJwk: { x: string };
}
interface IssuerDocument {
  id: string;
  verificationMethod: Method[];
  authentication: string[];
  assertionMethod: (string | Method)[];
}
interface Documents {
  didDocuments: Record<string, IssuerDocument>;
}
type ChainInput = DelegationChainInput & Documents & { leaf: Signed };
type JwtChainInput = DelegationChainInput & Documents & { leaf: string };
type ListInput = StatusListInput & Documents & { credential: Signed; statusLists: Record<string, Signed> };

const ISSUER = 'did:web:issuer.example.com';
const OTHER = 'did:web:other.example.com';
const LOGIN_KEY = `${ISSUER}#login-1`;
const ASSERT_KEY = `${ISSUER}#assert-1`;
const UNLISTED_KEY = `${ISSUER}#unlisted-1`;
/** `#assert-1` under another DID. */
const OTHER_ASSERT_KEY = `${OTHER}#assert-1`;
const LIST = 'https://issuer.example.com/status/revocation/1';
const PASS: AdapterResult = { outcome: 'pass' };

const vectors = loadVectors();
const adapter = new ReferenceConformanceAdapter();

function inputOf<T>(id: string, expected: ExpectedOutcome): T {
  const vector = vectors.find((v) => v.id === id);
  if (!vector) throw new Error(`missing vector ${id}`);
  expect(vector.expected).toBe(expected);
  return vector.input as T;
}

function issuerDocumentOf(input: Documents): IssuerDocument {
  const document = input.didDocuments[ISSUER];
  if (!document) throw new Error(`no DID document for ${ISSUER}`);
  return document;
}

function withIssuerDocument<T extends Documents>(input: T, change: Partial<IssuerDocument>): T {
  return { ...input, didDocuments: { ...input.didDocuments, [ISSUER]: { ...issuerDocumentOf(input), ...change } } };
}

/** The input with the issuer's document also listing `key` under `assertionMethod`. */
function listingUnderAssertion<T extends Documents>(input: T, key: string): T {
  return withIssuerDocument(input, { assertionMethod: [...issuerDocumentOf(input).assertionMethod, key] });
}

/** The method the issuer's document publishes for `key`. */
function publishedMethod(input: Documents, key: string): Method {
  const method = issuerDocumentOf(input).verificationMethod.find((m) => m.id === key);
  if (!method) throw new Error(`no verification method ${key}`);
  return method;
}

/** The input with the issuer's document publishing `key`'s method as `change` rewrites it. */
function withMethod<T extends Documents>(input: T, key: string, change: (method: Method) => Method): T {
  const verificationMethod = issuerDocumentOf(input).verificationMethod.map((m) => (m.id === key ? change(m) : m));
  return withIssuerDocument(input, { verificationMethod });
}

/** The input with the issuer's document naming `controller` as the controller of `key`'s method. */
function withController<T extends Documents>(input: T, key: string, controller: string): T {
  return withMethod(input, key, (m) => ({ ...m, controller }));
}

/** The JOSE header and the claims of a VC-JWT. */
function jwtParts(jwt: string): { header: unknown; payload: Record<string, unknown> } {
  const [header, payload] = jwt.split('.').slice(0, 2).map((part) => JSON.parse(Buffer.from(part, 'base64url').toString('utf8')));
  return { header, payload };
}

/** Whether `method`'s Ed25519 key made the signature of the VC-JWT `jwt`. */
function signedBy(jwt: string, method: Method): boolean {
  const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: method.publicKeyJwk.x }, format: 'jwk' });
  const signingInput = jwt.slice(0, jwt.lastIndexOf('.'));
  return verifySignature(null, Buffer.from(signingInput), key, Buffer.from(jwt.slice(jwt.lastIndexOf('.') + 1), 'base64url'));
}

function stating<T extends Signed>(signed: T, proofPurpose: string): T {
  return { ...signed, proof: { ...signed.proof, proofPurpose } };
}

/** The signed artifact with the key it names and its signature blanked, to compare the rest. */
function withoutKeyAndSignature<T extends Signed>(signed: T): T {
  return { ...signed, proof: { ...signed.proof, verificationMethod: '', proofValue: '' } };
}

const notUnderAssertion = (key: string): string =>
  `Verification method "${key}" not found under assertionMethod of "${ISSUER}"`;
const PURPOSE_REFUSED = 'Proof purpose "authentication" is not assertionMethod';
/** The issuer, and the DID its document names in place of its own, as a refusal for another DID quotes them. */
const ISSUER_AND_OTHER = { did: ISSUER, other: OTHER };
/** How the chain walk refuses the vectors' delegation for `reason`. */
const refused = (reason: string): AdapterResult => ({
  outcome: 'fail',
  detail: `Delegation del-issuer-agent invalid: ${reason}`,
});

describe('delegation-chain key-relationship vectors', () => {
  const verify = (input: ChainInput) => adapter.verifyDelegationChain(input);
  const positive = inputOf<ChainInput>('delegation-chain/assertion-method-key', 'pass');

  it('assertion-method-key: a delegation signed with #assert-1 verifies', async () => {
    expect(positive.leaf.proof.verificationMethod).toBe(ASSERT_KEY);
    expect(positive.leaf.proof.proofPurpose).toBe('assertionMethod');
    expect(issuerDocumentOf(positive).id).toBe(ISSUER);
    expect(await verify(positive)).toEqual(PASS);
  });

  it('authentication-key: the same delegation signed with #login-1 is refused for its key alone', async () => {
    const negative = inputOf<ChainInput>('delegation-chain/authentication-key', 'fail');
    expect(negative.leaf.proof.verificationMethod).toBe(LOGIN_KEY);
    expect(withoutKeyAndSignature(negative.leaf)).toEqual(withoutKeyAndSignature(positive.leaf));
    expect(negative.didDocuments).toEqual(positive.didDocuments);
    expect(await verify(negative)).toEqual(refused(notUnderAssertion(LOGIN_KEY)));
    expect(await verify(listingUnderAssertion(negative, LOGIN_KEY))).toEqual(PASS);
  });

  it('proof-purpose-authentication: a stated authentication purpose is refused for itself alone', async () => {
    const negative = inputOf<ChainInput>('delegation-chain/proof-purpose-authentication', 'fail');
    expect({ ...negative, leaf: stating(negative.leaf, 'assertionMethod') }).toEqual(positive);
    expect(await verify(negative)).toEqual(refused(PURPOSE_REFUSED));
  });

  it("issuer-document-id-mismatch: another DID's document is refused for its id alone", async () => {
    const negative = inputOf<ChainInput>('delegation-chain/issuer-document-id-mismatch', 'fail');
    expect(issuerDocumentOf(negative).id).toBe(OTHER);
    expect(withIssuerDocument(negative, { id: ISSUER })).toEqual(positive);
    expect(await verify(negative)).toEqual(refused(anotherDidReason(ASSERT_KEY, "document's id", ISSUER_AND_OTHER)));
  });

  it('assertion-key-other-controller: #assert-1 under another controller is refused for its controller alone', async () => {
    const negative = inputOf<ChainInput>('delegation-chain/assertion-key-other-controller', 'fail');
    expect(publishedMethod(negative, ASSERT_KEY).controller).toBe(OTHER);
    expect(withController(negative, ASSERT_KEY, ISSUER)).toEqual(positive);
    expect(await verify(negative)).toEqual(refused(anotherDidReason(ASSERT_KEY, 'controller', ISSUER_AND_OTHER)));
  });

  it('assertion-key-defined-twice: #assert-1 defined again under assertionMethod is refused for that alone', async () => {
    const negative = inputOf<ChainInput>('delegation-chain/assertion-key-defined-twice', 'fail');
    expect(issuerDocumentOf(negative).assertionMethod).toEqual([publishedMethod(negative, ASSERT_KEY)]);
    expect(withIssuerDocument(negative, { assertionMethod: [ASSERT_KEY] })).toEqual(positive);
    expect(await verify(negative)).toEqual(refused(notUnderAssertion(ASSERT_KEY)));
    // Either definition alone verifies: the embedded one, once verificationMethod no longer repeats it.
    const embeddedOnly = withIssuerDocument(negative, { verificationMethod: [publishedMethod(negative, LOGIN_KEY)] });
    expect(await verify(embeddedOnly)).toEqual(PASS);
  });

  it("assertion-entry-other-did: #assert-1 under another DID is refused for its id alone, though the issuer's document defines and lists it", async () => {
    const negative = inputOf<ChainInput>('delegation-chain/assertion-entry-other-did', 'fail');
    expect(negative.leaf.proof.verificationMethod).toBe(OTHER_ASSERT_KEY);
    expect(issuerDocumentOf(negative).assertionMethod).toEqual([OTHER_ASSERT_KEY]);
    expect(publishedMethod(negative, OTHER_ASSERT_KEY).controller).toBe(ISSUER);
    expect(JSON.parse(JSON.stringify(negative).split(OTHER_ASSERT_KEY).join(ASSERT_KEY))).toEqual(positive);
    expect(await verify(negative)).toEqual(refused(notUnderAssertion(OTHER_ASSERT_KEY)));
  });

  it('unlisted-key: the same delegation signed with #unlisted-1, which no relationship lists, is refused for that alone', async () => {
    const negative = inputOf<ChainInput>('delegation-chain/unlisted-key', 'fail');
    const document = issuerDocumentOf(negative);
    expect(negative.leaf.proof.verificationMethod).toBe(UNLISTED_KEY);
    expect(withoutKeyAndSignature(negative.leaf)).toEqual(withoutKeyAndSignature(positive.leaf));
    expect(publishedMethod(negative, UNLISTED_KEY).controller).toBe(ISSUER);
    expect([...document.authentication, ...document.assertionMethod]).not.toContain(UNLISTED_KEY);
    const unpublished = withIssuerDocument(negative, { verificationMethod: document.verificationMethod.filter((m) => m.id !== UNLISTED_KEY) });
    expect(unpublished.didDocuments).toEqual(positive.didDocuments);
    expect(await verify(negative)).toEqual(refused(notUnderAssertion(UNLISTED_KEY)));
    expect(await verify(listingUnderAssertion(negative, UNLISTED_KEY))).toEqual(PASS);
  });

  it.each(['type', 'controller'] as const)('assertion-key-without-%s: #assert-1 published with no %s is refused for that alone', async (member) => {
    const negative = inputOf<ChainInput>(`delegation-chain/assertion-key-without-${member}`, 'fail');
    expect(publishedMethod(negative, ASSERT_KEY)).not.toHaveProperty(member);
    const restored = withMethod(negative, ASSERT_KEY, (m) => ({ ...m, [member]: publishedMethod(positive, ASSERT_KEY)[member] }));
    expect(restored).toEqual(positive);
    expect(await verify(negative)).toEqual(refused(notUnderAssertion(ASSERT_KEY)));
  });
});

describe('delegation-chain key-relationship vectors as VC-JWTs', () => {
  const verify = (input: JwtChainInput) => adapter.verifyDelegationChain(input);
  const positive = inputOf<JwtChainInput>('delegation-chain/vc-jwt-no-kid-first-entry', 'pass');

  it('vc-jwt-no-kid-first-entry: a VC-JWT with no kid verifies with the key the first assertionMethod entry names, not the first published', async () => {
    const dataIntegrity = inputOf<ChainInput>('delegation-chain/assertion-method-key', 'pass');
    const { proof: _proof, ...credential } = dataIntegrity.leaf as Signed & Record<string, unknown>;
    expect(jwtParts(positive.leaf)).toEqual({ header: { alg: 'EdDSA', typ: 'JWT' }, payload: expect.objectContaining({ iss: ISSUER, vc: credential }) });
    expect(positive.didDocuments).toEqual(dataIntegrity.didDocuments);
    expect(issuerDocumentOf(positive).verificationMethod.map((m) => m.id)).toEqual([LOGIN_KEY, ASSERT_KEY]);
    expect(await verify(positive)).toEqual(PASS);
    // Only the first entry is tried: listed after #login-1, #assert-1 is not.
    expect(await verify(withIssuerDocument(positive, { assertionMethod: [LOGIN_KEY, ASSERT_KEY] }))).toMatchObject({ outcome: 'fail' });
  });

  it('vc-jwt-kid-authentication-key: the same VC-JWT signed with #login-1, which its kid names, is refused for its key alone', async () => {
    const negative = inputOf<JwtChainInput>('delegation-chain/vc-jwt-kid-authentication-key', 'fail');
    expect(jwtParts(negative.leaf)).toEqual({ header: { alg: 'EdDSA', typ: 'JWT', kid: LOGIN_KEY }, payload: jwtParts(positive.leaf).payload });
    expect(negative.didDocuments).toEqual(positive.didDocuments);
    expect(await verify(negative)).toEqual(refused(notUnderAssertion(LOGIN_KEY)));
    expect(await verify(listingUnderAssertion(negative, LOGIN_KEY))).toEqual(PASS);
  });

  it('vc-jwt-empty-kid: the same VC-JWT under an empty kid is refused for the kid alone', async () => {
    const negative = inputOf<JwtChainInput>('delegation-chain/vc-jwt-empty-kid', 'fail');
    expect(jwtParts(negative.leaf)).toEqual({ header: { alg: 'EdDSA', typ: 'JWT', kid: '' }, payload: jwtParts(positive.leaf).payload });
    expect(negative.didDocuments).toEqual(positive.didDocuments);
    // #assert-1, which the first assertionMethod entry names, made the signature, so a verifier that
    // read the empty kid as none would accept the VC-JWT.
    expect(signedBy(negative.leaf, publishedMethod(negative, ASSERT_KEY))).toBe(true);
    expect(await verify(negative)).toEqual(refused('JWT kid "" is not a DID URL'));
  });
});

describe('status-list key-relationship vectors', () => {
  const verify = (input: ListInput) => adapter.verifyStatusList(input);
  const listRefused = (reason: string): AdapterResult => ({
    outcome: 'fail',
    detail: `Status check error: status list ${LIST} proof rejected: ${reason}`,
  });
  const listOf = (input: ListInput): Signed => {
    const list = input.statusLists[LIST];
    if (!list) throw new Error(`no status list at ${LIST}`);
    return list;
  };
  const withList = (input: ListInput, list: Signed): ListInput => ({ ...input, statusLists: { [LIST]: list } });
  const positive = inputOf<ListInput>('status-list/assertion-method-key-list', 'pass');

  it('assertion-method-key-list: an active delegation whose list is signed with #assert-1 verifies', async () => {
    expect(positive.credential.proof.verificationMethod).toBe(ASSERT_KEY);
    expect(listOf(positive).proof.verificationMethod).toBe(ASSERT_KEY);
    expect(listOf(positive).proof.proofPurpose).toBe('assertionMethod');
    expect(await verify(positive)).toEqual(PASS);
  });

  it('authentication-key-list: the same list signed with #login-1 is refused for its key alone', async () => {
    const negative = inputOf<ListInput>('status-list/authentication-key-list', 'fail');
    expect(listOf(negative).proof.verificationMethod).toBe(LOGIN_KEY);
    expect(withList(negative, withoutKeyAndSignature(listOf(negative)))).toEqual(
      withList(positive, withoutKeyAndSignature(listOf(positive))),
    );
    expect(await verify(negative)).toEqual(listRefused(notUnderAssertion(LOGIN_KEY)));
    expect(await verify(listingUnderAssertion(negative, LOGIN_KEY))).toEqual(PASS);
  });

  it("proof-purpose-authentication-list: a list's stated authentication purpose is refused for itself alone", async () => {
    const negative = inputOf<ListInput>('status-list/proof-purpose-authentication-list', 'fail');
    expect(withList(negative, stating(listOf(negative), 'assertionMethod'))).toEqual(positive);
    expect(await verify(negative)).toEqual(listRefused(PURPOSE_REFUSED));
  });

  it("issuer-document-id-mismatch: another DID's document is refused, at the credential's proof", async () => {
    const negative = inputOf<ListInput>('status-list/issuer-document-id-mismatch', 'fail');
    expect(issuerDocumentOf(negative).id).toBe(OTHER);
    expect(withIssuerDocument(negative, { id: ISSUER })).toEqual(positive);
    expect(await verify(negative)).toEqual({ outcome: 'fail', detail: anotherDidReason(ASSERT_KEY, "document's id", ISSUER_AND_OTHER) });
  });

  it("assertion-key-other-controller-list: the list's key under another controller is refused for its controller alone", async () => {
    const negative = inputOf<ListInput>('status-list/assertion-key-other-controller-list', 'fail');
    expect(listOf(negative).proof.verificationMethod).toBe(LOGIN_KEY);
    expect(publishedMethod(negative, LOGIN_KEY).controller).toBe(OTHER);
    expect(issuerDocumentOf(negative).assertionMethod).toEqual([ASSERT_KEY, LOGIN_KEY]);
    // The credential is the positive's, the list is the positive's but for its key, and the
    // document is the positive's with #login-1 under assertionMethod and another controller.
    const relisted = listingUnderAssertion(withController(positive, LOGIN_KEY, OTHER), LOGIN_KEY);
    expect(withList(negative, withoutKeyAndSignature(listOf(negative)))).toEqual(
      withList(relisted, withoutKeyAndSignature(listOf(positive))),
    );
    expect(await verify(negative)).toEqual(listRefused(anotherDidReason(LOGIN_KEY, 'controller', ISSUER_AND_OTHER)));
    expect(await verify(withController(negative, LOGIN_KEY, ISSUER))).toEqual(PASS);
  });

  it("assertion-key-defined-twice-list: the list's key defined again under assertionMethod is refused for that alone", async () => {
    const negative = inputOf<ListInput>('status-list/assertion-key-defined-twice-list', 'fail');
    expect(listOf(negative).proof.verificationMethod).toBe(LOGIN_KEY);
    expect(issuerDocumentOf(negative).assertionMethod).toEqual([ASSERT_KEY, publishedMethod(negative, LOGIN_KEY)]);
    // The credential and the document are the positive's but for the embedded #login-1, the list the positive's but for its key.
    expect(withList(withIssuerDocument(negative, { assertionMethod: [ASSERT_KEY] }), withoutKeyAndSignature(listOf(negative)))).toEqual(
      withList(positive, withoutKeyAndSignature(listOf(positive))),
    );
    expect(await verify(negative)).toEqual(listRefused(notUnderAssertion(LOGIN_KEY)));
    expect(await verify(withIssuerDocument(negative, { assertionMethod: [ASSERT_KEY, LOGIN_KEY] }))).toEqual(PASS);
  });
});
