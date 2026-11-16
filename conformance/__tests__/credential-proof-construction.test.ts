/**
 * The base-profile credential proof, checked against the vectors as SPEC.md
 * §6.2 states it: Ed25519 over the JCS canonicalization of the credential
 * without `proof`, `proofValue` as unpadded base64url, the key the one
 * `proof.verificationMethod` names among those the issuer's own DID document
 * lists under `assertionMethod`, its method defined once among
 * `verificationMethod` and the methods `assertionMethod` embeds, naming a type
 * and the issuer as its controller, and a stated `proofPurpose` other than
 * `assertionMethod` refused. A delegation that travels as a VC-JWT is checked
 * as §6.2 states that form: EdDSA over its signing input, with the key its
 * non-empty `kid` names, or with no `kid` the first `assertionMethod` entry,
 * under the same rules. It uses node:crypto and json-canonicalize
 * directly rather than the library's verifier, because an outside implementer
 * builds from that text and the text has to match the bytes the suite ships.
 * It checks the specification's construction against those bytes; it is not
 * an implementation, and no adapter runs it.
 */

import { createPublicKey, verify } from 'node:crypto';
import { canonicalize } from 'json-canonicalize';
import { describe, it, expect } from 'vitest';
import { loadVectors } from '../loader.js';

type Json = Record<string, unknown>;
interface Proof { type: string; created: string; verificationMethod: string; proofPurpose?: string; proofValue: string }
interface Credential extends Json { issuer: string | { id: string }; proof: Proof }
interface Method { id: string; type?: unknown; controller?: unknown; publicKeyJwk: { x: string } }
interface DidDocument extends Json { id: string; verificationMethod?: Method[]; assertionMethod?: (string | Method)[] }
interface Vector { id: string; input: Json }
type DidDocuments = Record<string, DidDocument>;

/**
 * Every credential with an embedded proof a vector carries, labeled by where
 * it sits: the delegation credentials and, in the status-list vectors, the
 * StatusList2021Credential, which §6.2 signs the same way.
 */
function credentialsOf(vector: Vector): [string, Credential][] {
  const { leaf, ancestors, credential, statusLists } = vector.input as {
    leaf?: Credential | string;
    ancestors?: Credential[];
    credential?: Credential;
    statusLists?: Record<string, Credential>;
  };
  return [
    ...(leaf && typeof leaf !== 'string' ? [['leaf', leaf] as [string, Credential]] : []),
    ...(ancestors ?? []).map((c, i): [string, Credential] => [`ancestors[${i}]`, c]),
    ...(credential ? [['credential', credential] as [string, Credential]] : []),
    ...Object.values(statusLists ?? {}).map((c, i): [string, Credential] => [`statusLists[${i}]`, c]),
  ];
}

/**
 * The method SPEC.md §6.2 checks a proof of `issuer`'s with, the one `name`
 * names (a DID URL or a `#fragment`), step by step, reading the issuer's
 * document once; or none.
 */
function assertionKey(issuer: string, name: string, didDocuments: DidDocuments): Method | undefined {
  const document = didDocuments[issuer];
  if (document?.id !== issuer) return undefined;
  const absolute = (id: string) => (id.startsWith('#') ? `${issuer}${id}` : id);
  const named = absolute(name);
  if (named.split('#')[0] !== issuer) return undefined;
  const listing = document.assertionMethod ?? [];
  const embedded = listing.filter((entry): entry is Method => typeof entry !== 'string');
  const definitions = [...(document.verificationMethod ?? []), ...embedded].filter((m) => absolute(m.id) === named);
  if (definitions.length !== 1) return undefined;
  const method = definitions[0]!;
  if (!listing.some((entry) => absolute(typeof entry === 'string' ? entry : entry.id) === named)) return undefined;
  if (typeof method.type !== 'string' || method.type === '' || method.controller !== issuer) return undefined;
  return method;
}

/** Whether `method`'s Ed25519 key made `signature`, unpadded base64url, over `data`. */
function signedBy(method: Method | undefined, data: string, signature: string): boolean {
  if (method === undefined) return false;
  const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: method.publicKeyJwk.x }, format: 'jwk' });
  return verify(null, Buffer.from(data, 'utf8'), key, Buffer.from(signature, 'base64url'));
}

const issuerOf = (vc: Credential): string => (typeof vc.issuer === 'string' ? vc.issuer : vc.issuer.id);

/** SPEC.md §6.2 for a credential with an embedded proof. */
function verifiesPerSpec(vc: Credential, didDocuments: DidDocuments): boolean {
  const { proof, ...unsigned } = vc;
  if (proof.proofPurpose !== undefined && proof.proofPurpose !== 'assertionMethod') return false;
  return signedBy(assertionKey(issuerOf(vc), proof.verificationMethod, didDocuments), canonicalize(unsigned), proof.proofValue);
}

/** SPEC.md §6.2 for the VC-JWT form, whose `iss` is its credential's issuer. */
function jwtVerifiesPerSpec(jwt: string, didDocuments: DidDocuments): boolean {
  const [header, payload] = jwt.split('.').slice(0, 2).map((part) => JSON.parse(Buffer.from(part, 'base64url').toString('utf8')));
  const { iss, vc } = payload as { iss: unknown; vc: Credential };
  if (header.alg !== 'EdDSA' || typeof iss !== 'string' || issuerOf(vc) !== iss) return false;
  const kid: unknown = header.kid;
  if (kid !== undefined && (typeof kid !== 'string' || kid === '')) return false;
  const first = didDocuments[iss]?.assertionMethod?.[0];
  const name = kid ?? (typeof first === 'string' ? first : first?.id);
  const at = jwt.lastIndexOf('.');
  return name !== undefined && signedBy(assertionKey(iss, name, didDocuments), jwt.slice(0, at), jwt.slice(at + 1));
}

/**
 * The credentials the suite makes for §6.2 to refuse: altered after signing,
 * signed with a key their issuer lists only under `authentication`, or under
 * no relationship, stating another purpose, checked against a document that
 * is not their issuer's, signed with a key whose method names another
 * controller, names no type or controller, is under another DID's id, or the
 * document defines twice; and the VC-JWTs whose `kid` names a key listed only
 * under `authentication`, or is empty.
 */
const REFUSED = new Set([
  'delegation-chain/tampered-signature leaf',
  'delegation-chain/authentication-key leaf',
  'delegation-chain/proof-purpose-authentication leaf',
  'delegation-chain/issuer-document-id-mismatch leaf',
  'delegation-chain/assertion-key-other-controller leaf',
  'delegation-chain/assertion-key-defined-twice leaf',
  'delegation-chain/assertion-entry-other-did leaf',
  'delegation-chain/unlisted-key leaf',
  'delegation-chain/assertion-key-without-type leaf',
  'delegation-chain/assertion-key-without-controller leaf',
  'delegation-chain/vc-jwt-kid-authentication-key leaf',
  'delegation-chain/vc-jwt-empty-kid leaf',
  'status-list/tampered-list statusLists[0]',
  'status-list/authentication-key-list statusLists[0]',
  'status-list/proof-purpose-authentication-list statusLists[0]',
  'status-list/issuer-document-id-mismatch credential',
  'status-list/issuer-document-id-mismatch statusLists[0]',
  'status-list/assertion-key-other-controller-list statusLists[0]',
  'status-list/assertion-key-defined-twice-list statusLists[0]',
]);

const vectors = loadVectors().filter(
  (v) => v.category === 'delegation-chain' || v.category === 'status-list',
) as Vector[];
const cases = vectors.flatMap((v) =>
  credentialsOf(v).map(([where, vc]) => ({
    name: `${v.id} ${where}`,
    vc,
    didDocuments: v.input.didDocuments as DidDocuments,
    refused: REFUSED.has(`${v.id} ${where}`),
  })),
);
const jwtCases = vectors.flatMap((v) =>
  typeof v.input.leaf === 'string'
    ? [{ name: `${v.id} leaf`, jwt: v.input.leaf, didDocuments: v.input.didDocuments as DidDocuments, refused: REFUSED.has(`${v.id} leaf`) }]
    : [],
);

describe('base-profile credential proof as SPEC.md §6.2 states it', () => {
  it('covers every credential in the delegation-chain and status-list vectors', () => {
    expect(cases.length).toBeGreaterThanOrEqual(vectors.length - jwtCases.length);
    expect(jwtCases.map((c) => c.name)).toEqual([
      'delegation-chain/vc-jwt-no-kid-first-entry leaf',
      'delegation-chain/vc-jwt-kid-authentication-key leaf',
      'delegation-chain/vc-jwt-empty-kid leaf',
    ]);
    expect(cases.filter((c) => c.name.includes('statusLists[')).length).toBe(
      vectors.filter((v) => v.id.startsWith('status-list/')).length,
    );
    expect([...cases, ...jwtCases].filter((c) => c.refused).map((c) => c.name).sort()).toEqual([...REFUSED].sort());
  });

  it.each(jwtCases)('$name: verifies as a VC-JWT over its signing input', ({ jwt, didDocuments, refused }) => {
    expect(jwtVerifiesPerSpec(jwt, didDocuments)).toBe(!refused);
  });

  it.each(cases)('$name: proofValue is unpadded base64url with no multibase prefix', ({ vc }) => {
    expect(vc.proof.type).toBe('Ed25519Signature2020');
    expect(vc.proof.proofValue).toMatch(/^[A-Za-z0-9_-]{86}$/);
    expect(Buffer.from(vc.proof.proofValue, 'base64url')).toHaveLength(64);
  });

  it.each(cases)('$name: verifies over JCS of the credential without proof', ({ vc, didDocuments, refused }) => {
    expect(verifiesPerSpec(vc, didDocuments)).toBe(!refused);
  });

  it.each(cases.filter((c) => !c.refused))(
    '$name: the proof options are outside the signature',
    ({ vc, didDocuments }) => {
      const { proofPurpose: _purpose, ...options } = vc.proof;
      const restamped = { ...vc, proof: { ...options, created: '1999-01-01T00:00:00Z' } };
      expect(verifiesPerSpec(restamped, didDocuments)).toBe(true);
    },
  );

  it.each(cases.filter((c) => !c.refused))(
    '$name: a proof that states another purpose does not verify',
    ({ vc, didDocuments }) => {
      expect(verifiesPerSpec({ ...vc, proof: { ...vc.proof, proofPurpose: 'authentication' } }, didDocuments)).toBe(false);
    },
  );

  it.each(cases.filter((c) => !c.refused))(
    '$name: the key does not verify once the issuer defines its method twice',
    ({ vc, didDocuments }) => {
      const issuer = typeof vc.issuer === 'string' ? vc.issuer : vc.issuer.id;
      const document = didDocuments[issuer]!;
      const method = document.verificationMethod?.find((m) => m.id === vc.proof.verificationMethod);
      expect(method).toBeDefined();
      expect(method!.id.startsWith(`${issuer}#`)).toBe(true);
      const embeddedAgain = { ...document, assertionMethod: [...(document.assertionMethod ?? []), method!] };
      const publishedAgain = { ...document, verificationMethod: [...document.verificationMethod!, method!] };
      const relative = { ...method!, id: method!.id.slice(issuer.length) };
      const publishedAgainAsFragment = { ...document, verificationMethod: [...document.verificationMethod!, relative] };
      for (const twice of [embeddedAgain, publishedAgain, publishedAgainAsFragment]) {
        expect(verifiesPerSpec(vc, { ...didDocuments, [issuer]: twice })).toBe(false);
      }
    },
  );

  it.each(cases.filter((c) => !c.refused))(
    '$name: the key still verifies when another relationship embeds a method of the same id',
    ({ vc, didDocuments }) => {
      const issuer = typeof vc.issuer === 'string' ? vc.issuer : vc.issuer.id;
      const document = didDocuments[issuer]!;
      const method = document.verificationMethod?.find((m) => m.id === vc.proof.verificationMethod);
      expect(method).toBeDefined();
      const embeddedElsewhere = { ...document, authentication: [method!] };
      expect(verifiesPerSpec(vc, { ...didDocuments, [issuer]: embeddedElsewhere })).toBe(true);
    },
  );

  it.each(cases.filter((c) => !c.refused))(
    '$name: the key does not verify once the issuer lists it only under authentication',
    ({ vc, didDocuments }) => {
      const issuer = typeof vc.issuer === 'string' ? vc.issuer : vc.issuer.id;
      const { assertionMethod: _listed, ...document } = didDocuments[issuer]!;
      const relisted = { ...didDocuments, [issuer]: { ...document, authentication: [vc.proof.verificationMethod] } };
      expect(verifiesPerSpec(vc, relisted)).toBe(false);
    },
  );
});
