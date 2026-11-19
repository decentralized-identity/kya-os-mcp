/**
 * Test helpers: real Ed25519 did:key identities, `DelegationCredential` hops signed with
 * `eddsa-jcs-2022`, and a signed Bitstring Status List served by an in-memory fetch. The signing is
 * written out independently of the module under test, so a verifier bug cannot hide behind a
 * matching signer bug.
 */

import { createHash, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { canonicalize } from 'json-canonicalize';
import { base58Encode } from '../../utils/base58.js';
import { generateDidKeyFromBytes } from '../../utils/did-helpers.js';
import {
  DELEGATION_CONTEXT_V2,
  KYA_OS_DELEGATION_CONTEXT,
  ZCAP_CONTEXT,
  type Caveat,
  type DelegationCredential,
} from '../delegation.js';
import type { SafeFetch } from '../../utils/safe-fetch.js';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import type { DIDResolver } from '../../delegation/vc-verifier.types.js';
import { issuerDidDocument, methodOf } from '../../__tests__/utils/did-documents.js';

export const NOW_MS = Date.parse('2026-11-04T00:00:00Z');
/** The clock every verifier and checker in these tests is given: it always reads {@link NOW_MS}. */
export const now = (): number => NOW_MS;
export const RESOURCE = 'did:web:merchant.example';
export const STATUS_URL = 'https://acme.example/status/delegations';

/** An Ed25519 did:key identity: the DID, its verification method id, and both keys as JWK. */
export interface TestIdentity {
  did: string;
  method: string;
  privateKey: KeyObject;
  publicJwk: { kty: 'OKP'; crv: 'Ed25519'; x: string };
  privateJwk: { kty: 'OKP'; crv: 'Ed25519'; x: string; d: string };
}

export function identity(): TestIdentity {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const pub = publicKey.export({ format: 'jwk' }) as { x: string };
  const priv = privateKey.export({ format: 'jwk' }) as { x: string; d: string };
  const did = generateDidKeyFromBytes(new Uint8Array(Buffer.from(pub.x, 'base64url')));
  return {
    did,
    method: `${did}#${did.slice('did:key:'.length)}`,
    privateKey,
    publicJwk: { kty: 'OKP', crv: 'Ed25519', x: pub.x },
    privateJwk: { kty: 'OKP', crv: 'Ed25519', x: priv.x, d: priv.d },
  };
}

/** An Ed25519 key published as the verification method `<did>#key-1` of the did:web DID `did`. */
export function webIdentity(did: string): TestIdentity {
  return { ...identity(), did, method: `${did}#key-1` };
}

/**
 * A resolver that serves the DID document of each identity in `web`, read when a DID is resolved,
 * naming its key for assertions, and resolves any did:key DID as `createDidKeyResolver` does.
 */
export function resolverServing(web: readonly TestIdentity[]): DIDResolver {
  const didKeys = createDidKeyResolver();
  return {
    resolve: async (did) => {
      const party = web.find((identity) => identity.did === did);
      return party ? issuerDidDocument(methodOf(published(party))) : didKeys.resolve(did);
    },
  };
}

/**
 * `key` as the shared DID document helpers (`methodOf`, `issuerDidDocument`, `acmeDocument`) take a
 * key: with its verification method id as `kid` and its raw public key in base64.
 */
export function published(key: TestIdentity): TestIdentity & { kid: string; publicKey: string } {
  return { ...key, kid: key.method, publicKey: Buffer.from(key.publicJwk.x, 'base64url').toString('base64') };
}

/**
 * Where a proof puts the document's `@context`: in the proof, and so in the signed configuration,
 * as W3C vc-di-eddsa §3.3.1 step 2 has an issuer put it (`standard`); nowhere, as an issuer that
 * skips step 2 signs (`unstated`); or in the signed configuration but not in the proof, as 1.22.0
 * to 1.25.0 issued it (`legacy`), which a verifier accepts during 1.x only.
 */
export type ProofContextForm = 'standard' | 'unstated' | 'legacy';

/**
 * eddsa-jcs-2022 over `document`, signed by `signer` (proof options, `@context` included,
 * overridable). A proof states the document's `@context` by default, as the library's issuers
 * write it; this helper wrote the legacy form until that form was found to fail a standard
 * verifier. `form` makes the other two.
 */
export function signEddsaJcs2022<T extends Record<string, unknown>>(
  document: T,
  signer: TestIdentity,
  options: Record<string, unknown> = {},
  form: ProofContextForm = 'standard',
): T & { proof: Record<string, unknown> } {
  const defaults: Record<string, unknown> = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    created: '2026-11-01T00:00:00Z',
    verificationMethod: signer.method,
    proofPurpose: 'assertionMethod',
  };
  const context = document['@context'] === undefined ? {} : { '@context': document['@context'] };
  const proof = form === 'standard' ? { ...defaults, ...context, ...options } : { ...defaults, ...options };
  const config = form === 'legacy' ? { ...proof, ...context } : proof;
  const hash = (value: unknown) => createHash('sha256').update(canonicalize(value)).digest();
  const signature = sign(null, Buffer.concat([hash(config), hash(document)]), signer.privateKey);
  return { ...document, proof: { ...proof, proofValue: `z${base58Encode(new Uint8Array(signature))}` } };
}

export interface HopOptions {
  issuer: TestIdentity;
  invoker: string;
  id: string;
  parentCapability: string;
  invocationTarget?: string;
  allowedAction: string[];
  caveats?: Caveat[];
  /** Status-list index; omitted means the hop carries no `credentialStatus`. */
  statusIndex?: number;
  /** The status list the index is in; default `STATUS_URL`. */
  statusListCredential?: string;
  validUntil?: string;
  /** Sign with this identity instead of the issuer (to forge a hop). */
  signer?: TestIdentity;
  /** The `parentCredentialDigest` the hop states; omitted means it states none. */
  parentCredentialDigest?: unknown;
}

/** One signed §6.10 hop. */
export function hop(opts: HopOptions): DelegationCredential {
  const unsigned: Record<string, unknown> = {
    '@context': [DELEGATION_CONTEXT_V2, ZCAP_CONTEXT, KYA_OS_DELEGATION_CONTEXT],
    type: ['VerifiableCredential', 'DelegationCredential'],
    issuer: opts.issuer.did,
    validUntil: opts.validUntil ?? '2027-01-01T00:00:00Z',
    credentialSubject: {
      id: opts.id,
      invoker: opts.invoker,
      parentCapability: opts.parentCapability,
      invocationTarget: opts.invocationTarget ?? RESOURCE,
      allowedAction: opts.allowedAction,
      ...(opts.caveats ? { caveats: opts.caveats } : {}),
      ...(opts.parentCredentialDigest === undefined ? {} : { parentCredentialDigest: opts.parentCredentialDigest }),
    },
    ...(opts.statusIndex !== undefined
      ? {
          credentialStatus: {
            type: 'BitstringStatusListEntry',
            statusPurpose: 'revocation',
            statusListIndex: String(opts.statusIndex),
            statusListCredential: opts.statusListCredential ?? STATUS_URL,
          },
        }
      : {}),
  };
  return signEddsaJcs2022(unsigned, opts.signer ?? opts.issuer) as unknown as DelegationCredential;
}

/** The parties of the standard two-hop chain: Acme (root) to agent, agent to sub-agent. */
export interface ChainParties {
  acme: TestIdentity;
  agent: TestIdentity;
  subAgent: TestIdentity;
}

export function parties(): ChainParties {
  return { acme: identity(), agent: identity(), subAgent: identity() };
}

/** Acme grants the agent `orders.place` + `orders.read`; the agent re-delegates `orders.place`. */
export function twoHopChain(p: ChainParties): [DelegationCredential, DelegationCredential] {
  const root = hop({
    issuer: p.acme,
    invoker: p.agent.did,
    id: 'urn:zcap:acme-root',
    parentCapability: RESOURCE,
    allowedAction: ['orders.place', 'orders.read'],
    caveats: [{ type: 'MaxAmount', limit: '500.00', currency: 'USD' }],
    statusIndex: 3,
  });
  const leaf = hop({
    issuer: p.agent,
    invoker: p.subAgent.did,
    id: 'urn:zcap:agent-leaf',
    parentCapability: 'urn:zcap:acme-root',
    allowedAction: ['orders.place'],
    caveats: [{ type: 'MaxAmount', limit: '100.00', currency: 'USD' }],
    statusIndex: 7,
  });
  return [root, leaf];
}

/**
 * A Bitstring Status List with `revoked` indices set (16 KiB, MSB-first), issued at `STATUS_URL` by
 * `signer` and signed by it. `fields` replace top-level members, or `credentialSubject` members
 * when given there, before signing.
 */
export function statusList(
  signer: TestIdentity,
  revoked: number[] = [],
  fields: Record<string, unknown> & { credentialSubject?: Record<string, unknown> } = {},
): Record<string, unknown> {
  const bytes = new Uint8Array(16 * 1024);
  for (const i of revoked) bytes[i >>> 3] = (bytes[i >>> 3] ?? 0) | (0x80 >> (i & 7));
  const { credentialSubject, ...members } = fields;
  return signEddsaJcs2022(
    {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: STATUS_URL,
      type: ['VerifiableCredential', 'BitstringStatusListCredential'],
      issuer: signer.did,
      validFrom: '2026-01-01T00:00:00Z',
      credentialSubject: {
        id: `${STATUS_URL}#list`,
        type: 'BitstringStatusList',
        statusPurpose: 'revocation',
        encodedList: `u${gzipSync(bytes).toString('base64url')}`,
        ...credentialSubject,
      },
      ...members,
    },
    signer,
  );
}

/** A SafeFetch that serves `body` at `STATUS_URL` and fails for anything else. */
export function serve(body: Record<string, unknown> | undefined): SafeFetch {
  return serveAt(body === undefined ? {} : { [STATUS_URL]: body });
}

/** A SafeFetch that serves each body at its URL and fails for anything else. */
export function serveAt(bodies: Record<string, Record<string, unknown>>): SafeFetch {
  return async (url) =>
    Object.prototype.hasOwnProperty.call(bodies, url)
      ? { ok: true, status: 200, json: () => Promise.resolve(bodies[url]) }
      : { ok: false, status: 503, json: () => Promise.resolve({}) };
}
