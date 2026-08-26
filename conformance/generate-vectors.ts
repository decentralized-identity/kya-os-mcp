#!/usr/bin/env node
/**
 * Generator for the KYA-OS conformance vectors.
 *
 * Produces the committed `conformance/vectors/*.json` files by minting real
 * signed artifacts (proofs, delegation credentials, status lists, DID
 * documents) with the package's own primitives, then deriving negative variants
 * by surgical tampering. The OUTPUT (the JSON) is what ships and is
 * implementation-agnostic; this generator is a dev tool, run via
 * `npm run conformance:generate`.
 *
 * Determinism: keypairs are minted once per run; the resulting JSON is committed,
 * so the suite is stable across machines/CI. Re-running regenerates fresh keys —
 * that is fine because positive/negative relationships are preserved by
 * construction.
 */

import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalize } from 'json-canonicalize';
import { CompactSign, importPKCS8 } from 'jose';
import { NodeCryptoProvider } from '../src/providers/node-crypto.js';
import { ED25519_PKCS8_DER_HEADER, ED25519_KEY_SIZE } from '../src/utils/ed25519-constants.js';
import { base64ToBytes, bytesToBase64 } from '../src/utils/base64.js';
import {
  ProofGenerator,
  buildProofJwsPayload,
  generateDidKeyFromBase64,
  didKeyFragment,
  wrapDelegationAsVC,
  BitstringManager,
  buildDidWebDocument,
  RESPONSE_PROOF_PROFILE_V2,
  type DelegationCredential,
  type StatusList2021Credential,
  type CredentialStatus,
  type DetachedProof,
} from '../src/index.js';
import { extractPublicKeyFromDidKey, publicKeyToJwk } from '../src/delegation/did-key-resolver.js';
import { VECTORS_DIR } from './loader.js';
import {
  signVC,
  conformanceCompressor,
  conformanceDecompressor,
} from './crypto-kit.js';
import type {
  ConformanceVector,
  VectorFile,
} from './types.js';

const crypto = new NodeCryptoProvider();
const NOW = 1_750_000_000; // fixed epoch-seconds anchor for proof timestamps
const SERVER_DID = 'did:web:server.example.com';

interface Party {
  did: string;
  kid: string;
  privateKey: string;
  publicKey: string;
}

async function mintParty(): Promise<Party> {
  const { privateKey, publicKey } = await crypto.generateKeyPair();
  const did = generateDidKeyFromBase64(publicKey);
  return { did, kid: `${did}#${didKeyFragment(did)}`, privateKey, publicKey };
}

function jwkFor(party: Party) {
  const raw = extractPublicKeyFromDidKey(party.did)!;
  const jwk = publicKeyToJwk(raw);
  return { ...jwk, kid: party.kid };
}

function writeFile(file: VectorFile, name: string): void {
  writeFileSync(join(VECTORS_DIR, name), JSON.stringify(file, null, 2) + '\n', 'utf8');
  console.log(`wrote ${name} (${file.vectors.length} vectors)`);
}

// ── signed-proof vectors ──────────────────────────────────────────────────────

async function signedProofVectors(): Promise<VectorFile> {
  const agent = await mintParty();
  const gen = new ProofGenerator(
    { did: agent.did, kid: agent.kid, privateKey: agent.privateKey, publicKey: agent.publicKey },
    crypto,
  );
  const session = {
    sessionId: 'sess_conformance',
    audience: SERVER_DID,
    nonce: 'nonce-conformance-0001',
    timestamp: NOW,
    createdAt: NOW,
    lastActivity: NOW,
    ttlMinutes: 30,
    identityState: 'anonymous' as const,
  };

  const draft = await gen.generateProof(
    { method: 'tools/call', params: { name: 'echo', arguments: { msg: 'hi' } } },
    { data: { output: 'hi' } },
    session,
  );
  // Pin the timestamp to the anchor and re-sign so the JWS matches the pinned ts.
  const validRetimed = await signProofMeta(agent, { ...draft.meta, ts: NOW });

  const jwk = jwkFor(agent);

  // Negative: tampered signature (flip the JWS).
  const tamperedSig: DetachedProof = {
    ...validRetimed,
    jws: flipSignatureChar(validRetimed.jws),
  };

  // Negative: tampered meta (requestHash mutated; signature no longer matches).
  const tamperedMeta: DetachedProof = {
    ...validRetimed,
    meta: { ...validRetimed.meta, requestHash: 'sha256:' + 'de'.repeat(32) },
  };

  // Negative: wrong public key (different agent).
  const wrongAgent = await mintParty();
  const wrongJwk = jwkFor(wrongAgent);

  // Negative: timestamp outside the skew window (authentically signed at a stale ts).
  const staleSigned = await signProofMeta(agent, { ...validRetimed.meta, ts: NOW - 10_000 });

  // ── Envelope-coverage profile (`org.kya-os/response-proof.v2`, suite ≥ 1.1.0) ─
  // The profile binds `responseHash` over the FULL result envelope minus the
  // top-level `_meta` member; it is named by a signature-covered `prf` claim.
  const envelopeRequest = { method: 'tools/call', params: { name: 'echo', arguments: { msg: 'hi' } } };
  const resultEnvelope = {
    content: [{ type: 'text', text: 'hi' }],
    structuredContent: { msg: 'hi' },
    isError: false,
    resultType: 'complete',
  };
  const envelopeDraft = await gen.generateProof(
    envelopeRequest,
    { data: resultEnvelope },
    session,
    { profile: RESPONSE_PROOF_PROFILE_V2 },
  );
  const envelopeProof = await signProofMeta(agent, { ...envelopeDraft.meta, ts: NOW });

  // Negative: `prf` stripped after signing — reconstructing a body-only
  // payload no longer matches the signature, so the downgrade is a hard fail,
  // not a silent fallback to weaker (body-only) coverage.
  const strippedMeta = { ...envelopeProof.meta };
  delete (strippedMeta as Record<string, unknown>)['prf'];
  const prfStrippedProof: DetachedProof = { jws: envelopeProof.jws, meta: strippedMeta };

  // Negative: unknown profile value — structure validation rejects fail-closed.
  const unknownProfileProof: DetachedProof = {
    ...envelopeProof,
    meta: { ...envelopeProof.meta, prf: 'org.example/unknown-profile.v9' as never },
  };

  const vectors: ConformanceVector[] = [
    {
      id: 'signed-proof/valid-basic',
      category: 'signed-proof',
      description: 'A well-formed proof with a valid Ed25519 signature and in-window timestamp',
      expected: 'pass',
      reason: 'Signature verifies against the signer key and ts is within skew',
      input: { proof: validRetimed, publicKeyJwk: jwk, now: NOW, skewSeconds: 300 },
    },
    {
      id: 'signed-proof/tampered-signature',
      category: 'signed-proof',
      description: 'Proof whose JWS signature bytes were altered',
      expected: 'fail',
      reason: 'A mutated signature must fail EdDSA verification',
      input: { proof: tamperedSig, publicKeyJwk: jwk, now: NOW, skewSeconds: 300 },
    },
    {
      id: 'signed-proof/tampered-meta',
      category: 'signed-proof',
      description: 'Proof whose signed requestHash was altered after signing',
      expected: 'fail',
      reason: 'The reconstructed canonical payload no longer matches the signature',
      input: { proof: tamperedMeta, publicKeyJwk: jwk, now: NOW, skewSeconds: 300 },
    },
    {
      id: 'signed-proof/wrong-key',
      category: 'signed-proof',
      description: 'Valid proof verified against a different agent public key',
      expected: 'fail',
      reason: 'Signature does not verify under an unrelated key',
      input: { proof: validRetimed, publicKeyJwk: wrongJwk, now: NOW, skewSeconds: 300 },
    },
    {
      id: 'signed-proof/timestamp-skew-exceeded',
      category: 'signed-proof',
      description: 'Authentically signed proof whose timestamp is far outside the skew window',
      expected: 'fail',
      reason: 'ts is 10000s before now with a 300s skew — replay/stale guard must reject',
      input: { proof: staleSigned, publicKeyJwk: jwk, now: NOW, skewSeconds: 300 },
    },
    {
      id: 'signed-proof/envelope-binding',
      category: 'signed-proof',
      description:
        'Proof under profile org.kya-os/response-proof.v2 whose responseHash binds the full result envelope; verified against the received result with a mutated _meta',
      expected: 'pass',
      reason:
        'Under prf=org.kya-os/response-proof.v2 the verifier hashes the received result with the top-level _meta removed, so a _meta-only mutation never invalidates the binding',
      input: {
        proof: envelopeProof,
        publicKeyJwk: jwk,
        now: NOW,
        skewSeconds: 300,
        expected: {
          request: envelopeRequest,
          response: { data: { ...resultEnvelope, _meta: { 'io.modelcontextprotocol/trace': 'added-in-flight' } } },
        },
      },
    },
    {
      id: 'signed-proof/envelope-tampered-structured-content',
      category: 'signed-proof',
      description:
        'Envelope-profile proof verified against a result whose structuredContent was swapped in flight (unauthenticated under the body-only profile)',
      expected: 'fail',
      reason:
        'Envelope coverage authenticates structuredContent/isError/resultType — the recomputed responseHash must mismatch the bound one',
      input: {
        proof: envelopeProof,
        publicKeyJwk: jwk,
        now: NOW,
        skewSeconds: 300,
        expected: {
          request: envelopeRequest,
          response: { data: { ...resultEnvelope, structuredContent: { msg: 'TAMPERED' } } },
        },
      },
    },
    {
      id: 'signed-proof/prf-stripped-downgrade',
      category: 'signed-proof',
      description: 'Envelope-profile proof whose signature-covered prf claim was stripped after signing',
      expected: 'fail',
      reason:
        'prf is a covered claim: without it the reconstructed payload no longer matches the signature — a downgrade to body-only semantics must be a hard fail',
      input: { proof: prfStrippedProof, publicKeyJwk: jwk, now: NOW, skewSeconds: 300 },
    },
    {
      id: 'signed-proof/unknown-profile',
      category: 'signed-proof',
      description: 'Proof carrying an unrecognized prf value',
      expected: 'fail',
      reason:
        'Unknown response-proof profiles are rejected fail-closed — never verified under weaker (body-only) semantics',
      input: { proof: unknownProfileProof, publicKeyJwk: jwk, now: NOW, skewSeconds: 300 },
    },
  ];

  return { version: '1.1.0', category: 'signed-proof', vectors };
}

/**
 * Sign a proof meta into a DetachedProof using the SAME canonical payload shape
 * the package's ProofGenerator/ProofVerifier use (RFC 8785). The generator needs
 * to mint proofs at arbitrary pinned timestamps; ProofGenerator only signs at
 * Date.now(), so the generator reproduces the documented payload shape directly.
 */
async function signProofMeta(party: Party, meta: DetachedProof['meta']): Promise<DetachedProof> {
  // The payload SHAPE comes from the library's own buildProofJwsPayload — the
  // single source of truth shared with ProofGenerator/ProofVerifier — so a
  // covered claim (e.g. the v2 `prf` discriminator) can never drift between
  // the library and the committed vectors.
  const payload = buildProofJwsPayload(meta);
  const canonical = canonicalize(payload as Parameters<typeof canonicalize>[0]);
  const pem = formatPrivateKeyAsPEM(party.privateKey);
  const key = await importPKCS8(pem, 'EdDSA');
  const jws = await new CompactSign(new TextEncoder().encode(canonical))
    .setProtectedHeader({ alg: 'EdDSA', kid: party.kid })
    .sign(key);
  return { jws, meta };
}

function formatPrivateKeyAsPEM(base64PrivateKey: string): string {
  const keyData = base64ToBytes(base64PrivateKey);
  const rawKey = keyData.subarray(0, ED25519_KEY_SIZE);
  const fullKey = new Uint8Array(ED25519_PKCS8_DER_HEADER.length + rawKey.length);
  fullKey.set(ED25519_PKCS8_DER_HEADER);
  fullKey.set(rawKey, ED25519_PKCS8_DER_HEADER.length);
  const b64 = bytesToBase64(fullKey);
  const formatted = b64.match(/.{1,64}/g)?.join('\n') ?? b64;
  return `-----BEGIN PRIVATE KEY-----\n${formatted}\n-----END PRIVATE KEY-----`;
}

/**
 * Corrupt a JWS signature by flipping the FIRST character of its signature
 * segment. The first character's bits are all significant, so the decoded
 * signature bytes are guaranteed to change. (Flipping the LAST character is
 * not a reliable tamper: an 86-char base64url segment for a 64-byte Ed25519
 * signature carries only 2 significant bits in its final character, and
 * lenient decoders ignore the 4 padding bits — an 'A'↔'B' swap there can
 * decode to the identical signature.)
 */
function flipSignatureChar(jws: string): string {
  const [header, payload, signature] = jws.split('.');
  const first = signature![0];
  const swap = first === 'A' ? 'B' : 'A';
  return `${header}.${payload}.${swap}${signature!.slice(1)}`;
}

// ── delegation-chain vectors ───────────────────────────────────────────────────

function didDocFor(party: Party): Record<string, unknown> {
  const raw = extractPublicKeyFromDidKey(party.did)!;
  return {
    id: party.did,
    verificationMethod: [
      {
        id: party.kid,
        type: 'Ed25519VerificationKey2020',
        controller: party.did,
        publicKeyJwk: publicKeyToJwk(raw),
      },
    ],
    assertionMethod: [party.kid],
    authentication: [party.kid],
  };
}

async function buildSignedDelegation(args: {
  issuer: Party;
  subjectDid: string;
  id: string;
  parentId?: string;
  scopes: string[];
  audience: string | string[];
  status?: 'active' | 'revoked';
  credentialStatus?: CredentialStatus;
}): Promise<DelegationCredential> {
  const unsigned = wrapDelegationAsVC(
    {
      id: args.id,
      issuerDid: args.issuer.did,
      subjectDid: args.subjectDid,
      vcId: `urn:uuid:${args.id}`,
      parentId: args.parentId,
      constraints: { scopes: args.scopes, audience: args.audience },
      signature: '',
      status: args.status ?? 'active',
      createdAt: NOW * 1000,
    },
    {
      issuanceDate: '2026-01-01T00:00:00.000Z',
      ...(args.credentialStatus ? { credentialStatus: args.credentialStatus } : {}),
    },
  );
  const proof = await signVC(crypto, unsigned as Record<string, unknown>, args.issuer.privateKey, args.issuer.kid);
  return { ...unsigned, proof } as DelegationCredential;
}

async function delegationChainVectors(): Promise<VectorFile> {
  const root = await mintParty(); // issuer (user/org)
  const agent = await mintParty(); // leaf subject
  const intermediary = await mintParty();

  const didDocuments = {
    [root.did]: didDocFor(root),
    [agent.did]: didDocFor(agent),
    [intermediary.did]: didDocFor(intermediary),
  };

  // Single-hop valid delegation root → agent.
  const validSingle = await buildSignedDelegation({
    issuer: root,
    subjectDid: agent.did,
    id: 'del-root-agent',
    scopes: ['greeting:read'],
    audience: SERVER_DID,
  });

  // Valid two-hop chain: root → intermediary → agent, attenuated scope.
  const parent = await buildSignedDelegation({
    issuer: root,
    subjectDid: intermediary.did,
    id: 'del-root-interm',
    scopes: ['greeting:read', 'greeting:write'],
    audience: SERVER_DID,
  });
  const child = await buildSignedDelegation({
    issuer: intermediary,
    subjectDid: agent.did,
    id: 'del-interm-agent',
    parentId: 'del-root-interm',
    scopes: ['greeting:read'], // attenuated subset of parent
    audience: SERVER_DID,
  });

  // Negative: broken chain — child claims a parentId that the resolved chain's
  // parent does not match (issuerDid != parent.subjectDid).
  const forgedChild = await buildSignedDelegation({
    issuer: agent, // NOT the intermediary the parent delegated to
    subjectDid: agent.did,
    id: 'del-forged-child',
    parentId: 'del-root-interm',
    scopes: ['greeting:read'],
    audience: SERVER_DID,
  });

  // Negative: scope widening — child requests a scope absent from parent.
  const wideningChild = await buildSignedDelegation({
    issuer: intermediary,
    subjectDid: agent.did,
    id: 'del-widening-child',
    parentId: 'del-root-interm',
    scopes: ['admin:all'], // not a subset of parent scopes
    audience: SERVER_DID,
  });

  // Negative: tampered leaf signature.
  const tamperedLeaf: DelegationCredential = {
    ...validSingle,
    proof: { ...validSingle.proof!, proofValue: flipB64url(validSingle.proof!.proofValue as string) },
  };

  // Negative: audience mismatch — credential bound to a different server.
  const wrongAudience = await buildSignedDelegation({
    issuer: root,
    subjectDid: agent.did,
    id: 'del-wrong-audience',
    scopes: ['greeting:read'],
    audience: 'did:web:other.example.com',
  });

  const vectors: ConformanceVector[] = [
    {
      id: 'delegation-chain/valid-single-hop',
      category: 'delegation-chain',
      description: 'A directly-issued, signed delegation bound to the server',
      expected: 'pass',
      reason: 'Signature, audience, and shape all valid; no parent to resolve',
      input: { leaf: validSingle, serverDid: SERVER_DID, didDocuments },
    },
    {
      id: 'delegation-chain/valid-two-hop-attenuated',
      category: 'delegation-chain',
      description: 'Root → intermediary → agent with a correctly attenuated child scope',
      expected: 'pass',
      reason: 'Linkage, audience, and scope subset all hold across the chain',
      input: { leaf: child, ancestors: [parent], serverDid: SERVER_DID, didDocuments },
    },
    {
      id: 'delegation-chain/broken-linkage',
      category: 'delegation-chain',
      description: 'Child issuerDid does not equal the parent subjectDid',
      expected: 'fail',
      reason: 'A broken issuer↔subject link must reject the chain',
      input: { leaf: forgedChild, ancestors: [parent], serverDid: SERVER_DID, didDocuments },
    },
    {
      id: 'delegation-chain/scope-widening',
      category: 'delegation-chain',
      description: 'Child introduces a scope absent from its parent',
      expected: 'fail',
      reason: 'A re-delegation may only narrow authority; widening must reject',
      input: { leaf: wideningChild, ancestors: [parent], serverDid: SERVER_DID, didDocuments },
    },
    {
      id: 'delegation-chain/tampered-signature',
      category: 'delegation-chain',
      description: 'Leaf credential whose Ed25519 proofValue was altered',
      expected: 'fail',
      reason: 'A mutated VC signature must fail verification',
      input: { leaf: tamperedLeaf, serverDid: SERVER_DID, didDocuments },
    },
    {
      id: 'delegation-chain/audience-mismatch',
      category: 'delegation-chain',
      description: 'Credential bound to a different server than the verifier',
      expected: 'fail',
      reason: 'Audience binding (confused-deputy guard) must reject a mismatched server',
      input: { leaf: wrongAudience, serverDid: SERVER_DID, didDocuments },
    },
  ];

  return { version: '1.1.0', category: 'delegation-chain', vectors };
}

function flipB64url(value: string): string {
  const last = value[value.length - 1];
  const swap = last === 'A' ? 'B' : 'A';
  return value.slice(0, -1) + swap;
}

// ── status-list vectors ─────────────────────────────────────────────────────────

async function statusListVectors(): Promise<VectorFile> {
  const issuer = await mintParty();
  const agent = await mintParty();
  const didDocuments = { [issuer.did]: didDocFor(issuer) };

  const listId = 'https://status.example.com/revocation/v1';
  const listSize = 131072;

  async function buildStatusList(revokedIndices: number[]): Promise<StatusList2021Credential> {
    const bitstring = new BitstringManager(listSize, conformanceCompressor, conformanceDecompressor);
    for (const i of revokedIndices) bitstring.setBit(i, true);
    const encodedList = await bitstring.encode();
    const unsigned = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://w3id.org/vc/status-list/2021/v1',
      ],
      id: listId,
      type: ['VerifiableCredential', 'StatusList2021Credential'],
      issuer: issuer.did,
      issuanceDate: '2026-01-01T00:00:00.000Z',
      credentialSubject: {
        id: `${listId}#list`,
        type: 'StatusList2021' as const,
        statusPurpose: 'revocation' as const,
        encodedList,
      },
    };
    const proof = await signVC(crypto, unsigned, issuer.privateKey, issuer.kid);
    return { ...unsigned, proof } as StatusList2021Credential;
  }

  const activeIndex = 7;
  const revokedIndex = 42;
  const statusFor = (index: number): CredentialStatus => ({
    id: `${listId}#${index}`,
    type: 'StatusList2021Entry',
    statusPurpose: 'revocation',
    statusListIndex: index.toString(),
    statusListCredential: listId,
  });

  const activeCred = await buildSignedDelegationWith(issuer, agent.did, 'del-active', statusFor(activeIndex));
  const revokedCred = await buildSignedDelegationWith(issuer, agent.did, 'del-revoked', statusFor(revokedIndex));
  const statusLists = { [listId]: await buildStatusList([revokedIndex]) };

  const vectors: ConformanceVector[] = [
    {
      id: 'status-list/active-credential',
      category: 'status-list',
      description: 'Delegation whose StatusList2021 bit is 0 (not revoked)',
      expected: 'pass',
      reason: 'An unset revocation bit means the credential is active',
      input: { credential: activeCred, statusLists, didDocuments, serverDid: SERVER_DID },
    },
    {
      id: 'status-list/revoked-credential',
      category: 'status-list',
      description: 'Delegation whose StatusList2021 bit is 1 (revoked)',
      expected: 'fail',
      reason: 'A set revocation bit must reject the credential',
      input: { credential: revokedCred, statusLists, didDocuments, serverDid: SERVER_DID },
    },
  ];

  return { version: '1.1.0', category: 'status-list', vectors };
}

async function buildSignedDelegationWith(
  issuer: Party,
  subjectDid: string,
  id: string,
  credentialStatus: CredentialStatus,
): Promise<DelegationCredential> {
  return buildSignedDelegation({
    issuer,
    subjectDid,
    id,
    scopes: ['greeting:read'],
    audience: SERVER_DID,
    credentialStatus,
  });
}

// ── did:key resolution vectors ──────────────────────────────────────────────────

async function didKeyVectors(): Promise<VectorFile> {
  const party = await mintParty();
  const vectors: ConformanceVector[] = [
    {
      id: 'did-key/valid-ed25519',
      category: 'did-key-resolution',
      description: 'A well-formed Ed25519 did:key',
      expected: 'pass',
      reason: 'Resolves to a single Ed25519 verification method',
      input: { did: party.did },
    },
    {
      id: 'did-key/malformed-multibase',
      category: 'did-key-resolution',
      description: 'A did:key with corrupted base58 multibase payload',
      expected: 'fail',
      reason: 'Invalid multibase cannot decode to a key — must reject',
      input: { did: 'did:key:z6MkNOTVALIDbase58!!!!' },
    },
    {
      id: 'did-key/wrong-method',
      category: 'did-key-resolution',
      description: 'A non-did:key DID passed to the did:key resolver',
      expected: 'fail',
      reason: 'did:web is out of scope for the did:key resolver — must not resolve',
      input: { did: 'did:web:example.com' },
    },
  ];
  return { version: '1.1.0', category: 'did-key-resolution', vectors };
}

// ── did:web resolution vectors ──────────────────────────────────────────────────

async function didWebVectors(): Promise<VectorFile> {
  const party = await mintParty();
  const webDid = 'did:web:agent.example.com';
  const webKid = `${webDid}#keys-1`;
  const document = buildDidWebDocument({
    did: webDid,
    kid: webKid,
    publicKey: party.publicKey,
    createdAt: '2026-01-01T00:00:00.000Z',
  });

  // Negative: served document whose id does not match the requested DID.
  const mismatched = { ...document, id: 'did:web:evil.example.com' };

  const vectors: ConformanceVector[] = [
    {
      id: 'did-web/valid',
      category: 'did-web-resolution',
      description: 'A did:web whose well-known document is well-formed and id-matched',
      expected: 'pass',
      reason: 'Resolves to a usable Ed25519 verification method',
      input: { did: webDid, didDocument: document },
    },
    {
      id: 'did-web/id-mismatch',
      category: 'did-web-resolution',
      description: 'Served document id does not equal the requested DID',
      expected: 'fail',
      reason: 'An id mismatch is a substitution attempt — must reject',
      input: { did: webDid, didDocument: mismatched },
    },
    {
      id: 'did-web/not-found',
      category: 'did-web-resolution',
      description: 'No document served at the well-known URL',
      expected: 'fail',
      reason: 'Resolution must fail closed when the document cannot be fetched',
      input: { did: webDid },
    },
  ];
  return { version: '1.1.0', category: 'did-web-resolution', vectors };
}

// ── orchestration ───────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  mkdirSync(VECTORS_DIR, { recursive: true });

  writeFile(await signedProofVectors(), 'signed-proof.json');
  writeFile(await delegationChainVectors(), 'delegation-chain.json');
  writeFile(await statusListVectors(), 'status-list.json');
  writeFile(await didKeyVectors(), 'did-key-resolution.json');
  writeFile(await didWebVectors(), 'did-web-resolution.json');
  console.log('All conformance vectors generated.');
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
