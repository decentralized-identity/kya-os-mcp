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

import { mkdirSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { NodeCryptoProvider } from '../src/providers/node-crypto.js';
import {
  ProofGenerator,
  buildDidWebDocument,
  RESPONSE_PROOF_PROFILE_ENVELOPE,
  type DelegationCredential,
  type CredentialStatus,
  type DetachedProof,
} from '../src/index.js';
import { extractPublicKeyFromDidKey, publicKeyToJwk } from '../src/delegation/did-key-resolver.js';
import { VECTORS_DIR } from './loader.js';
import { signedDelegation, type SignedDelegationArgs } from './credential-kit.js';
import { ed25519VerificationMethod, partyOf, signProofMeta, signVcJwt, type KeyedParty } from './crypto-kit.js';
import { delegationBindingVectors } from './delegation-binding-vectors.js';
import { READ_AS_LARGE_INTEGER } from './numbers-as-written.js';
import { statusListVectors, type StatusListVectorDeps } from './status-list-vectors.js';
import { flipB64url, flipSignatureChar } from './tampering.js';
import { SUITE_VERSION, writeVectorFile } from './vector-files.js';
import type {
  ConformanceVector,
  VectorFile,
} from './types.js';

const crypto = new NodeCryptoProvider();
const NOW = 1_750_000_000; // fixed epoch-seconds anchor for proof timestamps
const SERVER_DID = 'did:web:server.example.com';

type Party = KeyedParty;

async function mintParty(): Promise<Party> {
  return partyOf(await crypto.generateKeyPair());
}

function jwkFor(party: Party) {
  const raw = extractPublicKeyFromDidKey(party.did)!;
  const jwk = publicKeyToJwk(raw);
  return { ...jwk, kid: party.kid };
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

  // ── Envelope-coverage profile (`org.kya-os/response-proof.envelope`, suite ≥ 1.1.0) ─
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
    { profile: RESPONSE_PROOF_PROFILE_ENVELOPE },
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

  // ── 1.x legacy request shapes (SPEC §7.3, suite 1.11.0 or later) ─
  // Proofs over `{method: <tool name>, params: <arguments>}`, held against the
  // `tools/call` request as sent, which carries a control argument.
  const heldCall = {
    method: 'tools/call',
    params: { name: 'echo', arguments: { msg: 'hi', _kyaos_delegation: 'vc-jwt-of-the-delegation' } },
  };
  const legacyInput = async (method: string, params: Record<string, unknown>) => {
    const legacy = await gen.generateProof({ method, params }, { data: { output: 'hi' } }, session);
    const proof = await signProofMeta(agent, { ...legacy.meta, ts: NOW });
    const expected = { request: heldCall, response: { data: { output: 'hi' } } };
    return { proof, publicKeyJwk: jwk, now: NOW, skewSeconds: 300, expected };
  };
  const legacyAsReceived = await legacyInput('echo', heldCall.params.arguments);
  const legacyWithoutControlArgs = await legacyInput('echo', { msg: 'hi' });
  const legacyOtherTool = await legacyInput('delete', { msg: 'hi' });

  // ── Delegation chain binding (`delegationChainDigest`, SPEC §7.8; suite 1.5.0 or later) ─
  const delegationBinding = await delegationBindingVectors<Party>({
    publicKeyJwk: jwk,
    now: NOW,
    hash: (bytes) => crypto.hash(bytes),
    party: mintParty,
    credential: (args) => buildSignedDelegation({ ...args, audience: SERVER_DID }),
    vcJwt: signVcJwt,
    proof: async (request, response, options) =>
      signProofMeta(agent, { ...(await gen.generateProof(request, response, session, options)).meta, ts: NOW }),
    signedUnder: (meta, header) => signProofMeta(agent, meta, header),
  });

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
        'Proof under profile org.kya-os/response-proof.envelope whose responseHash binds the full result envelope; verified against the received result with a mutated _meta',
      expected: 'pass',
      reason:
        'Under prf=org.kya-os/response-proof.envelope the verifier hashes the received result with the top-level _meta removed, so a _meta-only mutation never invalidates the binding',
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
    {
      id: 'signed-proof/legacy-request-shape',
      category: 'signed-proof',
      description:
        'Proof whose requestHash is over the 1.x legacy shape {method: <tool name>, params: <arguments as received>}, verified against the tools/call request as sent',
      expected: 'pass',
      reason: 'During 1.x a verifier accepts a requestHash over the legacy shape with the arguments as received (SPEC.md §7.3)',
      input: legacyAsReceived,
    },
    {
      id: 'signed-proof/legacy-request-shape-without-control-args',
      category: 'signed-proof',
      description:
        'Proof whose requestHash is over the 1.x legacy shape with every _kyaos* argument removed, verified against the tools/call request as sent',
      expected: 'pass',
      reason: 'During 1.x a verifier accepts a requestHash over the legacy shape with the control arguments removed (SPEC.md §7.3)',
      input: legacyWithoutControlArgs,
    },
    {
      id: 'signed-proof/legacy-request-shape-other-tool',
      category: 'signed-proof',
      description: 'Proof whose requestHash is over the 1.x legacy shape of a call to another tool with the same arguments',
      expected: 'fail',
      reason: 'The hash is over none of the three shapes of the call held, so the request mismatches',
      input: legacyOtherTool,
    },
    ...delegationBinding,
  ];

  return { version: SUITE_VERSION, category: 'signed-proof', vectors };
}

// ── delegation-chain vectors ───────────────────────────────────────────────────

function didDocFor(party: Party): Record<string, unknown> {
  return {
    id: party.did,
    verificationMethod: [ed25519VerificationMethod(party.kid, party.did, extractPublicKeyFromDidKey(party.did)!)],
    assertionMethod: [party.kid],
    authentication: [party.kid],
  };
}

/** A delegation signed by its issuer at the suite's fixed time (./credential-kit.ts). */
const buildSignedDelegation = (args: SignedDelegationArgs): Promise<DelegationCredential> =>
  signedDelegation(crypto, args, NOW);

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

  // Negative: a parent with no scopes grants none, so a child that states one widens it.
  const scopelessParent = await buildSignedDelegation({
    issuer: root,
    subjectDid: intermediary.did,
    id: 'del-root-interm-scopeless',
    scopes: [],
    audience: SERVER_DID,
  });
  const scopeUnderScopeless = await buildSignedDelegation({
    issuer: intermediary,
    subjectDid: agent.did,
    id: 'del-scopeless-widening-child',
    parentId: 'del-root-interm-scopeless',
    scopes: ['greeting:read'],
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

  // Negative: a subject id holding a line break, which a log line or an audit
  // record that prints the acting agent's DID would read as two lines.
  const controlCharacterSubject = await buildSignedDelegation({
    issuer: root,
    subjectDid: `${agent.did}\n${root.did}`,
    id: 'del-control-character-subject',
    scopes: ['greeting:read'],
    audience: SERVER_DID,
  });

  // Negative: an issuanceDate a century ahead of any verifier's clock.
  const issuedInFuture = await buildSignedDelegation({
    issuer: root,
    subjectDid: agent.did,
    id: 'del-issued-in-future',
    scopes: ['greeting:read'],
    audience: SERVER_DID,
    members: [['issuanceDate', '2126-01-01T00:00:00.000Z']],
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
      id: 'delegation-chain/scopeless-parent-widening',
      category: 'delegation-chain',
      description: 'Child states a scope under a parent that states none',
      expected: 'fail',
      reason: 'A parent with no scopes grants none, so a child that states one widens it and must reject',
      input: { leaf: scopeUnderScopeless, ancestors: [scopelessParent], serverDid: SERVER_DID, didDocuments },
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
    {
      id: 'delegation-chain/subject-id-control-character',
      category: 'delegation-chain',
      description: 'Signed delegation whose credentialSubject.id holds a line feed between two DIDs',
      expected: 'fail',
      reason:
        'A subject id is held to the rule an issuer is: a URL as it stands, with no character a reader does not see. The verifier hands it on as the acting agent\'s DID, where a line break forges a line (delegation_malformed)',
      input: { leaf: controlCharacterSubject, serverDid: SERVER_DID, didDocuments },
    },
    {
      id: 'delegation-chain/issued-in-future',
      category: 'delegation-chain',
      description: 'Signed delegation whose issuanceDate is 2126-01-01, far past the 120 s clock tolerance',
      expected: 'fail',
      reason:
        'issuanceDate is when the credential becomes valid, held with the clock tolerance a status list\'s start is, so one beyond it is not yet valid (delegation_not_yet_valid)',
      input: { leaf: issuedInFuture, serverDid: SERVER_DID, didDocuments },
    },
  ];

  return { version: SUITE_VERSION, category: 'delegation-chain', vectors };
}

// ── status-list vectors ─────────────────────────────────────────────────────────

/** A delegation for the status-list category (./status-list-vectors.ts), signed as every category's is. */
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

/** Party minting and delegation signing for `status-list.json` and `status-list-authority.json`. */
export const statusListVectorDeps: StatusListVectorDeps<Party> = {
  crypto, mintParty, didDocumentFor: didDocFor,
  signDelegation: buildSignedDelegationWith, serverDid: SERVER_DID,
};

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
  return { version: SUITE_VERSION, category: 'did-key-resolution', vectors };
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
  return { version: SUITE_VERSION, category: 'did-web-resolution', vectors };
}

// ── orchestration ───────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  mkdirSync(VECTORS_DIR, { recursive: true });

  writeVectorFile(await signedProofVectors(), 'signed-proof.json', [READ_AS_LARGE_INTEGER]);
  writeVectorFile(await delegationChainVectors(), 'delegation-chain.json');
  writeVectorFile(await statusListVectors(statusListVectorDeps), 'status-list.json');
  writeVectorFile(await didKeyVectors(), 'did-key-resolution.json');
  writeVectorFile(await didWebVectors(), 'did-web-resolution.json');
  console.log('All conformance vectors generated.');
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  main().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}
