/**
 * Deterministic fixtures for the Entity Card conformance vectors.
 *
 * FIXED test keys + a FIXED clock, so the card vectors regenerate byte-identically
 * (unlike the fresh-key legacy `generate-vectors.ts`). These constants are the
 * single source the `card-vectors` generator, the `src/card/__tests__` round-trip,
 * and `conformance/verify.py` all reproduce against. The keys are TEST-ONLY (their
 * private `d` is committed here); NEVER reuse them for anything real.
 */

import type { Ed25519PrivateJwk } from '../src/card/index.js';

/** The signing key behind the golden `org.kya-os/proof.v1` proof (TEST-ONLY). */
export const ENTITY_KEY: Ed25519PrivateJwk = {
  kty: 'OKP',
  crv: 'Ed25519',
  x: 'RvWVWwqcVO9f_7aQ8dXf0F16aoQsE4i_Ebjqo8mn_Ts',
  d: 'Yaa31QgNkAKKHjqn6yEu2vXQTMUEbeBMwIJ4h55Ukh4',
};

// ── Fixed identity coordinates ──────────────────────────────────────────────────
export const ENTITY_DID = 'did:web:example.com:agents:acme-pay';
export const KID = `${ENTITY_DID}#key-1`;
export const AUDIENCE = 'did:web:example.com:mcp:server';
export const NONCE = 'n-0123456789abcdef0123456789abcdef';
export const T0_MS = Date.parse('2026-06-30T12:00:00Z');
/** The victim DID a kid⇄did forgery claims while `kid` still names the real signer. */
export const VICTIM_DID = 'did:web:victim.example';

/** The DID-keyed JWKS the proof verifies against (`resolveKey` / `resolveDidKeys` source). */
export const JWKS = {
  keys: [{ kty: 'OKP', crv: 'Ed25519', x: ENTITY_KEY.x, kid: KID }],
};

/** A payments request — all-string params, so JCS is unambiguous cross-language. */
export const REQUEST = {
  method: 'tools/call',
  params: {
    name: 'payments.transfer',
    arguments: { to: 'did:web:merchant.example', amount: '42.00', currency: 'USD' },
  },
};

// ── Delegation chain coordinates (the multi-hop ZCAP chain) ──────────────────────
export const OWNER = 'did:web:api.example'; // root issuer === responsibleParty
export const RESOURCE = 'did:web:api.example:payments'; // constant invocationTarget
export const AGENT_A = 'did:web:agent-a.example';

const DELEGATION_CONTEXT = [
  'https://www.w3.org/ns/credentials/v2',
  'https://w3id.org/security/zcap/v1',
  'https://kya-os.org/ns/delegation/v1',
];

/** A multi-hop W3C VC 2.0 + ZCAP-LD chain (root → leaf) with CRISP attenuation. */
export const DELEGATION_CHAIN: unknown[] = [
  {
    '@context': DELEGATION_CONTEXT,
    id: 'urn:zcap:root',
    type: ['VerifiableCredential', 'DelegationCredential'],
    issuer: OWNER,
    validUntil: '2027-01-01T00:00:00Z',
    credentialSubject: {
      id: 'urn:zcap:root',
      invoker: AGENT_A,
      parentCapability: RESOURCE,
      invocationTarget: RESOURCE,
      allowedAction: ['payments.transfer', 'payments.read'],
      caveats: [
        { type: 'MaxAmount', limit: '1000.00', currency: 'USD' },
        { type: 'ValidUntil', date: '2027-01-01T00:00:00Z' },
      ],
    },
    credentialStatus: {
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: '7',
      statusListCredential: 'https://api.example/status/delegations',
    },
    proof: { type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', proofValue: 'z-root-placeholder' },
  },
  {
    '@context': DELEGATION_CONTEXT,
    id: 'urn:zcap:del1',
    type: ['VerifiableCredential', 'DelegationCredential'],
    issuer: AGENT_A,
    validUntil: '2026-07-01T00:00:00Z',
    credentialSubject: {
      id: 'urn:zcap:del1',
      invoker: ENTITY_DID,
      parentCapability: 'urn:zcap:root',
      invocationTarget: RESOURCE,
      allowedAction: ['payments.transfer'],
      caveats: [
        { type: 'MaxAmount', limit: '500.00', currency: 'USD' },
        { type: 'ValidUntil', date: '2026-07-01T00:00:00Z' },
      ],
    },
    credentialStatus: {
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: '42',
      statusListCredential: 'https://agent-a.example/status/delegations',
    },
    proof: { type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', proofValue: 'z-leaf-placeholder' },
  },
];

/** Golden `parseCard`-valid Entity Cards, one per `entityType`. */
export const GOLDEN_CARDS = {
  mcp: {
    id: AUDIENCE,
    entityType: 'mcp',
    name: 'Acme MCP Server',
    capabilities: ['tools/list', 'tools/call'],
    proofProfile: 'org.kya-os/proof.v1',
  },
  agent: {
    id: ENTITY_DID,
    entityType: 'agent',
    name: 'Acme Pay Agent',
    kid: KID,
    capabilities: ['handshake', { name: 'payments.transfer', attestations: [{ vc: 'jwt-cap-attestation' }] }],
    responsibleParty: OWNER,
    principal: 'did:web:example.com:users:alice',
    delegationRef: 'urn:zcap:root>urn:zcap:del1',
    proofProfile: 'org.kya-os/proof.v1',
    revocation: { statusListCredential: 'https://example.com/status/cards', statusListIndex: '3' },
  },
  client: {
    id: 'did:web:app.example:clients:acme-cli',
    entityType: 'client',
    name: 'Acme CLI',
    proofProfile: 'org.kya-os/proof.v1',
    cimd: { clientId: 'https://app.example/clients/acme-cli', jwksUri: 'https://app.example/clients/acme-cli/jwks.json' },
  },
  verifier: {
    id: 'did:web:verifier.example',
    entityType: 'verifier',
    name: 'Acme Verifier',
    capabilities: ['proof.verify'],
  },
  human: {
    id: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
    entityType: 'human',
    name: 'Alice (delegating principal)',
  },
} as const;
