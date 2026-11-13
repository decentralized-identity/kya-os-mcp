import { sign, verify, createPublicKey, type JsonWebKeyInput } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { importJWK, SignJWT } from 'jose';
import { withStatusCache } from '../status-cache.js';
import { DelegationCredentialVerifier, type StatusListResolver } from '../vc-verifier.js';
import { createDidKeyResolver } from '../did-key-resolver.js';
import { canonicalizeJSON } from '../utils.js';
import { createRevocationChecker } from '../../card/revocation.js';
import { createStatusListProofVerifier } from '../../card/status-list-proof.js';
import { identity, statusList, serve, STATUS_URL } from '../../card/__tests__/signed-chain-helpers.js';
import type { CredentialStatus, DelegationCredential } from '../../types/protocol.js';

describe('status caching preserves omitted versus malformed purposes', () => {
  it.each(['object', 'JWT'] as const)('%s: cannot reuse an omitted-purpose allow for an explicit null', async form => {
    const issuer = identity();
    const didResolver = createDidKeyResolver();
    const checker = createRevocationChecker({
      fetch: serve(statusList(issuer)),
      verifyStatusList: createStatusListProofVerifier({ didResolver }),
    });
    // A common adapter between the two exported status-check interfaces.
    const resolver: StatusListResolver = {
      checkStatus: async (status, context) => (await checker(status, context)).revoked,
    };
    const cached = withStatusCache(resolver, { maxStalenessMs: 60_000 });
    const makeVerifier = (statusListResolver: StatusListResolver) => new DelegationCredentialVerifier({
      didResolver, statusListResolver,
      signatureVerifier: async (vc, jwk) => {
        const { proof, ...unsigned } = vc;
        return { valid: verify(null, Buffer.from(canonicalizeJSON(unsigned)),
          createPublicKey({ key: jwk as JsonWebKeyInput['key'], format: 'jwk' }),
          Buffer.from(proof!.proofValue as string, 'base64url')) };
      },
    });
    const credential = (status: CredentialStatus): DelegationCredential => {
      const unsigned = {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential', 'DelegationCredential'], issuer: issuer.did,
        issuanceDate: '2026-01-01T00:00:00Z',
        credentialSubject: { id: 'did:example:holder', delegation: {
          id: 'del-cache-purpose', issuerDid: issuer.did, subjectDid: 'did:example:holder',
          constraints: { scopes: ['read'] }, status: 'active',
        } },
        credentialStatus: status,
      };
      return { ...unsigned, proof: {
        type: 'Ed25519Signature2020', verificationMethod: issuer.method, proofPurpose: 'assertionMethod',
        proofValue: sign(null, Buffer.from(canonicalizeJSON(unsigned)), issuer.privateKey).toString('base64url'),
      } } as DelegationCredential;
    };
    const run = async (verifier: DelegationCredentialVerifier, status: CredentialStatus) => {
      const vc = credential(status);
      if (form === 'object') return verifier.verifyDelegationCredential(vc);
      const { proof: _proof, ...unsigned } = vc;
      const jwt = await new SignJWT({ vc: unsigned }).setProtectedHeader({ alg: 'EdDSA', kid: issuer.method })
        .setIssuer(issuer.did).sign(await importJWK(issuer.privateJwk, 'EdDSA'));
      return verifier.verifyDelegationJwt(jwt);
    };
    // The checker deliberately accepts absence (Card entries use it), while
    // explicit null must be refused. Both inputs and proofs are real JSON.
    const omitted = { type: 'BitstringStatusListEntry', statusListCredential: STATUS_URL, statusListIndex: '7' } as CredentialStatus;
    const malformed = { ...omitted, statusPurpose: null } as unknown as CredentialStatus;
    expect((await run(makeVerifier(resolver), omitted)).valid).toBe(true);
    expect((await run(makeVerifier(resolver), malformed)).valid).toBe(false);
    const verifier = makeVerifier(cached);
    expect((await run(verifier, omitted)).valid).toBe(true);
    expect((await run(verifier, malformed)).valid).toBe(false);
    expect((await run(verifier, omitted)).valid).toBe(true);
  });
});
