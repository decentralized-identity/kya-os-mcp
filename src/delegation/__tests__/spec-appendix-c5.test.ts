/**
 * SPEC.md Appendix C.5: a holder's request proof that states its delegation in its protected header
 * (SPEC §7.8), written out to the last byte. Ed25519 signs deterministically, so the vector is
 * reproduced here by hand, with nothing from the modules under test, then read by them. The key is
 * the first test key of RFC 8032 §7.1.
 */
import { createHash, createPrivateKey, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { delegationCredentialDigest } from '../chain-digest.js';
import { verifyDelegatedCallProof } from '../delegated-call-proof.js';
import { delegationStatement, statedDelegationOf } from '../stated-delegation.js';
import type { DetachedProof } from '../../types/protocol.js';
import { jwsProtectedHeader } from '../../utils/crypto-service.js';
import { didKeyFragment, generateDidKeyFromBase64 } from '../../utils/did-helpers.js';
import { hash, proofVerifier } from './helpers/request-proofs.js';

const SEED = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
const PUBLIC_KEY = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
const DID = 'did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw';
const KID = `${DID}#z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw`;
const SERVER = 'did:web:server.example.com';
const TS = 1710288000;

const CREDENTIAL = {
  id: 'urn:uuid:2222-bbbb',
  type: ['VerifiableCredential', 'DelegationCredential'],
  issuer: 'did:web:user.example.com',
  credentialSubject: { id: DID },
  proof: {
    type: 'Ed25519Signature2020',
    created: '2024-03-01T12:00:00Z',
    verificationMethod: 'did:web:user.example.com#key-1',
    proofPurpose: 'assertionMethod',
    proofValue: 'c2lnbmF0dXJlLW9mLWNyZWRlbnRpYWw',
  },
};
const SIGNED_FORM =
  `{"credential":{"credentialSubject":{"id":"${DID}"},"id":"urn:uuid:2222-bbbb",` +
  '"issuer":"did:web:user.example.com","type":["VerifiableCredential","DelegationCredential"]},' +
  '"signature":"c2lnbmF0dXJlLW9mLWNyZWRlbnRpYWw"}';
const DIGEST = 'sha256:52bf13b89717bcec22e230f770471f09746b081b7f73da43094cd9aad511dc1a';
/** The call of Appendix C.1 whose business arguments stay covered: `echo` with `{ msg: 'hi' }`. */
const REQUEST = { method: 'tools/call', params: { name: 'echo', arguments: { msg: 'hi' } } };
const REQUEST_HASH = 'sha256:c8f3d59959c9247211de8c76b94ef17f0c279f09362350ced67f69ecdb89d6c7';
const META = { did: DID, kid: KID, ts: TS, nonce: 'bm9uY2UtYzUtMDAwMDAwMQ', audience: SERVER, sessionId: 'kyaos_c5-session', requestHash: REQUEST_HASH };
const PAYLOAD =
  `{"aud":"${SERVER}","iss":"${DID}","nonce":"bm9uY2UtYzUtMDAwMDAwMQ","requestHash":"${REQUEST_HASH}",` +
  `"sessionId":"kyaos_c5-session","sub":"${DID}","ts":${TS}}`;
const headerStating = (statement: string): string => `{"alg":"EdDSA","kid":"${KID}","org.kya-os/delegation":"${statement}"}`;
const SIGNATURE_NAMING = 'wn1TFvrzCXbbYlB4f8q3g3JTJvVZOO7CzyutpqvVILWfAo1Xg-VXJZ1H0lbVgfi_ImIPdytpT561MBCOUqwtBw';
const SIGNATURE_NONE = 'o0ar1iBiL7mHkjvhOEvKqgtBqxG5t6O_byDoAqUv3ZXB9pwvlCHqG9fhFS1ugg2vznN1D-FFgpI_LCly9FAJBA';

const base64url = (value: string | Uint8Array): string => Buffer.from(value).toString('base64url');

/** The same delegation as a compact VC-JWT, shortened as the object is: another form, so another digest. */
const VC_JWT_HEADER = '{"alg":"EdDSA","typ":"JWT"}';
const VC_JWT_PAYLOAD =
  `{"iss":"did:web:user.example.com","sub":"${DID}","jti":"urn:uuid:2222-bbbb",` +
  '"vc":{"type":["VerifiableCredential","DelegationCredential"]}}';
const VC_JWT_SIGNED = `${base64url(VC_JWT_HEADER)}.${base64url(VC_JWT_PAYLOAD)}`;
const VC_JWT = `${VC_JWT_SIGNED}.c2lnbmF0dXJlLW9mLWNyZWRlbnRpYWw`;
const VC_JWT_SIGNED_FORM = `{"jwt":"${VC_JWT_SIGNED}","signature":"c2lnbmF0dXJlLW9mLWNyZWRlbnRpYWw"}`;
const VC_JWT_DIGEST = 'sha256:118311d6a525a36fe5e3d7fc5dc67b7e4fdd032d8b9b71799b476a82cbacb1ca';
const SIGNATURE_NAMING_VC_JWT = 'tki3aTL2MZwFUmKHZHQ28GRmI1kEahphrsJr-1v245z4M_n-qVp_Wabn-gdaIFjy1YYHCFalRarTOMzs9DT1Dg';
/** The compact JWS over `header` and {@link PAYLOAD}, signed by hand with the RFC 8032 key. */
function signedByHand(header: string): string {
  const key = createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(SEED, 'hex')]),
    format: 'der',
    type: 'pkcs8',
  });
  const signingInput = `${base64url(header)}.${base64url(PAYLOAD)}`;
  return `${signingInput}.${base64url(sign(null, Buffer.from(signingInput), key))}`;
}
const proofStating = (statement: string): DetachedProof => ({ jws: signedByHand(headerStating(statement)), meta: META });
const held = (proof: DetachedProof, presented: unknown, mode: 'prefer' | 'require' = 'require') =>
  verifyDelegatedCallProof({
    proof,
    subjectDid: DID,
    request: REQUEST,
    expectedAudience: SERVER,
    proofVerifier: proofVerifier(),
    presented: presented as never,
    mode,
    hash,
  });

describe('SPEC Appendix C.5: a request proof that names its delegation', () => {
  beforeAll(() => {
    vi.useFakeTimers({ toFake: ['Date'], now: TS * 1000 });
  });
  afterAll(() => {
    vi.useRealTimers();
  });

  it('uses the first RFC 8032 test key, under the did:key SPEC §4.3 derives for it', () => {
    expect(generateDidKeyFromBase64(Buffer.from(PUBLIC_KEY, 'hex').toString('base64'))).toBe(DID);
    expect(KID).toBe(`${DID}#${didKeyFragment(DID)}`);
  });

  it('states the SPEC §7.8 digest of the credential presented, over its signed form', async () => {
    const byHand = createHash('sha256').update(`org.kya-os.delegation.credential.v1\0${SIGNED_FORM}`, 'utf8').digest('hex');
    expect(DIGEST).toBe(`sha256:${byHand}`);
    expect(await delegationCredentialDigest(CREDENTIAL, hash)).toBe(DIGEST);
    expect(await delegationStatement(CREDENTIAL, hash)).toBe(DIGEST);
  });

  it('signs the header with the statement in it: the JWS of the appendix, to the last byte', () => {
    expect(signedByHand(headerStating(DIGEST)).split('.')[2]).toBe(SIGNATURE_NAMING);
    expect(signedByHand(headerStating('none')).split('.')[2]).toBe(SIGNATURE_NONE);
    expect(statedDelegationOf(jwsProtectedHeader(signedByHand(headerStating(DIGEST))))).toEqual({ kind: 'credential', digest: DIGEST });
    expect(statedDelegationOf(jwsProtectedHeader(signedByHand(headerStating('none'))))).toEqual({ kind: 'none' });
  });

  it('is bound beside the credential it names, and beside no other', async () => {
    const proof = proofStating(DIGEST);
    expect(await held(proof, CREDENTIAL)).toMatchObject({ status: 'bound', named: true });
    const reissued = { ...CREDENTIAL, proof: { ...CREDENTIAL.proof, proofValue: 'c2lnbmF0dXJlLW9mLWFub3RoZXI' } };
    expect(await held(proof, reissued)).toMatchObject({ status: 'unbound', cause: 'delegation_mismatch' });
    expect(await held(proof, reissued, 'prefer')).toMatchObject({ status: 'unbound', cause: 'delegation_mismatch' });
  });

  it('states another digest for the same delegation sent as a VC-JWT: the digest of that form', async () => {
    const byHand = createHash('sha256').update(`org.kya-os.delegation.credential.v1\0${VC_JWT_SIGNED_FORM}`, 'utf8').digest('hex');
    expect(VC_JWT_DIGEST).toBe(`sha256:${byHand}`);
    expect(await delegationStatement(VC_JWT, hash)).toBe(VC_JWT_DIGEST);
    expect(VC_JWT_DIGEST).not.toBe(DIGEST);
    expect(signedByHand(headerStating(VC_JWT_DIGEST)).split('.')[2]).toBe(SIGNATURE_NAMING_VC_JWT);
  });

  it('is bound beside the form it names, and not beside the other form of the same delegation', async () => {
    expect(await held(proofStating(VC_JWT_DIGEST), VC_JWT)).toMatchObject({ status: 'bound', named: true });
    expect(await held(proofStating(VC_JWT_DIGEST), CREDENTIAL)).toMatchObject({ status: 'unbound', cause: 'delegation_mismatch' });
    expect(await held(proofStating(DIGEST), VC_JWT)).toMatchObject({ status: 'unbound', cause: 'delegation_mismatch' });
  });

  it('states "none" for a call that presents no delegation, which a verifier that requires naming refuses beside one', async () => {
    const proof = proofStating('none');
    expect(await held(proof, null)).toMatchObject({ status: 'bound', named: true });
    expect(await held(proof, CREDENTIAL)).toMatchObject({ status: 'unbound', cause: 'delegation_stated_none' });
  });

  it('is written in SPEC.md as it is computed here', () => {
    const spec = readFileSync(fileURLToPath(new URL('../../../SPEC.md', import.meta.url)), 'utf8');
    const appendix = spec.slice(spec.indexOf('### C.5 '));
    for (const written of [
      SEED,
      PUBLIC_KEY,
      KID,
      SIGNED_FORM,
      DIGEST,
      headerStating(DIGEST),
      PAYLOAD,
      signedByHand(headerStating(DIGEST)),
      VC_JWT,
      VC_JWT_SIGNED_FORM,
      VC_JWT_DIGEST,
      headerStating(VC_JWT_DIGEST),
      signedByHand(headerStating(VC_JWT_DIGEST)),
      headerStating('none'),
      signedByHand(headerStating('none')),
    ]) {
      expect(appendix, written).toContain(written);
    }
  });
});
