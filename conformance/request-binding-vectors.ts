#!/usr/bin/env node
/**
 * Deterministic generator for the vectors of a holder's request proof and the delegation presented
 * beside it (SPEC.md §7.8, suite 1.13.0), `conformance/vectors/signed-proof-request-binding.json`,
 * and of a re-delegation's commitment to its parent in the base profile (SPEC.md §6.2),
 * `conformance/vectors/delegation-chain-parent-commitment.json` (./parent-commitment-vectors.ts).
 *
 * A request proof covers the call, not the delegation beside it, so it states the credential the
 * call presents in its JWS protected header, under `org.kya-os/delegation`: that credential's §7.8
 * digest, or `none`. Each vector turns on one rule of how a verifier holds a proof to that
 * statement. The parties' keys and the clock are fixed (./request-binding-kit.ts), so re-running
 * reproduces byte-identical files.
 *
 *   run:  tsx conformance/request-binding-vectors.ts   (npm run conformance:generate:request-binding)
 */

import { pathToFileURL } from 'node:url';
import { DELEGATION_HEADER_PARAMETER, delegationCredentialDigest, delegationRefOf } from '../src/index.js';
import { signVcJwt } from './crypto-kit.js';
import { parentCommitmentVectorFile } from './parent-commitment-vectors.js';
import {
  AGENT,
  USER,
  credential,
  crypto,
  inputOf,
  requestProof,
  requestProofUnder,
  withHeaderReplaced,
} from './request-binding-kit.js';
import type { ConformanceVector, SignedProofInput, VectorFile } from './types.js';
import { SUITE_VERSION, writeVectorFile } from './vector-files.js';

const hash = (bytes: Uint8Array): Promise<string> => crypto.hash(bytes);
const digestOf = (delegation: Parameters<typeof delegationCredentialDigest>[0]): Promise<string> =>
  delegationCredentialDigest(delegation, hash);

export async function requestBindingVectorFile(): Promise<VectorFile> {
  // Two delegations the user gave the agent, and the first issued again under the same id.
  const read = await credential({ issuer: USER, subjectDid: AGENT.did, id: 'del-records-read', scopes: ['records:read'] });
  const write = await credential({ issuer: USER, subjectDid: AGENT.did, id: 'del-records-write', scopes: ['records:read', 'records:write'] });
  const reissued = await credential({ issuer: USER, subjectDid: AGENT.did, id: 'del-records-read', scopes: ['records:read', 'records:write'] });
  const readJwt = await signVcJwt(USER, read);
  // The first again, differing in nothing its issuer signed: other proof metadata, and its signature padded.
  const readCopy = {
    ...read,
    proof: { ...read.proof, created: '2031-01-01T00:00:00.000Z', note: 'added by a holder', proofValue: `${String(read.proof?.proofValue)}==` },
  };
  const [readDigest, writeDigest] = await Promise.all([digestOf(read), digestOf(write)]);

  // Each proof is the agent's, for the same call, under a nonce of its own.
  const named = await requestProof(read, 'nonce-request-binding-0001');
  const namedJwt = await requestProof(readJwt, 'nonce-request-binding-0002');
  const none = await requestProof(null, 'nonce-request-binding-0003');
  const stating = (nonce: string, statement: unknown, meta = {}) =>
    requestProofUnder(nonce, (own) => ({ ...own, [DELEGATION_HEADER_PARAMETER]: statement }), meta);
  const unnamed = await requestProofUnder('nonce-request-binding-0004', (own) => own);
  const upperCase = await stating('nonce-request-binding-0005', readDigest.toUpperCase().replace('SHA256:', 'sha256:'));
  const inArray = await stating('nonce-request-binding-0006', [readDigest]);
  const twice = await requestProofUnder(
    'nonce-request-binding-0007',
    ({ alg, kid }) =>
      `{"alg":${JSON.stringify(alg)},"kid":${JSON.stringify(kid)},` +
      `${JSON.stringify(DELEGATION_HEADER_PARAMETER)}:${JSON.stringify(readDigest)},` +
      `${JSON.stringify(DELEGATION_HEADER_PARAMETER)}:${JSON.stringify(writeDigest)}}`,
  );
  const otherRef = await stating('nonce-request-binding-0008', readDigest, { delegationRef: await delegationRefOf(write, hash) });
  const own = { alg: 'EdDSA', kid: AGENT.kid };
  const altered = withHeaderReplaced(named, { ...own, [DELEGATION_HEADER_PARAMETER]: writeDigest });
  const stripped = withHeaderReplaced(named, own);

  const vector = (
    name: string,
    expected: 'pass' | 'fail',
    description: string,
    reason: string,
    input: SignedProofInput,
  ): ConformanceVector => ({ id: `signed-proof/request-binding-${name}`, category: 'signed-proof', description, expected, reason, input });

  const vectors: ConformanceVector[] = [
    vector('named', 'pass',
      'Request proof whose protected header states the §7.8 digest of the credential object its call presents, as the generator writes it with no input but the arguments the call sends',
      'The holder names the credential it presents, in the form it is sent, so the proof is bound to that delegation',
      inputOf(named, read)),
    vector('named-vc-jwt', 'pass',
      'Request proof that states the digest of the compact VC-JWT its call presents',
      'A credential sent as a VC-JWT is named by the digest of that form',
      inputOf(namedJwt, readJwt)),
    vector('reserialized', 'pass',
      'The proof that names a credential object, beside a copy of it that differs in nothing its issuer signed: other proof metadata, and its signature padded',
      'A credential is digested by what its issuer signed and the signature bytes, so a copy that differs in nothing signed is the credential named',
      inputOf(named, readCopy)),
    vector('other-delegation', 'fail',
      'The proof that names one delegation of the agent, beside another delegation the same user gave the same agent',
      'A party on the path that holds another delegation of the agent cannot put it in place of the one the holder named: the digests differ',
      inputOf(named, write)),
    vector('reissued-under-same-id', 'fail',
      'The proof that names a credential, beside one its issuer issued again under the same id with wider scopes',
      'The statement is a digest of what the issuer signed, not an id, so a credential issued again under the same id is another credential',
      inputOf(named, reissued)),
    vector('other-form', 'fail',
      'The proof that names a credential object, beside the same delegation sent as a compact VC-JWT',
      'A proof names the credential in the form it is sent; the object and the VC-JWT of one delegation have different signed forms, so different digests',
      inputOf(named, readJwt)),
    vector('none', 'pass',
      'Request proof that states "none", for a call that presents no delegation',
      'A holder that presents no delegation says so, and the statement holds beside none',
      inputOf(none, null)),
    vector('none-beside-delegation', 'fail',
      'The proof that states "none", beside a delegation, held by a verifier that requires a proof to name the credential presented',
      'A delegation added beside a proof that says its call presents none is not the holder\'s choice',
      inputOf(none, read, 'require')),
    vector('unnamed-beside-delegation', 'fail',
      'Request proof whose protected header states nothing of its delegation, beside a delegation, held by a verifier that requires a proof to name the credential presented',
      'A proof that names no delegation is good beside any delegation of its subject, so a verifier that requires naming refuses it',
      inputOf(unnamed, read, 'require')),
    vector('unnamed', 'fail',
      'The proof that states nothing of its delegation, for a call that presents none, held by a verifier that requires a proof to name the credential presented',
      'A holder that presents no delegation states "none"; a proof that states nothing does not say which authority its call is made under',
      inputOf(unnamed, null, 'require')),
    vector('statement-not-lowercase', 'fail',
      'Request proof that states the digest of the credential presented with its hex digits in upper case',
      'The statement is a credential digest as §7.8 writes one, sha256: and 64 lowercase hex digits, or "none"; any other value is malformed and refused',
      inputOf(upperCase, read)),
    vector('statement-not-a-string', 'fail',
      'Request proof that states an array holding the digest of the credential presented',
      'A statement that is not a string is neither a credential digest nor "none", so it is malformed and refused',
      inputOf(inArray, read)),
    vector('statement-altered', 'fail',
      'The proof that names one delegation, its protected header rewritten after signing to state another, beside that other delegation',
      'The protected header is part of the JWS signing input, so a statement changed without the holder\'s key breaks the signature',
      inputOf(altered, write)),
    vector('statement-stripped', 'fail',
      'The proof that names one delegation, its protected header rewritten after signing to state nothing, beside another delegation',
      'A named proof cannot be made an unnamed one: removing the statement breaks the signature, whether or not the verifier requires naming',
      inputOf(stripped, write)),
    vector('statement-duplicated', 'fail',
      'Request proof signed over a protected header that holds the parameter twice, the first stating the credential presented and the last another',
      'Of header parameters that share a name a verifier reads the last or refuses the JWS (RFC 7515 §4), so the first never binds the proof',
      inputOf(twice, read)),
    vector('payload-names-another', 'fail',
      'Request proof whose protected header states the credential presented and whose signed delegationRef names another',
      'A proof is held to every name of a delegation its signature covers, so one that also names another credential in its payload is refused',
      inputOf(otherRef, read)),
  ];
  return { version: SUITE_VERSION, category: 'signed-proof', vectors };
}

export async function generateRequestBindingVectors(): Promise<void> {
  writeVectorFile(await requestBindingVectorFile(), 'signed-proof-request-binding.json');
  writeVectorFile(await parentCommitmentVectorFile(), 'delegation-chain-parent-commitment.json');
  console.log('Request-binding and parent-commitment conformance vectors generated (deterministic).');
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  generateRequestBindingVectors().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}
