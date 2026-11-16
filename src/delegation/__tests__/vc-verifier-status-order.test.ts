/**
 * `DelegationCredentialVerifier` reads a credential's status only after its signature verifies, on
 * both of its paths, so a credential that only names an issuer costs no status read. A status it
 * did not read is reported as not checked, never as valid: the result's `checks` then has no
 * `statusValid`, and no `statusOutcome`. Acme's keys are real Ed25519 keys.
 */

import { beforeAll, describe, expect, it, vi } from 'vitest';
import { DelegationCredentialVerifier } from '../vc-verifier.js';
import { createRealCryptoProvider, createRealSignatureVerifier } from '../../__tests__/audit/helpers/crypto-helpers.js';
import { ACME, acmeDocument } from '../../__tests__/utils/did-documents.js';
import { keyOf, signedCredential, signedJwt } from '../../__tests__/utils/delegation-credentials.js';
import type { AgentIdentity } from '../../providers/base.js';
import type { CredentialStatus } from '../../types/protocol.js';
import type { DIDDocument } from '../vc-verifier.types.js';

const LIST = 'https://status.example/list';
const credentialStatus: CredentialStatus = {
  id: `${LIST}#0`, type: 'StatusList2021Entry', statusPurpose: 'revocation', statusListIndex: '0', statusListCredential: LIST,
};

let login: AgentIdentity;
let assert: AgentIdentity;

beforeAll(async () => {
  login = await keyOf(ACME, 'login-1');
  assert = await keyOf(ACME, 'assert-1');
});

/**
 * A verifier whose resolver answers Acme's document once `answer` is called, and whose status list
 * resolver records each read and finds the credential not revoked.
 */
function verifying() {
  let answer!: (document: DIDDocument) => void;
  const resolving = new Promise<DIDDocument>(resolve => { answer = resolve; });
  const checkStatus = vi.fn(async () => false);
  const verifier = new DelegationCredentialVerifier({
    didResolver: { resolve: async did => (did === ACME ? resolving : null) },
    statusListResolver: { checkStatus },
    signatureVerifier: createRealSignatureVerifier(createRealCryptoProvider()),
  });
  return { verifier, checkStatus, answer: () => answer(acmeDocument(login, assert)) };
}

/** Each path, verifying a delegation `key` signs with `credentialStatus`. */
const paths: [string, (verifier: DelegationCredentialVerifier, key: AgentIdentity) => Promise<unknown>][] = [
  ['Data Integrity', async (verifier, key) =>
    verifier.verifyDelegationCredential(await signedCredential(key, { credentialStatus }), { skipCache: true })],
  ['VC-JWT', async (verifier, key) =>
    verifier.verifyDelegationJwt(await signedJwt(key, { kid: key.kid, credentialStatus }), { skipCache: true })],
];

describe.each(paths)('%s: the status of a delegation credential', (_path, verify) => {
  it('is read only once the signature has verified, and reported valid', async () => {
    const { verifier, checkStatus, answer } = verifying();
    const verifying_ = verify(verifier, assert);
    await new Promise(resolve => setTimeout(resolve, 10));
    expect(checkStatus).not.toHaveBeenCalled();
    answer();
    expect(await verifying_).toMatchObject({
      valid: true, stage: 'complete', checks: { basicValid: true, signatureValid: true, statusValid: true },
    });
    expect(checkStatus).toHaveBeenCalledOnce();
  });

  it('is not read for a signature that fails, and is reported as not checked', async () => {
    const { verifier, checkStatus, answer } = verifying();
    answer();
    const result = await verify(verifier, login) as Record<string, unknown>;
    expect(result).toMatchObject({ valid: false, stage: 'signature' });
    expect(result.checks).toStrictEqual({ basicValid: true, signatureValid: false });
    expect(result.statusOutcome).toBeUndefined();
    expect(checkStatus).not.toHaveBeenCalled();
  });
});
