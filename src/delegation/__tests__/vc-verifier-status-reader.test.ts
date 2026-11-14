/**
 * The one status reader of `DelegationCredentialVerifier`, on both of its paths: it reads through
 * the call's status-list resolver before the verifier's own, and reads nothing, reporting the
 * status valid, when the call skips status or the credential names none. Acme's keys are real
 * Ed25519 keys.
 */

import { beforeAll, describe, expect, it, vi } from 'vitest';
import { DelegationCredentialVerifier } from '../vc-verifier.js';
import { createRealCryptoProvider, createRealSignatureVerifier } from '../../__tests__/audit/helpers/crypto-helpers.js';
import { ACME, acmeDocument } from '../../__tests__/utils/did-documents.js';
import { keyOf, signedCredential, signedJwt } from '../../__tests__/utils/delegation-credentials.js';
import type { AgentIdentity } from '../../providers/base.js';
import type { CredentialStatus } from '../../types/protocol.js';
import type { VerifyDelegationVCOptions } from '../vc-verifier.types.js';

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

/** A verifier that resolves Acme's document, and whose own status-list resolver records each read. */
function verifying() {
  const own = vi.fn(async () => false);
  const verifier = new DelegationCredentialVerifier({
    didResolver: { resolve: async did => (did === ACME ? acmeDocument(login, assert) : null) },
    statusListResolver: { checkStatus: own },
    signatureVerifier: createRealSignatureVerifier(createRealCryptoProvider()),
  });
  return { verifier, own };
}

type Status = { credentialStatus?: CredentialStatus };
type Verify = (verifier: DelegationCredentialVerifier, status: Status, options?: VerifyDelegationVCOptions) => Promise<unknown>;

const paths: [string, Verify][] = [
  ['Data Integrity', async (verifier, status, options = {}) =>
    verifier.verifyDelegationCredential(await signedCredential(assert, status), { skipCache: true, ...options })],
  ['VC-JWT', async (verifier, status, options = {}) =>
    verifier.verifyDelegationJwt(await signedJwt(assert, { kid: assert.kid, ...status }), { skipCache: true, ...options })],
];

const VALID = { valid: true, stage: 'complete', checks: { basicValid: true, signatureValid: true, statusValid: true } };

describe.each(paths)('%s: the status reader', (_path, verify) => {
  it("reads through the verifier's own resolver when the call names none, and refuses a revoked credential", async () => {
    const { verifier, own } = verifying();
    expect(await verify(verifier, { credentialStatus })).toMatchObject(VALID);
    expect(own).toHaveBeenCalledOnce();
    own.mockResolvedValue(true);
    expect(await verify(verifier, { credentialStatus })).toMatchObject({ valid: false, stage: 'status', checks: { statusValid: false } });
  });

  it("reads through the call's resolver in place of the verifier's own", async () => {
    const { verifier, own } = verifying();
    const checkStatus = vi.fn(async () => true);
    const result = await verify(verifier, { credentialStatus }, { statusListResolver: { checkStatus } });
    expect(result).toMatchObject({ valid: false, stage: 'status', checks: { statusValid: false } });
    expect(checkStatus).toHaveBeenCalledOnce();
    expect(own).not.toHaveBeenCalled();
  });

  it('reads nothing, and reports the status valid, when the call skips status', async () => {
    const { verifier, own } = verifying();
    own.mockResolvedValue(true);
    expect(await verify(verifier, { credentialStatus }, { skipStatus: true })).toMatchObject(VALID);
    expect(own).not.toHaveBeenCalled();
  });

  it('reads nothing, and reports the status valid, for a credential that names no status', async () => {
    const { verifier, own } = verifying();
    own.mockResolvedValue(true);
    expect(await verify(verifier, {})).toMatchObject(VALID);
    expect(own).not.toHaveBeenCalled();
  });
});
