/**
 * The delegation gate signs its refusal of a delegation whose status list is refused, with the reason
 * the status-list reader gives. A response proof signs the reason in RFC 8785 form, which refuses a
 * lone surrogate, so the reason must be well-formed text. The reader quotes a value as a JSON string
 * of at most its first 64 characters, counted as code points, so a cut just after a character outside
 * the Basic Multilingual Plane keeps that character whole, and it escapes a lone surrogate, as
 * `\ud83d`. The shipped CheqdStatusListResolver reads its pinned issuer's list, served
 * with another `id` or `issuer`; only the network is faked.
 */
import { describe, it, expect } from 'vitest';
import type { KyaOsToolHandler } from '../with-kya-os.js';
import { CheqdStatusListResolver } from '../../integrations/cheqd/statuslist-resolver.js';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import { DelegationCredentialIssuer } from '../../delegation/vc-issuer.js';
import { statusListGzipCodec } from '../../utils/statuslist-gzip.js';
import {
  createRealIdentity,
  createRealSigningFunction,
  createRealStatusListManager,
} from '../../__tests__/audit/helpers/crypto-helpers.js';
import type { FetchProvider } from '../../providers/base.js';
import { createMiddleware, crypto, handshake, proofOf, served, verifyReceived } from './helpers/received-proof.js';

const EMOJI = '\u{1F600}';
const LONE_HIGH = '\uD83D';
const LONE_LOW = '\uDE00';
const SCOPE = 'vault:read';
const CONSENT = { scopeId: SCOPE, consentUrl: 'https://example.com/consent' };
const ran: KyaOsToolHandler = async () => ({ content: [{ type: 'text', text: 'ran' }] });

/**
 * The gate's response to a delegation whose status list the resolver pinned to the list's issuer
 * reads with `change` made to it, and the issuer and URL of that list.
 */
async function refusing(change: (list: Record<string, unknown>) => Record<string, unknown>) {
  const statusIssuer = await createRealIdentity(crypto);
  const { manager, storage } = createRealStatusListManager(crypto, statusIssuer, { statusListBaseUrl: 'https://status.example' });
  const entry = await manager.allocateStatusEntry('revocation');
  const stored = await storage.getStatusList(entry.statusListCredential);
  if (!stored) throw new Error('fixture: status list not stored');
  const fetchProvider = {
    fetch: async () => ({ ok: true, status: 200, json: async () => change({ ...stored }) }) as unknown as Response,
  } as unknown as FetchProvider;
  const statusListResolver = new CheqdStatusListResolver({
    fetchProvider,
    didResolver: createDidKeyResolver(),
    cryptoProvider: crypto,
    expectedIssuerDid: statusIssuer.did,
    decompressor: statusListGzipCodec,
    cacheTtlMs: 0,
  });
  const kyaos = await served(await createMiddleware({ delegation: { statusListResolver } }));
  const sessionId = await handshake(kyaos);
  const grantor = await createRealIdentity(crypto);
  const agent = await createRealIdentity(crypto);
  const delegation = await new DelegationCredentialIssuer(
    { getDid: () => grantor.did, getKeyId: () => grantor.kid, getPrivateKey: () => grantor.privateKey },
    createRealSigningFunction(crypto, grantor),
  ).createAndIssueDelegation(
    {
      id: 'del-1',
      issuerDid: grantor.did,
      subjectDid: agent.did,
      constraints: { scopes: [SCOPE], notAfter: Math.floor(Date.now() / 1000) + 3600 },
    },
    { credentialStatus: entry },
  );
  const sent = { path: '/secret', _kyaos_delegation: delegation };
  const result = (await kyaos.wrapWithDelegation('vault', CONSENT, ran)(sent, sessionId)) as Record<string, unknown>;
  return { result, signer: kyaos.identity.did, sent, statusIssuer: statusIssuer.did, url: entry.statusListCredential };
}

/** That the gate refused the delegation with `reason` and signed it in a response proof that verifies. */
async function expectSignedRefusal(refusal: Awaited<ReturnType<typeof refusing>>, reason: string): Promise<void> {
  const { result, signer, sent } = refusal;
  expect(JSON.parse((result.content as Array<{ text: string }>)[0]!.text)).toEqual({ error: 'delegation_invalid', reason });
  expect(proofOf(result)?.meta.reason).toBe(reason);
  const verified = await verifyReceived(result, { signer, toolName: 'vault', params: sent, binds: 'nothing' });
  expect(verified.valid, verified.reason).toBe(true);
}

describe('the delegation gate refusing a status list', () => {
  it('signs a reason that cuts the list id just after a character outside the Basic Multilingual Plane', async () => {
    const refusal = await refusing((list) => ({ ...list, id: `${'p'.repeat(63)}${EMOJI}${'q'.repeat(100_000)}` }));
    await expectSignedRefusal(
      refusal,
      `Delegation del-1 invalid: Status check error: status list id "${'p'.repeat(63)}${EMOJI}"... ` +
        `is not the URL it was fetched from ("${refusal.url}")`,
    );
  });

  it('signs a reason that escapes a lone surrogate in the list id', async () => {
    const refusal = await refusing((list) => ({ ...list, id: `https://status.example/x${LONE_HIGH}y` }));
    await expectSignedRefusal(
      refusal,
      `Delegation del-1 invalid: Status check error: status list id "https://status.example/x\\ud83dy" ` +
        `is not the URL it was fetched from ("${refusal.url}")`,
    );
  });

  it("signs a reason that escapes a lone surrogate in the list's issuer", async () => {
    const refusal = await refusing((list) => ({ ...list, issuer: `did:key:z6Mk${LONE_LOW}y` }));
    await expectSignedRefusal(
      refusal,
      `Delegation del-1 invalid: Status check error: status list issuer "did:key:z6Mk\\ude00y" ` +
        `is not the expected issuer ("${refusal.statusIssuer}")`,
    );
  });
});
