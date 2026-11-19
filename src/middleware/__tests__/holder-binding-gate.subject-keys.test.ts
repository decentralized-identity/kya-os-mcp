/**
 * Holder binding at the gate for a did:key subject whose key it cannot bind. A did:key encodes its
 * key, so `holderBinding: 'enforce'` binds every did:key subject. A request proof is EdDSA, so a
 * did:key of any other key, a P-256 one as a hardware-backed agent key often is, can never be
 * bound: under `enforce` it is refused, with or without a proof, as an Ed25519 subject without one
 * is, and never let through as a bearer as a did:web subject is deferred. Under `warn` it is let
 * through and logged as a call holder binding did not bind, never as a subject that "is not
 * did:key". A session grant does not let it through under `enforce` either.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { generateRequestProof } from '../../delegation/holder-binding.js';
import { logger } from '../../logging/index.js';
import { MemoryGrantStore, type Grant } from '../../providers/grant-store.js';
import type { KyaOsDelegationConfig } from '../with-kya-os.config-types.js';
import { createKyaOsMiddleware } from '../with-kya-os.js';
import { delegate, party, type Party } from './helpers/delegating-party.js';
import { crypto, handshake, served } from './helpers/received-proof.js';

const SCOPE = 'orders:place';
/** The P-256 did:key of the did:key method's own test vectors. */
const P256_DID_KEY = 'did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169';

async function gate(server: Party, delegation: KyaOsDelegationConfig, grantStore?: MemoryGrantStore) {
  const kyaos = await served(createKyaOsMiddleware(
    { identity: server, session: { sessionTtlMinutes: 60 }, delegation, ...(grantStore ? { grantStore } : {}) },
    crypto,
  ));
  let runs = 0;
  const handler = kyaos.wrapWithDelegation(
    'orders.place',
    { scopeId: SCOPE, consentUrl: 'https://consent.example' },
    async () => {
      runs += 1;
      return { content: [{ type: 'text', text: 'placed' }] };
    },
  );
  /** The outcome of a call: `ran`, or the error it was refused with. */
  const call = async (args: Record<string, unknown>, sessionId?: string) => {
    const text = (await handler(args, sessionId)).content[0]!.text as string;
    return text === 'placed' ? 'ran' : (JSON.parse(text) as { error: string }).error;
  };
  return { kyaos, call, runs: () => runs };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('holder binding for a did:key subject whose key the gate cannot bind', () => {
  it('refuses the call under enforce, with no proof and with one, and does not run the tool', async () => {
    const [user, server, holder] = await Promise.all([party(), party(), party()]);
    const { call, runs } = await gate(server, { trustedRootIssuers: [user.did], holderBinding: 'enforce' });
    const credential = await delegate(user, P256_DID_KEY, { scopes: [SCOPE] });
    const args = { _kyaos_delegation: credential };
    // A proof that claims the subject, signed with an Ed25519 key, the only kind a request proof has.
    const proof = await generateRequestProof({ identity: holder, crypto, toolName: 'orders.place', args, audience: server.did });

    expect(await call(args)).toBe('holder_binding_failed');
    expect(await call({ ...args, _kyaos_proof: { ...proof, meta: { ...proof.meta, did: P256_DID_KEY } } })).toBe('holder_binding_failed');
    expect(runs()).toBe(0);
  });

  it('lets the call through under warn, and logs it as a call holder binding did not bind', async () => {
    const [user, server] = await Promise.all([party(), party()]);
    const { call, runs } = await gate(server, { trustedRootIssuers: [user.did], holderBinding: 'warn' });
    const credential = await delegate(user, P256_DID_KEY, { scopes: [SCOPE] });
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);

    expect(await call({ _kyaos_delegation: credential })).toBe('ran');
    expect(runs()).toBe(1);
    const lines = warn.mock.calls.map((line) => String(line[0]));
    expect(lines).toContain(
      '[kya-os] Holder binding: "orders.place" called without _kyaos_proof; the call was allowed, as holderBinding is "warn"',
    );
    expect(lines.filter((line) => line.includes('is not did:key'))).toEqual([]);
  });

  it('resolves no session grant for it under enforce, as for any did:key agent', async () => {
    const [user, server] = await Promise.all([party(), party()]);
    const grantStore = new MemoryGrantStore();
    const { kyaos, call, runs } = await gate(server, { trustedRootIssuers: [user.did], holderBinding: 'enforce' }, grantStore);
    const credential = await delegate(user, P256_DID_KEY, { scopes: [SCOPE] });
    const sessionId = await handshake(kyaos);
    // A grant bound for the agent in this session, as one bound under `warn` before the switch is.
    const grant: Grant = {
      id: 'grant-p256',
      agentDid: P256_DID_KEY,
      responsibleParty: user.did,
      scopes: [SCOPE],
      sessionId,
      authorization: { type: 'delegation' },
      delegationCredential: credential,
      issuedAt: Date.now(),
      status: 'active',
    };
    await grantStore.bind(grant);

    expect(await call({}, sessionId)).toBe('needs_authorization');
    expect(runs()).toBe(0);
  });
});
