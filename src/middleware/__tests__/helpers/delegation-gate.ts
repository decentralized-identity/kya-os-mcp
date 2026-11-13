/**
 * Test helper: a delegation gate in front of one tool, as a client meets it. A server with a fresh
 * did:key identity trusts the given issuers as roots, and its tool, `orders.place`, answers
 * `placed`, counts its runs and keeps the context it is called with. A call's answer is `ran`, or
 * the `error` of a refusal or a challenge, with its reason; in a session, whether the answer carries
 * the server's response proof, and whether that proof verifies as its client checks a refusal's.
 */
import type { AuditTrailService } from '../../../audit/service.js';
import type { DIDResolver } from '../../../delegation/vc-verifier.types.js';
import type { CryptoProvider, FetchProvider } from '../../../providers/base.js';
import type { GrantStore } from '../../../providers/grant-store.js';
import { didKeyFragment, generateDidKeyFromBase64 } from '../../../utils/did-helpers.js';
import { createKyaOsMiddleware } from '../../with-kya-os.js';
import type { KyaOsCallContext } from '../../with-kya-os.types.js';
import { crypto, handshake, proofOf, served, verifyReceived } from './received-proof.js';

/** How the gate resolves an issuer's DID: through a resolver, or by fetching a did:web document itself. */
export type Resolution = { readonly didResolver: DIDResolver } | { readonly fetchProvider: FetchProvider };

export interface GateOptions {
  /** The issuers the gate trusts as roots. */
  readonly trustedRootIssuers: string[];
  readonly resolution?: Resolution;
  /** The server's crypto (default: Node's). */
  readonly provider?: CryptoProvider;
  /** The scope the tool needs (default: `orders:place`). */
  readonly scopeId?: string;
  /** The audit store that receives the gate's events. */
  readonly record?: AuditTrailService['record'];
  readonly grantStore?: GrantStore;
}

export async function delegationGate({
  trustedRootIssuers,
  resolution,
  provider = crypto,
  scopeId = 'orders:place',
  record,
  grantStore,
}: GateOptions) {
  const server = await crypto.generateKeyPair();
  const did = generateDidKeyFromBase64(server.publicKey);
  const kyaos = await served(createKyaOsMiddleware(
    {
      identity: { did, kid: `${did}#${didKeyFragment(did)}`, ...server },
      session: { sessionTtlMinutes: 60 },
      delegation: { ...resolution, trustedRootIssuers },
      ...(record === undefined ? {} : { audit: { record } }),
      ...(grantStore === undefined ? {} : { grantStore }),
    },
    provider,
  ));
  let runs = 0;
  const contexts: (KyaOsCallContext | undefined)[] = [];
  const handler = kyaos.wrapWithDelegation(
    'orders.place',
    { scopeId, consentUrl: 'https://acme.example/consent' },
    async (_args, _sessionId, context) => {
      runs += 1;
      contexts.push(context);
      return { content: [{ type: 'text', text: 'placed' }] };
    },
  );
  /** The answer to a call in `sessionId` (default: none) with `delegation`, or with none when it is undefined. */
  const answer = async (delegation: unknown, sessionId?: string) => {
    const result = await handler(delegation === undefined ? {} : { _kyaos_delegation: delegation }, sessionId);
    const text = result.content[0]!.text;
    const denial = text === 'placed' ? undefined : (JSON.parse(text) as { error: string; reason?: string });
    return { result, outcome: denial?.error ?? 'ran', reason: denial?.reason };
  };
  return {
    call: async (delegation: unknown) => (await answer(delegation)).outcome,
    /** The gate's answer in `sessionId`, to a call with `delegation`, or with none. */
    callIn: async (sessionId: string, delegation?: unknown) => (await answer(delegation, sessionId)).outcome,
    /** The gate's answer, and its reason for a refusal. */
    reasoned: async (delegation: unknown) => {
      const { outcome, reason } = await answer(delegation);
      return { outcome, reason };
    },
    /** A session a client establishes with the gate's server. */
    session: () => handshake(kyaos),
    /**
     * The gate's answer in a fresh session, its reason for a refusal, whether it carries the gate's
     * response proof, and whether that proof verifies as its client checks a refusal's: it signs
     * the reason the client reads, over the call's arguments less the `_kyaos` control arguments,
     * which a proof does not cover (and a delegation the test sends may hold a lone surrogate,
     * which a request hash cannot).
     */
    inSession: async (delegation: unknown) => {
      const { result, outcome, reason } = await answer(delegation, await handshake(kyaos));
      const proof = proofOf(result);
      const received = result as unknown as Record<string, unknown>;
      const verified = proof !== undefined && proof.meta.reason === reason &&
        (await verifyReceived(received, { signer: did, toolName: 'orders.place', params: {}, binds: 'nothing' })).valid;
      return { outcome, reason, proved: proof !== undefined, verified };
    },
    runs: () => runs,
    /** The context of each call the tool ran, in order. */
    contexts,
  };
}
