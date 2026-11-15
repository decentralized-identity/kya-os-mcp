/**
 * Test helpers: a chain whose hops each have their entry on a status list at a party's own URL, and
 * the shipped paths that read a chain's status lists: `evaluateDelegationChain`, and the request
 * gate as `verifyRequestDelegation` and `requireDelegation`, which verify every hop proof first. Each
 * runs the shipped checker and proof verifiers over hops and lists signed by real keys; only the
 * network is faked.
 */

import { expect } from 'vitest';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import type { DIDResolver } from '../../delegation/vc-verifier.types.js';
import {
  evaluateDelegationChain,
  leafInvokerOf,
  responsiblePartyOf,
  type DelegationChain,
  type DelegationCredential,
} from '../delegation.js';
import { createDelegationProofVerifier } from '../delegation-proof.js';
import { requireDelegation, toDelegationChainMeta, verifyRequestDelegation } from '../request-delegation.js';
import { createRevocationChecker, type StatusListIssuers } from '../revocation.js';
import { createStatusListProofVerifier } from '../status-list-proof.js';
import {
  hop,
  identity,
  parties,
  RESOURCE,
  serveAt,
  signEddsaJcs2022,
  statusList,
  type TestIdentity,
  now,
} from './signed-chain-helpers.js';

const didKeys = createDidKeyResolver();
const ctx = { resource: RESOURCE, now };

/** Acme (root), the agent, the sub-agent and the worker, plus Mallory, who is in no chain. */
export function cast() {
  return { ...parties(), worker: identity(), mallory: identity() };
}
export type Cast = ReturnType<typeof cast>;

/** Each party's status list, at its own URL. */
export const listUrlOf = (party: TestIdentity) => `https://status.example/${party.did.slice(-12)}`;
export function listOf(party: TestIdentity, revoked: number[] = []): Record<string, unknown> {
  return listAt(party, listUrlOf(party), revoked);
}

/** The list {@link listOf} makes for `party`, signed again without its `id`. */
export function idlessListOf(party: TestIdentity, revoked: number[] = []): Record<string, unknown> {
  const { id: _id, proof: _proof, ...unsigned } = listOf(party, revoked);
  return signEddsaJcs2022(unsigned, party);
}

/** Lists keyed by the URL each states as its `id`. */
export const servedBy = (...lists: Record<string, unknown>[]) =>
  Object.fromEntries(lists.map((list) => [list.id as string, list]));

/** Three hops, root first, as a tuple so that each hop is typed at its position. */
export type ThreeHopChain = [DelegationCredential, DelegationCredential, DelegationCredential];

/** Where a hop's status entry is: on a party's list, at that party's URL, or at a URL named outright. */
export type ListOwner = TestIdentity | string;

/**
 * Acme grants the agent, the agent the sub-agent, the sub-agent the worker; hop `k` has its status
 * entry at index `k` of the list at `owners[k]`'s URL.
 */
export function threeHopChain(c: Cast, owners: [ListOwner, ListOwner, ListOwner]): ThreeHopChain {
  const urlOf = (owner: ListOwner) => (typeof owner === 'string' ? owner : listUrlOf(owner));
  const grant = (k: 0 | 1 | 2, issuer: TestIdentity, invoker: TestIdentity) =>
    hop({
      issuer,
      invoker: invoker.did,
      id: `urn:zcap:hop-${k}`,
      parentCapability: k === 0 ? RESOURCE : `urn:zcap:hop-${k - 1}`,
      allowedAction: ['orders.place'],
      statusIndex: k,
      statusListCredential: urlOf(owners[k]),
    });
  return [grant(0, c.acme, c.agent), grant(1, c.agent, c.subAgent), grant(2, c.subAgent, c.worker)];
}

export interface Verifier {
  /** Whether the verifier pins the chain's root: `resourceOwner` and `trustedRootIssuers`, or neither. */
  pinned?: boolean;
  statusListIssuers?: StatusListIssuers;
  /** The DID documents every proof is verified against, hops and lists alike; by default each did:key's own. */
  didResolver?: DIDResolver;
  /** Receives the URL of every status list the checker fetches, in order, over all three paths. */
  fetched?: string[];
}

/**
 * The chain through every shipped path, with the shipped checker reading `lists`: the structural and
 * revocation evaluation alone, and the request gate, which verifies every hop proof first, as a
 * result and as a guard. A pinned verifier expects the chain's own root, so the pin itself never
 * rejects the chain.
 */
export async function verdicts(
  chain: DelegationChain,
  lists: Record<string, Record<string, unknown>>,
  { pinned = true, statusListIssuers, didResolver = didKeys, fetched = [] }: Verifier = {},
) {
  const serve = serveAt(lists);
  const checkRevocation = createRevocationChecker({
    fetch: (url) => {
      fetched.push(url);
      return serve(url);
    },
    now,
    verifyStatusList: createStatusListProofVerifier({ didResolver }),
    ...(statusListIssuers ? { statusListIssuers } : {}),
  });
  const root = responsiblePartyOf(chain) ?? '';
  const evaluated = await evaluateDelegationChain(chain, checkRevocation, pinned ? { ...ctx, resourceOwner: root } : ctx);
  const input = { meta: toDelegationChainMeta(chain), proofDid: leafInvokerOf(chain) ?? '', action: 'orders.place' };
  const deps = {
    resource: RESOURCE,
    verifyHopProof: createDelegationProofVerifier({ didResolver }),
    checkRevocation,
    now,
    ...(pinned ? { trustedRootIssuers: [root] } : {}),
  };
  const request = await verifyRequestDelegation(input, deps);
  const guarded = await requireDelegation(deps)(input);
  return { evaluated, request, guarded };
}

export async function expectAccepted(
  chain: DelegationChain,
  lists: Record<string, Record<string, unknown>>,
  verifier?: Verifier,
) {
  const { evaluated, request, guarded } = await verdicts(chain, lists, verifier);
  expect(evaluated).toMatchObject({ ok: true, fresh: true });
  expect(request).toMatchObject({ ok: true });
  expect(guarded).toMatchObject({ ok: true });
}

/**
 * That every path refuses the chain at hop `hopIndex`, and, when `because` is given, that each
 * refusal ends with it: the reason the checker gave for the hop.
 */
export async function expectRevokedAt(
  hopIndex: number,
  chain: DelegationChain,
  lists: Record<string, Record<string, unknown>>,
  verifier?: Verifier,
  because?: string,
) {
  const { evaluated, request, guarded } = await verdicts(chain, lists, verifier);
  const reasons = [expect.stringMatching(new RegExp(`^revocation: hop ${hopIndex} `))];
  expect(evaluated.ok).toBe(false);
  expect(evaluated.reasons).toEqual(reasons);
  expect(request).toMatchObject({ ok: false, code: 'delegation_revoked', reasons });
  expect(guarded).toMatchObject({ ok: false, status: 403, error: { code: 'delegation_revoked', reasons } });
  if (because !== undefined) {
    const refused = [evaluated.reasons, request.ok ? [] : request.reasons, guarded.ok ? [] : guarded.error.reasons];
    for (const [reason] of refused) expect(reason?.endsWith(`, subtree invalidated: ${because}`), reason).toBe(true);
  }
}

/** A list `signer` signed that states `url` as its `id`, with the `revoked` bits set. */
export function listAt(signer: TestIdentity, url: string, revoked: number[] = []): Record<string, unknown> {
  return statusList(signer, revoked, { id: url, credentialSubject: { id: `${url}#list` } });
}

/** Why a list `signer` signed is refused at a URL `keeper` keeps, `as` saying why it keeps it. */
export const notKeeper = (signer: TestIdentity, keeper: TestIdentity, as: string): string =>
  `status list issuer "${signer.did}" does not keep this list's URL: "${keeper.did}" does, as ${as}`;
/** The phrases a refusal says a keeper keeps a URL by. */
export const AS_ISSUER = 'the issuer of the credential';
export const AS_ROOT = 'the pinned root whose own credential names it';
export const AS_BOUND_URL = 'the issuer statusListIssuers binds this URL to';
export const AS_BOUND_ORIGIN = "the issuer statusListIssuers binds this URL's origin to";
