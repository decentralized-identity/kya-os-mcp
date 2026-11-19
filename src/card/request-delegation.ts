/**
 * KYA-OS Entity Card: the delegation chain carried with a request (SPEC-ENTITY-CARD §10.5, §11.4).
 *
 * A request may carry its whole delegation chain, root to leaf, in
 * `_meta['org.kya-os/delegation-chain']`. A verifier in another organization can then check the
 * caller's authority from the request alone, without reaching the Delegation Registry (SPEC.md §6.8)
 * of whoever issued it. Every hop is verified exactly as a resolved one would be: its proof, the
 * SPEC.md §6.10 chain rules, and its revocation status.
 *
 * The member sits outside `requestHash` (§8.3 strips `_meta`), and that is safe. Each hop is signed
 * by its issuer, and the leaf delegate must be the DID the request proof verified for (§10.2), so a
 * carried chain grants nothing to a caller that does not hold the leaf key.
 *
 *   - {@link toDelegationChainMeta}: the caller side, the `_meta` member to send.
 *   - {@link readDelegationChain}: parse the member, fail-closed, bounded before any parsing.
 *   - {@link verifyRequestDelegation}: the §11.4 order. The chain comes from the request when it
 *     carries one, and from the injected by-reference resolver otherwise.
 *   - {@link requireDelegation}: the same check pre-bound to its seams, with 401/403-shaped results.
 */

import { answerWithinDeadline, dependencyTimeout } from '../utils/deadline.js';
import { refusalCodeOf } from '../utils/refusal.js';
import { thrownReason } from '../utils/thrown-words.js';
import type { RefusalCode } from '../refusal-codes.js';
import { admitsRootIssuer } from '../delegation/root-admission.js';
import { revocationEntriesOf, validateDelegationChain, type DelegationChain, type DelegationChainResult } from './delegation.js';
import { warnOfUnknownCaveats, type EffectiveCaveats } from './caveats.js';
import {
  KYA_OS_DELEGATION_CHAIN_META_KEY,
  parseCredentials,
  readCarriedChain,
  rejectionCoded,
  type RejectionCoded,
  type RejectionCoding,
} from './carried-chain.js';
import { firstHopProofRefusal } from './hop-proofs.js';
import { pinnedRootOf, withVerifiedRoot } from '../utils/verified-root.js';
import type { DelegationProofVerifier } from './delegation-proof.js';
import type { BitstringRevocationChecker } from './revocation.js';
import { walkRevocationChain, type RevocationChainWalk } from './revocation-chain.js';
import { admitRootIssuers } from './request-root-issuers.js';
import { clockSkewOption } from '../utils/validity-window.js';

export {
  DEFAULT_CARRIED_CHAIN_LIMIT,
  KYA_OS_DELEGATION_CHAIN_META_KEY,
  readDelegationChain,
  toDelegationChainMeta,
  type CarriedChainRead,
  type DelegationChainMeta,
  type RejectionCoding,
} from './carried-chain.js';

/**
 * A snake_case rejection code. `delegation_missing` means no authority was presented;
 * `delegation_unresolvable` means a by-reference lookup failed; the rest mean the chain was
 * presented and does not authorize the call.
 */
export type DelegationGateCode =
  | 'delegation_missing'
  | 'delegation_unresolvable'
  | 'delegation_invalid'
  | 'delegation_revoked'
  | 'action_not_delegated';

/** Where the verified chain came from. */
export type DelegationChainSource = 'carried' | 'resolved';

/** Seams and policy for {@link verifyRequestDelegation}. */
export interface VerifyRequestDelegationDeps {
  /**
   * This verifier's own DID. The root `invocationTarget` must name it, so a chain minted for a
   * different resource fails at the root (SPEC.md §6.10).
   */
  resource: string;
  /** Checks each hop's proof, e.g. {@link createDelegationProofVerifier}. A throw rejects the hop. */
  verifyHopProof: DelegationProofVerifier;
  /**
   * Reads each hop's revocation status, e.g. `createRevocationChecker` (fail-closed: an unreadable
   * list counts as revoked). Each call names the hop's issuer and, when `resourceOwner` or
   * `trustedRootIssuers` pins it, the chain's root issuer, whose lists may speak for the hop.
   */
  checkRevocation: BitstringRevocationChecker;
  /**
   * By reference: fetch the chain for a caller whose request carries none, for example from the
   * caller's Entity Card `delegationRef` and the issuer's Delegation Registry. It is never called
   * when the request carries a chain. Omit it to require every request to carry its chain.
   */
  resolveDelegationChain?: (ctx: { proofDid: string }) => Promise<DelegationChain | undefined>;
  /**
   * When set, the root issuer must equal it (the SPEC.md §6.10 root rule). It pins the chain's root,
   * as `trustedRootIssuers` does; with neither set, see `trustedRootIssuers`.
   */
  resourceOwner?: string;
  /**
   * When set, the root issuer (the Responsible Party) must be one of these DIDs, each compared
   * whole; an empty list trusts no issuer. Anything but an array of DIDs, each a string that starts
   * with `did:` and has no white space around it, throws a `TypeError` naming the option.
   *
   * With neither this nor `resourceOwner` set, a chain from any root would be accepted, including
   * one an agent signs for itself. So `requireDelegation` throws when the guard is built, and
   * `verifyRequestDelegation` rejects the call, with an `Error` naming every fix, unless
   * `development` or `allowAnyRootIssuer` is `true`; either of those runs with one warning.
   */
  trustedRootIssuers?: readonly string[];
  /**
   * Accept a chain from any root issuer, by name, with neither `trustedRootIssuers` nor
   * `resourceOwner` set: for a verifier whose seams already decide whose authority counts, or one
   * that accepts anyone's on purpose. It logs one warning, once for each guard `requireDelegation`
   * builds and once for each deps object `verifyRequestDelegation` is called with. Anything but a
   * boolean throws a `TypeError`, and so does `true` beside `trustedRootIssuers`, an empty list
   * included, or `resourceOwner`, since they contradict each other. Default `false`.
   */
  allowAnyRootIssuer?: boolean;
  /**
   * Local development: with neither `trustedRootIssuers` nor `resourceOwner` set, accept a chain
   * from any root issuer, with one warning, as `allowAnyRootIssuer` does. It changes nothing else.
   * Set while `NODE_ENV` is `production`, it throws an `Error` naming every fix, and anything but a
   * boolean throws a `TypeError`. A runtime with no `process`, such as Workers, has no `NODE_ENV` to
   * read unless its bundler defines `process.env.NODE_ENV`, so there it does not throw: keep it out
   * of production configuration. Default `false`.
   */
  development?: boolean;
  /**
   * Local cost limit: the most credentials to evaluate in one chain, root to leaf inclusive. A
   * carried chain is bounded by {@link DEFAULT_CARRIED_CHAIN_LIMIT} when this is unset; a resolved
   * chain comes from the verifier's own resolver and is bounded only when this is set.
   */
  maxChainLength?: number;
  /** Injectable clock (epoch ms) for the expiry gate; default `Date.now`. */
  now?: () => number;
  /**
   * The clock tolerance, in milliseconds, each hop's `validFrom`, `validUntil` and `ValidUntil`
   * caveat is held with, as `validateDelegationChain` holds them: a number from 0 to 600,000.
   * Default 120,000. Any other value throws a `TypeError` naming the option where the guard is built.
   */
  maxClockSkewMs?: number;
  /**
   * How long, in milliseconds, `resolveDelegationChain`, `verifyHopProof` and `checkRevocation` may each take to answer: a number greater than 0 and at most
   * 2,147,483,647. Default 5,000. Any other value throws a `TypeError` naming the option.
   */
  dependencyTimeoutMs?: number;
}

/** What one call presents for {@link verifyRequestDelegation}. */
export interface RequestDelegationInput {
  /** The request's `_meta`: the same bag that carried the request proof. */
  meta: unknown;
  /** The DID the request proof verified for (`requireProof`'s `did`). The leaf delegate must equal it. */
  proofDid: string;
  /** The action this call exercises. It must be in the leaf hop's `allowedAction`. */
  action: string;
}

/**
 * The authority a verified chain grants, recomputed from the chain, with the limits it grants it
 * under ({@link EffectiveCaveats}): `caveats`, at their tightest, the chain's expiry among them,
 * every one of which applies to the call, and `unknownCaveats`, which the host must enforce or
 * refuse. Hold the call to them with `caveatRefusal`, at the time of the call, which also refuses a
 * grant that lacks either member rather than read it as unlimited.
 */
export interface RequestDelegationGrant extends EffectiveCaveats {
  source: DelegationChainSource;
  /** The root issuer: the party accountable for the call (§10.2). */
  responsibleParty: string;
  /** The leaf delegate, equal to the request proof's DID. */
  leafInvoker: string;
  invocationTarget: string;
  allowedAction: string[];
  /** Credentials in the chain, root to leaf inclusive. */
  depth: number;
  /** True iff every hop's status was read from a live, in-window status list (§10.3). */
  fresh: boolean;
}

/**
 * The verdict on one request's authority: the grant, or a rejection with its gate `code`, its
 * `reasons`, and the finer {@link RejectionCoding} `refusalCode` and `transient`.
 */
export type RequestDelegationResult =
  | ({ ok: true } & RequestDelegationGrant)
  | ({ ok: false; code: DelegationGateCode; reasons: string[]; source?: DelegationChainSource } & RejectionCoding);

/** A rejection as the library builds it: with its refusal code. */
type Rejection = { ok: false; code: DelegationGateCode; reasons: string[]; source?: DelegationChainSource } & RejectionCoded;

/** What {@link verifyRequestDelegation} comes to, with a rejection that cannot be built without its code. */
type RequestVerdict = ({ ok: true } & RequestDelegationGrant) | Rejection;

/** The rejection under `code` for `reasons`, with `refusalCode`, from a chain obtained from `source`. */
function rejection(
  code: DelegationGateCode,
  refusalCode: RefusalCode,
  reasons: string[],
  source?: DelegationChainSource,
): Rejection {
  return { ok: false, code, reasons, ...(source === undefined ? {} : { source }), ...rejectionCoded(refusalCode) };
}

/**
 * Verify the authority behind one request, fail-closed, in the SPEC-ENTITY-CARD §11.4 order:
 *
 * 1. Obtain the chain: the carried member when present (never the resolver then), else the
 *    by-reference resolver, else `delegation_missing`.
 * 2. The SPEC.md §6.10 chain rules, with `resource` (and `resourceOwner`) asserted at the root.
 * 3. The join: the leaf delegate equals `proofDid`.
 * 4. The root issuer is trusted, when `trustedRootIssuers` is set.
 * 5. Every hop's proof, root to leaf.
 * 6. The action is in the leaf's `allowedAction`.
 * 7. Revocation, root to leaf, each hop's status list held to the one keeper of its URL: the hop's
 *    issuer or, when step 2 or 4 pinned the root and the root hop's own status entry names the same
 *    URL, the root issuer, as the proofs step 5 verified name them; a revoked ancestor invalidates
 *    the subtree.
 *
 * Cheap, local checks run before the ones that may touch the network. Never throws on a
 * malformed input, a throwing seam or a fault in its own chain rules, which it refuses as
 * `runtime_error`; returns `{ ok: false, code, reasons, refusalCode, transient }`.
 * The `refusalCode` says which rule refused the chain: for example `needs_authorization` for no
 * chain, `holder_binding_failed` for a leaf delegate that is not `proofDid`, `untrusted_root`,
 * `invalid_proof` for a hop's proof, `insufficient_scope` for the action, the code of the status
 * that refused a hop, and `deadline_exceeded` or `runtime_error` for a seam that did not answer in
 * time or threw. Rejects, before it reads the chain, with an `Error` naming every fix when neither
 * `trustedRootIssuers` nor `resourceOwner` pins the root, outside development and without
 * `allowAnyRootIssuer: true`, and with a `TypeError` for a `trustedRootIssuers` that is not an array
 * of DIDs, each a string that starts with `did:` and has no white space around it, for an
 * `allowAnyRootIssuer` or a `development` that is not a boolean, for `allowAnyRootIssuer: true`
 * beside a pin, and for a `dependencyTimeoutMs` that is not a number of milliseconds it can wait.
 */
export async function verifyRequestDelegation(
  input: RequestDelegationInput,
  deps: VerifyRequestDelegationDeps,
): Promise<RequestDelegationResult> {
  return verifyRequest(input, deps);
}

/** {@link verifyRequestDelegation}, with a rejection that cannot be built without its code. */
async function verifyRequest(input: RequestDelegationInput, deps: VerifyRequestDelegationDeps): Promise<RequestVerdict> {
  admitRootIssuers(deps, 'verifyRequestDelegation');
  const timeoutMs = dependencyTimeout(deps.dependencyTimeoutMs);
  const obtained = await obtainChain(input, deps, timeoutMs);
  if (!obtained.ok) return obtained;
  const { chain, credentials, source } = obtained;
  const reject = (code: DelegationGateCode, refusalCode: RefusalCode, reasons: string[]): Rejection =>
    rejection(code, refusalCode, reasons, source);

  let structural: DelegationChainResult;
  try {
    structural = validateDelegationChain(chain, {
      resource: deps.resource,
      ...(deps.resourceOwner !== undefined ? { resourceOwner: deps.resourceOwner } : {}),
      ...(deps.maxChainLength !== undefined ? { maxChainLength: deps.maxChainLength } : {}),
      ...(deps.now !== undefined ? { now: deps.now } : {}),
      ...(deps.maxClockSkewMs !== undefined ? { maxClockSkewMs: deps.maxClockSkewMs } : {}),
    });
  } catch (error) {
    // The chain rules refuse every input they cannot read; a throw is the library's own fault, for the operator's log.
    const reason = thrownReason(error, { withheld: 'delegation chain could not be checked: the chain rules faulted', tag: '[kya-os]' });
    return reject('delegation_invalid', 'runtime_error', [reason]);
  }
  // validateDelegationChain codes every chain it refuses.
  if (!structural.ok) return reject('delegation_invalid', structural.code ?? 'chain_invalid', structural.reasons);
  // validateDelegationChain sets `caveats` and `unknownCaveats` on every result, so the grant carries both.
  const { responsibleParty, leafInvoker, invocationTarget, allowedAction, caveats, unknownCaveats, depth } = structural;
  if (responsibleParty === undefined || leafInvoker === undefined || invocationTarget === undefined) {
    return reject('delegation_invalid', 'delegation_malformed', ['delegation chain has no root issuer or leaf delegate']);
  }

  if (leafInvoker !== input.proofDid) {
    return reject('delegation_invalid', 'holder_binding_failed', [
      `leaf delegate ${leafInvoker} is not the request proof's DID ${input.proofDid}`,
    ]);
  }
  if (!admitsRootIssuer(deps.trustedRootIssuers, responsibleParty)) {
    return reject('delegation_invalid', 'untrusted_root', [`root issuer ${responsibleParty} is not a trusted root issuer`]);
  }

  const proofRefusal = await firstHopProofRefusal(credentials, deps.verifyHopProof, timeoutMs);
  if (proofRefusal !== undefined) return reject('delegation_invalid', proofRefusal.code, [proofRefusal.reason]);

  if (!allowedAction.includes(input.action)) {
    return reject('action_not_delegated', 'insufficient_scope', [`action "${input.action}" is not in the delegated allowedAction`]);
  }

  const pinnedRoot = pinnedRootOf(responsibleParty, deps);
  let revocation: RevocationChainWalk;
  try {
    // Every hop proof has verified, so the pinned root's own list URL is its word (utils/verified-root.ts).
    revocation = await walkRevocationChain(withVerifiedRoot(revocationEntriesOf(chain, pinnedRoot)), deps.checkRevocation, {
      dependencyTimeoutMs: timeoutMs,
    });
  } catch {
    return reject('delegation_revoked', 'status_unavailable', ['revocation checker threw: status unprovable, fail-closed']);
  }
  if (!revocation.ok) return reject('delegation_revoked', revocation.code, revocation.reasons);

  warnOfUnknownCaveats(structural);
  return {
    ok: true,
    source,
    responsibleParty,
    leafInvoker,
    invocationTarget,
    allowedAction,
    caveats,
    unknownCaveats,
    depth,
    fresh: revocation.fresh,
  };
}

/** Step 1: the carried chain when present, else the by-reference resolver. */
async function obtainChain(
  input: RequestDelegationInput,
  deps: VerifyRequestDelegationDeps,
  timeoutMs: number,
): Promise<
  | { ok: true; chain: DelegationChain; credentials: readonly Record<string, unknown>[]; source: DelegationChainSource }
  | Rejection
> {
  const read = readCarriedChain(
    input.meta,
    deps.maxChainLength !== undefined ? { maxChainLength: deps.maxChainLength } : {},
  );
  if (read.carried) {
    if (!read.ok) return rejection('delegation_invalid', read.refusalCode, read.reasons, 'carried');
    return { ok: true, chain: read.chain, credentials: read.credentials, source: 'carried' };
  }

  if (deps.resolveDelegationChain === undefined) {
    return rejection('delegation_missing', 'needs_authorization', [
      `no ${KYA_OS_DELEGATION_CHAIN_META_KEY} in _meta, and no by-reference resolver is configured`,
    ]);
  }
  let resolved: DelegationChain | undefined;
  try {
    const resolve = deps.resolveDelegationChain;
    resolved = await answerWithinDeadline('the chain resolver', () => resolve({ proofDid: input.proofDid }), timeoutMs);
  } catch (error) {
    // The resolver is the host's, and may throw its transport's words, which only the operator's log is told.
    const reason = thrownReason(error, {
      withheld: 'delegation chain could not be resolved: the chain resolver failed',
      shown: (words) => `delegation chain could not be resolved: ${words}`,
      tag: '[kya-os]',
    });
    return rejection('delegation_unresolvable', refusalCodeOf(error, 'runtime_error'), [reason], 'resolved');
  }
  if (!Array.isArray(resolved) || resolved.length === 0) {
    return rejection('delegation_missing', 'needs_authorization', [`no delegation chain found for ${input.proofDid}`], 'resolved');
  }
  // The resolver is the verifier's own, but what it returns is still parsed: a malformed hop
  // rejects rather than reaching the chain rules.
  const parsed = parseCredentials(resolved);
  if (!parsed.ok) return rejection('delegation_invalid', parsed.refusalCode, parsed.reasons, 'resolved');
  return { ok: true, chain: parsed.chain, credentials: parsed.credentials, source: 'resolved' };
}

// ── Guard: requireDelegation ─────────────────────────────────────────────────

/** The guard's rejection: a stable `code`, a human message, and the recompute `reasons`. */
export interface DelegationGateError {
  code: DelegationGateCode;
  message: string;
  reasons: string[];
}

/**
 * The guard verdict. A pass carries the recomputed grant. A rejection is 401-shaped when no
 * authority was presented (`delegation_missing`, which a server may answer with a consent step-up)
 * and 403-shaped otherwise. A rejection carries its {@link RejectionCoding} beside `error`, not in
 * it, so an `error` a server sends to its client is unchanged.
 */
export type DelegationGateResult =
  | ({ ok: true } & RequestDelegationGrant)
  | ({ ok: false; status: 401 | 403; error: DelegationGateError } & RejectionCoding);

/** A per-request delegation guard. Run it after `requireProof`, passing the `did` it returned. */
export type DelegationGuard = (input: RequestDelegationInput) => Promise<DelegationGateResult>;

const GATE_MESSAGES: Record<DelegationGateCode, string> = {
  delegation_missing: 'no delegation chain was presented for this call',
  delegation_unresolvable: 'the delegation chain could not be resolved',
  delegation_invalid: 'the delegation chain does not authorize this caller',
  delegation_revoked: 'a credential in the delegation chain is revoked or its status is unprovable',
  action_not_delegated: 'the delegation chain does not grant this action',
};

/**
 * Build a per-request delegation guard from pre-bound seams: {@link verifyRequestDelegation} with
 * 401/403-shaped results. Compose it after `requireProof`, which proves the caller holds the key
 * the leaf hop names:
 *
 * ```ts
 * const proof = await proofGuard(req, meta);
 * if (!proof.ok) return proof;
 * const authority = await delegationGuard({ meta, proofDid: proof.did, action: req.params.name });
 * ```
 *
 * Throws an `Error` naming every fix when neither `trustedRootIssuers` nor `resourceOwner` pins the
 * chain's root, outside development and without `allowAnyRootIssuer: true`; with either of those,
 * it builds the guard and warns once. Throws a `TypeError`, naming the option, for a
 * `trustedRootIssuers` that is not an array of DIDs, each a string that starts with `did:` and has
 * no white space around it, for an `allowAnyRootIssuer` or a `development` that is not a boolean,
 * for `allowAnyRootIssuer: true` beside a pin, and for a `dependencyTimeoutMs` that is not a number
 * of milliseconds it can wait, so a mistyped option fails when the guard is built.
 */
export function requireDelegation(deps: VerifyRequestDelegationDeps): DelegationGuard {
  admitRootIssuers(deps, 'requireDelegation', true);
  dependencyTimeout(deps.dependencyTimeoutMs);
  clockSkewOption(deps.maxClockSkewMs);
  return async (input) => {
    const result = await verifyRequest(input, deps);
    if (result.ok) return result;
    return {
      ok: false,
      status: result.code === 'delegation_missing' ? 401 : 403,
      error: { code: result.code, message: GATE_MESSAGES[result.code], reasons: result.reasons },
      refusalCode: result.refusalCode,
      transient: result.transient,
    };
  };
}
