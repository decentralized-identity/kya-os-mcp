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

import { isRecord } from '../utils/guards.js';
import { admitsRootIssuer, assertTrustedRootIssuers } from '../delegation/root-admission.js';
import {
  DelegationCredentialSchema,
  MAX_DELEGATION_DEPTH,
  revocationEntriesOf,
  validateDelegationChain,
  type DelegationChain,
  type DelegationCredential,
} from './delegation.js';
import type { DelegationProofVerifier } from './delegation-proof.js';
import { evaluateRevocationChain, type BitstringRevocationChecker } from './revocation.js';

/** The `_meta` key that carries a request's delegation chain (registered in §14.1). */
export const KYA_OS_DELEGATION_CHAIN_META_KEY = 'org.kya-os/delegation-chain';

/**
 * The most credentials {@link verifyRequestDelegation} accepts in a CARRIED chain unless the caller
 * sets `maxChainLength`. A carried chain's length is chosen by the caller, and every hop can cost a
 * DID resolution and a status-list fetch, so a carried chain is bounded by default. It is a local
 * resource limit, not a protocol rule about how far authority may be delegated (SPEC.md §6.10).
 */
export const DEFAULT_CARRIED_CHAIN_LIMIT = MAX_DELEGATION_DEPTH;

/** The `_meta` member a caller sends: `{ 'org.kya-os/delegation-chain': [root, ..., leaf] }`. */
export type DelegationChainMeta = Record<typeof KYA_OS_DELEGATION_CHAIN_META_KEY, DelegationChain>;

/**
 * Build the `_meta` member that carries `chain` (root first, leaf last). Spread it into the same
 * `_meta` that carries the request proof:
 * `{ [KYA_OS_CARD_PROOF_META_KEY]: proof, ...toDelegationChainMeta(chain) }`.
 */
export function toDelegationChainMeta(chain: DelegationChain): DelegationChainMeta {
  return { [KYA_OS_DELEGATION_CHAIN_META_KEY]: [...chain] };
}

/** The outcome of reading the carried chain out of a request's `_meta`. */
export type CarriedChainRead =
  | { carried: false }
  | {
      carried: true;
      ok: true;
      /** The parsed hops, root to leaf, for the chain rules. */
      chain: DelegationChain;
      /** The same hops exactly as received, for proof verification (a proof covers every member). */
      credentials: readonly Record<string, unknown>[];
    }
  | { carried: true; ok: false; reasons: string[] };

/**
 * Read `_meta['org.kya-os/delegation-chain']`, fail-closed. Absent means not carried. Anything
 * present must be a non-empty array of `DelegationCredential` objects no longer than
 * `maxChainLength` (default {@link DEFAULT_CARRIED_CHAIN_LIMIT}); the length is checked before any
 * entry is parsed.
 */
export function readDelegationChain(meta: unknown, opts: { maxChainLength?: number } = {}): CarriedChainRead {
  if (!isRecord(meta)) return { carried: false };
  const value = meta[KYA_OS_DELEGATION_CHAIN_META_KEY];
  if (value === undefined) return { carried: false };

  const reject = (reason: string): CarriedChainRead => ({ carried: true, ok: false, reasons: [reason] });
  if (!Array.isArray(value)) {
    return reject(`${KYA_OS_DELEGATION_CHAIN_META_KEY} must be an array of DelegationCredential objects, root to leaf`);
  }
  if (value.length === 0) return reject('empty delegation chain');
  const limit = opts.maxChainLength ?? DEFAULT_CARRIED_CHAIN_LIMIT;
  if (!Number.isInteger(limit) || limit < 1) {
    return reject(`maxChainLength must be a positive integer (got ${String(limit)})`);
  }
  if (value.length > limit) {
    return reject(`carried delegation chain of ${value.length} credentials exceeds the limit of ${limit}`);
  }
  const parsed = parseCredentials(value);
  return parsed.ok ? { carried: true, ...parsed } : { carried: true, ok: false, reasons: parsed.reasons };
}

/** Schema-parse each hop, keeping the as-received object alongside the parsed one. */
function parseCredentials(
  entries: readonly unknown[],
):
  | { ok: true; chain: DelegationChain; credentials: readonly Record<string, unknown>[] }
  | { ok: false; reasons: string[] } {
  const chain: DelegationCredential[] = [];
  const credentials: Record<string, unknown>[] = [];
  for (const [hop, entry] of entries.entries()) {
    if (!isRecord(entry)) return { ok: false, reasons: [`hop ${hop}: not a credential object`] };
    const parsed = DelegationCredentialSchema.safeParse(entry);
    if (!parsed.success) {
      const issue = parsed.error.issues[0];
      const where = issue && issue.path.length > 0 ? ` at ${issue.path.join('.')}` : '';
      return {
        ok: false,
        reasons: [`hop ${hop}: not a DelegationCredential${where}: ${issue?.message ?? 'invalid'}`],
      };
    }
    chain.push(parsed.data);
    credentials.push(entry);
  }
  return { ok: true, chain, credentials };
}

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
  /** When set, the root issuer must equal it (the SPEC.md §6.10 root rule). */
  resourceOwner?: string;
  /**
   * When set, the root issuer (the Responsible Party) must be one of these DIDs, each compared
   * whole. Anything but an array of DIDs, each a string that starts with `did:` and has no white
   * space around it, throws a `TypeError` naming the option.
   */
  trustedRootIssuers?: readonly string[];
  /**
   * Local cost limit: the most credentials to evaluate in one chain, root to leaf inclusive. A
   * carried chain is bounded by {@link DEFAULT_CARRIED_CHAIN_LIMIT} when this is unset; a resolved
   * chain comes from the verifier's own resolver and is bounded only when this is set.
   */
  maxChainLength?: number;
  /** Injectable clock (epoch ms) for the expiry gate; default `Date.now`. */
  now?: () => number;
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

/** The authority a verified chain grants, recomputed from the chain. */
export interface RequestDelegationGrant {
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

export type RequestDelegationResult =
  | ({ ok: true } & RequestDelegationGrant)
  | { ok: false; code: DelegationGateCode; reasons: string[]; source?: DelegationChainSource };

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
 * 7. Revocation, root to leaf, each hop's status list held to the hop's issuer or, when step 2 or 4
 *    pinned it, the root issuer, as the proofs step 5 verified name them; a revoked ancestor
 *    invalidates the subtree.
 *
 * Cheap, local checks run before the ones that may touch the network. Never throws on a
 * malformed input or a throwing seam; returns `{ ok: false, code, reasons }`. Rejects with a
 * `TypeError` for a `trustedRootIssuers` that is not an array of DIDs, each a string that starts
 * with `did:` and has no white space around it.
 */
export async function verifyRequestDelegation(
  input: RequestDelegationInput,
  deps: VerifyRequestDelegationDeps,
): Promise<RequestDelegationResult> {
  assertTrustedRootIssuers(deps.trustedRootIssuers);
  const obtained = await obtainChain(input, deps);
  if (!obtained.ok) return obtained;
  const { chain, credentials, source } = obtained;
  const reject = (code: DelegationGateCode, reasons: string[]): RequestDelegationResult => ({
    ok: false,
    code,
    reasons,
    source,
  });

  const structural = validateDelegationChain(chain, {
    resource: deps.resource,
    ...(deps.resourceOwner !== undefined ? { resourceOwner: deps.resourceOwner } : {}),
    ...(deps.maxChainLength !== undefined ? { maxChainLength: deps.maxChainLength } : {}),
    ...(deps.now !== undefined ? { now: deps.now } : {}),
  });
  if (!structural.ok) return reject('delegation_invalid', structural.reasons);
  const { responsibleParty, leafInvoker, invocationTarget, allowedAction, depth } = structural;
  if (responsibleParty === undefined || leafInvoker === undefined || invocationTarget === undefined) {
    return reject('delegation_invalid', ['delegation chain has no root issuer or leaf delegate']);
  }

  if (leafInvoker !== input.proofDid) {
    return reject('delegation_invalid', [
      `leaf delegate ${leafInvoker} is not the request proof's DID ${input.proofDid}`,
    ]);
  }
  if (!admitsRootIssuer(deps.trustedRootIssuers, responsibleParty)) {
    return reject('delegation_invalid', [`root issuer ${responsibleParty} is not a trusted root issuer`]);
  }

  for (const [hop, credential] of credentials.entries()) {
    if (!(await hopProofVerifies(credential, deps.verifyHopProof))) {
      return reject('delegation_invalid', [`hop ${hop}: proof did not verify`]);
    }
  }

  if (!allowedAction.includes(input.action)) {
    return reject('action_not_delegated', [`action "${input.action}" is not in the delegated allowedAction`]);
  }

  const pinnedRoot =
    deps.resourceOwner !== undefined || deps.trustedRootIssuers !== undefined ? responsibleParty : undefined;
  let revocation: Awaited<ReturnType<typeof evaluateRevocationChain>>;
  try {
    revocation = await evaluateRevocationChain(revocationEntriesOf(chain, pinnedRoot), deps.checkRevocation);
  } catch {
    return reject('delegation_revoked', ['revocation checker threw: status unprovable, fail-closed']);
  }
  if (!revocation.ok) return reject('delegation_revoked', revocation.reasons);

  return {
    ok: true,
    source,
    responsibleParty,
    leafInvoker,
    invocationTarget,
    allowedAction,
    depth,
    fresh: revocation.fresh,
  };
}

/** Step 1: the carried chain when present, else the by-reference resolver. */
async function obtainChain(
  input: RequestDelegationInput,
  deps: VerifyRequestDelegationDeps,
): Promise<
  | { ok: true; chain: DelegationChain; credentials: readonly Record<string, unknown>[]; source: DelegationChainSource }
  | { ok: false; code: DelegationGateCode; reasons: string[]; source?: DelegationChainSource }
> {
  const read = readDelegationChain(
    input.meta,
    deps.maxChainLength !== undefined ? { maxChainLength: deps.maxChainLength } : {},
  );
  if (read.carried) {
    if (!read.ok) return { ok: false, code: 'delegation_invalid', reasons: read.reasons, source: 'carried' };
    return { ok: true, chain: read.chain, credentials: read.credentials, source: 'carried' };
  }

  if (deps.resolveDelegationChain === undefined) {
    return {
      ok: false,
      code: 'delegation_missing',
      reasons: [`no ${KYA_OS_DELEGATION_CHAIN_META_KEY} in _meta, and no by-reference resolver is configured`],
    };
  }
  let resolved: DelegationChain | undefined;
  try {
    resolved = await deps.resolveDelegationChain({ proofDid: input.proofDid });
  } catch (error) {
    const detail = error instanceof Error ? error.message : 'unknown error';
    return {
      ok: false,
      code: 'delegation_unresolvable',
      reasons: [`delegation chain could not be resolved: ${detail}`],
      source: 'resolved',
    };
  }
  if (!Array.isArray(resolved) || resolved.length === 0) {
    return {
      ok: false,
      code: 'delegation_missing',
      reasons: [`no delegation chain found for ${input.proofDid}`],
      source: 'resolved',
    };
  }
  // The resolver is the verifier's own, but what it returns is still parsed: a malformed hop
  // rejects rather than reaching the chain rules.
  const parsed = parseCredentials(resolved);
  if (!parsed.ok) return { ok: false, code: 'delegation_invalid', reasons: parsed.reasons, source: 'resolved' };
  return { ok: true, chain: parsed.chain, credentials: parsed.credentials, source: 'resolved' };
}

/** Run the hop-proof seam, fail-closed: a throw rejects the hop. */
async function hopProofVerifies(
  credential: Record<string, unknown>,
  verifyHopProof: DelegationProofVerifier,
): Promise<boolean> {
  try {
    return (await verifyHopProof(credential)) === true;
  } catch {
    return false;
  }
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
 * and 403-shaped otherwise.
 */
export type DelegationGateResult =
  | ({ ok: true } & RequestDelegationGrant)
  | { ok: false; status: 401 | 403; error: DelegationGateError };

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
 * Throws a `TypeError`, naming the option, for a `trustedRootIssuers` that is not an array of
 * DIDs, each a string that starts with `did:` and has no white space around it, so a mistyped list
 * fails when the guard is built.
 */
export function requireDelegation(deps: VerifyRequestDelegationDeps): DelegationGuard {
  assertTrustedRootIssuers(deps.trustedRootIssuers);
  return async (input) => {
    const result = await verifyRequestDelegation(input, deps);
    if (result.ok) return result;
    return {
      ok: false,
      status: result.code === 'delegation_missing' ? 401 : 403,
      error: { code: result.code, message: GATE_MESSAGES[result.code], reasons: result.reasons },
    };
  };
}
