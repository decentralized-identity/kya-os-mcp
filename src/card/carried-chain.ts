/**
 * KYA-OS Entity Card: the delegation chain a request carries in its `_meta`
 * (SPEC-ENTITY-CARD §10.5): the member a caller sends, and how a verifier reads it, fail-closed,
 * with the code of why when it refuses what it read. Re-exported from
 * `./request-delegation.ts`, which verifies what this reads.
 */

import { isRecord } from '../utils/guards.js';
import { coded } from '../utils/refusal.js';
import type { RefusalCode } from '../refusal-codes.js';
import {
  DelegationCredentialSchema,
  MAX_DELEGATION_DEPTH,
  type DelegationChain,
  type DelegationCredential,
} from './delegation.js';

/** The `_meta` key that carries a request's delegation chain (registered in §14.1). */
export const KYA_OS_DELEGATION_CHAIN_META_KEY = 'org.kya-os/delegation-chain';

/**
 * @deprecated Applied to nothing, and removed in 2.0.0: a carried chain has no limit unless the
 * caller sets `maxChainLength`, as a resolved one never had. Through 1.25 it was the most
 * credentials {@link verifyRequestDelegation} accepted in a carried chain by default. A host that
 * wants that limit passes `maxChainLength: MAX_DELEGATION_DEPTH`.
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

/**
 * The refusal code of a rejection, and whether it is transient, under names that leave `code` to the
 * {@link DelegationGateCode} the rejection already carries. The library sets both on every
 * rejection it returns. Both are for the operator's logs and retry logic, not for whoever presented
 * the request: the code can tell an outage from a host that answered, which the reasons keep from
 * that party.
 */
export interface RejectionCoding {
  /** Why the chain was rejected, as a stable code (`REFUSAL_CODES`), finer than the gate's `code`. */
  refusalCode?: RefusalCode;
  /** Whether {@link refusalCode} is transient: the verifier could not decide, and the same request may pass later. */
  transient?: boolean;
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
  | ({ carried: true; ok: false; reasons: string[] } & RejectionCoding);

/** A {@link RejectionCoding} as the library sets it: both members, from one code. */
export type RejectionCoded = Required<RejectionCoding>;

/** The {@link RejectionCoded} pair of `code`. */
export function rejectionCoded(code: RefusalCode): RejectionCoded {
  const { transient } = coded(code);
  return { refusalCode: code, transient };
}

/** A failed read or parse of carried hops, with the code of why. */
export type ReadRefusal = { ok: false; reasons: string[] } & RejectionCoded;

/** The read or parse refusal for `reason`, with `code`. */
export function readRefusal(code: RefusalCode, reason: string): ReadRefusal {
  return { ok: false, reasons: [reason], ...rejectionCoded(code) };
}

/**
 * Read `_meta['org.kya-os/delegation-chain']`, fail-closed. Absent means not carried. Anything
 * present must be a non-empty array of `DelegationCredential` objects, of any length unless the
 * caller sets `maxChainLength`, a positive integer; the length is then checked before any entry is
 * parsed. A delegation may be re-delegated any number of times (SPEC.md §6.10), so a limit is the
 * verifier's own policy, never a default.
 */
export function readDelegationChain(meta: unknown, opts: { maxChainLength?: number } = {}): CarriedChainRead {
  return readCarriedChain(meta, opts);
}

/** {@link readDelegationChain}, with a refusal that cannot be built without its code. */
export function readCarriedChain(
  meta: unknown,
  opts: { maxChainLength?: number },
): Exclude<CarriedChainRead, { ok: false }> | ({ carried: true } & ReadRefusal) {
  if (!isRecord(meta)) return { carried: false };
  const value = meta[KYA_OS_DELEGATION_CHAIN_META_KEY];
  if (value === undefined) return { carried: false };

  const reject = (code: RefusalCode, reason: string): { carried: true } & ReadRefusal => ({ carried: true, ...readRefusal(code, reason) });
  if (!Array.isArray(value)) {
    return reject('delegation_malformed', `${KYA_OS_DELEGATION_CHAIN_META_KEY} must be an array of DelegationCredential objects, root to leaf`);
  }
  if (value.length === 0) return reject('chain_invalid', 'empty delegation chain');
  const limit = opts.maxChainLength;
  if (limit !== undefined) {
    if (!Number.isInteger(limit) || limit < 1) {
      return reject('configuration_error', `maxChainLength must be a positive integer (got ${String(limit)})`);
    }
    if (value.length > limit) {
      return reject('chain_invalid', `carried delegation chain of ${value.length} credentials exceeds the limit of ${limit}`);
    }
  }
  return { carried: true, ...parseCredentials(value) };
}

/** Schema-parse each hop, keeping the as-received object alongside the parsed one. */
export function parseCredentials(
  entries: readonly unknown[],
):
  | { ok: true; chain: DelegationChain; credentials: readonly Record<string, unknown>[] }
  | ReadRefusal {
  const chain: DelegationCredential[] = [];
  const credentials: Record<string, unknown>[] = [];
  for (const [hop, entry] of entries.entries()) {
    if (!isRecord(entry)) return readRefusal('delegation_malformed', `hop ${hop}: not a credential object`);
    const parsed = DelegationCredentialSchema.safeParse(entry);
    if (!parsed.success) {
      const issue = parsed.error.issues[0];
      const where = issue && issue.path.length > 0 ? ` at ${issue.path.join('.')}` : '';
      return readRefusal('delegation_malformed', `hop ${hop}: not a DelegationCredential${where}: ${issue?.message ?? 'invalid'}`);
    }
    chain.push(parsed.data);
    credentials.push(entry);
  }
  return { ok: true, chain, credentials };
}
