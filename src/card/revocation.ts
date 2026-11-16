/**
 * KYA-OS Entity Card — REVOCATION seam (W3C Bitstring Status List v1.0).
 *
 * Capability + delegation credentials are revocable, so a verifier must be able to ask "is
 * THIS credential still live?" without the question's shape leaking into callers. This module
 * ships that question as a pluggable seam — `RevocationChecker` — so the VC-2.0 / status-list
 * churn stays behind one interface (the same injected-seam discipline `verifyCard` already
 * uses for its capability / attestation / accountability verifiers; NO `mcp-i-core` runtime
 * dependency leaks into `@kya-os/mcp`).
 *
 * `createRevocationChecker` is the DEFAULT implementation over W3C Bitstring Status List v1.0
 * (`BitstringStatusListEntry` — the StatusList2021 SUCCESSOR). It resolves the entry's
 * `statusListCredential` through the injected, SSRF-hardened {@link SafeFetch} seam. When given the
 * injected `verifyStatusList` seam, it holds the list to the credential the entry belongs to
 * ({@link acceptStatusList}) and checks the list's proof, then inflates the multibase / GZIP
 * `encodedList` bitstring and reads the bit at `statusListIndex`.
 *
 * FAIL-CLOSED is the invariant: an unreachable status list, a malformed credential, a list whose
 * proof is rejected, a list {@link acceptStatusList} refuses for the credential, an entry or a list
 * of another `statusPurpose`, an entry whose `statusSize` is not 1, or an out-of-range index all
 * resolve to `{ revoked: true }`: the
 * absence of proof-of-liveness is treated as revoked, never as "probably fine".
 *
 * Each verdict also reports `fresh`: `true` only when read from a LIVE, in-validity-window
 * status list. A stale (past `validUntil`) or not-yet-valid list still yields a readable bit
 * but `fresh: false`. {@link evaluateRevocationChain} walks a delegation chain root→leaf and
 * fail-closes (cascading: a revoked parent invalidates the whole subtree) on the first
 * revoked/unresolvable hop, threading `fresh` through every hop. The caller decides the gate:
 * L2 accepts a non-revoked chain (cached / offline-verifiable); L3 additionally requires
 * `fresh` (a live status check). NOT wired into `verifyCard` here — a later step injects it.
 */

import { answerWithinDeadline, dependencyTimeout } from '../utils/deadline.js';
import { describeValue } from '../utils/describe-value.js';
import { isRecord, issuerOf } from '../utils/guards.js';
import { sanitizeForMessage } from '../utils/message-text.js';
import { CHECKER_REASON_LENGTH, readRevocationAnswer } from '../utils/revocation-answer.js';
import { carriedContext } from '../utils/status-check-carrier.js';
import { withStatusListIssuersRemedy } from '../utils/statuslist-remedy.js';
import {
  acceptEntryPurpose,
  acceptEntrySize,
  acceptStatusList,
  acceptStatusPurpose,
  assertStatusListIssuers,
  statusListExpectationFor,
  type StatusCheckContext,
  type StatusListIssuers,
} from '../utils/statuslist-acceptance.js';
import {
  decodeStatusListPayload,
  parseStatusListIndex,
  readStatusBit,
} from '../utils/statuslist-bits.js';
import { statusListGzipCodec } from '../utils/statuslist-gzip.js';
import type { SafeFetch } from '../utils/safe-fetch.js';
import { checkWithinDeadline } from './revocation-deadline.js';
import type { BitstringStatusListEntry } from './schema.js';
import type { StatusListProofVerifier } from './status-list-proof.js';

export {
  acceptEntrySize,
  acceptStatusList,
  statusListExpectationFor,
  statusListKeeperFor,
  type StatusCheckContext,
  type StatusListExpectation,
  type StatusListIssuers,
  type StatusListKeeper,
  type StatusListVerdict,
} from '../utils/statuslist-acceptance.js';

/** The `statusPurpose` this checker evaluates by default (revocation, not suspension). */
export const STATUS_PURPOSE_REVOCATION = 'revocation';

/**
 * Inflate a GZIP `encodedList` payload to the raw status bitstring. The seam that keeps this
 * verifier ISOMORPHIC: the default is Node-only (`node:zlib`), but a Workers / Deno / browser
 * deployment injects a `DecompressionStream`-based impl so the bundle never pulls `node:zlib`.
 * MAY be sync or async; MUST reject (throw / reject) on non-inflatable input (fail-closed).
 */
export type Decompress = (bytes: Uint8Array) => Uint8Array | Promise<Uint8Array>;

// The 16 MiB inflation cap and the multibase/base64url/bit-read mechanics live in
// `utils/statuslist-bits` — ONE implementation shared with the delegation readers, so the two
// paths can no longer drift. Exceeding the cap (or any malformed input) throws, which this
// checker converts to FAIL_CLOSED — the module's uniform posture. Without the cap, the ~786 KB
// of GZIP that fits inside SafeFetch's 1 MiB body cap inflates to ~800 MB.

/** Verdict for ONE status entry. */
export interface RevocationStatus {
  /** True iff the status bit is set OR the status could not be proven clear (fail-closed). */
  revoked: boolean;
  /** True iff read from a LIVE, in-validity-window status list (drives the L2/L3 gate). */
  fresh: boolean;
  /**
   * Why the status could not be proven clear, when it could not: text for people, which
   * {@link evaluateRevocationChain} appends to the hop's refusal and `verifyCard` reports. The
   * checker {@link createRevocationChecker} builds gives one for every entry it fails closed on,
   * and none for an entry whose bit it read.
   */
  reason?: string;
}

/**
 * A status entry as the checker reads it: a {@link BitstringStatusListEntry}, with the
 * `statusPurpose` its credential states for it when it states one. A delegation hop's
 * `credentialStatus` may state one; a Card's `revocation` entry has none.
 */
export type RevocationStatusEntry = BitstringStatusListEntry & { statusPurpose?: string };

/**
 * The injected revocation seam: resolve a `BitstringStatusListEntry` to a {@link RevocationStatus}.
 * A runtime supplies an implementation (the default is {@link createRevocationChecker}); a
 * caller may inject a cache-backed or offline variant. Implementations MUST fail closed.
 *
 * Every caller in this package reads the answer through `readRevocationAnswer`, the reader the
 * delegation side shares: a credential passes only on an answer whose `revoked` is the literal
 * `false`, is revoked only on the literal `true`, and is fresh only when `fresh` is the literal
 * `true`. Any other answer, such as `undefined`, `{}`, `{ revoked: 0 }` or one with a getter that
 * throws, is refused as a status that could not be read.
 *
 * `context` names the issuer of the credential the entry belongs to and, when the verifier pins it,
 * the root issuer of its delegation chain with the status-list URL the root's own credential names,
 * so an implementation can hold the status list to the keeper of its URL.
 * Every caller in this package passes it, and a wrapping variant should pass it through unchanged.
 * Each caller in this package that passes it also passes a fresh copy of the entry that carries it,
 * under the non-enumerable key `Symbol.for('@kya-os/mcp/status-check-context')`, and the checkers
 * this package builds read it there when they are given no `context`, so a wrapping variant that
 * passes on only the very entry it was given still keeps it. The copy has the entry's own
 * enumerable members and no others; a copy made of it by spreading or by JSON does not carry it.
 * Whether a list may be read depends on the context, so a caching variant must key on it as well as
 * on the entry's URL, index and purpose, as `withStatusCache` does: a verdict for one context is no
 * answer for another.
 */
export type BitstringRevocationChecker = (
  entry: RevocationStatusEntry,
  context?: StatusCheckContext,
) => Promise<RevocationStatus>;

/**
 * @deprecated Use {@link BitstringRevocationChecker}. This alias collided with the
 * delegation-side `RevocationChecker` interface (`delegation/chain-enforcement.ts`) — two
 * identically named exports answering different questions. Alias removed at 2.0.
 */
export type RevocationChecker = BitstringRevocationChecker;

/** Result of a cascading root→leaf chain walk. */
export interface RevocationChainResult {
  /** True iff EVERY hop is non-revoked (fail-closed: any revoked/unresolvable hop ⇒ false). */
  ok: boolean;
  /** True iff EVERY checked hop was read from a live, in-window status list. */
  fresh: boolean;
  /** Fail-closed reasons (empty ⇒ ok). */
  reasons: string[];
}

/** Dependencies for the default Bitstring Status List v1.0 checker. */
export interface RevocationCheckerDeps {
  /** SSRF-hardened fetch seam used to resolve the `statusListCredential`. */
  fetch: SafeFetch;
  /** Injectable clock returning epoch MILLISECONDS (deterministic freshness tests). */
  now?: () => number;
  /**
   * `statusPurpose` to honour; default {@link STATUS_PURPOSE_REVOCATION}. An entry that states
   * another purpose resolves {@link FAIL_CLOSED}.
   */
  statusPurpose?: string;
  /**
   * Checks the fetched status-list credential's proof before any bit is read, as W3C Bitstring
   * Status List v1.0 requires (SPEC.md §6.10). A list it rejects (`false` or a throw) resolves
   * {@link FAIL_CLOSED}. {@link createStatusListProofVerifier} covers `eddsa-jcs-2022` lists.
   * A proof shows only who signed the list, so with this seam the checker also holds the list to
   * the credential it covers (see {@link createRevocationChecker}), by the list's `issuer`: the seam
   * resolves `true` only when the proof verifies under a key that `issuer` lists under
   * `assertionMethod`.
   * Without it the bits are read unchecked, so whoever serves the list can clear a revocation;
   * it stays optional until 2.0 only so existing callers keep working.
   */
  verifyStatusList?: StatusListProofVerifier;
  /**
   * The status-list URLs, or whole `https:` origins, each status-list issuer keeps, keyed by that
   * issuer's DID ({@link StatusListIssuers}). A list at a URL the map binds is read only from the
   * issuer it binds it to, whoever issued the credential. Off by default. It is checked when the
   * checker is created: a value {@link assertStatusListIssuers} refuses, or one given without
   * `verifyStatusList`, throws a `TypeError`.
   */
  statusListIssuers?: StatusListIssuers;
  /**
   * Injectable GZIP inflation seam ({@link Decompress}). DEFAULT = `statusListGzipCodec.decompress`,
   * which loads `node:zlib` on first use and bounds inflation to the 16 MiB cap (so a decompression
   * bomb THROWS mid-inflation ⇒ fail-closed, never allocating the whole payload). Non-Node
   * runtimes inject a `DecompressionStream`-based impl; when they do, `node:zlib` is never loaded.
   * An injected impl SHOULD bound its own output — {@link decodeStatusList} still applies the cap
   * as a post-inflation backstop regardless.
   */
  decompress?: Decompress;
  /**
   * How long, in milliseconds, one check, its list read and its `verifyStatusList` together, may take: a number greater than 0 and at most
   * 2,147,483,647. Default 5,000. Any other value throws a `TypeError` naming the option.
   */
  dependencyTimeoutMs?: number;
}

export { CHECKER_REASON_LENGTH } from '../utils/revocation-answer.js';

/** Fail-closed verdict: status indeterminate ⇒ treat as revoked AND not fresh. */
const FAIL_CLOSED: RevocationStatus = { revoked: true, fresh: false };

/**
 * Build the default `RevocationChecker` over W3C Bitstring Status List v1.0. Every outbound
 * request rides the injected {@link SafeFetch}; any failure on the path (unreachable, non-2xx,
 * malformed, wrong purpose, out-of-range index) resolves {@link FAIL_CLOSED}.
 *
 * The checker answers for one purpose, its `statusPurpose`. An entry that states another (a
 * `suspension` entry under a revocation checker), or a value that is not a string, `null` included,
 * says nothing about that purpose, so it resolves {@link FAIL_CLOSED} before any fetch rather than
 * being read as the checker's. Only an entry that states no purpose is read as the checker's.
 *
 * The checker reads one bit per entry, the bit at `statusListIndex`. An entry whose `statusSize` is
 * not 1 keeps its status elsewhere in the list, so it resolves {@link FAIL_CLOSED} before any fetch
 * as well ({@link acceptEntrySize}); an entry that states no `statusSize` is one bit wide.
 *
 * With `verifyStatusList`, a list is read only when {@link acceptStatusList} accepts it for the
 * entry and `context`: it must come from the one keeper of the entry's URL, which
 * {@link statusListKeeperFor} decides before any fetch from `statusListIssuers` and `context`, never
 * from the list. The rule is asked before the proof is checked, so a list from another issuer never
 * triggers a DID resolution. The context is `context` when it is given, or else the one `entry`
 * carries ({@link BitstringRevocationChecker}). A call that names no `credentialIssuer` either way
 * cannot be held to anyone and resolves {@link FAIL_CLOSED} before any fetch, with a reason that
 * says a checker or resolver wrapping this one must pass its second argument on. A list another DID
 * signed is refused with a reason that ends with the `statusListIssuers` configuration that would
 * accept it, as a condition the operator judges, or says where to name that DID when the
 * configuration cannot be printed whole within {@link CHECKER_REASON_LENGTH}.
 * Without `verifyStatusList` nothing about the list is authenticated, so only its `statusPurpose`
 * is checked and the bits are read as before.
 *
 * @throws TypeError when `statusListIssuers` is malformed, or given without `verifyStatusList`, or
 *   when `dependencyTimeoutMs` is not a number of milliseconds the checker can wait.
 */
export function createRevocationChecker(
  deps: RevocationCheckerDeps,
): BitstringRevocationChecker {
  assertStatusListIssuers(deps.statusListIssuers);
  if (deps.statusListIssuers !== undefined && deps.verifyStatusList === undefined) {
    throw new TypeError('statusListIssuers is set but verifyStatusList is not, so no status list is held to an issuer');
  }
  const clock = deps.now ?? (() => Date.now());
  const wantedPurpose = deps.statusPurpose ?? STATUS_PURPOSE_REVOCATION;
  const decompress = deps.decompress ?? statusListGzipCodec.decompress;
  const timeoutMs = dependencyTimeout(deps.dependencyTimeoutMs);
  const read = async function check(
    entry: RevocationStatusEntry,
    context?: StatusCheckContext,
  ): Promise<RevocationStatus> {
    try {
      const entryPurpose = acceptEntryPurpose(entry.statusPurpose, wantedPurpose);
      if (!entryPurpose.valid) throw new Error(`revocation: ${entryPurpose.reason}`);
      const entrySize = acceptEntrySize(entry.statusSize);
      if (!entrySize.valid) throw new Error(`revocation: ${entrySize.reason}`);
      const { statusListCredential } = entry;
      const { statusListIssuers } = deps;
      const heldTo = deps.verifyStatusList ? boundContext(context ?? carriedContext(entry)) : undefined;
      const expectation = heldTo
        ? statusListExpectationFor({ statusListCredential, statusPurpose: wantedPurpose }, heldTo, statusListIssuers)
        : undefined;
      const credential = await fetchStatusList(statusListCredential, deps.fetch);
      const verdict =
        expectation === undefined
          ? acceptStatusPurpose(credential, wantedPurpose)
          : acceptStatusList(credential, expectation);
      if (!verdict.valid) {
        const refused = heldTo && expectation && { list: credential, statusListCredential, context: heldTo, statusListIssuers, keeper: expectation.keeper };
        throw new Error(`revocation: ${refused ? withStatusListIssuersRemedy(verdict.reason, refused, CHECKER_REASON_LENGTH) : verdict.reason}`);
      }
      if (deps.verifyStatusList && (await deps.verifyStatusList(credential)) !== true) {
        throw new Error('revocation: status-list proof rejected');
      }
      const bits = await decodeStatusList(credential, decompress);
      const revoked = readStatusBit(bits, parseStatusListIndex(entry.statusListIndex));
      return { revoked, fresh: isLive(credential, clock()) };
    } catch (error) {
      return { ...FAIL_CLOSED, reason: failureReason(error) };
    }
  };
  // The list read and its proof check share one deadline, and a miss fails closed as a throw does.
  return (entry, context) =>
    answerWithinDeadline('the status list read', () => read(entry, context), timeoutMs).catch(() => FAIL_CLOSED);
}

/**
 * Why the checker failed closed, from what a step threw: the message of an `Error`, without the
 * `revocation: ` this module opens its own with, at most {@link CHECKER_REASON_LENGTH} UTF-16 code
 * units and free of control characters as `sanitizeForMessage` leaves it, since a fetch or a
 * decompressor the host injected may have thrown it. Anything else thrown is not converted.
 */
function failureReason(error: unknown): string {
  if (!(error instanceof Error)) return 'the status could not be proven';
  return sanitizeForMessage(error.message.replace(/^revocation: /, ''), CHECKER_REASON_LENGTH);
}

/**
 * One hop for {@link evaluateRevocationChain}: a status entry, with the `statusPurpose` its hop
 * states, and the context the checker holds the hop's status list to: the issuer of the credential
 * it belongs to and, when the verifier pins it, the chain's root issuer.
 */
export interface RevocationChainEntry extends Omit<StatusCheckContext, 'credentialIssuer'> {
  entry: RevocationStatusEntry;
  /**
   * The credential's issuer DID, or `undefined` when its `issuer` names none: the entry is then
   * checked with no context.
   */
  credentialIssuer: string | undefined;
  /**
   * The hop's position in its chain, the root being 0, which a refusal names it by. Omitted, the
   * hop is named by its place among the entries the walk is given.
   */
  position?: number;
}

/**
 * Walk a delegation/capability chain root→leaf and fail-close on the first revoked or
 * unresolvable hop (cascading — a revoked ancestor invalidates the subtree, so the walk
 * short-circuits). `fresh` is the AND of every checked hop's liveness.
 *
 * An empty set of status entries is trivially `ok` (nothing is revoked — an offline/L2-acceptable
 * verdict) but is NOT `fresh`: freshness is a LIVE-check signal, and zero checks obtained no live
 * signal. An L3 liveness gate that requires `fresh` therefore cannot be satisfied by a chain that
 * simply omits all `credentialStatus` entries — it must consult at least one live status list.
 *
 * Pass each hop as a {@link RevocationChainEntry} (`revocationEntriesOf` builds them from a
 * delegation chain) so the checker can hold the hop's list to the hop's issuer and the chain's pinned
 * root. A bare entry, like a hop that names no issuer, is checked with no context, which a checker
 * given `verifyStatusList` refuses (fail-closed). Any other item is checked as a bare entry, so it is
 * refused too, and the walk never throws on it.
 *
 * A checker's answer is read as {@link BitstringRevocationChecker} says: a hop passes only on a
 * literal `revoked: false`, and an answer that is neither that nor a literal `revoked: true` refuses
 * the hop with a reason that says what could not be read. No answer makes the walk throw; a checker
 * that throws or rejects still does, and the callers in this package catch that and fail closed.
 *
 * A revoked hop's refusal ends with the `reason` its checker gave, when it gave one, after a colon:
 * at most its first {@link CHECKER_REASON_LENGTH} UTF-16 code units, with every control character
 * replaced, as `sanitizeForMessage` leaves text.
 *
 * The reason for a refused hop names the hop by its `position` in the chain, or by its place among
 * `entries` when it has none, and names the list and the index its entry states. Whoever issued the
 * hop wrote both, so the reason quotes each as `describeValue` does, at most its first 64
 * characters, and names one that is not a string by its type alone, never converting it.
 *
 * Each answer of the checker gets `options.dependencyTimeoutMs`, 5,000 ms by default, and a hop
 * whose checker has not answered by then is unresolvable. Rejects with a `TypeError` for a value
 * that is not a number of milliseconds greater than 0 and at most 2,147,483,647.
 */
export async function evaluateRevocationChain(
  entries: readonly (RevocationStatusEntry | RevocationChainEntry)[],
  check: BitstringRevocationChecker,
  options: { dependencyTimeoutMs?: number } = {},
): Promise<RevocationChainResult> {
  const timeoutMs = dependencyTimeout(options.dependencyTimeoutMs);
  let fresh = entries.length > 0; // no entries ⇒ no live signal ⇒ not fresh (fail-closed for L3)
  for (const [index, item] of entries.entries()) {
    let entry: RevocationStatusEntry | undefined;
    let context: StatusCheckContext | undefined;
    let hop = index;
    if (isChainEntry(item)) {
      const { entry: hopEntry, credentialIssuer, position, ...pinned } = item;
      entry = hopEntry;
      if (isPosition(position)) hop = position;
      context = credentialIssuer === undefined ? undefined : { ...pinned, credentialIssuer };
    } else {
      entry = item;
    }
    const asked = await checkWithinDeadline(check, entry, context, timeoutMs);
    if ('expired' in asked) {
      return { ok: false, fresh: false, reasons: [`${hopName(hop, entry)} is unresolvable: ${asked.expired}`] };
    }
    const status = readRevocationAnswer(asked.answer);
    if (status.revoked === undefined) {
      const reason = `${hopName(hop, entry)} has a status that could not be read: ${status.unreadable}`;
      return { ok: false, fresh: false, reasons: [reason] };
    }
    fresh = fresh && status.fresh;
    if (status.revoked) {
      return {
        ok: false,
        fresh: false,
        reasons: [
          [
            `${hopName(hop, entry)} ` +
            'is revoked or unresolvable — fail-closed, subtree invalidated',
            ...(status.reason ? [sanitizeForMessage(status.reason, CHECKER_REASON_LENGTH)] : []),
          ].join(': '),
        ],
      };
    }
  }
  return { ok: true, fresh, reasons: [] };
}

// ── Internals ──────────────────────────────────────────────────────────────────

/** How a refusal names hop `hop`: by its position, and by the list and the index its entry states. */
function hopName(hop: number, entry: RevocationStatusEntry | undefined): string {
  return (
    `revocation: hop ${hop} (list ${describeValue(entry?.statusListCredential)}, ` +
    `index ${describeValue(entry?.statusListIndex)})`
  );
}

/** A hop paired with its context, as opposed to a bare status entry (or a malformed item). */
function isChainEntry(item: unknown): item is RevocationChainEntry {
  return isRecord(item) && isRecord(item.entry);
}

/** Whether a hop's stated `position` is one a refusal can name it by: a non-negative safe integer. */
function isPosition(position: unknown): position is number {
  return Number.isSafeInteger(position) && (position as number) >= 0;
}

/**
 * The credential a verified list is held to, its issuer read as a credential's `issuer` member names
 * one ({@link issuerOf}). A list's proof shows only who signed it, so a call that names no credential
 * issuer DID cannot be bound to anyone and throws (fail-closed), saying how a wrapper that dropped
 * the context keeps it.
 */
function boundContext(context: StatusCheckContext | undefined): StatusCheckContext {
  const credentialIssuer = issuerOf(context?.credentialIssuer);
  if (!credentialIssuer) {
    throw new Error(
      'revocation: no credential issuer named to hold the status list to: a resolver or checker that ' +
        'wraps a library checker must pass its second argument on, or else the very entry it was given',
    );
  }
  return { ...context, credentialIssuer };
}

/** GET the status-list credential through SafeFetch (throws on non-2xx / non-object body). */
async function fetchStatusList(url: string, fetch: SafeFetch): Promise<Record<string, unknown>> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`revocation: status-list GET ${url} → ${res.status}`);
  const body = await res.json();
  if (!isRecord(body)) throw new Error('revocation: status-list credential is not an object');
  return body;
}

/**
 * Inflate the multibase / GZIP `encodedList` into the raw status bitstring bytes via the shared
 * `decodeStatusListPayload` primitive (strip + decode + POST-inflation 16 MiB backstop): the
 * default gunzip caps mid-stream, but an injected (edge) decompressor that does not bound its
 * own output is still fail-closed against an oversized bitstring at this seam. The purpose rule
 * has already refused a list with no `credentialSubject`; read without one, a list has no
 * `encodedList`.
 */
async function decodeStatusList(
  credential: Record<string, unknown>,
  decompress: Decompress,
): Promise<Uint8Array> {
  const subject = credential.credentialSubject;
  const encoded = isRecord(subject) ? subject.encodedList : undefined;
  if (typeof encoded !== 'string' || encoded.length === 0) {
    throw new Error('revocation: status-list has no encodedList');
  }
  return decodeStatusListPayload(encoded, decompress);
}

/**
 * True iff `nowMs` falls inside the credential's `[validFrom, validUntil]` window (if declared). A
 * bound that is PRESENT but not a parseable date is not "absent": the list's validity window is then
 * unknown, so it cannot vouch for a live read (`false`, never an open window).
 */
function isLive(credential: Record<string, unknown>, nowMs: number): boolean {
  const validUntil = parseDate(firstPresent(credential.validUntil, credential.expirationDate));
  const validFrom = parseDate(firstPresent(credential.validFrom, credential.issuanceDate));
  if (validUntil === null || validFrom === null) return false; // unknown window → not provably live
  if (validUntil !== undefined && validUntil < nowMs) return false; // stale → cached-OK at L2 only
  if (validFrom !== undefined && validFrom > nowMs) return false; // not yet valid
  return true;
}

/** The VC 2.0 property when present (even as `null`), else its VC 1.1 predecessor. */
function firstPresent(current: unknown, legacy: unknown): unknown {
  return current !== undefined ? current : legacy;
}

/** Parse an ISO-8601 date to epoch ms: `undefined` when absent, `null` when present but unparseable. */
function parseDate(value: unknown): number | undefined | null {
  if (value === undefined) return undefined;
  if (typeof value !== 'string') return null;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : ms;
}
