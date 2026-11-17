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
 * proof is rejected, a list {@link acceptStatusList} refuses for the credential, a list outside the
 * validity window it states (`utils/statuslist-validity.ts`), an entry or a list of another
 * `statusPurpose`, an entry whose `statusSize` is not 1, or an out-of-range index all resolve to
 * `{ revoked: true }`: the absence of proof-of-liveness is treated as revoked, never as "probably fine".
 *
 * Each verdict also reports `fresh`: `true` only when read from a LIVE, in-validity-window
 * status list, as every list this checker reads is, since it refuses one outside its window; a
 * caching variant reports `false` for a verdict it did not read live. {@link evaluateRevocationChain}
 * walks a delegation chain root→leaf and fail-closes (cascading: a revoked parent invalidates the
 * whole subtree) on the first revoked/unresolvable hop, threading `fresh` through every hop. The
 * caller decides the gate: L2 accepts a non-revoked chain (cached / offline-verifiable); L3
 * additionally requires `fresh` (a live status check).
 */

import type { RefusalCode } from '../refusal-codes.js';
import { answerWithinDeadline, dependencyTimeout } from '../utils/deadline.js';
import { describeValue } from '../utils/describe-value.js';
import { isRecord, issuerOf } from '../utils/guards.js';
import { coded, RefusalError, refusalCodeOf, type Coded } from '../utils/refusal.js';
import { CHECKER_REASON_LENGTH } from '../utils/revocation-answer.js';
import { thrownReason, unreadStatusList } from '../utils/thrown-words.js';
import { carriedContext } from '../utils/status-check-carrier.js';
import { operatorNamedHops } from '../utils/verified-root.js';
import { codedVariantOf } from './coded-proof-verifier.js';
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
  type DecompressLimits,
} from '../utils/statuslist-bits.js';
import { statusListGzipCodec } from '../utils/statuslist-gzip.js';
import { assertStatusListValidity } from '../utils/statuslist-validity.js';
import { clockSkewOption } from '../utils/validity-window.js';
import type { SafeFetch } from '../utils/safe-fetch.js';
import type { BitstringStatusListEntry } from './schema.js';
import type { StatusListProofVerifier } from './status-list-proof.js';
import type { RefusalCoding } from '../delegation/vc-verifier.types.js';

export {
  evaluateRevocationChain,
  type RevocationChainEntry,
  type RevocationChainResult,
} from './revocation-chain.js';

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

export { acceptStatusListValidity } from '../utils/statuslist-validity.js';

/** The `statusPurpose` this checker evaluates by default (revocation, not suspension). */
export const STATUS_PURPOSE_REVOCATION = 'revocation';

/**
 * Inflate a GZIP `encodedList` payload to the raw status bitstring. The seam that keeps this
 * verifier ISOMORPHIC: the default is Node-only (`node:zlib`), but a Workers / Deno / browser
 * deployment injects a `DecompressionStream`-based impl so the bundle never pulls `node:zlib`.
 * MAY be sync or async; MUST reject (throw / reject) on non-inflatable input (fail-closed). The
 * checker passes `limits`, the 16 MiB cap, and an impl SHOULD stop inflating and reject once its
 * output would pass `limits.maxBytes` ({@link DecompressLimits}).
 */
export type Decompress = (bytes: Uint8Array, limits?: DecompressLimits) => Uint8Array | Promise<Uint8Array>;

// The 16 MiB inflation cap and the multibase/base64url/bit-read mechanics live in
// `utils/statuslist-bits` — ONE implementation shared with the delegation readers, so the two
// paths can no longer drift. Exceeding the cap (or any malformed input) throws, which this
// checker converts to a fail-closed verdict, the module's uniform posture. Without the cap, the ~786 KB
// of GZIP that fits inside SafeFetch's 1 MiB body cap inflates to ~800 MB.

/**
 * Verdict for ONE status entry. One that is not provably clear also carries `code` and `transient`:
 * `delegation_revoked` for a set bit, and the code of the step that failed for a status that could
 * not be proven clear.
 */
export interface RevocationStatus extends RefusalCoding {
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

/** Dependencies for the default Bitstring Status List v1.0 checker. */
export interface RevocationCheckerDeps {
  /** SSRF-hardened fetch seam used to resolve the `statusListCredential`. */
  fetch: SafeFetch;
  /** Injectable clock returning epoch MILLISECONDS, which a list's validity window is read against. */
  now?: () => number;
  /**
   * The clock tolerance, in milliseconds, each bound of a list's validity window is held with, so a
   * list issued a moment ago by an issuer whose clock runs ahead is read: a number from 0, which
   * holds each bound exactly, to 600,000. Default 120,000, the proof verifier's default skew. Any
   * other value throws a `TypeError` naming the option.
   */
  maxClockSkewMs?: number;
  /**
   * `statusPurpose` to honour; default {@link STATUS_PURPOSE_REVOCATION}. An entry that states
   * another purpose fails closed ({@link failedClosed}).
   */
  statusPurpose?: string;
  /**
   * Checks the fetched status-list credential's proof before any bit is read, as W3C Bitstring
   * Status List v1.0 requires (SPEC.md §6.10). A list it rejects (`false` or a throw) resolves
   * a fail-closed verdict ({@link failedClosed}). {@link createStatusListProofVerifier} covers `eddsa-jcs-2022` lists.
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
   * An injected impl is passed the cap as its second argument and SHOULD stop inflating there;
   * {@link decodeStatusList} still applies the cap as a post-inflation backstop regardless.
   */
  decompress?: Decompress;
  /**
   * How long, in milliseconds, one check, its list read and its `verifyStatusList` together, may take: a number greater than 0 and at most
   * 2,147,483,647. Default 5,000. Any other value throws a `TypeError` naming the option.
   */
  dependencyTimeoutMs?: number;
}

export { CHECKER_REASON_LENGTH } from '../utils/revocation-answer.js';

/**
 * The fail-closed verdict: a status that could not be proven clear is revoked AND not fresh, with
 * the code of why, and the reason when there is one.
 */
function failedClosed(code: RefusalCode, reason?: string): RevocationStatus & Coded {
  return { revoked: true, fresh: false, ...(reason === undefined ? {} : { reason }), ...coded(code) };
}

/**
 * Build the default `RevocationChecker` over W3C Bitstring Status List v1.0. Every outbound
 * request rides the injected {@link SafeFetch}; any failure on the path (unreachable, non-2xx,
 * malformed, wrong purpose, out-of-range index) fails closed ({@link failedClosed}).
 *
 * A list is read only inside the validity window it states, its `validFrom` and `validUntil`, or its
 * `issuanceDate` and `expirationDate`, at the time `now` gives, once its proof has verified, each
 * bound held with `maxClockSkewMs`. A list past its end, before its start or stating a bound that is
 * not an RFC 3339 date-time with its zone fails closed as `status_unavailable`, whatever its bits,
 * with a reason that names the bound and quotes the time the list states. A list that states no
 * bound is read.
 *
 * The checker answers for one purpose, its `statusPurpose`. An entry that states another (a
 * `suspension` entry under a revocation checker), or a value that is not a string, `null` included,
 * says nothing about that purpose, so it fails closed ({@link failedClosed}) before any fetch rather than
 * being read as the checker's. Only an entry that states no purpose is read as the checker's.
 *
 * The checker reads one bit per entry, the bit at `statusListIndex`. An entry whose `statusSize` is
 * not 1 keeps its status elsewhere in the list, so it fails closed ({@link failedClosed}) before any fetch
 * as well ({@link acceptEntrySize}); an entry that states no `statusSize` is one bit wide.
 *
 * With `verifyStatusList`, a list is read only when {@link acceptStatusList} accepts it for the
 * entry and `context`: it must come from the one keeper of the entry's URL, which
 * {@link statusListKeeperFor} decides before any fetch from `statusListIssuers` and `context`, never
 * from the list. The rule is asked before the proof is checked, so a list from another issuer never
 * triggers a DID resolution. The context is `context` when it is given, or else the one `entry`
 * carries ({@link BitstringRevocationChecker}). A call that names no `credentialIssuer` either way
 * cannot be held to anyone and fails closed ({@link failedClosed}) before any fetch, with a reason that
 * says a checker or resolver wrapping this one must pass its second argument on. A list another DID
 * signed is refused with a reason that ends with the `statusListIssuers` configuration that would
 * accept it, as a condition the operator judges, or says where to name that DID when the
 * configuration cannot be printed whole within {@link CHECKER_REASON_LENGTH}.
 * Without `verifyStatusList` nothing about the list is authenticated, so only its `statusPurpose`
 * is checked and the bits are read as before.
 *
 * @throws TypeError when `statusListIssuers` is malformed, or given without `verifyStatusList`, or
 *   when `dependencyTimeoutMs` is not a number of milliseconds the checker can wait, or
 *   `maxClockSkewMs` not one it can hold a bound with.
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
  const skewMs = clockSkewOption(deps.maxClockSkewMs);
  const read = async function check(
    entry: RevocationStatusEntry,
    context?: StatusCheckContext,
  ): Promise<RevocationStatus> {
    try {
      if (!isRecord(entry)) throw new RefusalError('delegation_malformed', `revocation: the status entry (${describeValue(entry)}) is not an object`);
      const entryPurpose = acceptEntryPurpose(entry.statusPurpose, wantedPurpose);
      if (!entryPurpose.valid) throw new RefusalError('delegation_malformed', `revocation: ${entryPurpose.reason}`);
      const entrySize = acceptEntrySize(entry.statusSize);
      if (!entrySize.valid) throw new RefusalError('delegation_malformed', `revocation: ${entrySize.reason}`);
      const { statusListCredential } = entry;
      const { statusListIssuers } = deps;
      const heldTo = deps.verifyStatusList ? boundContext(context ?? carriedContext(entry)) : undefined;
      const expectation = heldTo
        ? statusListExpectationFor({ statusListCredential, statusPurpose: wantedPurpose }, heldTo, statusListIssuers)
        : undefined;
      // A hop the operator named, bound by statusListIssuers or a verified pinned root's own list, is read on any host.
      const operatorNamed = operatorNamedHops(statusListCredential, context ?? carriedContext(entry), statusListIssuers);
      const credential = await fetchStatusList(statusListCredential, deps.fetch, operatorNamed);
      const verdict =
        expectation === undefined
          ? acceptStatusPurpose(credential, wantedPurpose)
          : acceptStatusList(credential, expectation);
      if (!verdict.valid) {
        const refused = heldTo && expectation && { list: credential, statusListCredential, context: heldTo, statusListIssuers, keeper: expectation.keeper };
        throw new RefusalError(
          'status_signer_untrusted',
          `revocation: ${refused ? withStatusListIssuersRemedy(verdict.reason, refused, CHECKER_REASON_LENGTH) : verdict.reason}`,
        );
      }
      if (deps.verifyStatusList && (await codedVariantOf(deps.verifyStatusList)(credential)) !== true) {
        throw new RefusalError('status_signer_untrusted', 'revocation: status-list proof rejected');
      }
      // A list outside the window it states says nothing of now, whatever its bits say.
      assertStatusListValidity(credential, clock(), skewMs);
      const bits = await decodeStatusList(credential, decompress);
      const revoked = readStatusBit(bits, parseStatusListIndex(entry.statusListIndex));
      return revoked ? { revoked, fresh: true, ...coded('delegation_revoked') } : { revoked, fresh: true };
    } catch (error) {
      // A step that refuses throws its code, an entry that is not an object included; a read or a
      // decoder that failed in its own words left the status unread.
      return failedClosed(refusalCodeOf(error, 'status_unavailable'), failureReason(error, isRecord(entry) ? entry.statusListCredential : undefined));
    }
  };
  // The list read and its proof check share one deadline, and a miss fails closed as a throw does.
  return (entry, context) =>
    answerWithinDeadline('the status list read', () => read(entry, context), timeoutMs).catch(() =>
      failedClosed('deadline_exceeded'),
    );
}

/**
 * Why the checker failed closed, from what a step threw: where the words of what it threw may reach
 * whoever presented the entry (`utils/thrown-words.ts`), as a step's own refusal, SafeFetch's
 * refusal of the URL before any request, or a deadline, may, its message without the `revocation: `
 * this module opens its own with, at most {@link CHECKER_REASON_LENGTH} UTF-16 code units and free
 * of control characters; otherwise only that the list at `url` could not be read or checked, with
 * what was thrown logged, since a fetch, a decompressor or a proof verifier the host injected, or
 * the network, may have written it.
 */
function failureReason(error: unknown, url: unknown): string {
  return thrownReason(error, { withheld: unreadStatusList(url), tag: '[revocation]', maxLength: CHECKER_REASON_LENGTH }).replace(/^revocation: /, '');
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
    throw new RefusalError(
      'configuration_error',
      'revocation: no credential issuer named to hold the status list to: a resolver or checker that ' +
        'wraps a library checker must pass its second argument on, or else the very entry it was given',
    );
  }
  return { ...context, credentialIssuer };
}

/**
 * GET the status-list credential through SafeFetch (throws on non-2xx / non-object body), each hop
 * `operatorNamed` names read as one the operator named (`SafeFetchInit.operatorNamed`).
 */
async function fetchStatusList(
  url: string,
  fetch: SafeFetch,
  operatorNamed: ((hop: string) => boolean) | undefined,
): Promise<Record<string, unknown>> {
  const res = await (operatorNamed === undefined ? fetch(url) : fetch(url, { operatorNamed }));
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
