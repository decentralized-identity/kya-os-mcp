/**
 * KYA-OS Entity Card — DELEGATION (W3C VC 2.0 + ZCAP-LD profile, CRISP attenuation).
 *
 * A DelegationCredential is a W3C VC 2.0 whose `credentialSubject` IS an attenuated ZCAP-LD
 * capability (`@context` carries `w3id.org/security/zcap/v1` + the KYA-OS delegation namespace).
 * One credential per HOP; a delegation CHAIN runs `root → … → leaf`. We PROFILE, not fork.
 *
 * CRISP attenuation is enforced structurally on resolve and is FAIL-CLOSED — any broadening hop
 * invalidates the whole chain: child `allowedAction` ⊆ parent; caveats monotone-narrowing (child
 * `MaxAmount`/`ValidUntil` ≤ parent, no parent caveat silently dropped, unknown caveats replicated
 * verbatim); top-level `validUntil` narrowing; CONTINUITY (the parent's delegate `invoker` MUST be
 * the child's `issuer` — you only re-delegate what was delegated to YOUR key — and
 * `child.parentCapability` references the parent `id`); a constant `invocationTarget`; at most
 * `ctx.maxChainLength` credentials, when the caller sets one; ROOT `parentCapability` = the resource,
 * `issuer`/`invocationTarget` = (optional) resource owner / resource. THE JOIN (recomputed, asserted nowhere):
 * {@link responsiblePartyOf} = `issuer(rootVC)`, {@link leafInvokerOf} = the leaf delegate a verifier
 * asserts equals `proof.did`. Revocation reuses the injected {@link BitstringRevocationChecker} seam from
 * `./revocation` (no status-list churn reaches callers; NO `mcp-i-core` runtime dep). Per-hop
 * signature verification is injected into evaluateDelegationChain, after local checks and before status.
 */

import { z } from 'zod';
import { issuerOf } from '../utils/guards.js';
import { Did, statusEntrySizeShape, type BitstringStatusListEntry } from './schema.js';
import type { BitstringRevocationChecker, RevocationChainEntry } from './revocation.js';
import { checkerThrew, walkRevocationChain } from './revocation-chain.js';
import type { RefusalCode } from '../refusal-codes.js';
import type { RefusalCoding } from '../delegation/vc-verifier.types.js';
import { coded } from '../utils/refusal.js';
import { dependencyTimeout } from '../utils/deadline.js';
import { logger } from '../logging/index.js';
import type { DelegationProofVerifier } from './delegation-proof.js';
import { firstHopProofRefusal } from './hop-proofs.js';
import { hopWindowRules } from './hop-window.js';
import { parseDateTime } from '../utils/rfc3339.js';
import { withVerifiedRoot } from '../utils/verified-root.js';

export const DELEGATION_CONTEXT_V2 = 'https://www.w3.org/ns/credentials/v2'; // VC 2.0 base `@context`
export const ZCAP_CONTEXT = 'https://w3id.org/security/zcap/v1'; // ZCAP-LD capability context
export const KYA_OS_DELEGATION_CONTEXT = 'https://kya-os.org/ns/delegation/v1'; // KYA-OS ns
export const DELEGATION_CREDENTIAL_TYPE = 'DelegationCredential'; // 2nd `type` after VerifiableCredential
export const MAX_DELEGATION_DEPTH = 10; // a suggested `maxChainLength`; applied only when a caller passes it

/** A monotone-narrowing constraint: `{type:'ValidUntil',date}` or `{type:'MaxAmount',limit,currency}`.
 *  The flat shape keeps typing clean; unknown caveat types are compared verbatim (fail-closed). */
export const CaveatSchema = z
  .object({
    type: z.string().min(1),
    date: z.string().optional(),
    limit: z.string().optional(),
    currency: z.string().optional(),
  })
  .passthrough();

/** The attenuated ZCAP capability carried as the VC `credentialSubject`. */
export const ZcapCapabilitySchema = z
  .object({
    id: z.string().min(1),
    controller: Did.optional(),
    invoker: Did.optional(),
    parentCapability: z.string().min(1),
    invocationTarget: z.string().min(1),
    allowedAction: z.array(z.string().min(1)),
    caveats: z.array(CaveatSchema).optional(),
  })
  .passthrough()
  .refine((s) => Boolean(s.controller ?? s.invoker), {
    message: 'ZCAP capability MUST name a controller or invoker (the delegate)',
  });

/** W3C Bitstring Status List v1.0 `credentialStatus` entry (the StatusList2021 successor). */
export const DelegationCredentialStatusSchema = z.object({
  id: z.string().optional(),
  type: z.literal('BitstringStatusListEntry'),
  statusPurpose: z.string().optional(),
  statusListIndex: z.string().min(1),
  statusListCredential: z.string().min(1),
  ...statusEntrySizeShape,
});

/** Data Integrity proof, `eddsa-jcs-2022` cryptosuite (verified by a separate injected seam). */
export const DataIntegrityProofSchema = z
  .object({ type: z.literal('DataIntegrityProof'), cryptosuite: z.literal('eddsa-jcs-2022') })
  .passthrough();
const IssuerSchema = z.union([Did, z.object({ id: Did }).passthrough()]);

/**
 * VC `type`: MUST name both `VerifiableCredential` and `DelegationCredential`. Without the second,
 * any VC whose subject happens to look like a ZCAP (a capability attestation, say) would be read as
 * a delegation hop — type confusion.
 */
const DelegationCredentialTypeSchema = z
  .array(z.string())
  .min(2)
  .refine((types) => types.includes('VerifiableCredential') && types.includes(DELEGATION_CREDENTIAL_TYPE), {
    message: `type MUST include "VerifiableCredential" and "${DELEGATION_CREDENTIAL_TYPE}"`,
  });

export const DelegationCredentialSchema = z
  .object({
    // >= 2 to match the published JSON Schema (VC 2.0 base + the ZCAP/KYA-OS delegation contexts).
    '@context': z.array(z.union([z.string(), z.record(z.string(), z.unknown())])).min(2),
    id: z.string().optional(),
    type: DelegationCredentialTypeSchema,
    issuer: IssuerSchema,
    validFrom: z.string().optional(),
    validUntil: z.string().optional(),
    credentialSubject: ZcapCapabilitySchema,
    credentialStatus: DelegationCredentialStatusSchema.optional(),
    proof: DataIntegrityProofSchema.optional(),
  })
  .passthrough();

export type Caveat = z.infer<typeof CaveatSchema>;
export type ZcapCapability = z.infer<typeof ZcapCapabilitySchema>;
export type DelegationCredentialStatus = z.infer<typeof DelegationCredentialStatusSchema>;
export type DelegationCredential = z.infer<typeof DelegationCredentialSchema>;
export type DelegationChain = readonly DelegationCredential[];

/**
 * The issuer (delegator) DID, whether `issuer` is a bare string or an `{id}` object, read as
 * {@link issuerOf} reads any `issuer` member. The schema admits only those two forms, each naming a
 * DID, so a `DelegationCredential` always names one.
 */
export function issuerDid(vc: DelegationCredential): string {
  return issuerOf(vc.issuer) as string;
}
/** The delegate DID granted this capability (`invoker`, falling back to `controller`). */
export function invokerDid(vc: DelegationCredential): string | undefined {
  return vc.credentialSubject.invoker ?? vc.credentialSubject.controller;
}
/** `responsibleParty` = the issuer of the ROOT VC (ultimately accountable). */
export function responsiblePartyOf(chain: DelegationChain): string | undefined {
  const root = chain[0];
  return root ? issuerDid(root) : undefined;
}
/** The LEAF invoker — a verifier asserts this equals `proof.did`. */
export function leafInvokerOf(chain: DelegationChain): string | undefined {
  const leaf = chain[chain.length - 1];
  return leaf ? invokerDid(leaf) : undefined;
}
/**
 * Project a hop's `credentialStatus` onto the revocation-seam entry shape (if present), with the
 * `statusSize` it states, so that a checker refuses an entry it cannot read from one bit.
 */
export function statusEntryOf(vc: DelegationCredential): BitstringStatusListEntry | undefined {
  const status = vc.credentialStatus;
  if (!status) return undefined;
  return {
    statusListCredential: status.statusListCredential,
    statusListIndex: status.statusListIndex,
    ...(status.statusSize === undefined ? {} : { statusSize: status.statusSize }),
  };
}
/**
 * Every hop's status entry, root to leaf, for {@link evaluateRevocationChain}, with the
 * `statusPurpose` the hop states, so a checker of another purpose refuses it rather than reading it,
 * and the hop's position in the chain, the root being 0, which a refusal names it by.
 * Each is paired with the hop's issuer DID, read as {@link issuerOf} reads an `issuer` member, and,
 * when `trustedRootIssuer` is the chain's own root issuer, with that root and the status-list URL
 * the root hop's own `credentialStatus` names, when it has one: pass it only for a root the verifier
 * pins (`trustedRootIssuers` or `resourceOwner`). The root's list then speaks for a hop whose entry
 * names that same URL, and the checker holds every other hop's list to the hop's issuer, or to the
 * issuer its configuration binds the URL to. The URL is read from the chain as presented, so it is
 * the root's word only once the root hop's proof has verified, which every caller in this package
 * requires before it accepts a chain. A hop whose `issuer` names no DID is paired with no issuer, so
 * a checker that holds lists to an issuer refuses the hop. Hops without a `credentialStatus` are
 * skipped.
 */
export function revocationEntriesOf(chain: DelegationChain, trustedRootIssuer?: string): RevocationChainEntry[] {
  const root = issuerOf(chain[0]?.issuer);
  const rootList = chain[0] === undefined ? undefined : statusEntryOf(chain[0])?.statusListCredential;
  const pinned =
    trustedRootIssuer !== undefined && trustedRootIssuer === root
      ? { trustedRootIssuer, ...(rootList === undefined ? {} : { trustedRootStatusList: rootList }) }
      : {};
  return chain.flatMap((vc, position) => {
    const entry = statusEntryOf(vc);
    if (entry === undefined) return [];
    const statusPurpose = vc.credentialStatus?.statusPurpose;
    const stated = statusPurpose === undefined ? entry : { ...entry, statusPurpose };
    return [{ entry: stated, credentialIssuer: issuerOf(vc.issuer), position, ...pinned }];
  });
}

/** A non-negative decimal split into its digit strings, or `undefined` when it is not one. */
function decimalParts(dec: string): { whole: string; fraction: string } | undefined {
  const match = /^(\d+)(?:\.(\d+))?$/.exec(dec.trim());
  return match?.[1] ? { whole: match[1], fraction: match[2] ?? '' } : undefined;
}

// `child ≤ parent`, compared EXACTLY, fail-closed (any unparseable value ⇒ false). Both sides are
// scaled to the longer fraction, never truncated: rounding to a fixed precision would let a child
// whose excess sits below that precision (100.0000009 under a parent of 100) pass as a narrowing.
function decimalLte(child: string, parent: string): boolean {
  const c = decimalParts(child);
  const p = decimalParts(parent);
  if (!c || !p) return false;
  const scale = Math.max(c.fraction.length, p.fraction.length);
  const scaled = ({ whole, fraction }: { whole: string; fraction: string }): bigint =>
    BigInt(whole + fraction.padEnd(scale, '0'));
  return scaled(c) <= scaled(p);
}
// `child ≤ parent`, each read as an RFC 3339 date-time with its zone, fail-closed (any other value ⇒ false).
function dateLte(child: string, parent: string): boolean {
  const c = parseDateTime(child);
  const p = parseDateTime(parent);
  return c !== undefined && p !== undefined && c <= p;
}

// Stable structural equality (sorted-key JSON) for verbatim unknown-caveat comparison.
function deepEqual(a: unknown, b: unknown): boolean {
  return JSON.stringify(sortKeys(a)) === JSON.stringify(sortKeys(b));
}
function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return Object.fromEntries(Object.keys(record).sort().map((k) => [k, sortKeys(record[k])]));
  }
  return value;
}

/** True iff `child` is at least as narrow as `parent` for the same caveat. */
function caveatNarrows(parent: Caveat, child: Caveat): boolean {
  if (parent.type !== child.type) return false;
  if (parent.type === 'ValidUntil') {
    return typeof parent.date === 'string' && typeof child.date === 'string' && dateLte(child.date, parent.date);
  }
  if (parent.type === 'MaxAmount') {
    // Currency is monotone, not strict-equal: a currency-LESS parent (any currency, per the optional
    // schema) may be narrowed by a child that pins one; a parent that already pins a currency requires
    // the SAME one (dropping/switching it broadens). Never fail-open — the amount must still narrow.
    const currencyNarrows = parent.currency === undefined || parent.currency === child.currency;
    return (
      currencyNarrows &&
      typeof parent.limit === 'string' &&
      typeof child.limit === 'string' &&
      decimalLte(child.limit, parent.limit)
    );
  }
  return deepEqual(parent, child); // unknown caveat type — must be replicated verbatim
}
function actionReasons(parent: readonly string[], child: readonly string[]): string[] {
  const parentSet = new Set(parent);
  const escalated = child.filter((action) => !parentSet.has(action));
  return escalated.length === 0 ? [] : [`allowedAction escalation: [${escalated.join(', ')}] ⊄ parent`];
}
function caveatReasons(parent: readonly Caveat[], child: readonly Caveat[]): string[] {
  return parent
    .filter((pc) => !child.some((cc) => caveatNarrows(pc, cc)))
    .map((pc) => `caveat "${pc.type}" broadened or dropped by child (monotone-narrowing violated)`);
}

/** Reasons the `child` FAILS to attenuate its `parent` (empty ⇒ valid hop): action subset, caveat
 *  monotonicity, `validUntil` narrowing, invoker→issuer continuity, `parentCapability` linkage,
 *  constant `invocationTarget`. */
export function attenuates(parent: DelegationCredential, child: DelegationCredential): string[] {
  const p = parent.credentialSubject;
  const c = child.credentialSubject;
  const reasons: string[] = [
    ...actionReasons(p.allowedAction, c.allowedAction),
    ...caveatReasons(p.caveats ?? [], c.caveats ?? []),
  ];
  if (parent.validUntil !== undefined && (child.validUntil === undefined || !dateLte(child.validUntil, parent.validUntil))) {
    reasons.push('validUntil broadened: child must expire no later than its parent');
  }
  const delegate = invokerDid(parent);
  if (delegate === undefined || delegate !== issuerDid(child)) {
    reasons.push('broken continuity: parent invoker ≠ child issuer (only the delegate may re-delegate)');
  }
  if (c.parentCapability !== p.id) {
    reasons.push('broken continuity: child.parentCapability ≠ parent capability id');
  }
  if (c.invocationTarget !== p.invocationTarget) {
    reasons.push('invocationTarget drift: the resource must be constant along the chain');
  }
  return reasons;
}

/**
 * Local chain policy and the injected proof verifier for {@link evaluateDelegationChain}.
 * Local validation runs first, then every hop proof, then status, each walk root to leaf.
 * {@link validateDelegationChain} uses only the local policy and performs no I/O.
 */
export interface DelegationChainContext {
  resourceOwner?: string; // asserted issuer of the ROOT VC (accountable resource owner)
  resource?: string; // asserted `invocationTarget` of the ROOT VC (the delegated resource)
  /**
   * Local cost limit: the most credentials to accept in one chain, root to leaf inclusive. Each hop
   * may cost a signature check and a status-list fetch. It bounds the verifier's own work, not how far
   * authority may be delegated. Unset accepts any length; a value that is not a positive integer
   * rejects every chain. {@link MAX_DELEGATION_DEPTH} is a suggested value. The base profile's
   * `validateDelegationChain` (`@kya-os/mcp/delegation`) takes the same option and counts the same way.
   */
  maxChainLength?: number;
  /** @deprecated Use `maxChainLength`, which takes precedence when both are set. */
  maxDepth?: number;
  /** Injectable clock (epoch ms) for the wall-clock expiry gate; default `Date.now` (deterministic tests inject it). */
  now?: () => number;
  /**
   * The clock tolerance, in milliseconds, each hop's `validFrom`, `validUntil` and `ValidUntil`
   * caveat is held with, as a status list's window is: a number from 0 to 600,000. Default 120,000,
   * the proof verifier's default skew. Any other value rejects every chain as `configuration_error`.
   */
  maxClockSkewMs?: number;
  /**
   * Check each hop's proof before any status read, e.g. `createDelegationProofVerifier({ didResolver })`.
   * A false answer or throw refuses the chain without reading status. Omission preserves the legacy
   * status-only evaluation with one process-wide warning; required in the next major version.
   */
  verifyHopProof?: DelegationProofVerifier;
  /**
   * How long, in milliseconds, `evaluateDelegationChain` waits for each hop proof and each answer of
   * its revocation checker: a number greater than 0 and at most
   * 2,147,483,647. Default 5,000. Any other value makes it reject with a `TypeError`.
   */
  dependencyTimeoutMs?: number;
}

/** A rule a chain breaks: why, and the code of that rule. */
interface BrokenRule {
  code: RefusalCode;
  reason: string;
}

/** The rules `reasons` name broken, each with `code`. */
const brokenAs = (code: RefusalCode, reasons: readonly string[]): BrokenRule[] => reasons.map((reason) => ({ code, reason }));

/**
 * What {@link validateDelegationChain} finds. A refused chain carries, beside its `reasons`, the
 * `code` of the first rule it breaks and whether that code is `transient`; a chain that passes
 * carries neither.
 */
export interface DelegationChainResult extends RefusalCoding {
  ok: boolean; // true iff the chain attenuates correctly at every hop (fail-closed)
  reasons: string[]; // fail-closed reasons (empty ⇒ ok)
  responsibleParty?: string; // recomputed `issuer(rootVC)` — the accountable party
  leafInvoker?: string; // recomputed leaf delegate — asserted `=== proof.did` by a verifier
  invocationTarget?: string; // the resource authorized (constant along the chain)
  allowedAction: string[]; // the effective (leaf) `allowedAction` set
  depth: number; // number of credentials, root to leaf
}

function rootReasons(root: DelegationCredential, ctx: DelegationChainContext): BrokenRule[] {
  const subject = root.credentialSubject;
  const broken: BrokenRule[] = [];
  if (subject.parentCapability !== subject.invocationTarget) {
    broken.push({ code: 'chain_invalid', reason: 'root delegation: parentCapability MUST equal invocationTarget (the resource)' });
  }
  if (ctx.resource !== undefined && subject.invocationTarget !== ctx.resource) {
    broken.push({ code: 'chain_invalid', reason: 'root invocationTarget ≠ the expected resource' });
  }
  if (ctx.resourceOwner !== undefined && issuerDid(root) !== ctx.resourceOwner) {
    broken.push({ code: 'untrusted_root', reason: 'root issuer ≠ the resource owner (responsibleParty mismatch)' });
  }
  return broken;
}

/**
 * Structurally validate a chain (CRISP + continuity), fail-closed. Signature + revocation
 * are separate injected concerns (see {@link evaluateDelegationChain}). A refused chain gives every
 * reason it breaks a rule, and the code of the first: `chain_invalid` for an empty chain, one longer
 * than `maxChainLength`, a root that does not name the resource and a hop that does not attenuate
 * its parent; `configuration_error` for a `maxChainLength` that is not a positive integer;
 * `untrusted_root` for a root not issued by `resourceOwner`; and `delegation_expired`,
 * `delegation_not_yet_valid` or `delegation_malformed` for a hop outside its validity window, held
 * with `maxClockSkewMs`, or one whose time is not an RFC 3339 date-time with its zone
 * (`./hop-window.ts`); `configuration_error` too for a `maxClockSkewMs` it cannot use.
 */
export function validateDelegationChain(
  chain: DelegationChain,
  ctx: DelegationChainContext = {},
): DelegationChainResult {
  const depth = chain.length;
  const maxChainLength = ctx.maxChainLength ?? ctx.maxDepth;
  if (depth === 0) {
    return { ok: false, reasons: ['empty delegation chain'], allowedAction: [], depth, ...coded('chain_invalid') };
  }
  const root = chain[0]!;
  const leaf = chain[depth - 1]!;
  const broken: BrokenRule[] = [];
  if (maxChainLength !== undefined) {
    if (!Number.isInteger(maxChainLength) || maxChainLength < 1) {
      broken.push({ code: 'configuration_error', reason: `maxChainLength must be a positive integer (got ${String(maxChainLength)})` });
    } else if (depth > maxChainLength) {
      broken.push({ code: 'chain_invalid', reason: `delegation chain depth ${depth} exceeds the maximum of ${maxChainLength}` });
    }
  }
  broken.push(...rootReasons(root, ctx));
  for (let i = 1; i < depth; i += 1) {
    broken.push(...brokenAs('chain_invalid', attenuates(chain[i - 1]!, chain[i]!)));
  }
  // Wall-clock gate: a chain can attenuate perfectly and still be fully EXPIRED. Default to real
  // time so the gate is never silently skipped; deterministic callers inject `ctx.now`.
  broken.push(...hopWindowRules(chain, (ctx.now ?? Date.now)(), ctx.maxClockSkewMs));
  const first = broken[0];
  return {
    ok: first === undefined,
    reasons: broken.map((rule) => rule.reason),
    ...(first === undefined ? {} : coded(first.code)),
    responsibleParty: responsiblePartyOf(chain),
    leafInvoker: leafInvokerOf(chain),
    invocationTarget: leaf.credentialSubject.invocationTarget,
    allowedAction: leaf.credentialSubject.allowedAction,
    depth,
  };
}

export interface DelegationChainEvaluation extends DelegationChainResult {
  fresh: boolean; // true iff every hop's status was read from a LIVE list (drives the L2/L3 gate)
}

/**
 * Validate local chain rules, then every hop's proof, then status, fail-closed.
 * After {@link validateDelegationChain} passes, `ctx.verifyHopProof` verifies the received hops
 * sequentially, root to leaf. The first proof refusal returns its code and `hop N: ...` reason,
 * with `fresh: false`, without calling the status checker or verifying later hops.
 * Only after every proof holds does the sequential revocation walk name each hop's issuer and,
 * when `ctx.resourceOwner` pins it, the root issuer and the root hop's own status-list URL.
 * The first revoked or unreadable hop stops that walk, carrying its refusal code, and so does a
 * checker that throws or rejects: `status_unavailable`, or the code of a `RefusalError` it throws.
 * Each proof and status answer gets `ctx.dependencyTimeoutMs` (5,000 ms by default).
 * Without `verifyHopProof`, legacy status-only evaluation continues with one process-wide warning;
 * issuers and status URLs are then only as authentic as the proofs the caller checks separately.
 * Pass `createDelegationProofVerifier({ didResolver })`; the next major version requires this option.
 */
export async function evaluateDelegationChain(
  chain: DelegationChain,
  check: BitstringRevocationChecker,
  ctx: DelegationChainContext = {},
): Promise<DelegationChainEvaluation> {
  const structural = validateDelegationChain(chain, ctx);
  if (!structural.ok) return { ...structural, fresh: false };
  const timeoutMs = dependencyTimeout(ctx.dependencyTimeoutMs);
  if (ctx.verifyHopProof !== undefined) {
    const refused = await firstHopProofRefusal(chain, ctx.verifyHopProof, timeoutMs);
    if (refused !== undefined) {
      return { ...structural, ok: false, ...coded(refused.code), reasons: [refused.reason], fresh: false };
    }
  } else {
    warnWithoutHopProofs();
  }
  // Once every hop proof has verified, the pinned root's own list URL is its word (utils/verified-root.ts).
  const entries = revocationEntriesOf(chain, ctx.resourceOwner);
  const revocation = await walkRevocationChain(
    ctx.verifyHopProof === undefined ? entries : withVerifiedRoot(entries),
    check,
    { dependencyTimeoutMs: timeoutMs },
  ).catch(checkerThrew);
  return {
    ...structural,
    ok: revocation.ok,
    reasons: [...structural.reasons, ...revocation.reasons],
    fresh: revocation.fresh,
    ...(revocation.ok ? {} : coded(revocation.code)),
  };
}

/** Where every copy of this package records the legacy evaluation warning for this process. */
const PROOFS_WARNED = Symbol.for('@kya-os/mcp/delegation-proofs-warned');

/** Warn once when a chain reaches status evaluation without the injected proof verifier. */
function warnWithoutHopProofs(): void {
  const registry = globalThis as { [PROOFS_WARNED]?: true };
  if (registry[PROOFS_WARNED]) return;
  registry[PROOFS_WARNED] = true;
  logger.warn(
    '[kya-os] evaluateDelegationChain reads status without checking hop proofs. ' +
      'Pass verifyHopProof: createDelegationProofVerifier({ didResolver }); required in the next major version.',
  );
}
