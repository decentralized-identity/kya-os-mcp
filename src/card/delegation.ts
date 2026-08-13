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
 * `child.parentCapability` references the parent `id`); a constant `invocationTarget`; depth ≤
 * {@link MAX_DELEGATION_DEPTH}; ROOT `parentCapability` = the resource, `issuer`/`invocationTarget`
 * = (optional) resource owner / resource. THE JOIN (recomputed, asserted nowhere):
 * {@link responsiblePartyOf} = `issuer(rootVC)`, {@link leafInvokerOf} = the leaf delegate a verifier
 * asserts equals `proof.did`. Revocation reuses the injected {@link BitstringRevocationChecker} seam from
 * `./revocation` (no status-list churn reaches callers; NO `mcp-i-core` runtime dep). Per-hop
 * signature verification is a SEPARATE injected concern; this module owns the CRISP + continuity recompute.
 */

import { z } from 'zod';
import { Did, type BitstringStatusListEntry } from './schema.js';
import {
  evaluateRevocationChain,
  type BitstringRevocationChecker,
  type RevocationChainResult,
} from './revocation.js';

export const DELEGATION_CONTEXT_V2 = 'https://www.w3.org/ns/credentials/v2'; // VC 2.0 base `@context`
export const ZCAP_CONTEXT = 'https://w3id.org/security/zcap/v1'; // ZCAP-LD capability context
export const KYA_OS_DELEGATION_CONTEXT = 'https://kya-os.org/ns/delegation/v1'; // KYA-OS ns
export const DELEGATION_CREDENTIAL_TYPE = 'DelegationCredential'; // 2nd `type` after VerifiableCredential
export const MAX_DELEGATION_DEPTH = 10; // fail-closed beyond this

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
});

/** Data Integrity proof, `eddsa-jcs-2022` cryptosuite (verified by a separate injected seam). */
export const DataIntegrityProofSchema = z
  .object({ type: z.literal('DataIntegrityProof'), cryptosuite: z.literal('eddsa-jcs-2022') })
  .passthrough();
const IssuerSchema = z.union([Did, z.object({ id: Did }).passthrough()]);

export const DelegationCredentialSchema = z
  .object({
    // >= 2 to match the published JSON Schema (VC 2.0 base + the ZCAP/KYA-OS delegation contexts).
    '@context': z.array(z.union([z.string(), z.record(z.string(), z.unknown())])).min(2),
    id: z.string().optional(),
    type: z.array(z.string()),
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

/** The issuer (delegator) DID, whether `issuer` is a bare string or an `{id}` object. */
export function issuerDid(vc: DelegationCredential): string {
  return typeof vc.issuer === 'string' ? vc.issuer : vc.issuer.id;
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
/** Project a hop's `credentialStatus` onto the revocation-seam entry shape (if present). */
export function statusEntryOf(vc: DelegationCredential): BitstringStatusListEntry | undefined {
  const status = vc.credentialStatus;
  if (!status) return undefined;
  return { statusListCredential: status.statusListCredential, statusListIndex: status.statusListIndex };
}

function toScaled(dec: string): bigint | undefined {
  const match = /^(\d+)(?:\.(\d+))?$/.exec(dec.trim());
  if (!match?.[1]) return undefined;
  const frac = (match[2] ?? '').padEnd(6, '0').slice(0, 6);
  try {
    return BigInt(match[1]) * 1_000_000n + BigInt(frac);
  } catch {
    return undefined;
  }
}

// `child ≤ parent`, fail-closed (any unparseable value ⇒ false).
function decimalLte(child: string, parent: string): boolean {
  const c = toScaled(child);
  const p = toScaled(parent);
  return c !== undefined && p !== undefined && c <= p;
}
function dateLte(child: string, parent: string): boolean {
  const c = Date.parse(child);
  const p = Date.parse(parent);
  return !Number.isNaN(c) && !Number.isNaN(p) && c <= p;
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

export interface DelegationChainContext {
  resourceOwner?: string; // asserted issuer of the ROOT VC (accountable resource owner)
  resource?: string; // asserted `invocationTarget` of the ROOT VC (the delegated resource)
  maxDepth?: number; // override the fail-closed depth cap (default MAX_DELEGATION_DEPTH)
  /** Injectable clock (epoch ms) for the wall-clock expiry gate; default `Date.now` (deterministic tests inject it). */
  now?: () => number;
}

/**
 * Reasons any hop is temporally INVALID at `nowMs`: an expired top-level `validUntil` or `ValidUntil`
 * caveat, or a not-yet-valid `validFrom`. Fail-closed on a present-but-unparseable timestamp. Empty ⇒
 * every hop is inside its validity window. This is the wall-clock gate — CRISP narrowing only proves a
 * child expires no later than its parent, which a FULLY-expired-but-well-attenuated chain still satisfies.
 */
function expiryReasons(chain: DelegationChain, nowMs: number): string[] {
  const reasons: string[] = [];
  chain.forEach((vc, i) => {
    if (vc.validUntil !== undefined) {
      const t = Date.parse(vc.validUntil);
      if (Number.isNaN(t)) reasons.push(`hop ${i}: unparseable validUntil "${vc.validUntil}"`);
      else if (t < nowMs) reasons.push(`hop ${i}: expired (validUntil ${vc.validUntil} is in the past)`);
    }
    if (vc.validFrom !== undefined) {
      const t = Date.parse(vc.validFrom);
      if (Number.isNaN(t)) reasons.push(`hop ${i}: unparseable validFrom "${vc.validFrom}"`);
      else if (t > nowMs) reasons.push(`hop ${i}: not yet valid (validFrom ${vc.validFrom} is in the future)`);
    }
    for (const caveat of vc.credentialSubject.caveats ?? []) {
      if (caveat.type === 'ValidUntil' && typeof caveat.date === 'string') {
        const t = Date.parse(caveat.date);
        if (Number.isNaN(t)) reasons.push(`hop ${i}: unparseable ValidUntil caveat "${caveat.date}"`);
        else if (t < nowMs) reasons.push(`hop ${i}: expired caveat (ValidUntil ${caveat.date} is in the past)`);
      }
    }
  });
  return reasons;
}

export interface DelegationChainResult {
  ok: boolean; // true iff the chain attenuates correctly at every hop (fail-closed)
  reasons: string[]; // fail-closed reasons (empty ⇒ ok)
  responsibleParty?: string; // recomputed `issuer(rootVC)` — the accountable party
  leafInvoker?: string; // recomputed leaf delegate — asserted `=== proof.did` by a verifier
  invocationTarget?: string; // the resource authorized (constant along the chain)
  allowedAction: string[]; // the effective (leaf) `allowedAction` set
  depth: number; // number of hops
}

function rootReasons(root: DelegationCredential, ctx: DelegationChainContext): string[] {
  const subject = root.credentialSubject;
  const reasons: string[] = [];
  if (subject.parentCapability !== subject.invocationTarget) {
    reasons.push('root delegation: parentCapability MUST equal invocationTarget (the resource)');
  }
  if (ctx.resource !== undefined && subject.invocationTarget !== ctx.resource) {
    reasons.push('root invocationTarget ≠ the expected resource');
  }
  if (ctx.resourceOwner !== undefined && issuerDid(root) !== ctx.resourceOwner) {
    reasons.push('root issuer ≠ the resource owner (responsibleParty mismatch)');
  }
  return reasons;
}

/** Structurally validate a chain (CRISP + continuity), fail-closed. Signature + revocation
 *  are separate injected concerns (see {@link evaluateDelegationChain}). */
export function validateDelegationChain(
  chain: DelegationChain,
  ctx: DelegationChainContext = {},
): DelegationChainResult {
  const depth = chain.length;
  const maxDepth = ctx.maxDepth ?? MAX_DELEGATION_DEPTH;
  if (depth === 0) {
    return { ok: false, reasons: ['empty delegation chain'], allowedAction: [], depth };
  }
  const root = chain[0]!;
  const leaf = chain[depth - 1]!;
  const reasons: string[] = [];
  if (depth > maxDepth) reasons.push(`delegation chain depth ${depth} exceeds the maximum of ${maxDepth}`);
  reasons.push(...rootReasons(root, ctx));
  for (let i = 1; i < depth; i += 1) {
    reasons.push(...attenuates(chain[i - 1]!, chain[i]!));
  }
  // Wall-clock gate: a chain can attenuate perfectly and still be fully EXPIRED. Default to real
  // time so the gate is never silently skipped; deterministic callers inject `ctx.now`.
  reasons.push(...expiryReasons(chain, (ctx.now ?? Date.now)()));
  return {
    ok: reasons.length === 0,
    reasons,
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

/** Validate structure AND revocation: run {@link validateDelegationChain}, then (only if it passes —
 *  fail-closed) cascade the injected {@link BitstringRevocationChecker} root→leaf via
 *  {@link evaluateRevocationChain}. A revoked ancestor invalidates the subtree. */
export async function evaluateDelegationChain(
  chain: DelegationChain,
  check: BitstringRevocationChecker,
  ctx: DelegationChainContext = {},
): Promise<DelegationChainEvaluation> {
  const structural = validateDelegationChain(chain, ctx);
  if (!structural.ok) return { ...structural, fresh: false };
  const entries = chain
    .map(statusEntryOf)
    .filter((entry): entry is BitstringStatusListEntry => entry !== undefined);
  const revocation: RevocationChainResult = await evaluateRevocationChain(entries, check);
  return {
    ...structural,
    ok: structural.ok && revocation.ok,
    reasons: [...structural.reasons, ...revocation.reasons],
    fresh: revocation.fresh,
  };
}
