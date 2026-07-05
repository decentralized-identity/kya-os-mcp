import { describe, it, expect } from 'vitest';
import {
  DelegationCredentialSchema,
  validateDelegationChain,
  evaluateDelegationChain,
  attenuates,
  responsiblePartyOf,
  leafInvokerOf,
  statusEntryOf,
  DELEGATION_CONTEXT_V2,
  ZCAP_CONTEXT,
  KYA_OS_DELEGATION_CONTEXT,
  DELEGATION_CREDENTIAL_TYPE,
  MAX_DELEGATION_DEPTH,
  type DelegationCredential,
  type Caveat,
} from '../delegation.js';
import type { RevocationChecker } from '../revocation.js';

// ── Fixtures ──────────────────────────────────────────────────────────────────

const OWNER = 'did:web:api.example'; // resource owner === root issuer
const RESOURCE = 'did:web:api.example:payments'; // the invocationTarget (constant along the chain)
const AGENT_A = 'did:web:agent-a.example';
const AGENT_B = 'did:web:agent-b.example';
const ATTACKER = 'did:web:attacker.example';

const maxAmount = (limit: string, currency = 'USD'): Caveat => ({ type: 'MaxAmount', limit, currency });
const validUntilCaveat = (date: string): Caveat => ({ type: 'ValidUntil', date });

interface VcFields {
  issuer: string;
  id: string;
  invoker: string;
  parentCapability: string;
  allowedAction: string[];
  invocationTarget?: string;
  validUntil?: string;
  caveats?: Caveat[];
  statusIndex?: string;
  statusUrl?: string;
}

/** Build a schema-valid DelegationCredential (parsing also exercises the re-profiled zod schema). */
function vc(f: VcFields): DelegationCredential {
  return DelegationCredentialSchema.parse({
    '@context': [DELEGATION_CONTEXT_V2, ZCAP_CONTEXT, KYA_OS_DELEGATION_CONTEXT],
    id: `urn:uuid:${f.id}`,
    type: ['VerifiableCredential', DELEGATION_CREDENTIAL_TYPE],
    issuer: f.issuer,
    ...(f.validUntil ? { validUntil: f.validUntil } : {}),
    credentialSubject: {
      id: f.id,
      invoker: f.invoker,
      parentCapability: f.parentCapability,
      invocationTarget: f.invocationTarget ?? RESOURCE,
      allowedAction: f.allowedAction,
      caveats: f.caveats ?? [],
    },
    proof: { type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', proofValue: 'z0' },
    ...(f.statusIndex
      ? {
          credentialStatus: {
            type: 'BitstringStatusListEntry',
            statusPurpose: 'revocation',
            statusListIndex: f.statusIndex,
            statusListCredential: f.statusUrl ?? 'https://issuer.example/status/1',
          },
        }
      : {}),
  });
}

/** ROOT: resource owner → AGENT_A, parentCapability = the resource itself. */
function root(over: Partial<VcFields> = {}): DelegationCredential {
  return vc({
    issuer: OWNER,
    id: 'urn:zcap:root',
    invoker: AGENT_A,
    parentCapability: RESOURCE,
    allowedAction: ['payments.transfer', 'payments.read'],
    validUntil: '2027-01-01T00:00:00Z',
    caveats: [maxAmount('1000.00'), validUntilCaveat('2027-01-01T00:00:00Z')],
    ...over,
  });
}

/** Well-formed attenuating child: AGENT_A → AGENT_B, narrower action + tighter caveats. */
function child(over: Partial<VcFields> = {}): DelegationCredential {
  return vc({
    issuer: AGENT_A,
    id: 'urn:zcap:del1',
    invoker: AGENT_B,
    parentCapability: 'urn:zcap:root',
    allowedAction: ['payments.transfer'],
    validUntil: '2026-06-01T00:00:00Z',
    caveats: [maxAmount('500.00'), validUntilCaveat('2026-06-01T00:00:00Z')],
    ...over,
  });
}

// Pinned clock inside every fixture's validity window, so the wall-clock expiry gate is
// deterministic regardless of the real date (the fixtures' validUntil dates are fixed).
const NOW_MS = Date.parse('2026-01-01T00:00:00Z');
const ownerCtx = { resourceOwner: OWNER, resource: RESOURCE, now: () => NOW_MS };

// ── Happy path + the recomputed JOIN ──────────────────────────────────────────

describe('validateDelegationChain (CRISP attenuation, fail-closed)', () => {
  it('accepts a well-formed root→leaf chain and recomputes responsibleParty + leafInvoker', () => {
    const result = validateDelegationChain([root(), child()], ownerCtx);
    expect(result.ok).toBe(true);
    expect(result.reasons).toEqual([]);
    expect(result.responsibleParty).toBe(OWNER); // issuer(rootVC)
    expect(result.leafInvoker).toBe(AGENT_B); // asserted === proof.did by a verifier
    expect(result.invocationTarget).toBe(RESOURCE);
    expect(result.allowedAction).toEqual(['payments.transfer']);
    expect(result.depth).toBe(2);
  });

  it('accepts an identical-authority child (⊆ is reflexive; equal caveats narrow)', () => {
    const equalChild = child({ allowedAction: ['payments.transfer'], caveats: [maxAmount('1000.00')] });
    expect(validateDelegationChain([root({ caveats: [maxAmount('1000.00')] }), equalChild], { now: () => NOW_MS }).ok).toBe(true);
  });

  it('rejects an empty chain (fail-closed)', () => {
    const result = validateDelegationChain([]);
    expect(result.ok).toBe(false);
    expect(result.reasons[0]).toMatch(/empty/);
  });

  // ── The required over-broad child rejection ──
  it('REJECTS an over-broad child that escalates allowedAction ⊄ parent', () => {
    const rogue = child({ allowedAction: ['payments.transfer', 'admin.reset'] });
    const result = validateDelegationChain([root(), rogue], ownerCtx);
    expect(result.ok).toBe(false);
    expect(result.reasons.some((r) => /allowedAction escalation/.test(r))).toBe(true);
  });

  it('REJECTS an over-broad child MaxAmount caveat (500 → 2000 broadens the budget)', () => {
    const rogue = child({ caveats: [maxAmount('2000.00'), validUntilCaveat('2026-06-01T00:00:00Z')] });
    const result = validateDelegationChain([root(), rogue], ownerCtx);
    expect(result.ok).toBe(false);
    expect(result.reasons.some((r) => /caveat "MaxAmount"/.test(r))).toBe(true);
  });

  it('REJECTS a child that silently DROPS a parent caveat (monotone-narrowing)', () => {
    const rogue = child({ caveats: [maxAmount('500.00')] }); // drops the ValidUntil caveat
    const result = validateDelegationChain([root(), rogue], ownerCtx);
    expect(result.ok).toBe(false);
    expect(result.reasons.some((r) => /caveat "ValidUntil"/.test(r))).toBe(true);
  });

  it('REJECTS a child that DROPS a parent UNKNOWN caveat type (deepEqual verbatim path)', () => {
    // An unrecognized caveat must be replicated verbatim (fail-closed) — dropping it broadens.
    const custom = { type: 'CustomLimit', limit: '5' } as Caveat;
    const withCustom = root({ caveats: [custom] });
    const rogue = child({ caveats: [] }); // drops the unknown caveat entirely
    const result = validateDelegationChain([withCustom, rogue], { now: () => NOW_MS });
    expect(result.ok).toBe(false);
    expect(result.reasons.some((r) => /caveat "CustomLimit"/.test(r))).toBe(true);
  });

  it('REJECTS a child whose top-level validUntil outlives its parent', () => {
    const rogue = child({ validUntil: '2099-01-01T00:00:00Z' });
    const result = validateDelegationChain([root(), rogue], ownerCtx);
    expect(result.ok).toBe(false);
    expect(result.reasons.some((r) => /validUntil broadened/.test(r))).toBe(true);
  });

  // ── The required broken-continuity rejection ──
  it('REJECTS broken continuity: the child issuer is not the parent invoker', () => {
    const rogue = child({ issuer: ATTACKER }); // AGENT_A delegated to AGENT_B, not ATTACKER
    const result = validateDelegationChain([root(), rogue], ownerCtx);
    expect(result.ok).toBe(false);
    expect(result.reasons.some((r) => /parent invoker ≠ child issuer/.test(r))).toBe(true);
  });

  it('REJECTS a child whose parentCapability does not reference the parent id', () => {
    const rogue = child({ parentCapability: 'urn:zcap:forged' });
    const result = validateDelegationChain([root(), rogue], ownerCtx);
    expect(result.ok).toBe(false);
    expect(result.reasons.some((r) => /child\.parentCapability/.test(r))).toBe(true);
  });

  it('REJECTS invocationTarget drift (the resource must stay constant)', () => {
    const rogue = child({ invocationTarget: 'did:web:other.example:resource' });
    const result = validateDelegationChain([root(), rogue], ownerCtx);
    expect(result.ok).toBe(false);
    expect(result.reasons.some((r) => /invocationTarget drift/.test(r))).toBe(true);
  });
});

// ── Root anchoring ────────────────────────────────────────────────────────────

describe('root anchoring (issuer/invocationTarget = resource owner)', () => {
  it('REJECTS a root whose parentCapability is not the resource itself', () => {
    const result = validateDelegationChain([root({ parentCapability: 'urn:zcap:elsewhere' }), child()], ownerCtx);
    expect(result.ok).toBe(false);
    expect(result.reasons.some((r) => /root delegation: parentCapability/.test(r))).toBe(true);
  });

  it('REJECTS a root issued by someone other than the asserted resource owner', () => {
    const result = validateDelegationChain([root({ issuer: ATTACKER, parentCapability: RESOURCE }), child({ issuer: ATTACKER })], ownerCtx);
    expect(result.ok).toBe(false);
    expect(result.reasons.some((r) => /root issuer ≠ the resource owner/.test(r))).toBe(true);
  });

  it('REJECTS a root anchored on the wrong resource', () => {
    const result = validateDelegationChain([root()], { resource: 'did:web:api.example:other' });
    expect(result.ok).toBe(false);
    expect(result.reasons.some((r) => /root invocationTarget ≠/.test(r))).toBe(true);
  });
});

// ── Depth cap ─────────────────────────────────────────────────────────────────

describe('max delegation depth', () => {
  it(`REJECTS a chain deeper than ${MAX_DELEGATION_DEPTH} hops`, () => {
    const deep: DelegationCredential[] = [root()];
    let previous = 'urn:zcap:root';
    let issuer = AGENT_A;
    for (let i = 0; i < MAX_DELEGATION_DEPTH; i += 1) {
      const id = `urn:zcap:d${i}`;
      deep.push(child({ issuer, id, invoker: `did:web:h${i}.example`, parentCapability: previous }));
      previous = id;
      issuer = `did:web:h${i}.example`;
    }
    expect(deep.length).toBeGreaterThan(MAX_DELEGATION_DEPTH);
    const result = validateDelegationChain(deep, ownerCtx);
    expect(result.ok).toBe(false);
    expect(result.reasons.some((r) => /exceeds the maximum/.test(r))).toBe(true);
  });
});

// ── Single-hop attenuates() + helper accessors ────────────────────────────────

describe('DelegationCredentialSchema — @context arity (JSON Schema parity)', () => {
  it('rejects a @context with fewer than 2 entries (JSON Schema requires minItems: 2)', () => {
    const oneContext = {
      '@context': [DELEGATION_CONTEXT_V2],
      type: ['VerifiableCredential', DELEGATION_CREDENTIAL_TYPE],
      issuer: OWNER,
      credentialSubject: {
        id: 'urn:zcap:x', invoker: AGENT_A, parentCapability: RESOURCE,
        invocationTarget: RESOURCE, allowedAction: ['payments.transfer'], caveats: [],
      },
      proof: { type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', proofValue: 'z0' },
    };
    expect(() => DelegationCredentialSchema.parse(oneContext)).toThrow();
  });
});

describe('attenuates + accessors', () => {
  it('attenuates() returns [] for a valid hop and reasons for a bad one', () => {
    expect(attenuates(root(), child())).toEqual([]);
    expect(attenuates(root(), child({ allowedAction: ['admin.reset'] })).length).toBeGreaterThan(0);
  });

  it('MaxAmount: a currency-LESS parent is narrowed by a child that pins a currency (adds a constraint)', () => {
    const p = root({ caveats: [{ type: 'MaxAmount', limit: '1000.00' }] }); // any currency, ≤ 1000
    const c = child({ caveats: [maxAmount('500.00', 'USD')] }); // pins USD and tightens the amount
    expect(attenuates(p, c)).toEqual([]);
  });

  it('MaxAmount: a currency-BEARING parent rejects a child that drops the currency (broadens)', () => {
    const p = root({ caveats: [maxAmount('1000.00', 'USD')] }); // USD-only
    const c = child({ caveats: [{ type: 'MaxAmount', limit: '500.00' }] }); // any currency — broader
    expect(attenuates(p, c).some((r) => /caveat "MaxAmount"/.test(r))).toBe(true);
  });

  it('responsiblePartyOf / leafInvokerOf are undefined for an empty chain', () => {
    expect(responsiblePartyOf([])).toBeUndefined();
    expect(leafInvokerOf([])).toBeUndefined();
  });

  it('statusEntryOf projects credentialStatus onto the revocation-seam shape', () => {
    expect(statusEntryOf(child())).toBeUndefined();
    expect(statusEntryOf(child({ statusIndex: '7' }))).toEqual({
      statusListCredential: 'https://issuer.example/status/1',
      statusListIndex: '7',
    });
  });
});

// ── evaluateDelegationChain: structure + revocation cascade ────────────────────

describe('evaluateDelegationChain (structure + revocation, fail-closed)', () => {
  const allClear: RevocationChecker = async () => ({ revoked: false, fresh: true });

  it('is ok + fresh when the chain attenuates and no hop is revoked', async () => {
    const chain = [root({ statusIndex: '0' }), child({ statusIndex: '1' })];
    const result = await evaluateDelegationChain(chain, allClear, ownerCtx);
    expect(result.ok).toBe(true);
    expect(result.fresh).toBe(true);
    expect(result.responsibleParty).toBe(OWNER);
  });

  it('FAILS the chain when a hop is revoked (cascading, fail-closed)', async () => {
    const revoked: RevocationChecker = async (entry) =>
      entry.statusListIndex === '1' ? { revoked: true, fresh: true } : { revoked: false, fresh: true };
    const chain = [root({ statusIndex: '0' }), child({ statusIndex: '1' })];
    const result = await evaluateDelegationChain(chain, revoked, ownerCtx);
    expect(result.ok).toBe(false);
    expect(result.reasons.some((r) => /revocation/.test(r))).toBe(true);
  });

  it('SHORT-CIRCUITS revocation when the structure is already invalid (never checks status)', async () => {
    let calls = 0;
    const counting: RevocationChecker = async () => {
      calls += 1;
      return { revoked: false, fresh: true };
    };
    const chain = [root({ statusIndex: '0' }), child({ issuer: ATTACKER, statusIndex: '1' })];
    const result = await evaluateDelegationChain(chain, counting, ownerCtx);
    expect(result.ok).toBe(false);
    expect(result.fresh).toBe(false);
    expect(calls).toBe(0); // fail-closed: a broken chain is never even revocation-checked
  });
});
