/**
 * The `entity-card` vectors that turn on one hop of the accountable agent's delegation chain
 * (SPEC.md §6.10; suite 1.13.0 or later).
 *
 * Two hold a hop to an end it states beside its `validUntil`: its `expirationDate`, and its
 * proof's `expires`. The rest hold a hop to its commitment to its parent,
 * `credentialSubject.parentCredentialDigest`, the SPEC §7.8 digest of the parent credential.
 * Their hops are signed with `signDelegationCredential` under the FIXED {@link OWNER_KEY} and
 * {@link AGENT_A_KEY}, so the root carries a real `eddsa-jcs-2022` `proofValue`, 89 characters of
 * multibase base58btc, which SPEC §7.8 reads as base64 characters, six bits each. Ed25519 signs
 * deterministically, so these vectors are byte-identical on every run.
 */

import {
  ed25519SignerFromJwk,
  signDelegationCredential,
  type DelegationCredential,
  type UnsignedDelegationCredential,
} from '../src/card/index.js';
import { signEddsaJcs2022 } from '../src/card/data-integrity.js';
import { parentCredentialDigestOf } from '../src/card/parent-digest.js';
import { AGENT_A, AGENT_A_KEY, DELEGATION_CHAIN, OWNER, OWNER_KEY } from './card-fixtures.js';
import type { ConformanceVector, EntityCardAccountabilityInput } from './types.js';

/** When every signed hop's proof was created: before the suite's fixed clock, inside each hop's window. */
const SIGNED_AT = '2026-06-01T00:00:00Z';

/** An end the suite's fixed clock (2026-06-30T12:00:00Z) is 12 hours past, far beyond its tolerance. */
const PAST_END = '2026-06-30T00:00:00Z';

/** The golden chain's two hops as their issuers write them, before signing. */
function unsignedHops(): [UnsignedDelegationCredential, UnsignedDelegationCredential] {
  const [root, leaf] = DELEGATION_CHAIN.map((hop) => {
    const unsigned: Partial<DelegationCredential> = { ...(hop as DelegationCredential) };
    delete unsigned.proof;
    return unsigned as UnsignedDelegationCredential;
  });
  return [root!, leaf!];
}

/** The golden chain with `leaf` in place of its leaf. */
function withLeaf(leaf: unknown): unknown[] {
  return [DELEGATION_CHAIN[0], leaf];
}

/**
 * The hop vectors for the accountable agent `card`, each held to `accountability` with the chain
 * it turns on in place of the golden one.
 */
export async function cardChainVectors(
  card: unknown,
  accountability: EntityCardAccountabilityInput,
): Promise<ConformanceVector[]> {
  const goldenLeaf = DELEGATION_CHAIN[1] as DelegationCredential;
  const owner = await ed25519SignerFromJwk({ did: OWNER, kid: `${OWNER}#key-1`, privateJwk: OWNER_KEY });
  const agentA = await ed25519SignerFromJwk({ did: AGENT_A, kid: `${AGENT_A}#key-1`, privateJwk: AGENT_A_KEY });
  const [unsignedRoot, unsignedLeaf] = unsignedHops();
  const signing = { created: SIGNED_AT };

  const root = await signDelegationCredential(unsignedRoot, owner, signing);
  const rootProofValue = String(root.proof?.proofValue);
  if (rootProofValue.length !== 89) throw new Error('expected an 89-character multibase root proofValue');
  const rootDigest = await parentCredentialDigestOf(root);
  const committedLeaf = await signDelegationCredential(unsignedLeaf, agentA, { ...signing, parent: root });
  const uncommittedLeaf = await signDelegationCredential(unsignedLeaf, agentA, signing);
  // The root issued again under the same id, after the first was revoked: a new status entry,
  // and a higher limit the leaf still narrows. Every id and parent link of the chain is unchanged.
  const reissuedRoot = await signDelegationCredential({
    ...unsignedRoot,
    credentialSubject: {
      ...unsignedRoot.credentialSubject,
      caveats: [
        { type: 'MaxAmount', limit: '2000.00', currency: 'USD' },
        { type: 'ValidUntil', date: '2027-01-01T00:00:00Z' },
      ],
    },
    credentialStatus: { ...unsignedRoot.credentialStatus!, statusListIndex: '8' },
  }, owner, signing);
  const committedRoot = await signDelegationCredential({
    ...unsignedRoot,
    credentialSubject: { ...unsignedRoot.credentialSubject, parentCredentialDigest: rootDigest },
  }, owner, signing);
  // `null` is a value stated, not a member left out, so each of these hops states a digest that is
  // not its parent's, or, on the root, states one at all. `signDelegationCredential` signs no such
  // hop, so its issuer signs it as data.
  const signedStatingNull = (hop: UnsignedDelegationCredential, issuer: typeof owner) => signEddsaJcs2022(
    { ...hop, credentialSubject: { ...hop.credentialSubject, parentCredentialDigest: null } },
    issuer,
    { proofPurpose: 'assertionMethod', created: SIGNED_AT },
  );
  const nullRoot = await signedStatingNull(unsignedRoot, owner);
  const nullLeaf = await signedStatingNull(unsignedLeaf, agentA);

  const holding = (chain: unknown[]) => ({ card, accountability: { ...accountability, chain } });
  return [
    {
      id: 'entity-card/hop-expiration-date-past',
      category: 'entity-card',
      description: `The accountable agent's chain, its leaf stating expirationDate ${PAST_END} beside validUntil 2026-07-01T00:00:00Z`,
      expected: 'fail',
      reason: 'A hop ends at the earliest end it states, so one past its expirationDate is refused whatever its validUntil says (delegation_expired)',
      input: holding(withLeaf({ ...goldenLeaf, expirationDate: PAST_END })),
    },
    {
      id: 'entity-card/hop-proof-expired',
      category: 'entity-card',
      description: `The accountable agent's chain, its leaf's proof stating expires ${PAST_END} beside validUntil 2026-07-01T00:00:00Z`,
      expected: 'fail',
      reason: 'A proof past its expires no longer says its issuer delegated, so the hop is refused whatever its validUntil says (delegation_expired)',
      input: holding(withLeaf({ ...goldenLeaf, proof: { ...goldenLeaf.proof, expires: PAST_END } })),
    },
    {
      id: 'entity-card/hop-parent-digest',
      category: 'entity-card',
      description:
        `The accountable agent's chain signed, its leaf stating parentCredentialDigest ${rootDigest}, the digest of the root. ` +
        'The root proofValue is 89 characters of multibase base58btc, which the digest reads as base64 characters',
      expected: 'pass',
      reason:
        'A hop that states parentCredentialDigest commits to its parent, and this is the parent\'s SPEC §7.8 digest. An implementation that decodes the proofValue as base58 digests other bytes and refuses the chain',
      input: holding([root, committedLeaf]),
    },
    {
      id: 'entity-card/hop-parent-digest-reissued-root',
      category: 'entity-card',
      description:
        'The signed leaf stating the digest of the root it was delegated under, presented under another root its issuer signed under the same id after revoking the first',
      expected: 'fail',
      reason:
        'Every id and parent link matches, so only the digest tells the roots apart: a hop whose parentCredentialDigest is not the digest of the hop before it is refused (chain_invalid)',
      input: holding([reissuedRoot, committedLeaf]),
    },
    {
      id: 'entity-card/root-states-parent-digest',
      category: 'entity-card',
      description: 'The signed chain, its root stating a parentCredentialDigest',
      expected: 'fail',
      reason: 'The root has no parent credential, so it states no parentCredentialDigest (chain_invalid)',
      input: holding([committedRoot, uncommittedLeaf]),
    },
    {
      id: 'entity-card/root-states-parent-digest-null',
      category: 'entity-card',
      description: 'The signed chain, its root stating parentCredentialDigest as null',
      expected: 'fail',
      reason: 'A member stated as null is stated: the root has no parent credential, so it states no parentCredentialDigest, null included (chain_invalid)',
      input: holding([nullRoot, uncommittedLeaf]),
    },
    {
      id: 'entity-card/hop-parent-digest-null',
      category: 'entity-card',
      description: 'The signed chain, its leaf stating parentCredentialDigest as null',
      expected: 'fail',
      reason: 'A member stated as null is stated, and null is not the digest of the hop before it (chain_invalid). Only a hop that leaves the member out states none',
      input: holding([root, nullLeaf]),
    },
    {
      id: 'entity-card/hop-parent-digest-absent',
      category: 'entity-card',
      description: 'The signed chain, its leaf stating no parentCredentialDigest',
      expected: 'pass',
      reason: 'A hop that states no parentCredentialDigest is not held to one in 1.x (SPEC §6.10)',
      input: holding([root, uncommittedLeaf]),
    },
  ];
}
