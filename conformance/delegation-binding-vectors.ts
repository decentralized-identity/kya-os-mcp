/**
 * The delegation-binding vectors (`signed-proof/delegation-*`, SPEC.md §7.8,
 * suite 1.5.0 or later): a proof names the credential a call presented by
 * `delegationRef`, and binds the chain the call was decided over by
 * `delegationChainDigest`. Each vector turns on one rule of §7.8, or on how
 * the proof that binds a chain is read (§7.4).
 */

import { BindingKit, type Mint } from './delegation-binding-kit.js';
import { chainVectors } from './delegation-binding-chain.js';
import { nestingVectors } from './delegation-binding-nesting.js';
import { readingVectors } from './delegation-binding-readings.js';
import { tamperedVectors } from './delegation-binding-tampered.js';
import type { ConformanceVector } from './types.js';

/** Every delegation-binding vector, minted with `mint`. */
export async function delegationBindingVectors<P extends { did: string }>(
  mint: Mint<P>,
): Promise<ConformanceVector[]> {
  const kit = await BindingKit.of(mint);
  const chain = await chainVectors(kit);
  const bound = chain.find((vector) => vector.id === 'signed-proof/delegation-chain-binding');
  if (bound === undefined) throw new Error('expected the chain-binding vector');
  return [
    ...chain,
    ...(await nestingVectors(kit)),
    ...(await readingVectors(kit)),
    ...(await tamperedVectors(kit, bound)),
  ];
}
