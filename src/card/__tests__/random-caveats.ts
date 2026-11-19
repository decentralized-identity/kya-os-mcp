/**
 * Random sets of caveats, and unsigned chains under them, for the property tests of the caveat
 * rules. The generator is seeded, so a failure is reproduced by its seed and run. The chain rules
 * read no proof, so the hops here are unsigned.
 */

import type { Caveat, DelegationChain, DelegationCredential } from '../delegation.js';
import { RESOURCE } from './signed-chain-helpers.js';

/** A seeded generator of numbers in [0, 1) (mulberry32). */
export function random(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** One of `values`, drawn with `next`. */
export const pick = <T>(next: () => number, values: readonly T[]): T => values[Math.floor(next() * values.length)]!;

/** Dates after the tests' `NOW_MS`, one of them written with another offset. */
export const DATES = ['2026-12-01T00:00:00Z', '2026-12-01T01:00:00+01:00', '2026-12-15T00:00:00Z', '2027-01-01T00:00:00Z'];
export const LIMITS = ['0', '10', '10.00', '50', '100', '100.5'];
export const CURRENCIES = [undefined, 'USD', 'EUR'];
/** Caveats of types the library does not know. */
export const UNKNOWN: Caveat[] = [{ type: 'Custom', n: 1 }, { type: 'Custom', n: 2 }, { type: 'Other' }, { type: 'Custom', n: 1, m: 'x' }];
/** Caveats of known types with a member the library does not know. */
export const EXTENDED: Caveat[] = [
  { type: 'MaxAmount', limit: '100', currency: 'USD', per: 'day' },
  { type: 'ValidUntil', date: '2027-01-01T00:00:00Z', note: 'quarter end' },
];

/** A well-formed caveat, of a known type with only the members it reads or of an unknown type; or, with `extended`, now and then one of {@link EXTENDED}. */
export function caveatFrom(next: () => number, extended = false): Caveat {
  const kind = next();
  if (kind < 0.3) return { type: 'ValidUntil', date: pick(next, DATES) };
  if (kind < 0.75) {
    const currency = pick(next, CURRENCIES);
    return { type: 'MaxAmount', limit: pick(next, LIMITS), ...(currency === undefined ? {} : { currency }) };
  }
  if (extended && kind < 0.8) return { ...pick(next, EXTENDED) };
  return { ...pick(next, UNKNOWN) };
}

/** Up to four caveats from {@link caveatFrom}. */
export const caveatsFrom = (next: () => number, extended = false): Caveat[] =>
  Array.from({ length: Math.floor(next() * 5) }, () => caveatFrom(next, extended));

/** An unsigned hop of a chain from `did:web:hop-0.example` down, under `caveats`, valid until `validUntil`. */
export function unsignedHop(index: number, caveats: Caveat[], validUntil = '2027-01-01T00:00:00Z'): DelegationCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2', 'https://w3id.org/security/zcap/v1'],
    type: ['VerifiableCredential', 'DelegationCredential'],
    issuer: `did:web:hop-${index}.example`,
    validUntil,
    credentialSubject: {
      id: `urn:zcap:hop-${index}`,
      invoker: `did:web:hop-${index + 1}.example`,
      parentCapability: index === 0 ? RESOURCE : `urn:zcap:hop-${index - 1}`,
      invocationTarget: RESOURCE,
      allowedAction: ['orders.place'],
      caveats,
    },
  } as DelegationCredential;
}

/** An unsigned chain with one hop for each entry of `caveats`, each hop valid until its entry of `validUntil`. */
export const unsignedChain = (caveats: Caveat[][], validUntil: readonly string[] = []): DelegationChain =>
  caveats.map((own, i) => unsignedHop(i, own, validUntil[i]));
