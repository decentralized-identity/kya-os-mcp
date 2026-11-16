/**
 * The key of order two that the proof cases forge a signature under
 * (`./proof_cases.py`, `./__tests__/proof-path-cases.test.ts`), and whether
 * the forgery holds over what a proof signs.
 *
 * Under the point of order two, A, the verification equation of RFC 8032
 * §5.1.7, [S]B = R + [k]A, holds for R = A and S = 0 when k is odd: [k]A is
 * then A, and A + A is the identity, [0]B. k is the SHA-512 of R, A and what
 * the JWS signs, so the forgery holds for about half of the proofs signed.
 */

import { createHash } from 'node:crypto';

/** The point of order two (y = p - 1), encoded as RFC 8032 §5.1.2 writes a point. */
export const ORDER_TWO = Uint8Array.from([0xec, ...Array<number>(30).fill(0xff), 0x7f]);

/** L, the order of the base point (RFC 8032 §5.1). */
export const BASE_POINT_ORDER = 2n ** 252n + 27742317777372353535851937790883648493n;

/** Whether R = ORDER_TWO and S = 0 satisfy the verification equation under ORDER_TWO over what `jws` signs. */
export function orderTwoForgeryHolds(jws: string): boolean {
  const signed = jws.slice(0, jws.lastIndexOf('.'));
  const digest = createHash('sha512').update(ORDER_TWO).update(ORDER_TWO).update(signed, 'ascii').digest();
  const k = BigInt(`0x${Buffer.from(digest).reverse().toString('hex')}`) % BASE_POINT_ORDER;
  return k % 2n === 1n;
}
