/**
 * The coded variant of a proof verifier the library builds. `createStatusListProofVerifier` and
 * `createDelegationProofVerifier` keep their 1.22.0 contract: the function each returns resolves
 * `false` on every failure, an issuer DID document that could not be read included. The library's
 * own callers, the revocation checker and the request verifier, ask the same verifier's coded
 * variant instead, which throws a refusal coded by why when that document cannot be read
 * (`did_unavailable` or `deadline_exceeded` for an outage), so an outage stays transient there and
 * is never a verdict on the proof. The variant is kept in a module-private map keyed by the function
 * the factory returned: it is no member of that function and no part of the package's surface, and a
 * verifier a host wrote, or wrapped in a function of its own, has none and is asked as it is.
 */

/** A proof verifier as the Card seams take one: `true` only for a proof that verifies. */
export type ProofVerifier = (credential: Record<string, unknown>) => boolean | Promise<boolean>;

/** The coded variant of each proof verifier the library built, by the function it returned. */
const CODED = new WeakMap<ProofVerifier, ProofVerifier>();

/**
 * The proof verifier an adopter is given for `coded`: the same answer, and `false` wherever `coded`
 * throws, with `coded` kept as its variant for {@link codedVariantOf}.
 */
export function booleanProofVerifier(coded: ProofVerifier): (credential: Record<string, unknown>) => Promise<boolean> {
  const verifier = async (credential: Record<string, unknown>): Promise<boolean> => {
    try {
      return (await coded(credential)) === true;
    } catch {
      return false;
    }
  };
  CODED.set(verifier, coded);
  return verifier;
}

/** The variant of `verifier` that codes why it could not verify, where the library built it; otherwise `verifier` itself. */
export function codedVariantOf(verifier: ProofVerifier): ProofVerifier {
  return CODED.get(verifier) ?? verifier;
}
