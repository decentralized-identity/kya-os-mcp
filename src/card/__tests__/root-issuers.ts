/**
 * Test helper: the trust-root options of a test's Card verifier. A verifier of a request's
 * delegation chain must pin the chain's root with `trustedRootIssuers` or `resourceOwner`, develop
 * locally, or accept any issuer by name. Most of these tests are about what the verifier does with
 * a chain once it accepts its root, whoever issued it, as every verifier did before 1.23.0, so they
 * accept any issuer by name unless they pin the root; `root-issuer-requirement.test.ts` tests the
 * requirement itself.
 */
import type { VerifyRequestDelegationDeps } from '../request-delegation.js';

/** `deps`, accepting a chain from any root issuer by name unless it pins the root. */
export function anyRootUnlessPinned(deps: VerifyRequestDelegationDeps): VerifyRequestDelegationDeps {
  return deps.trustedRootIssuers === undefined && deps.resourceOwner === undefined
    ? { allowAnyRootIssuer: true, ...deps }
    : deps;
}
