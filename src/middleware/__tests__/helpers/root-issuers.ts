/**
 * Test helper: the trust-root options of a test's middleware. A server that gates a tool on a
 * delegation must name its trusted root issuers, develop locally, or accept any issuer by name.
 * Most gate tests are about what the gate does once it accepts a delegation, whoever issued it, as
 * every middleware did before 1.23.0, so they accept any issuer by name unless they list the
 * trusted ones; `root-issuer-requirement.test.ts` tests the requirement itself.
 */
import type { KyaOsDelegationConfig } from '../../with-kya-os.config-types.js';

/** `delegation`, accepting a delegation from any issuer by name unless it lists trusted root issuers. */
export function anyRootUnlessListed(delegation: KyaOsDelegationConfig = {}): KyaOsDelegationConfig {
  return delegation.trustedRootIssuers === undefined ? { allowAnyRootIssuer: true, ...delegation } : delegation;
}
