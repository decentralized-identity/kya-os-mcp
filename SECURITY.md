# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |
| 0.x     | No        |

## Reporting a Vulnerability

Please do **not** open a public GitHub issue for security vulnerabilities.

Report issues privately to: **dylan.hobbs@vouched.id**

Include in your report:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

**Response timeline:**
- Acknowledgement within 48 hours
- Triage and severity assessment within 7 days
- Coordinated disclosure after 90 days (or sooner if a fix is ready)

Reporters will be credited in release notes unless they prefer to remain anonymous.

## Scope

This policy covers the `@kya-os/mcp` npm package and this repository. It includes:
- Cryptographic implementation errors (Ed25519, JWS, SHA-256)
- Delegation verification bypasses
- Session replay vulnerabilities
- DID resolution attacks

## Out of Scope

- Vulnerabilities in dependencies (report to the respective maintainers)
- Issues requiring physical access to the host

## Secure Defaults & Unsafe Delegation Modes

`@kya-os/mcp` ships with secure-by-default behavior. As of 1.3.x, three delegation knobs are wired to safe values; each can be opted out of for backward compatibility, and each emits a one-time per-process warning when set unsafely so operators can spot the configuration in logs.

### `requireAudienceOnRedelegation` — default `true`

Every non-root credential in a delegation chain MUST carry an `audience` constraint. This prevents confused-deputy attacks where a re-delegated credential issued for service A is forwarded to service B and accepted there. See `SPEC.md` §11.6 and Alan Karp's transitive-access analysis for the underlying vulnerability class.

- **When to set to `false`:** legacy integrations that issue re-delegations without an audience field and cannot yet update their issuance pipeline. Do this only as a temporary migration step. The middleware logs a warning on first use per process.
- **Migration path:** update your delegation issuer to bind `audience = <verifying-server-did>` on every non-root credential, then flip the flag back to `true` (or remove it).

### `allowLegacyUnsafeDelegation` — default `false`

When `false` (the default), the middleware enforces full delegation-chain resolution and `credentialStatus` / StatusList revocation checks on every invocation.

Setting this to `true` weakens verification:
- Parent-linked delegations are accepted without chain resolution.
- `credentialStatus` is accepted without StatusList lookups.

- **When to set to `true`:** integrations that have not yet provided `resolveDelegationChain` and `resolveStatusList` resolvers and need a controlled migration window. The middleware logs a warning on first use per process.
- **Migration path:** wire up `delegationConfig.resolveDelegationChain` and `delegationConfig.resolveStatusList`, then remove this flag.

### `allowNonDelegationSubjectFields` — default `false`

A `DelegationCredential` carries a permission, not a claim: its `credentialSubject` MUST contain only `id` and `delegation` (`SPEC.md` §6.2). The verifier rejects any credential whose subject carries extra, claim-bearing fields, because mixing claim semantics into a permission credential is the root of the confused-deputy class (`SPEC.md` §11.6).

Setting this to `true` accepts credentials whose `credentialSubject` carries non-delegation fields.

- **When to set to `true`:** bridging a non-conformant issuer that emits claim-bearing subjects during migration. The verifier logs a warning on first use per process, naming the offending fields.
- **Migration path:** move claim data out of the delegation subject (carry it in a separate credential), then remove this flag.

### Protections with no opt-out

Some safeguards have no escape hatch, by design:

- **Replay / nonce caching.** The proof verifier requires a `NonceCacheProvider`; there is no flag to disable replay protection. Implementations MUST NOT disable nonce caching in production — doing so is non-conformant at Conformance Level 2+ (`CONFORMANCE.md` L2.5, `SPEC.md` §11.2) and is trivially vulnerable to replay.
- **Verification bypass.** There is no "self-signed" or test-only mode that turns off signature or delegation-chain verification. `did:key` identities are appropriate for local development and testing (`SPEC.md` §4.1), but selecting that DID method does not weaken any verification step.

### What to do if you see the warning in production logs

Treat the warning as a configuration audit finding. Either:
1. The flag is set intentionally as part of a migration — track a deadline and close it.
2. The flag is set unintentionally (often inherited from copy-pasted test config) — remove it.

Either way the warning is a one-shot signal, not a per-request alarm.

