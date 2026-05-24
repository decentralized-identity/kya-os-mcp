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

`@kya-os/mcp` ships with secure-by-default behavior. As of 1.3.x, two delegation knobs are wired to safe values; both can be opted out of for backward compatibility, and both emit a one-time per-process warning when set unsafely so operators can spot the configuration in logs.

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

### What to do if you see the warning in production logs

Treat the warning as a configuration audit finding. Either:
1. The flag is set intentionally as part of a migration — track a deadline and close it.
2. The flag is set unintentionally (often inherited from copy-pasted test config) — remove it.

Either way the warning is a one-shot signal, not a per-request alarm.

