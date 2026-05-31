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

## Mandatory Delegation Protections

`@kya-os/mcp` is secure-by-default with no opt-outs on the delegation path. Through 1.3.x, three escape hatches existed for legacy migration — `requireAudienceOnRedelegation`, `allowLegacyUnsafeDelegation`, and `allowNonDelegationSubjectFields` — each emitting a runtime warning when set unsafely. **As of 1.4.0 these flags are removed.** The protections below are unconditional and cannot be disabled.

### Audience binding on re-delegation

Every non-root credential in a delegation chain MUST carry an `audience` constraint binding it to the verifying server's DID. This closes the confused-deputy class where a re-delegated credential issued for server A is forwarded to server B and accepted there (`SPEC.md` §11.6; Alan Karp's transitive-access analysis). A re-delegation without `audience` is rejected.

### Full chain and revocation verification

The middleware resolves and verifies the entire delegation chain and checks `credentialStatus` / StatusList revocation on every invocation:

- A parent-linked credential presented without a configured `resolveDelegationChain` handler is rejected.
- A credential carrying `credentialStatus` without a configured `statusListResolver` is rejected.

There is no mode that accepts parent-linked credentials without chain resolution or skips StatusList checks.

### Permission-only credential subject

A `DelegationCredential` carries a permission, not a claim: its `credentialSubject` MUST contain only `id` and `delegation` (`SPEC.md` §6.2). The verifier rejects any credential whose subject carries extra, claim-bearing fields — mixing claim semantics into a permission credential is the root of the confused-deputy class (`SPEC.md` §11.6).

### Replay / nonce caching

The proof verifier requires a `NonceCacheProvider`; there is no flag to disable replay protection. Implementations MUST NOT disable nonce caching in production — doing so is non-conformant at Conformance Level 2+ (`CONFORMANCE.md` L2.5, `SPEC.md` §11.2) and is trivially vulnerable to replay.

### No verification-bypass / self-signed mode

There is no "self-signed" or test-only mode that turns off signature or delegation-chain verification. `did:key` identities are appropriate for local development and testing (`SPEC.md` §4.1), but selecting that DID method does not weaken any verification step.

### Migrating off the removed flags

If you set any of the removed flags before 1.4.0:

- `requireAudienceOnRedelegation: false` → bind `audience = <verifying-server-did>` on every non-root credential at issuance.
- `allowLegacyUnsafeDelegation: true` → provide `delegationConfig.resolveDelegationChain` and `delegationConfig.resolveStatusList` resolvers.
- `allowNonDelegationSubjectFields: true` → move claim data out of the delegation subject into a separate credential.

After migrating, remove the flags from your config; they are no longer recognized.

## Outbound resolution & SSRF (`RuntimeFetchProvider`)

`RuntimeFetchProvider` resolves `did:web` and fetches StatusList2021 credentials over the network, and the target host is named by counterparty-controlled data — the DID or status-list URL embedded in a proof or credential. To blunt server-side request forgery it refuses requests to private / loopback / link-local **IP-literal** hosts by default (e.g. `did:web:169.254.169.254`, the cloud-metadata endpoint; `127.0.0.0/8`; RFC 1918 ranges; IPv6 loopback/link-local/unique-local). This is best-effort defense-in-depth for IP literals only — it does **not** stop a public domain that resolves to an internal address (DNS rebinding).

- **Real mitigation:** run verifier deployments behind an egress allowlist and treat did:web resolution as an outbound request to an untrusted host.
- **Opt out:** `new RuntimeFetchProvider({ allowPrivateNetworkHosts: true })`, for trusted internal deployments only.
- The raw `fetch()` escape hatch is intentionally unguarded — it is the caller's responsibility.

