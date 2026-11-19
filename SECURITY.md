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
The one exception is `allowAnyRootIssuer`, which a verifier sets by name to accept a delegation from any root issuer (see Trusted root issuers below).

### Audience binding on re-delegation

Every non-root credential in a delegation chain MUST carry an `audience` constraint binding it to the verifying server's DID. This closes the confused-deputy class where a re-delegated credential issued for server A is forwarded to server B and accepted there (`SPEC.md` §11.6; Alan Karp's transitive-access analysis). A re-delegation without `audience` is rejected.

### Trusted root issuers

A delegation chain's root is the issuer accountable for the authority the chain grants, so a verifier names the issuers it trusts as roots: `delegation.trustedRootIssuers` on the middleware, and `trustedRootIssuers` or `resourceOwner` on the Entity Card guards `requireDelegation` and `verifyRequestDelegation`.
With no root named, a delegation from any issuer would be accepted, including one an agent signs for itself.
So outside development, `wrapWithDelegation` throws when it wraps a tool, `requireDelegation` throws when it builds the guard, and `verifyRequestDelegation` rejects the call before it reads the chain, each with an error that names every fix.

- **Opt out:** `development: true` in local development, under the same production guard as the readers' setting, or `allowAnyRootIssuer: true` (`delegation.allowAnyRootIssuer` on the middleware) for a verifier that accepts any issuer on purpose.
  Either logs one warning, and `allowAnyRootIssuer: true` beside a named root throws a `TypeError`, since the two contradict each other.

### Full chain and revocation verification

The middleware resolves and verifies the entire delegation chain and checks `credentialStatus` / StatusList revocation on every invocation:

- A parent-linked credential presented without a configured `resolveDelegationChain` handler is rejected.
- A credential carrying `credentialStatus` without a configured `statusListResolver` is rejected.
- The `statusListResolver` is told each credential's issuer DID, so it can hold a status list to an issuer it trusts for that credential: `acceptStatusList` applies the rule, and `CheqdStatusListResolver` applies it with its `expectedIssuerDid` pin as the one issuer it trusts.
  It is not told the chain's root, even when `trustedRootIssuers` pins it, so a list the root signed for a re-delegated credential is refused unless the resolver's own configuration binds the list's URL, or its origin, to the root and the list states its URL as its `id`.

There is no mode that accepts parent-linked credentials without chain resolution or skips StatusList checks.

A status-list reader that verifies a list's proof reads the list only when its `issuer` is accepted for the credential, its `statusPurpose` includes the entry's, and its `id` is, byte for byte, the URL it was fetched from (`SPEC.md` §6.6).
A list may state no `id` only when the credential's own issuer signed it and is the only issuer accepted for the credential, and `CheqdStatusListResolver` reads no list without one.
The cheqd resolver's pin grants authority for every credential, even when it differs from the chain's root.
This is deliberate deployment policy, not evidence of chain membership.
Card accountability plugins are trusted authority providers: a positive verdict grants the responsible party status-list authority.
They must meet SPEC-ENTITY-CARD.md §10.3's proof, Card-binding and host-authorization contract.
A structural-only checker or unconditional `true` stub is unsafe for that purpose.
Only a literal `true`, returned bare or as `verified`, grants authority, and a `fresh` that is present and not a boolean reads as not fresh.
`withStatusCache` distinguishes omitted and explicit-null purposes and isolates issuer/root contexts.
Its `maxStalenessMs` permits stale results, and it keeps them across a change of trust configuration, so replace the cache along with that configuration.
Three substitutions remain open to whoever controls what a status-list URL returns:

- A list that states no `id` is bound to no URL, so it can be served in place of another list its own issuer signed, only where that issuer is the credential's own, the verifier pins no other root and its configuration names no other status-list issuer.
  An issuer should state the `id` of each list.
- An earlier version of a list, signed before a credential was revoked, can be served in place of the current one.
  Every reader refuses a version past its `validUntil` (or `expirationDate`), as `status_unavailable`, so an issuer that states a `validUntil` and republishes before it passes bounds how long an earlier version can be served; a list that states no end can be served for as long as it verifies (SPEC.md §6.6).
  Each reader holds that bound with its clock tolerance, `maxClockSkewMs`, 120 seconds unless set, so an earlier version can be served for up to that long past its `validUntil`; set it to 0 to hold the bound exactly.
- An Entity Card's Entity may sign its own Card's list, so with the Entity's key a list with the Card's bit clear can be served in place of the one its responsible party revoked the Card on.
  Against a compromised Entity key, the responsible party revokes the root delegation credential, which the Card's accountability check reads (SPEC-ENTITY-CARD.md §12.5).

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

## Outbound resolution & SSRF

A verifier reads documents from hosts that counterparty-controlled data names: the issuer DID of a delegation or a request proof, and the status-list URL of a credential.
Every did:web read, by the delegation gate, `DidWebResolver`, `createDidWebResolver` or `RuntimeFetchProvider.resolveDID`, and every status-list read, by `CheqdStatusListResolver` or `RuntimeFetchProvider.fetchStatusList`, goes through one private-network rule, whatever `FetchProvider` it is given (SPEC.md §4.4.2):

- A URL that is not an absolute http or https URL, such as a `data:`, `file:` or `ftp:` URL, is refused before any request.
- A status-list URL, and each redirect of one, must be https, under `allowPrivateNetworkHosts` and on a private host too: over http, an on-path party can replay an older signed list from before a revocation.
  http is read only at an exact URL your `statusListIssuers` binds, on any host, by the provider and by `createRevocationChecker` alike, and from a private or local host under `development: true`.
- A URL whose host is a non-public IP literal, with or without trailing dots, is refused before any request: loopback, private, link-local (including the cloud metadata address 169.254.169.254), unique-local, shared address space and the other ranges `SafeFetch` refuses, including an IPv4-mapped, IPv4-translated or NAT64 IPv6 form of one.
- So is a URL whose host is a local name, in any case and with any trailing dots: a single label, such as `ip6-localhost` or `metadata`, which a resolver completes through its search domains to a local host, or `localhost`, `localdomain`, `localdomain6`, `local`, `internal` or `home.arpa`, or a name under one of them, such as `localhost.localdomain` or `metadata.google.internal`.
- Each read asks its provider not to follow redirects and follows at most 3 itself, holding each target to the same rule and refusing a step from https down to http; a redirect to another origin carries only the CORS-safelisted request headers and the request's `Cache-Control` and `Pragma`.
- A provider that follows a redirect itself, because it does not pass `redirect: "manual"` on, has made that request before the reader sees the response; the reader refuses the response, unread, when it says it was redirected or names another URL.
  A custom provider's `fetch` must pass `redirect` on.

Where the runtime resolves names, as Node does, `RuntimeFetchProvider` also resolves each host before it connects, every redirect's included, refuses a host with any address that is not public, and connects only to the addresses it checked, trying each in turn as the runtime's own fallback does, pinned, so a second lookup cannot move it (DNS rebinding).
It does so by `SafeFetch`'s means: its `lookup` and `transport` options are `SafeFetch`'s seams, and `transport: fetchTransport`, for a serverless runtime where the pinned connection fails, connects by name after the check, which reopens the rebinding window.
Each pinned request has a connection of its own: it never reuses a socket `https.globalAgent` keeps alive for another request, which may have reached another address, and never goes through an agent or `https.request` an application or a package such as global-agent installs in their place, where a proxy would resolve the host again; it keeps only the TLS settings of `https.globalAgent`, such as a `ca`.
A runtime that resolves no name, such as a Cloudflare Worker or a browser, and a custom `FetchProvider`, or a subclass whose `fetch` is its own, make their own connections, so their reads are held to the URL alone and do not refuse a public name that points at a private address.
A runtime counts as one that resolves no name only when `node:dns` does not load or says its `lookup` is not implemented, so a lookup that fails for a moment never turns the check off, and each fall back to the URL alone is logged once, with its reason.
So does a request the provider's runtime `fetch` sends through a proxy, as Node's does under undici's `setGlobalDispatcher(new ProxyAgent(...))`, or under `NODE_USE_ENV_PROXY=1` with `HTTPS_PROXY` for a host `NO_PROXY` does not name: the proxy resolves the host, so the provider reads through `fetch`, as 1.23.0 did, and warns once that the proxy must refuse private and local addresses itself.
A host `NO_PROXY` names, and every request under any other dispatcher, such as an `Agent` subclass, a `RetryAgent` or a `MockAgent`, is read pinned: only a dispatcher known to proxy the request turns the check off.

- **Real mitigation:** run verifier deployments behind an egress control that refuses private addresses, and treat every DID resolution and status-list read as an outbound request to an untrusted host.
  On a runtime that resolves no name, or behind a proxy that carries the verifier's `fetch`, it is the only defense against a public name that points at a private address.
- **Hosts you name:** the did:web documents of the DIDs you pin in `trustedRootIssuers` and the status lists your `statusListIssuers` binds are read wherever they are, a private host included.
  That is decided for each request on the URL it asks for, so a redirect from one of them to a URL you did not name, through an open redirect on your own host or a path a presenter wrote under an origin you bind, is held to the rule as any presenter's URL is.
  The middleware passes `delegation.trustedRootIssuers` on itself; a `RuntimeFetchProvider` or `DidWebResolver` you build takes them as options of the same names.
  The status-list checker, `createRevocationChecker`, reads both kinds of list through its `SafeFetch` on any host, still pinned, and with them the list a pinned root's own credential names, once that credential's proof has verified: in `evaluateDelegationChain` given `verifyHopProof`, in `verifyRequestDelegation` and `requireDelegation`, and in `verifyCard` once its accountability check has verified the responsible party.
  It reads that root's list so only at the root's own host, the https origin, host and port, its did:web DID names; a root's list on any other private host, and every list of a did:key root, which has no host, needs a `statusListIssuers` binding to be read there.
  The root is pinned only when the operator names it, as the `resourceOwner` or in `trustedRootIssuers`, `verifyCard`'s own included: a root accepted under `allowAnyRootIssuer`, or on an accountability verdict alone, may be the presenter, so its list is read as any URL a presenter names.
  Only the library marks a root's list as verified, after that proof, so a chain whose root credential's proof fails, or is not checked, has its root's list read as any URL a presenter names.
  Each request is decided on its own URL, so a redirect from one of those lists to any other URL is held to the rule.
- **Opt out:** in local development, set `development: true` on `withKyaOs` or `createKyaOsMiddleware`, `DidWebResolverOptions`, `CheqdStatusListResolverOptions` or `RuntimeFetchProviderOptions`.
  It warns once per process, and while `NODE_ENV` is `production` building what it is set on throws, so a deployment that sets `NODE_ENV` to `production` does not start with it.
  The check reads `process.env.NODE_ENV` as written, so a bundle in which a bundler has put `"production"` in its place refuses it too; a runtime with no `process` counts as not production.
  For trusted internal deployments in production only, give the reader `new RuntimeFetchProvider({ allowPrivateNetworkHosts: true })`, or a custom `FetchProvider` whose `allowPrivateNetworkHosts` member is `true`.
  Each admits non-public IP literals, local names and names that resolve to private addresses, through the provider's own `fetch`; the scheme rule and the redirect checks still hold.
- The Entity Card's resolution and status-list reads go through `SafeFetch` (`createSafeFetch`) instead, which resolves each host name, refuses a private address, pins the connection to the addresses it checked, and follows only same-origin redirects.
  Its `development: true` admits private and local addresses for a local demo, under the same production guard, and in production `allowOrigins` names the origins you own, which it fetches without the guard.
- The raw `fetch()` escape hatch of a `FetchProvider` is intentionally unguarded: it is the caller's responsibility.
- A refusal tells whoever presented the credential nothing the verifier's network answered, since the presenter chooses the DIDs and status-list URLs the verifier reads, and their hosts may be internal ones.
  A refusal of a DID or a status list that could not be read says why only where the DID or the URL alone decided it, before any request or DNS lookup, as for a private or local host it names, or where the deadline passed; otherwise it reads `Could not resolve issuer DID: "<did>"` or `the status list at "<url>" could not be read or checked`.
  An HTTP status, a body over the byte cap or not JSON, a refused redirect, an address `SafeFetch` or `RuntimeFetchProvider` looked up and the words of a dependency the host supplies, unless it throws a `RefusalError`, go to the operator's log, and the refusal's code says which kind of failure it was.
  So do the words of a refusal of a status list that was read but whose proof has not verified, for its `issuer`, its `id`, its `statusPurpose`, or its dates where no proof is checked, the `statusListIssuers` configuration that would accept it among them, since they quote the document the URL answered with: the refusal reads `the status list at "<url>" could not be read or checked`.
  A name that resolves to a private address is coded as a name that does not resolve is, `did_unavailable` or `status_unavailable`, both transient, so the code does not tell whoever chose the name what the verifier's DNS answered; the log says `host_refused` and names the host and the address.

