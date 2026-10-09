# Changelog

All notable changes to @kya-os/mcp will be documented here.

Format: https://keepachangelog.com/en/1.0.0/
Versioning: https://semver.org/spec/v2.0.0.html

## [Unreleased]

## [1.19.0] - 2026-10-09

### Added

- **`proveOutcome` proves the authorization outcomes application code
  decides.** A server that enforces OAuth scopes in its tool handlers
  returns its own challenges and denials as tool results, and the
  `withKyaOs` transport sent such an error result unproven. The middleware
  now has `proveOutcome({ toolName, args, outcome, reason, result,
  sessionId? })`, which returns a copy of `result` carrying the proof the
  gates attach to their outcomes: the same claims, the same `_meta` keys,
  the configured response-proof profile and the same audit events. It runs
  the gates' own code, and the transport passes its result through as
  proven. A `needs_authorization` proof binds the result and a denial or
  step-up proof binds none, as SPEC.md §7.4 has it. The `_kyaos*` control
  arguments are left out of the signed request, `_meta` members only the
  middleware may set are dropped, and no session needs to be opened. Under
  the envelope profile, set `resultType: 'complete'` on the result first: on
  the 2026-07-28 revision the MCP SDK adds it after the handler returns,
  outside a proof made there. It is
  optional on `KyaOsMiddleware`, as `withPolicyGate` is, so structural
  implementers still type-check; the new `KyaOsOutcomeProver` role requires
  it. New types: `KyaOsOutcomeProofRequest`, `KyaOsAuthorizationOutcome`,
  `KyaOsToolResult`.
- **`formatChallenge` may return the whole challenge result.** Besides the
  content array, the delegation gate's hook may return `{ content,
  structuredContent?, isError?, _meta? }` (`KyaOsChallengeResult`; the hook
  type is `KyaOsChallengeFormatter`). The gate sets all of it before it
  signs the challenge, so the envelope profile covers `isError` and
  `structuredContent`; the body profile still covers `content` only.
  `_meta` members the middleware owns are dropped from what the hook
  returns. The array form and the default challenge are unchanged; the
  default challenge still carries no `isError`, unlike the policy gate's
  step-up.
- **`toMcpToolCallback` registers a wrapped handler with `registerTool`
  without a cast.** Passed straight to `McpServer.registerTool`, a
  `KyaOsToolHandler` needed `as never`, and the SDK's request context then
  arrived as the KYA-OS session id, so `wrapWithProof` found no session and
  sent the result unproven. The adapter passes the arguments alone. Types:
  `McpToolCallback`, `McpToolCallbackResult`.

### Changed

- **A `formatChallenge` hook that returns neither form gets the default
  challenge**, as a throwing hook does. Before, the value was emitted as
  `content`, which `McpServer` then rejected as an invalid result.
- **`wrapWithProof` keeps an outcome proof it is handed.** A result
  produced by the outcome-proof path, recognized by identity, is returned
  as it is. Before, a challenge that was not an error result was signed
  again there as an allowed call. No gate composition in this repository
  reached that path.

### Fixed

- **An allow result the session fallback cannot attribute says so.** A
  call that threads no session, which is every call on the `withKyaOs`
  transport path, is proved under the single established session. With
  more than one session live the middleware refuses to pick one and the
  result went out unproven, with only a log line; opening a session in the
  middleware's `SessionManager` from application code did this to every
  later allow result. Such a result now carries `_meta.proofError`, the
  marker a failed proof generation already sets. `isError`, the content and
  the audit events are unchanged, and a server with no session at all
  emits what it did before.
- **Three DID-document readers accept a key published as
  `publicKeyMultibase`.** `ProofVerifier.fetchPublicKeyFromDID`, the Entity
  Card `didKeyedJwks` projection, and the conformance adapter's DID-resolution
  check read only `publicKeyJwk`. A verification method that published its
  Ed25519 key as `publicKeyMultibase`, the material property of
  `Ed25519VerificationKey2020` and the form did:cheqd documents use, failed
  with `PUBLIC_KEY_NOT_FOUND`, projected no key, or failed the check. They now
  read the key through `verificationMethodJwk`, as the credential verifiers
  already do: a `publicKeyJwk` is used unchanged, otherwise the key is taken
  from `publicKeyMultibase` or `publicKeyBase58`, and anything that is not a
  32-byte Ed25519 key is still refused. The `PUBLIC_KEY_NOT_FOUND` message from
  `fetchPublicKeyFromDID` now names all three properties. The did:key resolver's
  output is unchanged.
- **Conformance suite 1.2.0: the status-list vectors' list verifies, and a
  list altered after signing must be rejected.** The StatusList2021Credential
  in `status-list.json` carried a proof that did not verify, and the reference
  adapter read its bits without checking it. The suite therefore passed an
  implementation that never checked a list's proof and failed one that did.
  The list is re-signed, the reference adapter verifies its proof on the
  delegation credentials' path before reading a bit, and a new negative
  vector, `status-list/tampered-list`, clears the revoked bit after signing.
  SPEC.md §6.6 and CONFORMANCE.md L3.11 state the check. The other eight
  vector files change only their `version`, the suite has 49 vectors, and the
  library is unchanged.

### Documentation

- **The README says what a response proof does not cover.** `_meta` is
  outside every response proof (SPEC.md §7.6), so a server should repeat
  security-relevant hints it carries there, such as an OAuth
  `resource_metadata`, `scope` or `error`, in `content` or
  `structuredContent`. The new section on proving application outcomes says
  so, and says which profile covers which members.
- **SPEC.md §6.2 states how a base-profile credential is signed.** Its
  example labels the proof `Ed25519Signature2020`, and CONFORMANCE.md L3.1
  asked for "Ed25519Signature2020 or equivalent", but the profile has never
  used the W3C suite of that name. §6.2 now specifies the construction the
  reference implementation and the vectors use: Ed25519 over the JCS
  canonicalization of the credential without `proof`, `proofValue` as
  unpadded base64url, the key found by `proof.verificationMethod`, and the
  proof options outside the signature. L3.1 and L3.5 point to it. A new
  conformance test checks the vectors' delegation credentials against that
  text with `node:crypto` rather than the library's verifier. Moving to a
  standard cryptosuite stays open in #184.

## [1.18.0] - 2026-10-08

### Added

- **`maxChainLength` for delegation chains.** `validateDelegationChain` and
  the middleware's `delegation` config take an optional cap on how many
  credentials one chain may hold, checked before any of them is verified. A
  resolver could return a chain of any length, and each credential costs a
  signature check and possibly a DID resolution. It is a local cost limit, not
  a protocol rule about how far authority may be delegated: it is unset by
  default, and SPEC.md §6.4 records that the base profile leaves chain length
  unbounded. The middleware refuses a value that is not a positive integer at
  startup rather than rejecting every call. The cap applies to the chain
  `resolveDelegationChain` returns, not to the resolver's own fetches.

### Changed

- **The Entity Card chain limit is opt-in, as on the base profile.**
  `validateDelegationChain` and `evaluateDelegationChain` in
  `@kya-os/mcp/card` rejected any chain of more than `MAX_DELEGATION_DEPTH`
  (10) credentials unless the caller passed a larger `maxDepth`. They now
  accept any length unless the caller sets `maxChainLength`, the option's name
  on both profiles. **A verifier that relied on the default now accepts chains
  of 11 credentials or more; pass `maxChainLength: MAX_DELEGATION_DEPTH` to
  keep the previous behavior.** A longer chain broadens nothing: every hop
  still attenuates its parent, so the cap bounded only the verifier's work.
  SPEC.md §6.10 drops the cap from the attenuation invariants and states it,
  non-normatively, as a local limit, as §6.4 does for the base profile. A
  limit that is not a positive integer rejects every chain; previously `NaN`
  accepted every length.

### Deprecated

- **`maxDepth` on the Entity Card `DelegationChainContext`.** Use
  `maxChainLength`, which wins when both are set.

### Fixed

- **The `example:*` scripts run from a fresh clone.** They resolved
  `@kya-os/mcp` to `dist/`, which a clone does not have until `npm run build`,
  and the node-server and authz-inspector examples, being packages of their
  own, could not resolve it at all without a per-example install. The scripts
  and `scripts/demo.sh` now run the examples from `src/` through
  `tsconfig.examples.json`, so the root `npm install` is all they need. Two
  scripts are added for the consent-persistence scenarios.
- **`withKyaOs()` warns when the server is already connected.** It wraps
  transports by patching `connect()`, so a transport connected before it ran
  was never wrapped, and its tool results went out without a KYA-OS proof or
  a transport audit record, silently. It now logs a warning saying so, on MCP
  SDK 1.3 and later. When the server had no tools before connecting, the
  warning also explains the SDK's refusal to register `_kyaos`.

### Documentation

- **CONFORMANCE.md L2.17 names the current proof keys.** It told verifiers to
  read `org.kya-os/proof`, a key no server writes since the role-named keys
  of SPEC.md §7.6. It now names `org.kya-os/response-proof`, keeps the prior
  keys as 1.x fallbacks, in that order, and separates the request proof under
  `org.kya-os/request-proof`.
- **SPEC.md §6.10 says how to tell the two delegation profiles apart.** The
  first `@context` entry selects the rule set.

## [1.17.0] - 2026-10-05

### Added

- **Scope helpers in `@kya-os/mcp/delegation`.** `matcherContains(outer,
  inner)` decides, by sound rules only, whether one scope matcher grants
  everything another grants. `authorityContains(authority)` builds that check
  once for a whole list of matchers. `scopeAuthority(credential)` returns a
  credential's flat scopes and CRISP matchers as one list of matchers.
  `crispScopes(credential)` returns its CRISP matchers. Scope attenuation
  below is built on them.
- **Signer binding options for `ProofVerifier.verifyProof`.** An optional
  fourth argument, `{ expectedDid, expectedAudience }` (type
  `ProofVerificationOptions`), rejects a proof from another signer
  (`DID_MISMATCH`) or addressed to another audience (`AUDIENCE_MISMATCH`);
  `expectedAudience` may list several DIDs. Omitting it verifies as before.
- **`withKyaOs` takes `nonceCache`, `requireAtomicNonce`, and
  `responseProofProfile`.** The adapter could not pass them to the middleware,
  and its `session` option documented a top-level `nonceCache` that did not
  exist. Each replica of a multi-replica deployment therefore kept a private
  in-memory nonce cache and accepted a handshake replayed from another
  replica (SPEC.md §5.5, §11.2; SPEC-MCP-EXTENSION.md §10.4),
  `requireAtomicNonce` was unreachable, and envelope-profile proofs could not
  be enabled. All three now pass through to `createKyaOsMiddleware`. Each is
  optional, and leaving it out keeps the previous default.
- **`KyaOsCallContext.principal` and `KyaOsCallContext.approvals`.**
  `wrapWithDelegation` fills them for the handler it wraps; see the
  `withPolicyGate` entry under Security. Both are optional members.
- **`verifyApprovalQuorum` takes several request hashes.** Its `requestHash`
  argument may be a list of hashes that identify the one suspended action; a
  grant over any of them counts. A single string works as before.

- **Audit verification and delivery hooks, all optional.**
  `AuditArtifactVerifier` gains `verifySignedCheckpoint` (a checkpoint without
  its leaves), `verifyCurrentKeys` (over `AuditSignedArtifacts`), a
  `maxClockSkewMs` option, and an optional
  `AuditVerificationContext` argument on `verifyEntries`, `verifyCheckpoint`,
  and `verifyObservation` that carries the checkpoints a policy's checkpoint
  bounds name. `applyRequiredAuditProfile` applies a policy's
  `requiredAuditProfile` to a report. `AUDIT_REASON_CODES` gains
  `KEY_BOUNDARY_UNRESOLVED`, `KEY_NOT_CURRENT`, `MERKLE_PROOF_MISSING`,
  `OBSERVATION_FUTURE_DATED`, and `REQUIRED_PROFILE_UNMET`. On the write path,
  `AuditOutboxItemKey` and `auditOutboxItemKey` identify an outbox item by
  source and event ID, `AuditOutboxProvider.capabilities.keyedBySource` opts an
  adapter into receiving that key, `AuditTrailConfiguration` gains
  `onAcknowledgementFailure`, `AuditSourceStateProvider` gains an optional
  `abandonClaim`, and `MemoryAuditSourceState` takes a `redeliveryWindow`.
  Every new provider member is optional, so existing adapters still implement
  their interfaces.

### Changed

- **SPEC.md: the `did:key` verification method id is `<did>#<multibase>`.**
  §4.3, the §6.2 example and Appendix C.2 and C.3 gave `<did>#keys-1`, which
  contradicts the W3C did:key method and which no standard resolver,
  including this one, resolves. They, and `CONFORMANCE.md` L1.1, now give the
  W3C form. No code changes.
- **`json-canonicalize` 3.0.1.** Entity Card proofs (the request hash and the
  covered claims) and cheqd DLR content still canonicalize through
  `json-canonicalize`. 3.x throws on `NaN` and `Infinity`, as RFC 8785
  §3.2.2.3 requires, where 2.0.0 wrote `null`; every JSON value canonicalizes
  to the same bytes as before. A received JSON-RPC request cannot carry those
  values, so verifying calls is unaffected. Minting a card proof, or preparing
  DLR content, with a non-finite number now fails instead of hashing `null`:
  the rule `canonicalizeJson` already applies to response proofs and audit
  records. The package also ships dual ESM/CJS builds.
- **Built with TypeScript 6.0.** The emitted JavaScript and declaration files
  are byte-identical to the 5.9 build.
- **Declaration maps are no longer published.** The `.d.ts.map` files pointed
  at `src/`, which the package does not include, so Go to Definition already
  fell back to the `.d.ts`. Types are unchanged. JavaScript source maps stay:
  under `node --enable-source-maps`, or an error tracker that applies source
  maps, stack traces still name the `src/*.ts` file and line. The package drops
  from 691 to 525 files and from 2.69 MB to 2.47 MB unpacked.

### Security

- **Scope attenuation across scope representations.** `validateScopeAttenuation`
  treated a parent credential that restricts scope only through
  `constraints.crisp.scopes` matchers as unrestricted, because its flat scope
  list was empty. A re-delegated child could then claim any flat scope (for
  example `admin:root` under a parent limited to the `safe:` prefix), and the
  chain validated. Both credentials are now read as one typed authority (flat
  scopes as `exact` matchers, plus CRISP matchers), and every scope and matcher
  the child grants must be proven inside the parent's authority by sound
  containment rules; anything unprovable is rejected. Sound narrowings that
  were rejected before are now accepted: a flat scope that a parent's matcher
  grants, an `exact` matcher for a parent's flat scope, and a narrower `prefix`
  or `path-prefix` under the parent's. A malformed scope entry proves nothing,
  so it fails closed instead of throwing. A parent with no scopes of either
  kind stays scope-unrestricted, as before (SPEC.md §6.3, §6.4).
- **`verifyProofDetached` replay and skew bypass.** The signature was checked
  over the payload the caller supplied, while the timestamp and replay checks
  read `proof.meta`, which that payload did not bind: an accepted proof with a
  fresh `meta.nonce`, `ts` or hash verified again. The supplied payload must
  now equal the payload rebuilt from `meta` byte for byte
  (`INVALID_JWS_PAYLOAD`). A caller that passes the canonical payload, as the
  method documents, sees no change.
- **`ProofGenerator.verifyProof` checks `meta` through the signature.** It
  verified the JWS against its embedded payload and compared the hashes in the
  unsigned `meta`, so a proof with rewritten `meta.requestHash` and
  `meta.responseHash` verified for a different call, and one without
  `meta.responseHash` accepted any response. It now verifies the signature
  over the payload rebuilt from `meta`, requires a response exactly when the
  proof binds one (the rule `ProofVerifier` already applied), and checks
  `meta.did` and `meta.kid` against its identity. It still checks the artifact
  only, with no freshness or replay state. Proofs it minted verify as before.
- **The embedded JWS payload must be the signed one.** Verification put the
  payload rebuilt from `meta` in place of the JWS's own payload segment
  without looking at that segment, so an intermediary could rewrite the
  embedded `aud`, `responseHash` or `outcome` that JWT tooling and audit
  stores read, and the proof still verified. `CryptoService.verifyJWS` with a
  detached payload now also requires an embedded payload that differs from it
  to verify under the same signature, which only the signed payload does
  (SPEC.md §7.4: the `meta` block and the decoded payload reconcile exactly).
  A JWS without a payload segment (`header..signature`) verifies as before,
  and so does every proof this library mints.
- **`kid` must belong to `did`.** A proof signed with one DID's key could name
  another DID as its signer (`iss`/`sub`) and verify against the key its `kid`
  named. `ProofVerifier` now rejects a DID URL `kid` whose DID is not
  `meta.did` (`KID_DID_MISMATCH`), as the Entity Card verifier already did
  (SPEC-ENTITY-CARD.md §8). A relative `kid` is unaffected.
- **The `withKyaOs` transport no longer re-signs results a wrapper already
  proved.** It ran `wrapWithProof` again over every non-error `tools/call`
  result. A `needs_authorization` challenge from `wrapWithDelegation` (not an
  error result) lost its signed `outcome: "needs_authorization"` proof to an
  outcome-less one, which SPEC.md §7.2 reads as `allowed`, and the audit trail
  gained a started and succeeded lifecycle for a call that never ran. A
  delegated call lost its scope-bearing proof and was recorded twice. Once a
  middleware is connected to the transport, its wrappers and outcome paths
  stamp what they return with a random per-middleware token in a private
  `_meta` member, and the transport passes a stamped result through untouched.
  The stamp lives in `_meta` because the MCP SDK re-creates the result object
  when it validates it. The transport removes it from every result before the
  message is sent, so it never reaches the wire. A result without the stamp
  is proved and audited as before, whatever proof, `proofError` or
  `org.kya-os/audit` members it carries: those are removed first, so content
  relayed from an upstream server cannot suppress this server's proof and
  audit events or ship its own proof in their place. Other `_meta` members are
  kept. A middleware used without the transport stamps nothing.
- **`withPolicyGate` composed inside `wrapWithDelegation` sees the verified
  call.** The delegation gate strips every `_kyaos*` argument before its
  handler runs. The policy gate then projected its principal from the already
  stripped `_kyaos_delegation`, so engines saw `agentDid: "unknown"` and no
  delegated scopes (a deny-list engine allowed everything), and
  `_kyaos_approvals` never arrived, so no step-up could be satisfied. The
  delegation gate now passes the authenticated principal and scopes (for a
  durable grant, those of its re-verified credential) and the approvals in the
  call context, and the policy gate prefers them. Approvals stay outside the
  holder-binding request hash. A policy gate used on its own behaves as
  before.
- **did:key and base58 input is bounded before decoding.** The did:key path
  decoded the whole counterparty-supplied DID before checking it was a 34-byte
  key, and `base58Decode` had no input limit and quadratic cost: one 100 KB
  `did:key:z…` in a tool call held the event loop for seconds. A did:key whose
  base58 part is longer than 64 characters (an Ed25519 key is always 47) is
  now rejected unread, and its payload must be exactly the prefix and 32-byte
  key. `publicKeyMultibase` and `publicKeyBase58` in DID documents are decoded
  only up to 1024 characters, enough for any published public key.
  `base58Decode` takes that bound as a new optional `maxLength` argument (the
  package root exports 1024 as `MAX_BASE58_DECODE_LENGTH`), and a `maxLength`
  that is not a non-negative integer throws a `RangeError`. Called without
  it, `base58Decode` decodes any length, as before. Its byte conversion is now
  linear; accumulating the digits stays quadratic, which the bound keeps
  small. Every well-formed Ed25519 did:key and verification method resolves
  as before.
- **`GenericOidcAdapter` accepts only a real token response.** Any 2xx JSON
  body from the token endpoint was a successful authorization, including `{}`
  and the HTTP 200 `{"error":"bad_verification_code"}` some providers return
  for a bad or replayed code. The body must now be a JSON object with no
  `error` member and a non-empty string `access_token` (RFC 6749 §5.1). A
  non-Bearer `token_type` (some providers send `bot`) is accepted. The granted
  scopes are read strictly: an absent `scope` means the requested scopes
  (RFC 6749 §5.1), a string is split on whitespace, so `""` grants none, a
  list of strings is taken as is, and any other `scope` fails the
  authorization instead of granting the requested scopes.
- **`DefaultPolicyEngine` step-up counts distinct, allowed approvers.** One
  approver listed twice in `humanApprovals` satisfied a quorum of two, and
  `stepUpApprovers` was returned in the step-up challenge but not enforced.
  Only distinct approvers, and only those on the allowlist when one is set,
  now count toward `stepUpQuorum`. `verifyApprovalQuorum` reports the verified
  approvers as `QuorumResult.approvers`, the set `humanApprovals` should be
  built from. It always sets the field; the field is optional, so code that
  builds its own `QuorumResult` still compiles. The `stepUpQuorum` value
  itself is read as before, and distinct, allowed approvals decide as before.
- **Small-order Ed25519 public keys are rejected.** Under such a key one
  signature verifies for every message, so anyone could sign as a did:key
  built from it, and OpenSSL, WebCrypto and `jose` all accept it.
  `NodeCryptoProvider` and `WebCryptoProvider` now refuse the small-order
  encodings libsodium blocks, and so does every path that imports a key
  itself: VC-JWT verification, Entity Card proofs and their HTTP message
  signatures, and `CompactJwsAuditSignatureVerifier`. Those check the imported
  key rather than the JWK, because Node's JWK import tolerates junk in `x`.
  The audit verifier cannot read back a public key its resolver imported as
  non-extractable, and verifies under such a key as before.
  `NodeCryptoProvider` also decodes keys strictly, as `WebCryptoProvider`
  already did: a 64-byte key or a key with trailing junk no longer verifies.
  ASCII whitespace in a key is still ignored, as both decoders did, so a key
  read from a file with its newline verifies as before, and so does a 32-byte
  key in base64, unpadded base64, or base64url.
- **Strict canonicalization never honours `toJSON`.** `canonicalizeJson` and
  `canonicalizeJsonBytes` validated their input and then serialized it with
  `json-canonicalize`, which hands any object with a `toJSON` member to
  `JSON.stringify`: `{"toJSON":"x", ...}` came out unsorted (not RFC 8785),
  and a hidden `toJSON` function, or one on an array, replaced the value that
  was hashed or signed. They now serialize the validated value themselves, in
  one pass linear in the size of the input. Properties JSON does not carry
  (non-enumerable ones, and an array's non-index ones such as a `toJSON`) are
  ignored, as before, and never consulted, so `'abc'.match(/b/)` still
  serializes as `["b"]`. An accessor array element is now refused, as an
  accessor member already was, because the value checked could differ from
  the value written. Output is byte-identical to `json-canonicalize` for plain
  JSON (anything `JSON.parse` returns or an object literal builds), and the
  conformance vectors are unchanged.

- **Graph revocation is checked for the whole chain.** `validateDelegationChain`
  asked its `RevocationChecker` about the leaf only, so a leaf minted after an
  ancestor's revocation, and therefore never registered in the graph, still
  validated. Every credential in the verified chain is now checked, root
  first, and a checker that throws fails the chain instead of throwing.

- **Revocation is recorded in the graph.** `revokeDelegation` only flipped a
  status bit when `credentialStatusId` had the form `<list>#<digits>`, and
  otherwise reported success while recording nothing, so a delegation whose
  status id was a `urn:uuid:` read as live after revocation (SPEC.md §6.5 step
  1). `DelegationNode` gains an optional `revoked` flag, which revocation sets,
  restore clears, and `isRevoked` honours alongside the status bit, and
  `registerDelegation` accepts an optional structured `credentialStatus` so no
  id has to be parsed. A status id that names no list entry still registers
  and revokes without error, as before; it now also reads as revoked. Both
  fields are optional, so existing storage providers keep working. One that
  persists a fixed set of node fields must also store `revoked`: revocation
  reads the node back, and revoking a delegation that has no status list
  entry through a provider that dropped the mark now throws, naming that
  requirement, instead of reporting success while recording nothing. With an
  entry, the status bit still records it.

- **Registering a delegation id again cannot replace it.** `registerDelegation`
  overwrote the stored node whenever an id was registered again, dropping its
  `credentialStatusId`, revocation and children: re-registering a revoked
  ancestor read its whole subtree as live again, and re-registering a node
  under its own descendant left a parent cycle that `getChain` walked forever.
  A repeat registration that matches the stored node in every registered field
  (`parentId`, `issuerDid`, `subjectDid`, `credentialStatusId`,
  `credentialStatus`) is now a no-op that returns the stored node, children
  and revocation intact, so retries stay safe. One that differs in any of them
  throws, as does a delegation naming itself as parent, on the non-atomic path
  and in `MemoryDelegationGraphStorage.registerNodeAtomic`; the memory store's
  chain walk throws on a cycle. A custom `AtomicDelegationGraphStorageProvider`
  should apply the same rule, since only it can close the race between the
  manager's check and its write.

- **First status list creation is serialized with updates.** A status list was
  created on first allocation outside its update lock, so a concurrent
  allocation could replace a list that had just recorded a revocation with a
  fresh, empty one (SPEC.md §11.10). Creation now runs inside the list's lock
  and re-reads the list there.

- **`did:web` host labels cannot smuggle in another URL.** The host label is
  percent-decoded, and what it decoded to was used unchecked:
  `did:web:trusted.example%40attacker.example` fetched its document from
  `attacker.example`, and `%2F`, `%3F` and `%23` injected a path, query or
  fragment. A host that decodes to `@`, `/`, `\`, `?`, `#`, whitespace, a
  control character, or a `:` beyond one port separator (a bracketed IPv6
  literal keeps its own colons) is now rejected, as is a path component that
  decodes to a separator, a dot-segment or nothing (SPEC.md §4.4). A malformed
  escape returns `null` instead of throwing. Ports, IPv4 and IPv6 literals and
  percent-encoded internationalized hosts resolve as before.

- **Unreadable validity bounds fail closed.** An `expirationDate` that did not
  parse (`2020-02-30T25:00:00Z`) and a non-numeric `constraints.notAfter` or
  `notBefore` were read as no bound at all, so the credential never expired;
  a `notAfter` of `0` was skipped the same way. A present bound that cannot be
  read now places the credential outside its validity window. Basic checks
  also accepted any delegation `status` other than `revoked` and `expired`
  (`suspended`, or none), though the type allows only `active`, `revoked` and
  `expired`; only `active` passes now.

- **VC-JWT verification no longer throws on hostile input.** A JOSE header or
  claims set that is not a JSON object (`null`, an array), a `kid` that is not
  a string, and a DID resolver that throws all escaped `verifyDelegationJwt`
  as exceptions, so a caller outside a `try` recorded no rejection. Each now
  returns a failed result.

- **CIMD documents can no longer speak for another origin's DID.**
  `cardFromClientMetadata` accepted any declared `_meta["org.kya-os/did"]`,
  and `verifyCimdBind` took the DID from the DID document rather than the card,
  so a document at `https://attacker.example/clients/x` declaring
  `did:web:victim.example:clients:acme` produced a victim-id card whose bind
  check passed. `cardFromClientMetadata` now rejects a declared `did:web`
  whose origin (host and port) differs from the `client_id`'s. Every
  same-origin shape the CIMD draft allows still derives a card: a root with a
  trailing slash, a query, an explicit `:443`, a root DID declared on a path
  `client_id`, and a declared `did:key`. `verifyCimdBind(cimd, didDoc,
  expectedDid?)` takes an optional third argument (pass the card's `id`) and
  then also requires `didDoc.id` to be that DID and `client_id` to be its HTTPS
  form, compared as normalized URLs. Two-argument calls behave exactly as
  before, so they cannot detect a card/document mismatch.

- **`resolveCard` no longer conflates distinct `did:web` DIDs.** The identity
  binding percent-decoded each segment and rejoined with `:`, so
  `did:web:host:users:alice%3Aagent` accepted Alice's card
  `did:web:host:users:alice:agent`, and `did:web:host:8443` accepted a card for
  the port-form `did:web:host%3A8443`. DIDs are now compared in canonical
  encoded form: host lowercased, each segment decoded and re-encoded, so two
  spellings of one DID still match.

- **`MaxAmount` attenuation compares exact decimals.** Limits were truncated to
  six fractional digits, so `100.0000009` passed as a narrowing of `100`, and a
  child `0.0000009` under a parent `0.0000001` (both scaled to zero) passed
  too. Both limits are now scaled to the longer fraction and compared exactly
  (SPEC.md §6.10).

- **Audit checkpoints no longer sign a rewritten history.**
  `AuditCheckpointBuilder.createCheckpoint` compared the journal with the latest
  checkpoint only when both had the same tree size. A journal that had been
  rewritten or restored and had since grown got a new signed checkpoint chained
  to the old one, which it does not extend: a split view carrying the
  recorder's own signature. The builder now checks that the journal still holds
  the latest checkpoint's exact tree as its prefix and fails with
  `AUDIT_CHECKPOINT_CONFLICT` otherwise.

- **Audit verification policies are enforced instead of ignored.** The
  `validFromCheckpoint` / `validUntilCheckpoint` bounds (on recorder, observer,
  and exporter keys and on trusted ledger epochs), `requiredAuditProfile`, and
  `keyRevocationMode` were schema-valid but never read, so an entry signed after
  its key's validity boundary verified, and a bundle without checkpoints passed
  an AAP-4 policy with exit code 0. Checkpoint bounds now place each artifact by
  tree position against checkpoints resolved by digest; a bound that cannot be
  placed (a missing boundary, one in another epoch, or any bound on an exporter
  key, since an export has no ledger position) makes the dimension
  `indeterminate`, never `valid`. A required profile marks each dimension it
  depends on `invalid` unless it is `valid`. Under `keyRevocationMode`
  `current` or `both`, every signing key must also still be valid at
  `verifiedAt`, reported in `currentAuthorization` (`AUDIT_KEY_NOT_CURRENT`);
  `as_observed` is unchanged. Every policy that 1.16 accepted is still
  accepted; none is rejected for the constraints it uses.

- **A predecessor epoch ends at the terminal checkpoint its successor
  committed.** The bundle verifier only checked that the committed terminal
  checkpoint was present, so a stale authority that kept checkpointing the old
  epoch after rollover verified as valid. A predecessor checkpoint over a larger
  tree than that terminal now reports `AUDIT_CHECKPOINT_FORK_DETECTED`. Entries
  past the terminal alone are not a fork, since the terminal checkpoint's own
  `checkpoint.created` event follows it.

- **The recorder fails closed when its journal moves backwards.** After a
  failover to a lagging primary or a restore, `AuditRecorderService` appended on
  the lower head and signed a second, different entry at an already receipted
  sequence. A head read below this recorder's own commits is now raised to its
  committed head for the compare-and-append, so a stale read replica still only
  costs a retry, and a journal whose compare-and-append answer reports a head
  below that committed head, or a different digest at a sequence it already
  reported, fails with `AUDIT_JOURNAL_FAILURE` before anything is appended.

- **Hostile references can no longer keep an MCP audit event out of the
  ledger.** `McpAuditEventAdapter` truncated references by UTF-16 code units and
  passed context references through unbounded, so a presented credential ID
  with a lone surrogate, a split surrogate pair, or more than 256 characters
  made the event fail canonicalization or schema validation, even in
  best-effort mode, and a rejected delegation went unrecorded. Every caller
  reference, including `authorization.*` and correlation/causation IDs, is now
  kept verbatim when well-formed and within bounds, and otherwise recorded as
  the `sha256:` digest of its UTF-8 encoding. An over-long tool name or
  reference that 1.16 truncated is recorded as that digest instead.
  `wrapWithDelegation` still truncates a rejected credential's ID to 256 code
  units before the adapter sees it, as in 1.16.

- **A failed append no longer disposes evidence a committed entry still uses.**
  The recorder's cleanup after a failed append disposed every submitted
  evidence object, including one that already existed and that an earlier
  committed entry references (a session's shared actor object, for example).
  Only objects that the failed submission newly stored are disposed now, and
  never one that a concurrent submission to the same recorder held at the same
  time, since that submission may have committed a reference to it.

- **A projection built from a forked history is never reported verified.**
  `AuditProjectionWorker.reconcile` reported a lagging projection as `pending`
  without checking its offset digest, and `synchronize` appended entries that do
  not chain from that offset. Reconciliation now compares the offset with the
  journal entry at that sequence (`gap_detected` on mismatch), and
  synchronization fails with `AUDIT_PROJECTION_CONFLICT` instead of extending a
  foreign prefix.

### Fixed

- **A `requestHash` over the request as sent now verifies.** SPEC.md §7.3 and
  Appendix C.1 describe `requestHash` over the `tools/call` request, while the
  middleware hashes `{method: <tool name>, params: <arguments>}`, so a client
  recomputing the hash from the request it sent always got
  `CONTENT_BINDING_MISMATCH`, and a holder-of-key request proof minted that
  way never bound at the PEP. Every verifier of a received request hash now
  accepts either shape of the same call: `ProofVerifier` content binding,
  `ProofGenerator.verifyProof`, the holder-binding check of
  `wrapWithDelegation` and durable-grant resolution, and step-up approval
  grants in `withPolicyGate`. The caller may hold the request in either shape
  (`{method: "tools/call", params: {name, arguments}}` as sent, or the legacy
  shape), and both hashes are derived from it; the §7.3 shape leaves out
  `params._meta` and the `_kyaos*` control arguments. Producers are
  unchanged: response and outcome proofs, the `requestHash` of a
  `needs_approval` challenge, and `generateRequestProof` still emit the
  legacy shape, so verifiers of earlier releases keep accepting them. Each
  accepted hash covers the same tool name and business arguments, so no proof
  over a different call is admitted. §7.3 now states the control-argument and
  `_meta` exclusions, and Appendix C.1 gives covered-request vectors.
- **`fetchPublicKeyFromDID` resolves the `kid` proofs carry.** It prefixed `#`
  to every `kid`, so a full DID URL (`did:key:z…#z…`, the form this library
  mints) never matched. A DID URL `kid` must now name the DID being resolved
  (`KID_DID_MISMATCH` otherwise) and match the verification method id; a bare
  fragment is still resolved against the DID.
- **`MemoryResumeTokenStore` stays bounded.** A token is minted for every
  unauthorized call, and was deleted only when that exact token was read after
  it expired; fulfilled tokens were never deleted. `create()` now drops expired
  tokens and `fulfill()` deletes the token. A challenge's `expiresAt` is now
  the expiry the store enforces, read back from the store: it came from
  `authorization.resumeTokenTtl`, so a configured hour was advertised for a
  token the default store expires after 10 minutes. `resumeTokenTtl` is now
  the fallback for a store that cannot report a future expiry in
  milliseconds.
- **Expired sessions no longer switch off the single-session fallback.** The
  fallback counted every stored session, live or expired, and nothing swept
  them, so once a second session had existed proofs stopped for every
  unthreaded call. A count above one now sweeps expired sessions first (at
  most once a minute). Concurrent first calls under `autoSession` share one
  auto-created session instead of racing into two.
- **Proofs keep handler `_meta` keys.** Attaching a proof, or a `proofError`
  in the middleware or the transport, replaced `_meta` and dropped keys such
  as `traceparent` and `io.modelcontextprotocol/related-task`. They are now
  merged (SPEC.md §7.6). The proof, `proofError` and `org.kya-os/audit`
  members are the exception: only the middleware sets them, so a handler's
  copies are still dropped when a proof or proof error is attached, and a
  relayed upstream result cannot place them next to this server's proof.
- **The transport matches proofs to responses only.** A server-initiated
  request (for example `elicitation/create`) whose id equalled a pending
  `tools/call` id consumed that call's entry, and the tool response shipped
  unproven. Entries for cancelled calls are also dropped on
  `notifications/cancelled`.
- **SPEC.md: nonce retention is bounded by the acceptance window.** §5.2, §5.5
  and §11.2 required nonces to be kept for the session TTL plus a minute,
  while §5.2 also recommended 60 seconds. A nonce presented after its
  timestamp leaves the acceptance window is rejected on that timestamp, so the
  longer retention bought memory and denial-of-service exposure and no
  protection. §5.5 now requires retention until `ts + skew` plus a margin, for
  the widest skew the verifier may apply, which is what the reference
  implementation already does, and says why the bound holds on every
  nonce-checked path. CONFORMANCE.md L2.5 follows, and L2.11 describes the
  per-proof nonce and both request-hash shapes.
- **In-memory replay and pending-flow stores evict on their own.**
  `MemoryNonceCacheProvider`, the default replay store for `withKyaOs` and
  `SessionManager`, and `MemoryPendingFlowStore` freed expired entries only on
  an explicit `cleanup()`, which nothing schedules, so every handshake nonce
  and abandoned authorization flow stayed resident. Both now sweep expired
  entries as they are written to: every 1000 writes, or after a minute. A live
  entry is never swept, and `cleanup()` works as before.
- **`@kya-os/mcp/providers` bundles for browsers and Workers again.** The
  entry documented for `WebCryptoProvider` also exports `NodeCryptoProvider`,
  which imported `node:crypto` at module load and broke every browser bundle.
  `node:crypto` now loads on first use; the exports are unchanged.
- **cheqd DLR content hashes are always computed.** `prepareCheqdDlrResource`
  returned a caller-supplied `contentHash` as the artifact's content address
  without checking it against the bytes being anchored. The hash is now
  always computed from the canonical content bytes, and a supplied one that
  differs throws. Canonicalization of the content is unchanged.

- **Status list indexes stay inside the list.** `updateStatus` parsed
  `statusListIndex` with `parseInt`, so revoking `"5abc"` flipped bit 5, which
  belongs to another credential, while `checkStatus` already parsed strictly.
  Both now share the strict parser. `allocateStatusEntry` also handed out
  indexes past the end of the list, which no read or revocation could reach;
  it now throws once the list is full (SPEC.md §6.7).

- **A status list with an unreadable validity window is not fresh.** A
  `validUntil` / `validFrom` (or `expirationDate` / `issuanceDate`) that was
  present but not a parseable date was treated as absent, so the list read as
  live. It now reads as not fresh (L3 → L2); the revocation bit is still read.

- **Card schemas match the published JSON Schemas.** `CapabilityAttestation`
  stripped unknown members (the JSON Schema allows them), dropping sidecar
  fields such as `credentialStatus` before the capability verifier saw them;
  extra members are now preserved. `DelegationCredentialSchema.type` accepted
  any string array; it now requires `VerifiableCredential` and
  `DelegationCredential`, so another VC with a ZCAP-shaped subject is not read
  as a delegation hop. `schemas/card-delegation-credential.json` enforces the
  same two types it already documented.

- **`getInclusionProof` works for sequence 1.** The entry lookup started its
  range read after sequence 1 for any sequence up to 1, so the first entry after
  genesis could never be proven.

- **`listEntries` pages are bounded by the head they echo.** The head was read
  after the page, so a concurrent append could return `nextAfterSequence: null`
  with a head beyond the last entry, contrary to SPEC-AUDIT-READ §2.2. The head
  is now read first and bounds the page.

- **Subset replay bundles verify.** A checkpoint was verified only against every
  leaf of its tree, and included checkpoints had to link directly, so a
  legitimate export of a sequence range or of non-adjacent checkpoints was
  invalid. Without its complete prefix, a checkpoint is now verified by
  signature, digest, trust, and declared range, and each covered entry needs a
  verified inclusion proof (`AUDIT_MERKLE_PROOF_MISSING` otherwise).
  Checkpoints that could have omitted ones between them may be bound by a
  verified consistency proof instead of a direct `previousCheckpointDigest`
  link, the rule independent observers already apply.

- **Concurrent checkpoints on one builder chain in order.** Two concurrent
  `createCheckpoint` calls at different sizes could both chain to the same
  predecessor. A builder now serializes its calls per ledger epoch. The
  `AuditCheckpointStore` contract is unchanged.

- **A failed checkpoint lifecycle hook runs again.** When `onCheckpointCreated`
  threw after the checkpoint was stored, a retry returned the stored checkpoint
  without calling the hook, losing the lifecycle event. The builder's next
  `createCheckpoint` call now runs the hook again for every checkpoint whose
  hook failed, oldest first and before any newer checkpoint's, even when the
  ledger has grown in between; the hook should be idempotent on the checkpoint
  digest. A hook that completed is not repeated.

- **A future-dated observation is not fresh.** With a freshness requirement,
  an observation dated after `verifiedAt` passed. One dated beyond the clock
  skew allowance (`maxClockSkewMs`, default 120 s) is now `invalid` with
  `AUDIT_OBSERVATION_FUTURE_DATED`.

- **Redelivering a stable event ID returns the original receipt.**
  `MemoryAuditSourceState` dropped the claims of receipted events, so an
  at-least-once redelivery after later events got a new source sequence and was
  rejected as `AUDIT_EVENT_ID_CONFLICT`. Receipted claims are now retained for a
  bounded `redeliveryWindow` (default 1024 per source). Different content under
  a retained event ID is still an `AuditProtocolError` with
  `AUDIT_EVENT_ID_CONFLICT`, now raised by the source state; it was a plain
  `Error` there before.

- **Rejected input no longer consumes a source sequence.** The trail claimed a
  source sequence before validating the event, so schema-invalid input, a lone
  surrogate, or an unreferenced evidence object left a permanent gap and a
  broken `previousSourceEventDigest` link. Validation now runs first, and a
  claim whose event cannot be emitted is released through the optional
  `abandonClaim`.

- **Source state no longer leaks behind an open gap.** One unreceipted sequence
  stopped `MemoryAuditSourceState` from pruning anything after it. It now keeps
  only pending events plus the redelivery window.

- **A replica that loses the cold-start genesis race recovers.** When every read
  was stale, the losing genesis surfaced as an idempotency conflict and failed
  with `AUDIT_EVENT_ID_CONFLICT`; it is now validated against the epoch
  configuration like any raced genesis.

- **A committed outbox item is never reported as a delivery failure.** If
  `markDelivered` threw after the recorder committed, `flush()` called
  `markFailed` and `onDeliveryFailure`. The item now counts as delivered, the
  error goes to the new `onAcknowledgementFailure` callback, and redelivery
  resolves to the same receipt.

- **Outbox items are identified by source and event ID.** Event IDs are unique
  only within a source, but `MemoryAuditOutbox` keyed items by event ID alone,
  so one source could acknowledge or displace another's pending item.
  `markDelivered` and `markFailed` now accept an `AuditOutboxItemKey` as well as
  a bare event ID, and the trail passes the key to an outbox that declares
  `capabilities.keyedBySource`, as `MemoryAuditOutbox` now does. An adapter
  that implements `markDelivered(eventId: string)` still type-checks and still
  receives the bare event ID, and so does a `MemoryAuditOutbox` subclass that
  overrides `markDelivered` or `markFailed`: the memory outbox declares the
  capability only for its own implementations, unless the subclass declares it
  again. `MemoryAuditOutbox` throws on a bare event ID that more than one source
  has pending instead of guessing.

- **Default audit event IDs are random.** `audit_<time>_<counter>` was unique
  only per trail instance, so two trails sharing an outbox collided. Defaults
  are now `audit_<uuid>`; `eventIdFactory` still overrides them.

### Deprecated

- **The legacy request-hash shape.** `requestHash` over
  `{method: <tool name>, params: <arguments>}` is deprecated in favour of the
  SPEC.md §7.3 covered `tools/call` request. Producers switch to the §7.3
  shape in 2.0.0; verifiers accept both until then.
- `ProofVerifier.verifyProofDetached`. The payload it takes must now equal the
  payload rebuilt from `proof.meta`, so it adds nothing over `verifyProof`.

## [1.16.2] - 2026-09-21

### Changed

- **`schemas/delegation-credential.json` accepts a Bitstring status entry.**
  Its `CredentialStatus` definition pinned `type` to `StatusList2021Entry`
  with `id` required, while `card-delegation-credential.json` and the
  TypeScript type (1.16.1) already describe the Bitstring Status List v1.0
  entry. The published schema now admits either `type` and makes `id`
  optional, so a credential carrying a Bitstring entry validates against the
  same schema the runtime parser accepts.

## [1.16.1] - 2026-09-21

### Changed

- **`CredentialStatus` matches the wire schema.** The TypeScript type said
  `type: 'StatusList2021Entry'` with `id` required, while
  `DelegationCredentialStatusSchema` has accepted `BitstringStatusListEntry`
  (the StatusList2021 successor) with `id` optional. The type now admits
  either `type` and makes `id` optional, so a wallet can stamp a Bitstring
  entry without casting. `statusPurpose` stays required: both specs require
  it and the purpose-parity check depends on it. Nothing on the wire changes.

## [1.16.0] - 2026-09-19

### Added

- **`path-prefix` CRISP scope matcher.** `prefix` is character-level and right
  for scope identifiers, but applied to a resource path it lets a grant for
  `notes` authorize `notesx/secret.md`. `path-prefix` matches the path itself
  or anything beneath it as a `/`-separated path, with an optional trailing `/`
  or `/*`; an empty base grants nothing. Added to `matchScope`, the `CrispScope`
  type, `schemas/delegation-credential.json`, and SPEC.md §6.3/§6.4.1.

### Fixed

- **`DelegationVCVerificationResult.stage` names the failing check.** A failed
  verdict from `verifyDelegationCredential` / `verifyDelegationJwt` reported
  `stage: "complete"` once both the signature and status checks had run, leaving
  only the `checks` flags to say which one failed. It now reports `"signature"` or
  `"status"`; `"complete"` accompanies `valid: true` only.
- The revocation reason names the status method on the credential
  (`Credential revoked via <credentialStatus.type> (…)`) instead of always
  saying `StatusList2021`.
- `schemas/well-known-mcpi.json`: `version` accepts the three-part protocol
  version the reference implementation advertises (`1.0.0`); `endpoints.handshake`
  is no longer required — it belongs to the legacy 1.x session profile
  (SPEC-MCP-EXTENSION.md §4).

### Documentation

- SPEC.md §10: the discovery example now validates against the schema
  (`serverDid`, not `did`; schema capability names; `statusListCredential`;
  camelCase advisory fields) and says when `endpoints.handshake` applies.
- CONFORMANCE.md: names the three ladders (Core L1–L3, Card L1–L3, AAP-0–4) and
  asks claims to say which; the Entity Card section uses the terminal `_meta`
  key names (`org.kya-os/response-proof`, `org.kya-os/request-proof` carrying
  `prf: "org.kya-os/proof.v1"`).

## [1.15.0] - 2026-08-25

### Added

- **Response-proof `envelope` profile** (`org.kya-os/response-proof.envelope`).
  The `body` profile binds `responseHash` over the response body only, leaving
  result members such as `structuredContent`, `isError` and `resultType`
  unauthenticated - an in-path intermediary could rewrite them under a still
  valid proof. The envelope profile covers the ENTIRE result object with the
  top-level `_meta` member removed, mirroring the request side's
  `{method, params minus _meta}` rule, so every present and future result
  member is authenticated while `_meta` stays intermediary-mutable (which is
  what keeps attach-after-sign sound). The profile is discriminated by a `prf`
  claim COVERED by the JWS signature, so a proof cannot be silently downgraded
  to body semantics, and `validateDetachedProof` rejects unknown `prf` values
  fail-closed. Verification always derives the profile from the proof's own
  claim, never from configuration, so one verifier accepts both.
- **Conformance vector-set immutability.** `conformance/SUITE-MANIFEST.json`
  pins the vector set by hash, `scripts/suite-hash.mjs` computes and checks it,
  and CI enforces it as its own line - a published vector set can no longer be
  edited in place without the check failing. Suite is at 1.1.0.
- **`DEPRECATIONS.md`** - an internal ledger of deferred breaking changes.

### Fixed

- **Sessionless request proofs now bind.** `generateRequestProof` defaulted
  `meta.sessionId` to `''` when the caller omitted it, but `sessionId` is a
  required non-empty string in the proof meta schema, so the proof failed
  validation as `INVALID_PROOF_STRUCTURE` and `assertHolderBinding` returned
  `unbound` for the LEGITIMATE holder - indistinguishable from the thief the
  gate exists to catch. `sessionId` is documented as optional and a request
  proof routinely precedes any handshake on a stateless core, so this was the
  normal path rather than an edge case. It failed closed (nothing was wrongly
  admitted), but phase-1 holder binding was unusable without a `sessionId` the
  signature never said was mandatory. A per-proof id is now minted when none is
  supplied; verification, the schema and the conformance vectors are unchanged.
- The `prf` claim is derived only from the profile option, and the proof schema
  id is bumped accordingly.
- A challenge proof that the degraded-audit `isError` flip would have broken is
  now stripped rather than emitted.
- `suite-hash` hashes the committed blob bytes rather than the working tree, so
  a dirty checkout cannot produce a passing hash.

### Changed

- **Response-proof profiles are named by mechanism, not sequence**:
  `org.kya-os/response-proof.v2` -> `.envelope`, `.v1` -> `.body`, and
  `RESPONSE_PROOF_PROFILE_V2`/`_V1` -> `_ENVELOPE`/`_BODY`. The sequence
  framing was wrong on its own terms - original proofs carry no profile
  identifier at all, so the first wire identifier would have debuted as `.v2`
  naming a v1 that never existed. **No published API changes**: these
  identifiers and constants are new in this release and never shipped in
  1.14.2, so nothing downstream can be pinned to the old names. The
  request-proof profile keeps its shipped `org.kya-os/proof.v1` name.
- Conformance vectors use semantic names and a more robust signature-tamper
  case.
- Dependency bumps across the minor-and-patch group.
- README restructures `did:cheqd` into a hierarchical Integrations section.

## [1.14.2] - 2026-08-19

### Fixed

- VC-JWT (string) delegations are now verified by their envelope signature in
  the delegation gate before authorization, matching the embedded-proof (object)
  path. Existing object and signed `did:key` VC-JWT flows are unaffected.

## [1.14.1] - 2026-08-15

### Fixed

- **Fresh installs no longer break on `json-canonicalize`.** The dependency is
  now pinned to `2.0.0` exactly. The upstream `2.0.1` publish ships raw
  TypeScript sources with no compiled JavaScript (its `main` points at a
  nonexistent path), so any install resolving `^2.0.0` without a lockfile -
  every new adopter - got a package that cannot be imported. Pinning restores
  installability for `@kya-os/mcp` and everything downstream of it. The pin
  can be relaxed once upstream publishes a corrected release.

## [1.14.0] - 2026-08-13

### Added

- **`CheqdStatusListResolver`** (`@kya-os/mcp/cheqd`) — on-chain StatusList2021
  revocation checks against a cheqd DID-Linked Resource, upstreamed from the
  DEF CON 34 "REVOKED" demo as a thin consumer of the shared primitives. The
  only status-list reader that verifies the LIST itself: issuer pinned to
  `expectedIssuerDid` and the Ed25519Signature2020 proof checked against the
  issuer's on-chain DID document ("the resolver returned it" is never
  sufficient). Fail-closed on every unprovable path (the delegation verifier
  denies as `status_unresolvable`); internal verified-document `TtlCache`
  (default 10 s, `invalidateCache()` busts upstream HTTP caches) composable
  with `withStatusCache` for per-bit staleness SLAs; version-independent
  resolver URLs with header-only cache-busting (the cheqd resolver 400s on
  query params — verified live).
- **Multibase verification-method keys.** Both delegation signature paths
  (Data Integrity and VC-JWT) now accept verification methods that publish
  `publicKeyMultibase` (base58btc Ed25519, with or without the 0xed01
  multicodec prefix) or legacy `publicKeyBase58`, synthesizing the OKP JWK at
  the point of use — did:cheqd issuers verify end-to-end without a
  JWK-rewriting resolver. Fail-closed: anything not provably a 32-byte
  Ed25519 key still denies.
- **`StatusListCredential` DLR artifact type.** `prepareCheqdDlrResource`
  now anchors status lists: the artifact's `content` is the WHOLE SIGNED
  StatusList2021 credential (hash-what-you-publish — the canonical bytes
  anchored on-chain are exactly the credential a verifier fetches), so
  content hashes remain byte-compatible with resources already anchored via
  the DEF CON demo's vendored publisher. Anchor-fitness is enforced by the
  new method-agnostic `assertAnchorableStatusListCredential` guard in
  `utils/statuslist-bits` (refuses unsigned or bitstring-less lists).

### Changed

- **Status-list reading mechanics consolidated into `utils/statuslist-bits`.**
  Canonical index parsing, the 16 MiB inflation cap, multibase/base64url
  payload decoding, and the MSB-first bit read previously existed as separate
  copies in the delegation readers (`bitstring.ts`, `statuslist-manager.ts`)
  and the card revocation reader (`card/revocation.ts`) — held in sync only by
  source comments. One shared implementation now serves both seams; each
  seam's policy (throw → `status_unresolvable` vs `FAIL_CLOSED`, freshness)
  is unchanged. Behavior-preserving: every existing test passes unmodified.

### Deprecated

- **`RevocationChecker` (card module).** Renamed to
  `BitstringRevocationChecker` — the old name collided with the
  delegation-side `RevocationChecker` interface (`chain-enforcement.ts`), two
  identically named exports answering different questions. The old name
  remains as a deprecated alias until 2.0.

## [1.13.0] - 2026-08-12

### Security

- **Delegation verifier: revocation status and expiry are now evaluated on
  every verification.** The per-instance cache previously stored the entire
  verdict for `cacheTtl` (default 60 s), so a cache hit skipped the
  credential-status check — a revoked credential kept verifying (and, on the
  Data Integrity path, an expired one) until the entry lapsed. The cache now
  holds only the signature/DID-validity result; basic checks and revocation
  status run on every call, with signature and status still checked in
  parallel. Warm-path latency now includes one status read — freshness policy
  belongs in your `StatusListResolver`, never in the verdict. The `cached`
  result flag now means "signature served from cache".

### Added

- **`withStatusCache(resolver, { maxStalenessMs, maxEntries? })`** — wraps any
  `StatusListResolver` to cache status *bits* for an explicitly declared
  staleness bound: the deployment names its revocation SLA instead of
  inheriting a silent verdict cache. Throws are never cached (fail-closed
  retry); `maxStalenessMs: 0` is a pass-through.
- **`delegation.verificationCache` middleware config** (`{ ttlMs, maxEntries }`)
  tuning the signature-verification cache; `ttlMs: 0` disables signature
  caching (immediate issuer key-rotation pickup). Constructor `cacheTtl: 0`
  is now honored (`??`, previously swallowed by `||`), and
  `createDelegationVerifier` gains `maxCacheSize` parity.

## [1.12.0] - 2026-08-04

### Added

- **MCP `2026-07-28` extension binding: `org.kya-os/decentralized-authority`.**
  Per-request admission via `requireExtension`, capability declaration via
  `buildExtensionsEntry`, and a hand-rolled `server/discover` advertisement
  (SEP-2133). Required mode rejects a non-declaring client with the core
  `-32021` error carrying the `requiredCapabilities` member; discovery and ping
  are exempt from the gate.
- **Audit operator read/replay contract and a reference recorder.**

### Changed

- **Terminal proof-key naming.** Role-named `_meta` carriers
  `org.kya-os/request-proof` and `org.kya-os/response-proof`, with the profile
  version carried in the `org.kya-os/proof.v1` profile id. The legacy keys and
  `prf` value (`org.kya-os/proof@1`, `org.kya-os/proof`) are read-accepted for
  one major version, so existing producers and verifiers keep working.

## [1.11.0] - 2026-07-22

### Added

- **Verifiable auditability protocol and `@kya-os/mcp/audit`.** Adds strict,
  versioned, privacy-minimal events; an authoritative recorder with signed
  append receipts, atomic compare-and-append, logical-ledger idempotency, and
  epoch transitions; producer delivery modes and source high-water evidence;
  RFC 9162 Merkle checkpoints, inclusion/consistency proofs, independent
  observation, and supporting anchors; encrypted evidence lifecycle; pure
  historical verification; signed replay bundles; rebuildable projections; and
  the `kya-audit` offline verification CLI.
- **Provider contract kit.** `@kya-os/mcp/audit/testing` supplies executable,
  framework-neutral journal, evidence, observer, and anchor contracts. Memory
  reference providers cover concurrency, stale heads, duplicates, snapshots,
  legal holds, disposal, observation conflicts, and role separation.
- **MCP audit instrumentation and capability discovery.** Typed lifecycle events
  cover calls, errors, denials, step-up/authorization challenges, handshake
  rejection, replay rejection, consent/credential/key/config/policy changes,
  checkpoints, evidence, projections, exports, retention, and administration.
- **Audit schemas and conformance.** Publishes JSON Schemas for all portable
  audit artifacts, an `audit-integrity` vector category, independent Python
  verification of audit JCS/domain-separated hashes/RFC 9162 proofs, an
  end-to-end walkthrough, and the normative `AUDITABILITY.md` operations guide.

### Fixed

- **Entity Card spec corrections from working-group review.** Three defects raised
  against SPEC-ENTITY-CARD.md are resolved. (1) The Status section said the
  `org.kya-os/proof@1` and legacy proofs share one `_meta` key discriminated by
  `prf`; they ride separate keys (`org.kya-os/proof@1` vs `org.kya-os/proof`), as
  §8.1 and the implementation always had it, and the Status text now matches.
  (2) §8.3 now specifies the exact pre-signing transformation for `requestHash`:
  the `_meta` member of `params` (the proof's own carrier) is removed before JCS
  canonicalization, on both the mint and verify sides. Without that rule the
  definition was circular for MCP requests, where the proof travels inside
  `params._meta`. (3) Terminology now distinguishes the self-contained proof
  object from stateful replay prevention: a verifier still needs a nonce store
  and fails closed (`nonce_seam_missing`) without one, so the spec no longer
  describes verification as stateless.
- **`computeRequestHash` applies the §8.3 transformation itself.** The card
  hasher removes `params._meta` before canonicalizing, so a verifier handed the
  raw inbound request (proof still attached) recomputes the hash the minter
  signed instead of failing on a self-referential body. Requests without
  `params._meta` hash byte-identically to before; all golden vectors are
  unchanged.
- Historical proof verification no longer consumes live nonce state or applies
  present-time freshness rules, and protected JWS `kid` values are bound to the
  expected verification key.
- Failed child-delegation registration can no longer leave an orphan graph node,
  and cached VC results cannot be reused across differing trust/status inputs.

### Changed

- **SPEC-ENTITY-CARD.md editorial pass.** Tightened the abstract and framing
  sections, replaced em dashes with plain punctuation throughout, clarified that
  a declared capability name conveys no authority (authority travels only in the
  delegation chain), noted that a verifying resource should assert itself as the
  expected `invocationTarget` when evaluating a chain, and updated the
  reference-implementation version pointer.
- **The delegation profile moved into the core specification's delegation
  chapter.** Working-group review made the case that an extended description of
  delegation does not belong in the Entity Card specification: the card asserts
  locators, so the card document should point at the delegation profile rather
  than contain it. SPEC-ENTITY-CARD.md section 10 is now a compact section
  holding only what card verification consumes directly (the two recomputed
  accountability equalities, the meaning of the `revocation` field, and the
  KYC/KYB surface). The full profile (the VC 2.0 + ZCAP-LD credential shape,
  delegate rules, attenuation invariants, Bitstring revocation mechanics, and
  the KYC/KYB shape) now lives in SPEC.md section 6.10, beside the legacy
  credential shape it succeeds, so delegation has one home. The chain
  attenuation rules are now called attenuation invariants to end a naming
  collision with the CRISP constraint envelope of SPEC.md section 6.3. Content
  moved verbatim; wire shapes, schemas, and all other section numbering are
  unchanged, and every cross-reference was updated. A candidate card field
  naming the access-control mechanisms an entity supports is recorded as an
  open coordination item (section 15.7).
- Proof generation now uses a fresh cryptographic nonce for every proof artifact
  while preserving the session nonce as session-establishment evidence.
- Canonical JSON handling is shared and strict RFC 8785, rejecting unsafe
  integers, cycles, sparse arrays, accessors, and unsupported values before
  hashing or signing.
- Delegation graph registration supports atomic parent validation, status-list
  history is retained for historical decisions, and VC verification cache keys
  bind all decision inputs.
- Replayed handshake nonces now report the precise `nonce_replay` protocol code,
  allowing audit instrumentation to classify replay rejection independently.

## [1.10.1] - 2026-07-08

### Fixed

- **Cloudflare Worker / workerd bundle compatibility.** `safe-fetch-transports`
  statically imported `node:dns/promises` and `node:https` at the module top
  level, so anything that builds a `SafeFetch` — including the Entity Card /
  VC-JWT verification path (card resolution + status-list revocation) — required
  those node built-ins at bundle time and broke workerd builds. They now load
  **lazily** (only when a node code path actually runs), so the module bundles
  cleanly for workerd / browser. `selectDefaultTransport` transparently falls
  back to `fetchTransport` where `node:https` is absent. The SSRF policy
  (resolve-and-pin, private-range denial, redirect + size + timeout guards) is
  unchanged; a Worker injects its own DNS seam (or uses trusted origins +
  `fetchTransport`) to avoid `node:dns` at runtime.

## [1.10.0] - 2026-07-08

### Added

- **`ProofGenerator` accepts a non-extractable signing key.**
  `ProofAgentIdentity.privateKey` and `KyaOsIdentityConfig.privateKey` now
  accept a `CryptoKey` handle in addition to a base64 private-key string. A
  non-extractable WebCrypto key (e.g. a passkey-PRF-derived or HSM/KMS-fronted
  key) can now produce `org.kya-os/proof` proofs without the secret ever being
  materialized by the caller — realizing the signer-hook model the spec already
  describes (§4.5) — end-to-end through `withKyaOs`. Both key forms yield an
  equally valid, verifier-accepted proof. Backward-compatible: existing string
  keys are unaffected (the string path is byte-for-byte unchanged); the only
  source-level impact is that external code which reads `.privateKey` expecting
  a `string` now sees a `string | CryptoKey` union.

## [1.9.0] - 2026-07-07

Entity Card (`@kya-os/mcp/card`) — a typed, DID-anchored, per-request
holder-of-key identity layer that rides existing rails (MCP server-card `_meta`,
A2A extension, NANDA AgentFacts) instead of a new well-known doc. Additive.

First npm release since 1.7.0 (the prepared 1.8.0 was never published). See the
BREAKING status-list note below — persisted 1.x status lists MUST be
regenerated on upgrade.

### Added

- **`./card`** — the `card()` builder, `withKyaOsCard` / `requireProof`
  middleware, and `buildCard` / `resolveCard` / `verifyCard`. Conformance is
  recomputed on verify, never self-claimed.
- **Stateless proof (`org.kya-os/proof@1`)** and a **VC 2.0 / ZCAP-LD**
  delegation profile with Bitstring Status List v1.0 revocation. Both run
  alongside the legacy session proof + delegation for all of 1.x; the legacy
  paths drop at 2.0.
- **CIMD L1 on-ramp** — `client_id ⇄ did:web`, so an OAuth `private_key_jwt`
  doubles as a DID-key proof (RFC 9449 `cnf.jkt` sender-constrains it).
- Conformance vectors + a cross-language verifier folded into the existing
  `conformance/` harness (new `card-proof` / `entity-card` categories).
- **Proof crypto agility (`ES256`)** — the per-request proof now accepts an
  ALLOW-LIST of two signing algorithms, `EdDSA` (Ed25519) and `ES256` (ECDSA
  P-256, FIPS-eligible via HSM/KMS), never negotiated. `alg` is a signed covered
  claim and the resolved key type MUST match it (`alg_key_mismatch`), so adding a
  second curve introduces no algorithm-confusion surface. `es256SignerFromJwk`
  ships alongside `ed25519SignerFromJwk`; the RFC 9421 sibling carries the
  matching `ecdsa-p256-sha256` label. (CIMD DID-keyed JWKS extraction stays
  Ed25519-only for now — a P-256 verifier supplies its own `resolveDidKeys`.)
- **VC-JWT verification (`./delegation`)** — `DelegationCredentialVerifier.verifyDelegationJwt()`
  verifies the JWT serialization of a Verifiable Credential (compact JWS, where
  the envelope signature over `header.payload` IS the proof — no embedded
  `proof` block), so credentials minted by browser / passkey wallets verify
  without a hand-rolled path. `algorithms` is pinned to `EdDSA`, and the
  credential `issuer` must equal the signed `iss`. Additive; the Data Integrity
  path is unchanged.
- **Multi-key did:web documents** — `buildDidWebDocument` now accepts
  `Identity | Identity[]`, emitting one verification method per key under a
  single controller DID. This is the basis for multi-device identity: a device
  is added or removed by adding or removing a verification method, and a
  verifier selects the signing key by `kid`. Backward-compatible — a lone
  identity yields the same single-method document as before.

### Changed — BREAKING for persisted status lists

- **Status-list bit order corrected to W3C MSB-first.** `BitstringManager`
  (StatusList2021 / Bitstring Status List) now reads and writes bits
  most-significant-first (`0x80 >> i`), matching the W3C spec and the Digital
  Bazaar reference — and the Entity Card revocation reader — so both code paths
  read an identical `encodedList` to the same verdict. The prior LSB-first order
  was self-consistent but non-interoperable with any standard tool.
  - **⚠️ MIGRATION — READ THIS.** A status list generated by a 1.x release is
    encoded LSB-first. Read by this release it is **misread silently**: a
    **revoked credential can read as LIVE** (the bit mirrors within its byte, so
    e.g. revoked index 42 → clear, and phantom index 45 → revoked). The W3C
    credential carries no bit-order/version field, so old lists **cannot be
    auto-detected**. You MUST **regenerate every persisted status list** on
    upgrade; do not read 1.x-encoded lists with this release. (Tracking a
    KYA-OS-side encoding-version marker + a bit-reverse migration helper as a
    follow-up so future changes are detectable.)
- **Fail-closed hardening.** `isIndexSet` / `BitstringManager.getBit` now throw
  on an out-of-range or `NaN` index (were fail-open), `BitstringManager.decode`
  caps the inflated bitstring at 16 MiB (decompression-bomb guard), and the card
  `statusListIndex` must be a canonical decimal (a whitespace/hex value no longer
  silently reads bit 0). IPv6 NAT64 / 6to4 / Teredo / site-local addresses are
  now treated as non-public by the SSRF guard.

## [1.7.0] - 2026-06-17

Durable consent persistence. Pluggable `GrantStore` / `PendingFlowStore` /
`SessionStore` seams so consent, grant, and PKCE state survive restarts and
resolve across load-balanced instances — the holder-of-key (`getByAgent`)
no-paste retry, with session-bearer (`getBySession`) as a fallback. The detached
proof is namespaced under `_meta["org.kya-os/proof"]` and still dual-emitted
under the legacy bare key (ON for all of 1.x, dropped at 2.0). Additive over
1.6.x, with one documented behavioral change: a `strict` verifier now ignores
MCP-reserved foreign `_meta` keys instead of rejecting them.

### Added

- **Durable consent persistence (optional, in-memory defaults — no breaking
  change).** New pluggable seams so consent / grant / PKCE state survives
  restarts and resolves across load-balanced instances: `grantStore` (the
  no-paste retry — holder-of-key `getByAgent` first, then session-bearer
  `getBySession`), `PendingFlowStore` (durable OAuth/OIDC PKCE state with an
  atomic `consume()`), and an optional `SessionStore`. The detached proof is now
  namespaced under `_meta["org.kya-os/proof"]`; the legacy bare `proof` key is
  still accepted on verify and (by default) still emitted — toggle with
  `emitLegacyProofKey`. The legacy mirror stays **ON by default for the entire
  1.x line** (a pre-1.1 reader of bare `_meta.proof` would otherwise silently get
  no proof; the cost is ~1.5 KB of `_meta`, which is outside the response hash)
  and will be **dropped at 2.0**.

### Changed

- **BEHAVIORAL — `strict` `metaPolicy` now IGNORES foreign `_meta` keys instead
  of rejecting them.** Previously a `strict` verifier rejected any `_meta` key
  other than the proof. Under MCP 2026-07-28 (SEP-414) `_meta` legitimately
  carries reserved `io.modelcontextprotocol/*` and W3C trace-context keys
  (`traceparent`/`tracestate`/`baggage`), so `strict` now ignores every
  non-KYA-OS key (never hashed, trusted, or rejected) and `allow-extensions`
  additionally surfaces them. The zero-trust boundary is unchanged — only the
  KYA-OS proof key is ever hashed or trusted. **Migration:** anyone relying on
  `strict` to REJECT foreign `_meta` keys must now enforce that themselves; the
  verifier no longer fails on them.

### Fixed

- **Appendix A error codes corrected** to match `src/errors.ts`, the single
  source of truth. The table listed prefixed codes (`KYA_OS_EHANDSHAKE`,
  `KYA_OS_EPROOF`, ...) that no part of the codebase emits; the runtime,
  middleware, and session manager all return bare snake_case codes
  (`handshake_failed`, `invalid_proof`, ...). Documentation only — no behaviour
  change.

## [1.6.1] - 2026-06-10

Releases the schema-host migration already merged on `main` (it was unshipped:
`1.6.0` still carried the prior host). Schema-only; no code or API changes.

### Changed

- **Schema `$id` and JSON-LD `@context` hosts migrated** to the DIF-registered
  `schema.kya-os.org` — now live. All five shipped JSON Schemas
  (`schemas/*.json`), the spec's context references, and the
  `DELEGATION_CREDENTIAL_CONTEXT` constant resolve under `schema.kya-os.org`.
  The prior `schema.kya-os.ai` host served the same documents during the
  migration window; no `$id` is 301-redirected. Consumers that pinned a
  `schema.kya-os.ai` `$id` should update to `schema.kya-os.org`.

## [1.6.0] - 2026-06-03

Advances the E3 verifier-consolidation groundwork and hardens the delegation
gate: an isomorphic WebCrypto provider so the proof verifier can run on edge
runtimes without `node:crypto`, the delegation chain-enforcement rules lifted
into a framework-agnostic core reusable by any host, and holder-of-key binding
enforced at the inbound gate. Additive over 1.5.x.

### Added

- `./authz` authorization seam: a neutral, method-agnostic
  `AuthorizationServerAdapter` port with a shared dispatch predicate, an
  `AuthorizationServerRegistry` that routes a tool's protection to one adapter,
  and a generic-OIDC reference adapter under `authz/oidc/` (mandatory S256 PKCE,
  RFC 8707 resource binding, injectable fetch seam — no named vendor IdP, per
  the donation's vendor-neutrality). The `AuthorizationRequirement` union
  (`oauth`/`mdl`/`idv`/`credential`/`none`) anticipates further adapters as
  siblings of `oidc/`.
- `AccountabilityContext` projection (agent → accountable-admin → user →
  intent) that feeds the policy principal's `responsibleParty`; `orgRootDid` is
  a forward-compatible slot pending the organization root identity.
- A deterministic, network-free in-memory OIDC example exercising the full
  authorization path. Additive; no new runtime dependency (zod, jose, Web
  Crypto only).
- `GrantStore` provider + `MemoryGrantStore` reference implementation: the
  post-approval counterpart to `ResumeTokenStore`. A grant binds to the agent
  DID (durable authority) and optionally to a session (the confused-deputy-safe,
  no-paste retry convenience — a grant bound to one session is never returned to
  another). Soft revocation, TTL cleanup, lookup by agent or session. The memory
  impl is the dev/reference store; production injects Redis / a Durable Object /
  a database behind the same interface (mirroring `NonceCacheProvider`).
- **Holder-of-key binding** at the inbound gate (spec §11.8). A delegation
  credential is a bearer token, so the caller must now prove possession of the
  delegation subject's key on the request itself. For a `did:key` subject the
  DID encodes the public key, so binding needs no new credential fields and no
  new crypto: `assertHolderBinding` verifies the request proof against the key
  derived from the subject DID — a stolen-credential replay fails signature
  binding, a tampered request fails content binding, and a proof minted for
  another server fails audience binding (RFC 8707). The client half
  (`generateRequestProof`, request-only with a fresh nonce per call) and the PEP
  half (`assertHolderBinding`) ship in `delegation/holder-binding`. Opt-in.
- Framework-agnostic delegation **chain-enforcement core**
  (`validateDelegationChain`, with the injected `DelegationCredentialVerifierPort`
  and `RevocationChecker` ports, plus `validateScopeAttenuation` /
  `getDelegationScopes`), lifted out of the `with-kya-os` middleware closure so
  the leaf→root chain walk, scope attenuation, audience / confused-deputy
  binding (§11.6), and ancestor-revocation rules run identically in any host
  (MCP middleware, an HTTP PEP, the conformance harness) instead of a
  per-transport fork. Dependencies are injected as ports; nothing imports a
  transport. Includes the correctness fix behind the new graph-backed
  `RevocationChecker` (reference adapter `CascadingRevocationManager`): a
  cascade-revoked ancestor is now caught even when the leaf's own StatusList bit
  never flipped. Exported from `@kya-os/mcp/delegation`.
- `NoopFetchProvider` — the offline `FetchProvider` fallback (used when the
  runtime exposes no global `fetch`) extracted from an inline literal into a
  named, exported class alongside `RuntimeFetchProvider`, and reused at the
  holder-binding gate.
- `WebCryptoProvider` — an isomorphic `CryptoProvider` backed by the WebCrypto
  API (`globalThis.crypto.subtle`, Ed25519), so an edge runtime (Cloudflare
  Workers, Deno, browsers, Node 20+) can drive `ProofVerifier` without
  `node:crypto`. Mirrors `NodeCryptoProvider`'s key formats exactly — raw
  32-byte Ed25519 keys, base64-encoded; `sha256:<hex>` digests — so the two are
  drop-in interchangeable: a proof signed under one verifies under the other,
  with byte-identical signatures. Exported from `@kya-os/mcp/providers`.

## [1.5.0] - 2026-06-01

Exposes the policy-request projection as a reusable primitive and adds a
dedicated `./policy` entry point, so hosts beyond the bundled middleware (for
example a gateway) can build a `PolicyRequest` from their own resolved facts
without copying internal logic. Additive over 1.4.x.

### Added

- **`buildPolicyRequest(input)` projection helper.** Pure, transport-agnostic
  assembly of resolved facts — principal, delegated scopes, risk, scope-match,
  and optional approvals / budget — into the canonical `PolicyRequest` a
  `PolicyEngine` evaluates. Lets any host present an identical request contract
  to the engine instead of re-deriving the shape.
- **`./policy` subpath export.** The policy seam (`PolicyRequest`,
  `PolicyDecision`, `PolicyEngine`, `DefaultPolicyEngine`, `RiskClassifier`,
  `buildPolicyRequest`) is now importable directly from `@kya-os/mcp/policy`,
  alongside the existing re-export from the package root.

### Changed

- The bundled per-action policy gate now builds its `PolicyRequest` via
  `buildPolicyRequest` rather than an inline literal. No behavior change.

## [1.4.0] - 2026-05-31

Ports the KYA-OS authorization primitives developed upstream (xmcp-i) into
`@kya-os/mcp`: a per-action policy / step-up gate, scope-matcher enforcement,
signed `needs_authorization` challenges with verifier content binding, and
shipped runtime providers. Additive over 1.3.x except where noted under
**Changed** and **Removed**.

### Added

- **Signed `needs_authorization` challenge.** The delegation challenge returned
  when a protected tool is invoked without a credential now carries a signed
  detached-JWS proof in `_meta` (`outcome: 'needs_authorization'`). The proof
  binds a `responseHash` over the challenge content — including the
  `authorizationUrl`. A verifier that recomputes the response hash over the
  content it received — via the new `ProofVerifier` content binding (below) —
  detects a tampered / MITM-swapped consent URL; the signature alone proves
  authenticity, not content-match. The challenge content/shape is unchanged; attachment
  is best-effort (no-ops when no session can be resolved). The proof `outcome`
  enum widened to include `'needs_authorization'` across `ProofMeta`,
  `ProofOptions`, `validateDetachedProof`, and the `detached-proof` JSON Schema.
  Success proofs are byte-identical (unaffected).
- **`wrapWithDelegation` `formatChallenge` hook.** An optional config callback
  that renders the `needs_authorization` challenge content (e.g. a clickable
  markdown consent link for LLM / chat-style MCP clients) **before** the proof is
  signed — so the challenge `responseHash` binds exactly what the client
  receives, keeping the `authorizationUrl` tamper-evident regardless of
  presentation. Defaults to the structured JSON challenge. The consent-basic /
  consent-full examples now render their consent link via this hook instead of
  rewriting the response after signing (which had left the proof bound to stale
  content).
- **`ProofVerifier` content binding.** `verifyProof(proof, jwk, { request, response })`
  recomputes `requestHash`/`responseHash` over the request/response the verifier
  actually received — via a shared `computeCanonicalHashes` (single source of
  truth with the signer, so they can't drift) — and fails `CONTENT_BINDING_MISMATCH`
  on divergence. This is what realizes substitution detection (the signed
  challenge's anti-MITM, and content-binding for any proof); the signature alone
  proves only authenticity. New `CONTENT_BINDING_MISMATCH` proof-verification
  error code.
- **Concrete `SystemClockProvider` + `RuntimeFetchProvider`.** The package now
  ships a wall-clock `ClockProvider` and a network-capable `FetchProvider`
  (did:key resolved locally, did:web over HTTPS, StatusList2021 fetch) so a
  consumer no longer hand-rolls them to drive `ProofVerifier`. `RuntimeFetchProvider`
  is the default the middleware uses and replaces the prior internal stub (whose
  `resolveDID` returned `null`); it refuses private-network targets by default
  (see **Security**). The verify-proof / anti-MITM examples now consume both.
- **Per-action policy / step-up gate (`withPolicyGate`).** A new opt-in
  middleware wrapper that classifies an action's risk (reversibility, blast
  radius, severity) and consults a pluggable Policy-as-Code `PolicyEngine`:
  `allow` runs the handler, `deny` returns a `policy_denied` error, and
  `step_up` returns a `needs_approval` error until N-of-M signed `ApprovalGrant`s
  — each bound to the request hash (TOCTOU-safe) — are supplied. Ships a
  fail-closed `DefaultPolicyEngine` and a built-in `RiskClassifier`; OPA/Rego and
  Cedar adapters are intended follow-ups. Composes after `wrapWithDelegation`;
  no behavior change unless adopted.
- **`PolicyEngine` PaC port + `policy/` subsystem** (`PolicyRequest`,
  `PolicyDecision`, `RiskClassifier`, `DefaultPolicyEngine`, `ApprovalGrant`,
  `verifyApprovalQuorum`), exported from the package root.
- **`needs_approval` error** (`NeedsApprovalError`, `createNeedsApprovalError`,
  `isNeedsApprovalError`) and the `policy_denied` error code.
- **`bytesToBase64` / `base64ToBytes`** are now re-exported from the package root
  (standard-base64 byte helpers, alongside the existing base64url variants).
- **`AuditLogProvider` — pluggable sink for audit-record retention.** A new
  provider (abstract base + `MemoryAuditLogProvider` / `NoopAuditLogProvider`
  defaults, exported from the root and `./providers`) for persisting the frozen
  `audit.v1` record of each verified tool call. Wire it via `KyaOsConfig.auditLog`
  (default: no-op); `createKyaOsMiddleware` emits a record after each proofed
  call, and a sink failure never breaks the tool response. `buildAuditRecord(ctx)`
  exposes the context→record mapping. Records carry only DID/key id, session,
  audience, scope, request/response hashes, and the verification result — never
  key material or nonces. The storage backend is operator-provided (durable,
  append-only); the package stays storage-agnostic, like the other providers.
- **Delegation scope on audit records.** Delegation-protected tools record the
  scope they were authorized under: `wrapWithDelegation` threads its `scopeId`
  through a new optional `KyaOsCallContext` (3rd handler argument) into the proof
  meta, so the audit record's `scope` reflects it (was `'-'`). The argument is
  optional and backward-compatible; tool handlers that ignore it are unaffected.

### Changed

- **`ProofMeta.responseHash` is now optional** (`string | undefined`). Denial /
  step-up proofs carry no response, so code reading `responseHash` must treat it
  as possibly-absent. `validateDetachedProof` and the `detached-proof` JSON
  Schema no longer require it (and now permit `outcome`/`reason`).
- **`CrispScope` `prefix`/`regex` matchers are now enforced** (previously inert —
  only exact membership in the flat `scopes[]` was checked). A credential
  declaring a non-exact matcher now grants its pattern set, with ReDoS-safe regex
  evaluation; flat `scopes[]` remain exact-match (unchanged). **Behavioral
  change** for any credential that declared a `prefix`/`regex` matcher: it now
  grants where it previously granted nothing, and a one-time warning is logged on
  first non-exact use. Re-delegations may not introduce crisp matchers absent
  from the parent.
- **`withPolicyGate`'s `scopeMatched` defaults to `false`** (fail-closed): compose
  it after `wrapWithDelegation` and pass `scopeMatched: true`, or it denies.
  `withPolicyGate` is an optional member of the `KyaOsMiddleware` interface
  (additive; structural implementers/mocks are not broken). New in this release,
  so no prior consumer is affected.
- **Bundled examples now consume the built `@kya-os/mcp` package** rather than
  reaching into `src/` via relative paths. Nested example packages (consent-basic,
  consent-full, context7, brave-search) link the local build via `file:../..`;
  root-tree examples (node-server, verify-proof, outbound-delegation, statuslist)
  resolve it by package self-reference. Fixes the context7 example, which had
  pinned a stale published `@kya-os/mcp@^1.3.0` (pre-`withKyaOs` rename).

### Spec

- **§4.2 — normative MUST on key generation.** An agent's key pair MUST be
  generated by the agent or its designated custodian; the secret key MUST NOT be
  generated by, transmitted to, or escrowed with any registration, DID,
  directory, or reputation service (which receive only the public key). Carves
  out agent-side proxy/HSM custody (§11.0). Closes the key-escrow / IBE-style
  concern where a directory service implicitly holds agents' secret keys.
- **§6.6 — revocation needs no global list.** Clarified that a verifier checks
  revocation only for the resources it gates and MAY hold revocation state
  locally; `StatusList2021` is the interoperable publish format, not a required
  public certificate-revocation list.
- **§11.0 — "L2+ is not OAuth-style client registration."** Direct (Level 2+)
  verification still gates on the presented delegation chain, not the agent's
  identity alone — inverting the OAuth Dynamic Client Registration pattern.
- **§12.5 — per-delegation keys (delegate unlinkability).** Non-normative
  pattern: delegate to a fresh one-off public key per delegation to prevent
  cross-delegation correlation through a shared subject DID.
- **§2 — reputation scope.** The Responsible Party definition now states that
  reputation and accountability signals are scoped primarily to the Responsible
  Party, not an agent's ephemeral identity.
- **Terminology.** Standardized on _secret key_ (synonymous with _private key_,
  retained in PKCS#8 / JWK references); fixed the one residual _private key_
  usage in §7.

### Security

- **Malformed delegation input no longer crashes.** A malformed `_kyaos_delegation`
  (non-object, missing `credentialSubject.delegation`, or even a throwing
  getter/Proxy accessor) previously surfaced as a JSON-RPC internal error (`-32603`);
  it now returns a clean, signed `delegation_invalid` denial. `validateDelegationChain`
  shape-checks the leaf and returns `{ valid, reason }` (honouring the
  `verify*`/`validate*` never-throw contract); `extractDelegationFromVC` fails
  with a clear error instead of a cryptic `TypeError`; the middleware try/catch is
  now a pure backstop that logs the detail server-side and returns a generic
  reason (no internal/stack detail leaks to the client). The invalid-VC-JWT path
  is now signed as well.
- **Log-injection / reflection hardening.** Caller-derived values (credential
  ids, scopes) interpolated into delegation-failure reasons and logs are now
  stripped of control characters and length-capped before emission, so a hostile
  credential cannot forge log lines, corrupt a terminal, or reflect raw control
  bytes into a client response.
- **`RuntimeFetchProvider` refuses private-network targets by default (SSRF).**
  did:web resolution and StatusList2021 fetches reject loopback / link-local /
  RFC-1918 IP-literal hosts (e.g. `did:web:169.254.169.254`, the cloud-metadata
  endpoint) unless constructed with `{ allowPrivateNetworkHosts: true }`. This
  is best-effort defense-in-depth for IP literals — not DNS rebinding; run
  verifiers behind an egress allowlist (`SECURITY.md`).
- **Signed proofs are now emitted on denial and step-up.** Delegation/scope
  denials and policy step-ups previously produced no proof; they now attach a
  signed detached-JWS proof (`outcome: 'denied' | 'step_up_required'`, no
  `responseHash`), so rejected privileged attempts are non-repudiably auditable.
- **Fail-closed policy default.** Unclassified ("unknown") high-risk actions are
  denied by the `DefaultPolicyEngine` rather than forwarded.
- **Denial/step-up proofs are verifiable end-to-end.** `validateDetachedProof`
  and `ProofVerifier` accept response-less proofs (the earlier fix only corrected
  canonical-payload reconstruction); added a real-crypto end-to-end test.
- **Crisp-scope attenuation.** Re-delegations cannot widen authority via crisp
  matchers absent from the parent — closes a privilege-escalation path that
  enforcing the matcher would otherwise have opened.
- **ReDoS hardening.** The `regex` matcher rejects nested-quantifier patterns and
  bounds input length. This is a conservative guard, **not** a guarantee — prefer
  `exact`/`prefix` for untrusted issuers, or evaluate via a linear-time engine.
  The `prefix` matcher refuses an empty/`*`-only base (no universal grant).

### Removed

- **BREAKING: removed the three unsafe delegation opt-outs.** The
  secure-by-default behavior they bypassed is now unconditional and cannot be
  disabled:
  - `delegation.requireAudienceOnRedelegation` — audience binding on every
    non-root credential in a chain is now mandatory (`SPEC.md` §11.6).
  - `delegation.allowLegacyUnsafeDelegation` — full delegation-chain resolution
    and `credentialStatus` / StatusList revocation checks are always enforced;
    parent-linked credentials without a `resolveDelegationChain` handler, and
    `credentialStatus` without a `statusListResolver`, are rejected.
  - `VerifyDelegationVCOptions.allowNonDelegationSubjectFields` — the
    `credentialSubject` shape check (only `id` + `delegation`) is always
    enforced (`SPEC.md` §6.2; conformance L3.5a).

  The associated one-time `console.warn` notices are removed along with the
  flags. Migration guidance: `SECURITY.md` → Mandatory Delegation Protections.
  Consumers that did not set these flags are unaffected — the reference issuer
  and all bundled examples already emit conformant credentials.

### Known limitations (policy gate — experimental, non-normative)

- Step-up approval grants are **not yet single-use or expiry-bound** (replayable
  for the same action); a server-issued single-use challenge is a planned follow-up.
- The default approval-signature verifier **rejects all** — integrators must supply
  a real verifier; `isValidApprovalSignature: async () => true` is test-only.
- `policy_denied` / `needs_approval`, the step-up flow, and the now-normative
  `CrispScope` matcher semantics are **not yet documented in `SPEC.md` /
  `CONFORMANCE.md`** (tracked as follow-ups).

## [1.3.2] - 2026-05-26

### Security

- **Verifier rejects claim-contaminated delegation credentials.** A
  `DelegationCredential` whose `credentialSubject` carries properties beyond
  `id` and `delegation` is now rejected by default — claim-bearing fields in a
  permission credential separate designation from authorization (the
  confused-deputy class, `SPEC.md` §6.2 / §11.6). The reference verifier exposes
  `allowNonDelegationSubjectFields` (default `false`) as an audited opt-out that
  logs a one-time per-process warning. Spec-conformant issuers are unaffected;
  the reference issuer already emits `{ id, delegation }` subjects. New
  conformance requirement L3.5a. (#67)

### Changed

- **Schema `$id` and JSON-LD `@context` hosts migrated** off the
  `modelcontextprotocol-identity.io` trademark domain to the foundation-owned
  `schema.kya-os.ai`. All five shipped JSON Schemas (`schemas/*.json`), the
  spec's context references, and the `DELEGATION_CREDENTIAL_CONTEXT` constant
  now resolve under `schema.kya-os.ai`; schemas are served identically at both
  hosts during the migration window (no `$id` is 301-redirected). (#65)

## [1.3.1] - 2026-05-26

> These entries accreted across the 1.2.0 → 1.3.1 donation cutover and were
> published without strict per-version sectioning. They are grouped here for
> completeness; see `npm view @kya-os/mcp time` and git history for exact ship
> points. A clean per-version backfill is tracked separately.

### Added

- Export the byte-variant base64url helpers (`base64urlEncodeFromBytes`, `base64urlDecodeToBytes`) from the package entry point. They existed in `src/utils/base64.ts` but were not on the public API; downstream consumers need them for DID/JWK key encoding.

### Docs

- Tightened two capability-language hits inside the spec that survived the Responsible Party rename: §8.2 `DelegationProofJWT.sub` comment now describes the Responsible Party explicitly (was "User DID (on whose behalf)"), and the `userDid` field description in `schemas/delegation-credential.json` now reads "whose delegated authority the agent exercises" instead of "on whose behalf the delegation acts."

### Spec

- Added §11.0 (Trust Model) naming the three trust boundaries explicitly: the agent process, the verifier (with the Edge Verifier called out as a TCB component at L1), and the service / resource owner. Includes key custody options (software, proxy-managed, hardware-attested) and a mutual-authentication recommendation for services.
- Added §11.1 (Threat Model Summary) as a structured table: threat → mitigation → residual risk. Covers impersonation, replay, scope escalation, confused deputy, credential theft, agent abuse, key compromise, revocation race, downgrade, and DoS — with cross-references to detailed sections and to the cap-sec invariants in §6.4.1 / §6.5.
- Renumbered §11 subsections to fit the new structure (Revocation Freshness moved to §11.10; previous §11.1–§11.5 shifted by one).
- Introduced **Principal** and **Responsible Party** as first-class terms (§2). The Responsible Party is the entity ultimately accountable for actions taken under a delegation chain — the root issuer of the chain. Distinguished from the Principal (the immediate human delegator) to support organizational deployments where the operating human is not the accountable entity.
- Added a normative invariant to §6.4: every delegation chain MUST terminate at a Responsible Party, identified by the `issuerDid` of the root `DelegationCredential`.
- Reworded the Abstract to drop "on whose behalf" (impersonation framing) in favor of "what authority they hold (a delegation chain rooted at a Responsible Party)" — capability-security framing that matches the protocol's actual semantics.
- Added normative _meta hash exclusion paragraph and `session.metaPolicy` opt-in (default: `strict`).
- Documented anonymous handshake nonce-dedupe boundary; reference impl now uses a 60s TTL for anonymous nonces.
- Added `clockSkewSeconds` field to `.well-known/mcp` for server-advertised skew negotiation.
- Added the **designation invariant** to §6.4.1 as a normative MUST: invocations must designate the specific resource being exercised, even when the delegation authorizes multiple resources. The reference implementation already enforces this via the per-tool `scopeId` check; this change makes the behavior normative and cross-references it from §11.6 (Confused Deputy Attacks).
- Added §6.5.1 (Revocation Rights) defining who may revoke a delegation in v1.0: direct issuer, any ancestor issuer in the chain, and the responsible party at the root. Subject-side revocation is explicitly disallowed in v1.0; UCAN-style "revocation as a delegatable permission" is tracked for v1.1.
- Added §6.5.2 (Concurrency and the Revocation Race) acknowledging the Lamport-concurrent race between revocation issuance and propagation, with implementation guidance on bounding the window.

### Security

- **BREAKING (default flip): `requireAudienceOnRedelegation` now defaults to `true`.**
  Every non-root credential in a delegation chain must carry an `audience`
  constraint. Closes the confused-deputy class flagged by Alan Karp's
  transitive-access analysis and matches `SPEC.md` §11.6. Integrations that
  cannot yet bind audience on every re-delegation can set the flag to `false`
  explicitly to preserve legacy behavior; doing so logs a one-time
  per-process warning so the configuration is auditable in production logs.
- **Unsafe-mode warning:** setting `allowLegacyUnsafeDelegation` to `true`
  now emits a one-time per-process `console.warn` on first use. Default
  is unchanged (`false` / strict). The warning surfaces accidental
  configuration in production logs without spamming per-session.
- `SECURITY.md` gained a "Secure Defaults & Unsafe Delegation Modes" section
  documenting both flags, when to opt out, and the migration path back to
  safe defaults.
- Added test coverage pinning the warn-once behavior on both unsafe-mode
  flags: warns exactly once per process on opt-in, silent on safe defaults,
  no duplicate warnings across repeated `wrapWithDelegation` calls.

### Added

- **Generic `Identity` interface** exported from the root entry point.
  Captures the shape shared by every subject the protocol speaks about
  (DID + verification-method id + key material). `AgentIdentity` now
  extends `Identity`; the agent-flavoured shape is unchanged for
  existing consumers.
- **`buildDidWebDocument(identity, options?)`** in
  `delegation/did-web-resolver`. Produces the DID Document a `did:web`
  controller serves at its resolution URL (see `didWebToUrl`),
  completing the producer/consumer round-trip with `DidWebResolver`.
  Emits both `publicKeyJwk` and `publicKeyMultibase` for cross-format
  interop, matching the `Ed25519VerificationKey2020` form used by the
  did:key resolver.
- Optional `@context` field on `DIDDocument` so produced documents can
  declare the JSON-LD contexts they reference.

### Changed

- **Package renamed from `@mcp-i/core` to `@kya-os/mcp`.** Renamed
  under the KYA-OS protocol (Know Your Agent Operating System), the
  agent identity, authorization, and observability protocol donated
  to DIF TAAWG. Version stays at 1.2.0 — the wire format, public
  exports, and behavior are unchanged. The old `@mcp-i/core` package
  is deprecated and points at this one.
- **Spec renamed from MCP-I to KYA-OS** across `SPEC.md`,
  `CONFORMANCE.md`, `GOVERNANCE.md`, and example READMEs. Wire-format
  identifiers (`_kyaos` tool name, well-known path, JSON Schema
  files, JSON-LD context URLs) are deferred to a later cutover so
  this doc-only rename doesn't break running implementations.

  Why the rename: two forces.

  First, MCP is Anthropic's trademark and lives under Anthropic's
  governance. Calling a DIF-track identity protocol "MCP-Identity"
  suggested an official extension of MCP and tied the protocol to a
  single vendor's roadmap. The Linux Foundation flagged this during
  pre-donation review and we agreed: a foundation-owned identity
  protocol should not carry another foundation's (or vendor's)
  trademark in its name.

  Second, the protocol was never going to be MCP-only. The design
  intent was a primitive layer for identity, authority, and
  accountability that other agent-facing protocols adopt, analogous
  to how TLS is a security layer that transports adopt rather than
  a transport itself. KYA-OS primitives are intended to embed in
  three kinds of host surface: transport bindings (wire protocols
  an agent's calls ride over, e.g. MCP, HTTPS, gRPC, SMTP, Matrix,
  browser-driven actions), runtime bindings (agent harnesses where
  the loop runs and tool invocations can be wrapped uniformly), and
  manifest / assertion embeddings (host formats like C2PA manifests
  that already carry signed assertions and can carry a KYA-OS proof
  as one assertion type). Naming the protocol after one binding
  undersold the surface.

  The MCP binding ships first because MCP is the most concentrated
  agent-to-tool RPC surface today. Additional bindings will be
  specified in the working group as they reach consensus.
- **Spec cut to `1.0.0`** (was `0.1.0-draft` in `SPEC.md`, `1.0.0-draft`
  in `CONFORMANCE.md`). The wire format was already pinned at `1.0.0`
  in the handshake protocol-version field; the spec docs now match.
  Status: Stable — donated to DIF TAAWG for ratification review. Spec
  semver is independent of package semver: the spec describes the wire
  protocol, the package describes the implementation shipping it.
- Delegation middleware remains strict by default for chain and status-list validation.
- Added `delegation.allowLegacyUnsafeDelegation` to `createKyaOsMiddleware` as a temporary migration escape hatch for legacy integrations.
- Added middleware tests covering legacy-compatibility behavior for parent-linked and status-list credentials.

### Docs

- L1 revocation terminology clarified (verifier-local, not global CRL).
- Orchestration directory scope explicitly narrowed from global to service-local.
- Nonce lifetime documented to prevent early-eviction replay class.
- Multi-level audit record example added.
- Conformance-tiered audit-logging requirements added.
- Registry types (Delegation / Credential / Trust) disambiguated.
- Broken link to Protocol Registry fixed.
- Key Topics ordering aligned with site navigation.

## [1.0.0-draft] - 2026-03-12

### Added

- SPEC.md protocol specification defining KYA-OS extension for cryptographic identity
- Supported DID methods: `did:key` (ephemeral/dev) and `did:web` (production)
- Ed25519/EdDSA cryptography for signing and verification
- Delegation module with W3C Verifiable Credential issuance and verification
- CRISP constraint envelopes for scope, budget, temporal bounds, and audience
- Delegation graph management with parent-child relationships
- Cascading revocation via StatusList2021
- `did:key` resolver for synchronous DID Document resolution
- `did:web` resolver with HTTPS fetching and caching
- Proof module with detached JWS generation over canonicalized request/response
- Proof verification with DID resolution and timestamp validation
- SHA-256 hashing with RFC 8785 JCS canonicalization
- Session module with handshake validation and nonce-based replay prevention
- Session TTL management with idle timeout tracking
- Auth module with `verifyOrHints` orchestration and sensitive scope detection
- Resume token storage for authorization flows
- `needs_authorization` hint response pattern
- MCP SDK middleware wrapper (`createKyaOsMiddleware`)
- Tool wrapping with automatic proof generation
- Handshake tool registration and handling
- Provider abstractions: CryptoProvider, ClockProvider, FetchProvider, StorageProvider, NonceCacheProvider, IdentityProvider
- In-memory implementations for all providers (testing)
- Configurable logging with debug, info, warn, error levels
- Pure TypeScript protocol type definitions (zero runtime dependencies)
- Well-known endpoint (`/.well-known/mcp`) for server discovery
- Outbound delegation proof JWT builder for downstream API calls
- Three-tier conformance levels:
  - Level 1: Core Crypto (key generation, signing, hashing, DID resolution)
  - Level 2: Full Session (handshake, nonce, replay prevention, proofs)
  - Level 3: Full Delegation (VCs, CRISP, graphs, revocation, chain validation)
- Example implementations: Node.js server, proof verification, delegation issuance
- Vitest test suite covering all conformance levels
- GitHub Actions CI with type checking, build, test, and coverage
