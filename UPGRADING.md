# Upgrading @kya-os/mcp

This file holds the detail behind the Upgrading entries in CHANGELOG.md: the steps for each setup, the limits, and the tables of changed refusal reasons.
Each release has one section, newest first, and declares every change of behaviour against the release before it.
CHANGELOG.md says what changed and names the section here that says what to do about it.

## From 1.22.0

### Signing keys and `assertionMethod`

A delegation credential, a status list and a delegation hop verify only under a key their issuer's own DID document lists under `assertionMethod` (SPEC.md §6.2, §6.10, §11.5).
A key the document lists only under another relationship, such as `authentication`, or under none, no longer verifies one.
Update issuers before verifiers upgrade.

What each setup has to do:

| Setup | Action |
| --- | --- |
| did:key issuers | None: a did:key document lists its key under `assertionMethod`. |
| did:web documents built with `buildDidWebDocument` | None: every key is listed under `assertionMethod`. |
| `signDelegationCredential` and `signStatusListCredential` | None: each states `proofPurpose: "assertionMethod"` and names its key. |
| A `VCSigningFunction` you give `DelegationCredentialIssuer` or `StatusList2021Manager` | The proof it returns names the signing key in `verificationMethod`, and a `proofPurpose` it states is `assertionMethod`. |
| Hand-written did:web documents | List each signing key under `assertionMethod`, as below. |
| did:cheqd documents made with `@cheqd/sdk` before 5.3.3 | Update the DID as `src/integrations/cheqd/README.md` shows, since they list keys only under `authentication`. |

An issuer whose documents or credentials do not yet comply must:

1. List each signing key under `assertionMethod` of its own DID document, by reference or embedded.
   The method is defined once, has an id under the issuer's DID and a `type`, and names the issuer's DID as its `controller`.
2. Set each proof's `proofPurpose` to `assertionMethod`.
   Only the legacy proof profile of SPEC.md §6.2 permits an omitted purpose; the Card `eddsa-jcs-2022` profile requires it.
3. Name the signing key with a non-empty `kid` or `proof.verificationMethod`.
   A VC-JWT with no `kid`, or a status list read by `CheqdStatusListResolver` with no `verificationMethod`, is checked only with the first `assertionMethod` entry.
   Card `eddsa-jcs-2022` proofs must name their key.

### Issuer identifiers

A credential names its issuer, in `issuer`, in an issuer object's `id` and in a VC-JWT's `iss`, by a URL as written (SPEC.md §6.2).
A value with white space at either end, or with a control or format character, U+2028, U+2029, a character that renders as nothing by default or a lone surrogate anywhere, is refused before any DID is resolved.
The characters are a fixed list, `conformance/unseen-code-points.json`, the same on every runtime: Unicode's Cc, Cf, Zl, Zp and Default_Ignorable_Code_Point as of Unicode 17.0, such as a variation selector, a Hangul filler or a combining grapheme joiner.

### Delegations the gate cannot encode

The delegation gate refuses, as `delegation_invalid`, a delegation holding a value RFC 8785 cannot encode.
In 1.22.0 such a call threw a `TypeError` or ran the tool.
Issue no delegation that holds one.

### Changed refusal reasons

A refusal reason is text for people, and its wording changed where it quotes a value the other party chose.
`"<v>"` quotes a value as a JSON string of at most its first 64 characters, with `...` after it when cut, and with control and hidden characters, quote marks, backslashes and lone surrogates escaped.
A value that is not a string reads `of type <type>`.
Code that matches on reason text needs the new wording.

| 1.22.0 | Now |
| --- | --- |
| `Verification method <id> not found`, `Verification method <kid> not found in DID Document`, `Issuer DID document has no verification method matching "<id>"` | `Verification method "<id>" not found under assertionMethod of "<issuer>"` |
| `DID Document has no verification method`, `Issuer DID document has no verification method matching "(any)"` | `JWT kid is absent, and assertionMethod of "<issuer>" has no usable first entry`, or the same starting `Status list proof verificationMethod is absent` |
| `Proof missing verificationMethod` for `""`, `null` or `0`, `Verification method 42 not found`; an empty `kid`, or a list `verificationMethod` that is empty or not a string, read as none | `Proof verificationMethod "<v>" is not a DID URL`, `JWT kid "" is not a DID URL`, `Status list proof verificationMethod "<v>" is not a DID URL` |
| none: the key verified | `Verification method "<id>" under assertionMethod of "<issuer>" has another DID as its controller: "<did>"`, or `as its document's id: "<did>"` |
| none: the proof verified | `Proof purpose "<v>" is not assertionMethod` |
| `Could not resolve issuer DID: <issuer>`; for a VC-JWT `iss` that is not a string, ``Credential `issuer` does not match the JWT `iss` (the verified signer)`` | `Credential issuer "<v>" is not a URL`, `Credential issuer id "<v>" is not a URL`, `JWT iss "<v>" is not a URL` |
| a `TypeError`, or the tool ran | `Delegation credential holds a value that cannot be encoded as RFC 8785 text` |
| `Delegation status is revoked`, `Unsupported credential proof.type: <type>`, `Could not resolve issuer DID: <issuer>`, `Could not resolve issuer DID <issuer>: <error>`, `Credential revoked via <type> (<purpose>)`, `credentialSubject contains non-delegation field(s): <a>, <b>`, `Status list fetch failed: HTTP <status> for <url>`, `Revocation check failed for delegation <id>: <error>`, `Delegation <id> is revoked via ancestor <id>`, `Delegation <id> is revoked: <reason>` | the same with each value quoted, as in `Delegation status is "revoked"` and `credentialSubject contains non-delegation field(s): "<a>, <b>"` |
| `Status list issuer "<issuer>" is not the expected issuer "<issuer>"`, values as written | `status list issuer "<issuer>" is not the expected issuer ("<issuer>")`, naming at most three accepted issuers and then how many more, as in `("<a>" or "<b>" or "<c>" and 47 more)`, or `status list names no issuer` for an `issuer` that is neither a string nor an object with a string `id` |
| `status list statusPurpose mismatch: "<purpose>" ≠ "<purpose>"`, values as written | `status list statusPurpose mismatch: the list's is "<purpose>" and the entry's is "<purpose>"` |
| `status list has no statusPurpose (expected "<purpose>")`, an em dash and `fail-closed`, also for a `statusPurpose` array | `status list has no statusPurpose (the entry's is "<purpose>")`, or for an array on a list that is not a Bitstring Status List, `status list statusPurpose is an array, which only a BitstringStatusListCredential with a BitstringStatusList subject may state (the entry's is "<purpose>")` |
| none: the list was read | `status list id "<id>" is not the URL it was fetched from ("<url>")`, adding `; they first differ at character <n>` when the two read the same once cut, or `status list states no id, but must state the URL it was fetched from ("<url>")` |
| `Invalid statusListIndex "<index>"`, an em dash and `must be a canonical non-negative decimal`; for an index that is not a string, such as `7` or `["7"]`, none: it was converted and read | `Invalid statusListIndex "<index>": must be a non-negative decimal string`, ending `must be a non-negative safe integer or a non-negative decimal string` from `StatusList2021Manager.updateStatus` and `CascadingRevocationManager`, which read their own records |
| `statusListIndex "<index>" exceeds the safe integer range`, the index as written | the same with the index quoted |
| `revocation: hop <n> (<url>#<index>) is revoked or unresolvable` and the rest, `<n>` counting only the hops with a status entry | `revocation: hop <n> (list "<url>", index "<index>") is revoked or unresolvable` and the same rest, `<n>` the hop's position in its chain, the root being 0 |
| the `<error>` or `<reason>` in `Status check error`, `Signature verification error`, `Could not resolve issuer DID`, `JWT envelope signature is not valid`, `Failed to resolve delegation chain`, `Revocation check failed` and `Delegation <id> is revoked`, as written | cut after 256 UTF-16 code units and marked with U+2026, with control and hidden characters and lone surrogates read as U+FFFD |

### Status lists held to their credential

A status list is read only when an issuer the verifier accepts for the credential signed it, its `statusPurpose` includes the entry's, and it states as its `id` the URL it was fetched from (SPEC.md §6.6).
So a status check that passed on 1.22.0 can deny.
Find your setup below.

#### A hop whose status entry is on a list its own issuer did not issue

With `verifyStatusList` it reads as revoked, unless the list's issuer is the chain's root and the verifier pins that root, or the checker's `statusListIssuers` accepts the list's issuer for the hop's issuer.
A list signed by an issuer between the root and the hop needs that issuer listed under `statusListIssuers` for the hop's issuer.

#### A chain whose root signs the lists of the hops below it, checked without a pinned root

The root's list now counts only for the root's own credential.
Pin the root, with `trustedRootIssuers` or `resourceOwner` for `verifyRequestDelegation` and `requireDelegation`, or `resourceOwner` for `evaluateDelegationChain`, and its list counts for every hop of its chains.

#### A Card whose `revocation` list another DID issues

With `verifyStatusList` it reads as revoked, unless that DID is the Card's `responsibleParty` and the Card's `accountabilityVerifier` verifies it as the root issuer of the Card's delegation chain, or `statusListIssuers` accepts it for the Card's `id`.
A responsible party's list counts for its Cards only once verified, never as the Card states it.

#### A list that states no `id`, signed by anyone but the credential's own issuer

The checker with `verifyStatusList` rejects it, so a list from the pinned root, from an issuer `statusListIssuers` accepts, or from a Card's responsible party must state, as its `id`, the URL it is served at.
`CheqdStatusListResolver` rejects every list that states no `id`.
`StatusList2021Manager` and the publisher in `examples/revoked` state the `id` of every list they write; re-issue any other list with its URL as its `id`.

#### A list that states no `id`, signed by the credential's own issuer, where the verifier pins a root other than that issuer or `statusListIssuers` accepts another issuer for it

The checker with `verifyStatusList` rejects it too, since it could otherwise stand in for a list another accepted issuer keeps.
So does `verifyCard` for a Card's own list once the Card's `responsibleParty`, another DID, is verified.
State the list's URL as its `id`.

#### A list that states an `id` other than its URL, byte for byte

The checker with `verifyStatusList` and `CheqdStatusListResolver` reject it.
A DID URL naming the same resource is another `id`, so `CheqdStatusListResolver`, which fetches only https URLs, refuses a list whose `id` is a DID URL.

#### A direct call to a checker built with `verifyStatusList`

Name the credential's issuer, `check(entry, { credentialIssuer })`, and the chain's root as `trustedRootIssuer` for a hop of a chain whose root you pin.
A call that names no issuer resolves to revoked and not fresh, before any fetch.
Pass `evaluateRevocationChain` the hops `revocationEntriesOf(chain, trustedRootIssuer)` builds.

#### A hop whose `credentialStatus` states a `statusPurpose` other than the checker's, or one that is not a string, `null` included

It resolves to revoked and not fresh, before any fetch.
On 1.22.0 its bit was read whenever its list declared the checker's purpose.

#### A `credentialStatus` whose `statusListIndex` is not a string, such as `7` or `["7"]`

Every status-list reader refuses it, so a checker `createRevocationChecker` builds resolves it to revoked and not fresh, and `CheqdStatusListResolver` and `StatusList2021Manager.checkStatus` throw.
On 1.22.0 it was converted to a string and that bit read.
Write each index as a string of decimal digits, as the library's issuers do.
`StatusList2021Manager.updateStatus`, which writes the manager's own record, still sets the bit of an index stored as a whole number, as on 1.22.0, but now throws on one that is neither a number nor a string, such as `["7"]`, which 1.22.0 converted to a string.
`CascadingRevocationManager` reads the delegation graph's stored entries, the same records, the same way.

#### An `accountabilityVerifier` that returns a value other than a boolean

`verifyCard` takes only a literal `true`, returned bare or as `verified`, as verified, so a truthy value such as `"false"` or `1` now fails the Card's accountability check, and it reads a `fresh` that is present and not a boolean as `false`, which demotes L3 to L2.
Since a verified responsible party's lists now count for the Card, SPEC-ENTITY-CARD.md §10.3 states what the verifier must check before it returns `true`: a check of the chain's structure alone, or a stub that always returns `true`, is not enough.

#### A checker built without `verifyStatusList`

It authenticates no list, so it still reads whatever list it is served, as on 1.22.0 (see DEPRECATIONS.md).
Give it `createStatusListProofVerifier`, or a check that resolves `true` only for a proof that verifies under a key the list's `issuer` lists under `assertionMethod`.

#### A custom `StatusListResolver` given to `withKyaOs` or `DelegationCredentialVerifier`

The library reads a list only through it, so a list is held to the credential only as the resolver holds it.
`checkStatus` is now told the credential's issuer; once a list's proof verifies, pass `acceptStatusList(list, statusListExpectationFor(status, context, statusListIssuers))`, as `CheqdStatusListResolver` applies the rule to its pin.

### Status-list exports for a custom reader

These are new in `@kya-os/mcp`, `@kya-os/mcp/delegation` and `@kya-os/mcp/card`, for a `StatusListResolver` or checker of your own.

Given a fetched list and the entry's `statusListCredential`, `statusPurpose` and `acceptedIssuers`, `acceptStatusList` returns a `StatusListVerdict`, `{ valid: true }` or `{ valid: false, reason }`.
The list's `issuer` must be one of `acceptedIssuers`, its `statusPurpose` must include the entry's, as one string unless the list is a `BitstringStatusListCredential` with a `BitstringStatusList` subject, and its `id` must be, byte for byte, the URL it was fetched from.
A list may leave the `id` out only when its issuer is the one issuer `acceptedIssuers` names, and not even then when the optional `requireId` is `true`, as `CheqdStatusListResolver` sets it.
The rule decides by the list's `issuer` and checks no proof, so a custom `StatusListResolver` applies it once the list's proof verifies under a key that `issuer` lists under `assertionMethod`.
`acceptedStatusListIssuers(context, statusListIssuers)` lists, each once, the credential's issuer, the chain's root issuer when the context names it as `trustedRootIssuer`, and those `statusListIssuers` accepts for the credential's issuer, and throws the `TypeError` `createRevocationChecker` throws for a `statusListIssuers` that is not a plain object of string arrays.
`statusListExpectationFor(entry, context, statusListIssuers)` builds, from those issuers, the expectation `acceptStatusList` takes for an entry, as each reader in the library that holds a list to its credential does, so a custom `StatusListResolver` passes `acceptStatusList(list, statusListExpectationFor(status, context, statusListIssuers))`.
All three, with their types, are exported from `@kya-os/mcp`, `@kya-os/mcp/delegation` and `@kya-os/mcp/card`.
`StatusListResolver.checkStatus` and `BitstringRevocationChecker` take that `StatusCheckContext` as an optional second argument, `withStatusCache` passes it on and caches per context, and `revocationEntriesOf(chain, trustedRootIssuer)` builds it for every hop of a delegation chain, as a `RevocationChainEntry` that carries the hop's `statusPurpose` and its `position` in the chain.
`createRevocationChecker` takes `statusListIssuers`, keyed by credential issuer: a deployment whose lists one status service signs lists that service under each credential issuer, or has the chain's pinned root sign its lists.
It throws a `TypeError` when the value is not a plain object of string arrays, or is given without `verifyStatusList`.
The delegation middleware names only the credential's own issuer to its resolver, even when `trustedRootIssuers` pins the chain's root, so on that path a list the root signed for a re-delegated credential is refused unless the resolver's own configuration accepts the root for the credential's issuer and the list states its `id`.

### Conformance suite 1.4.0

The suite adds status-list vectors for the acceptance rule, each with a list whose proof verifies, and has 87 vectors in all.

Six new negative vectors check a revoked credential against a list with its bit unset and a proof that verifies: one another DID issued (`status-list/foreign-issuer-list`), a `suspension` list (`status-list/purpose-mismatch-list`), a StatusList2021 list that states its purposes in an array that includes `revocation` (`status-list/purpose-array-2021-list`), one that states another URL as its `id` (`status-list/id-mismatch-list`), and one that states no `id` from the pinned root of the credential's chain (`status-list/root-no-id-list`) or from an issuer the verifier is configured to accept (`status-list/configured-issuer-no-id-list`).
Those two carry the new optional inputs `trustedRootIssuer` and `statusListIssuers`, and a verifier without that configuration refuses their lists for the issuer.
Two new positive vectors check an active credential against its issuer's list re-issued without an `id` (`status-list/no-id-list`) and against its issuer's `BitstringStatusListCredential` for the purposes `suspension` and `revocation` (`status-list/purpose-array-list`), so an implementation that refuses either form fails.
`status-list.json` is regenerated in one run, so its three existing vectors change bytes with the same cases and verdicts, and the other files change only their `version`.
A new file, `status-list-authority.json`, adds six more vectors: a clear list from the pinned root (`status-list/pinned-root-list`) or from an issuer `statusListIssuers` accepts for the credential's issuer (`status-list/configured-service-list`) must be read, so an implementation that reads only the credential's own issuer's lists fails; the second list must be refused when `statusListIssuers` has no entry for the credential's issuer (`status-list/unconfigured-service-list`) or names the credential's issuer under the list's (`status-list/wrong-direction-service-map`); a list without an `id` must be read when the credential's own issuer signed it, even if the verifier also pins that issuer as the root (`status-list/owner-root-alias-no-id`); and such a list must be refused when the verifier pins another root, at whose URL it is served (`status-list/owner-no-id-at-pinned-root-url`).
Five more vectors in that file hold a signed `statusListIndex` that is not a whole decimal string (`status-list/index-suffix`, `status-list/index-fraction`, `status-list/index-space`, `status-list/index-number`), which must be refused, or one that opens with zeros (`status-list/index-leading-zeros`), which must be read.
The reference adapter applies `acceptStatusList`, and `conformance/verify.py` checks every status-list vector too.
