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
| `Status list issuer "<issuer>" is not the expected issuer "<issuer>"`, values as written | `status list issuer "<issuer>" does not keep this list's URL: "<keeper>" does, as <why>`, where `<why>` is `the issuer statusListIssuers binds this URL to`, `the issuer statusListIssuers binds this URL's origin to`, `the pinned root whose own credential names it`, `the issuer of the credential` or, from `CheqdStatusListResolver`, `the issuer this resolver is configured with`; or `status list names no issuer` for an `issuer` that is neither a string nor an object with a string `id` |
| `status list statusPurpose mismatch: "<purpose>" ≠ "<purpose>"`, values as written | `status list statusPurpose mismatch: the list's is "<purpose>" and the entry's is "<purpose>"` |
| `status list has no statusPurpose (expected "<purpose>")`, an em dash and `fail-closed`, also for a `statusPurpose` array | `status list has no statusPurpose (the entry's is "<purpose>")`, or for an array on a list that is not a Bitstring Status List, `status list statusPurpose is an array, which only a BitstringStatusListCredential with a BitstringStatusList subject may state (the entry's is "<purpose>")` |
| none: the list was read | `status list id "<id>" is not the URL it was fetched from ("<url>")`, adding `; they first differ at character <n>` when the two read the same once cut, or `status list states no id, but must state the URL it was fetched from ("<url>")` |
| none: the credential passed, or `Credential revoked via "<type>" ("<purpose>")`, for a `checkStatus` answer that is not a boolean | `Credential status could not be read: the status list resolver's answer (<v>) is neither true nor false` |
| none: the chain passed, a revoked reason, or a `TypeError`, for an `isRevoked` answer that is not an object with a boolean `revoked` | `Revocation status of delegation "<id>" could not be read: the revocation checker's answer (<v>) is not an object`, or ending `the revoked member of the revocation checker's answer (<v>) is neither true nor false` |
| `Invalid statusListIndex "<index>"`, an em dash and `must be a canonical non-negative decimal`; for an index that is not a string, such as `7` or `["7"]`, none: it was converted and read | `Invalid statusListIndex "<index>": must be a non-negative decimal string`, ending `must be a non-negative safe integer or a non-negative decimal string` from `StatusList2021Manager.updateStatus` and `CascadingRevocationManager`, which read their own records |
| `statusListIndex "<index>" exceeds the safe integer range`, the index as written | the same with the index quoted |
| `revocation: hop <n> (<url>#<index>) is revoked or unresolvable` and the rest, `<n>` counting only the hops with a status entry | `revocation: hop <n> (list "<url>", index "<index>") is revoked or unresolvable` and the same rest, `<n>` the hop's position in its chain, the root being 0, then `: <reason>` when the checker said why, as the checker `createRevocationChecker` builds does for every entry it fails closed on; a reason is cut after 256 UTF-16 code units and marked with U+2026, with control and hidden characters read as U+FFFD |
| the `<error>` or `<reason>` in `Status check error`, `Signature verification error`, `Could not resolve issuer DID`, `JWT envelope signature is not valid`, `Failed to resolve delegation chain`, `Revocation check failed` and `Delegation <id> is revoked`, as written | cut after 256 UTF-16 code units and marked with U+2026, with control and hidden characters and lone surrogates read as U+FFFD |
| the gate threw, for a value with no JSON form, such as `undefined`, among what a presented credential's issuer signed | `Unreadable credential content: <why>`, given before the reason above |
| the gate threw for a presented credential holding a value that is not plain data, such as an accessor or a class instance, and an ancestor holding one at its top level or in its `proof`, or a Proxy that passes every read through, verified | `Malformed delegation credential: it is not plain data`, or for an ancestor `Resolved delegation chain for <id> holds a value that could not be copied` |
| none: a credential nested deeper than 64 levels, and within the runtime's call stack, verified | `Malformed delegation credential: it nests more than 64 levels deep`, for an ancestor `Resolved delegation chain for <id> holds a value that could not be copied`, and for a VC-JWT `Invalid VC-JWT format` |
| `Delegation credential could not be verified`, where reading a value the resolver returned threw | `Resolved delegation chain for <id> holds a value that is not a delegation credential` |
| `Delegation chain of <n> credentials exceeds the maximum of <max>`, for a resolver that returned more values than `maxChainLength` | `Delegation chain of at least <n> credentials exceeds the maximum of <max>`, `<n>` the number of values returned |
| none: the gate threw when its hash provider failed on a verified delegation | `Delegation credential could not be verified`, with the fault logged |
| `Signature verification error: <error>` from the runtime's base64 decoder, or a verdict on the bytes it gave, for a `proofValue` with a character outside base64, `=` ahead of a base64 character, or no bytes | `Unreadable proofValue: A credential signature is base64url`, or the same and `of at least one byte`; for a status list `CheqdStatusListResolver` reads, `Status list signature verification FAILED against the issuer DID document` |
| none: the signature verified, for an Ed25519 `x` padded with `=` or holding white space, and, but for a response proof, one in the base64 alphabet | `Unreadable x in publicKeyJwk: <why>` for a delegation credential's embedded signature, `Status list signature verification FAILED against the issuer DID document` for a status list `CheqdStatusListResolver` reads, and `errorCode` `INVALID_JWS_SIGNATURE` for a response proof |
| none: the response proof verified, for a JWS segment padded to complete its last group or holding two spaces or a line break | `errorCode` `INVALID_JWS_SIGNATURE` |
| `Proof binds a response (responseHash present) but no response was supplied to verify against`, an em dash and `pass expected.response`; `A response was supplied but the proof binds none`, an em dash and `content/proof mismatch` | the same with a colon for the em dash |

### Status lists held to their credential

A status list is read only when the one keeper of its URL signed it, its `statusPurpose` includes the entry's, and it states as its `id` the URL it was fetched from (SPEC.md §6.6).
So a status check that passed on 1.22.0 can deny.
Read the first two subsections, then find your setup below.

#### Who keeps a status-list URL

Every `statusListCredential` URL has one keeper, the issuer whose signature a list fetched from it must carry.
A reader given `verifyStatusList` decides the keeper before it fetches, from its configuration and the signed credentials, never from the list, by the first of these that applies:

1. the issuer `statusListIssuers` binds that exact URL to;
2. the issuer `statusListIssuers` binds the URL's `https:` origin to;
3. the chain's root issuer, when the verifier pins it and the root's own credential's status entry names the same URL, byte for byte;
4. the credential's own issuer.

A list any other issuer signed is refused, with a reason that names the keeper and why it keeps the URL, such as `status list issuer "did:web:a.example" does not keep this list's URL: "did:web:b.example" does, as the pinned root whose own credential names it`.
The configuration decides before a root's credential does, and at a URL a configured issuer or the root keeps, a list the credential's own issuer signed is refused as any other is.
On 1.22.0 a list was read whoever signed it, so the DID that signed a list could differ from every one of these.

#### How to write `statusListIssuers`

`createRevocationChecker` takes `statusListIssuers`, keyed by the DID of the issuer that keeps the lists, each value the URLs that issuer keeps:

```ts
statusListIssuers: {
  'did:web:status.example': ['https://status.example'],
  'did:web:acme.example': ['https://lists.acme.example/herd/1', 'https://lists.acme.example/herd/2'],
}
```

A value is a whole origin, written `https://`, a lower-case host and an optional port with nothing after it, or an exact URL, which an entry must name byte for byte.
A URL is at an origin when it continues the origin's string with `/`, `?` or `#`; nothing is parsed or normalised, so `https://status.example.evil.example/1`, `https://status.example:8443/1` and `https://STATUS.example/1` are not at `https://status.example`.
An origin whose host is an IPv6 literal is not offered; bind exact URLs.
The map is not scoped by credential issuer: a credential opts in to a keeper by naming, in the status entry its issuer signed, a URL the map binds to that keeper.
One URL or origin has one keeper, so the same value under two issuers throws.
An exact URL of one issuer may lie at an origin of another, and the exact URL decides.
The checker throws a `TypeError` when it is built if the map is not a plain object, a key is empty, a value is not an array, an array holds anything but a string that starts with `https://` or `http://`, or one value is under two issuers, or if the map is given without `verifyStatusList`.
A map from a credential issuer to the issuers accepted for it holds DIDs where URLs belong, so it throws as well, with a message that says each value names the URLs an issuer keeps.

#### A hop whose status entry is on a list its own issuer did not issue

With `verifyStatusList` it reads as revoked, unless the list's issuer is the keeper of the entry's URL: `statusListIssuers` binds that URL, or its origin, to the list's issuer, or the list's issuer is the chain's pinned root and the root's own credential names the same list.
A list signed by an issuer between the root and the hop needs its URL bound to that issuer in `statusListIssuers`.
A deployment whose lists one status service signs binds the service's origin, or each list URL, to the service.

#### A chain whose root signs the lists of the hops below it

The root's list counts for a hop below it only at the URL the root's own credential names, when the verifier pins the root, or at a URL `statusListIssuers` binds to the root.
Pin the root, with `trustedRootIssuers` or `resourceOwner` for `verifyRequestDelegation` and `requireDelegation`, or `resourceOwner` for `evaluateDelegationChain`, and a hop whose entry names the list the root's own credential is on is read from the root's list.
`revocationEntriesOf(chain, trustedRootIssuer)` reads that URL from the root hop's `credentialStatus` and names it to the checker as `trustedRootStatusList`.
A root that keeps other lists for its delegates, the shards of one herd list for example, binds them once, by URL or by origin, as `statusListIssuers: { [root]: [...] }`, and they count for every delegate, pinned or not.
A deployment whose root credential carries no status entry does one of two things: it binds the root's list URLs to the root in `statusListIssuers`, or it gives the root credential a status entry on that list.
Without either, a hop's entry is held to the hop's own issuer, so the root's list at the URL that entry names is refused.
That holds even where the root in fact serves a list at that URL: nothing the verifier holds says the URL is the root's, so the list is refused, which fails closed, and a list the hop's own issuer signs there is read as that issuer's own list.
A hop's issuer always decides the status of its own credential by the list it names; bind a URL to the root for the root's list to decide it there.

#### A Card whose `revocation` list another DID issues

With `verifyStatusList` it reads as revoked, unless `statusListIssuers` binds the list's URL, or its origin, to that DID.
That holds for the Card's `responsibleParty` too.
Once the Card's `accountabilityVerifier` verifies it as the root issuer of the Card's delegation chain, `verifyCard` names it to the checker as the root, with no status-list URL, so its list counts for the Card only at a URL the configuration binds to it, and at the Card's own list URL a list it signs is refused.
At a URL bound to it, the Entity's own list is refused.
A responsible party's list counts for its Cards only once verified, never as the Card states it.

#### A list that states no `id`, signed by anyone but the credential's own issuer

The checker with `verifyStatusList` rejects it, so a list from the pinned root, from an issuer `statusListIssuers` binds the URL to, or from a Card's responsible party must state, as its `id`, the URL it is served at.
`CheqdStatusListResolver` rejects every list that states no `id`.
`StatusList2021Manager` and the publisher in `examples/revoked` state the `id` of every list they write; re-issue any other list with its URL as its `id`.

#### A list that states no `id`, signed by the credential's own issuer

The checker with `verifyStatusList` reads it only where the credential's issuer keeps the URL as that issuer, by rule 4 or as the pinned root whose own credential it is, the verifier pins no other root, and `statusListIssuers` names no other issuer, whatever it binds to it.
Everywhere else it is rejected, since it could otherwise stand in for a list at another URL.
So it is rejected where the verifier pins a root other than that issuer, where `statusListIssuers` has a key other than that issuer, and where `statusListIssuers` binds the URL to that issuer itself.
A pinned root's own list is read without an `id` for the root's own credential, as on a verifier that pins no root, and for no hop below it.
So does `verifyCard` reject a Card's own list without an `id` once the Card's `responsibleParty`, another DID, is verified.
State the list's URL as its `id`.

#### A list that states an `id` other than its URL, byte for byte

The checker with `verifyStatusList` and `CheqdStatusListResolver` reject it.
A DID URL naming the same resource is another `id`, so `CheqdStatusListResolver`, which fetches only https URLs, refuses a list whose `id` is a DID URL.

#### A direct call to a checker built with `verifyStatusList`

Name the credential's issuer, `check(entry, { credentialIssuer })`, and, for a hop of a chain whose root you pin, the root as `trustedRootIssuer` with the URL the root's own credential names as `trustedRootStatusList`.
A `trustedRootStatusList` given without `trustedRootIssuer` is ignored.
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

#### A `credentialStatus`, or a Card's `revocation` entry, that states a `statusSize`

W3C Bitstring Status List v1.0 §2.1 lets an entry state `statusSize`, the size of its status in bits, an integer greater than zero that is processed as 1 when the entry states none, and its §3.2 (Validate Algorithm, step 10) reads an entry's status at the position its `statusListIndex` multiplied by its `statusSize` gives.
§2.1 describes the `revocation` and `suspension` purposes as one status bit each and gives entries of several values to the `message` purpose, so a checker of either purpose refuses a wider entry.
Every status-list reader in the library reads the one bit at the index.
So on 1.22.0 an entry of two bits at index 7 was read from bit 7, which is entry 3's, and not from its own bits, 14 and 15: a credential whose own bits were set passed, and one whose own bits were clear was refused on another entry's status.
Each reader now refuses, before it fetches or reads any list, every entry whose `statusSize` is not `1`.
An entry that states no `statusSize` is one bit wide and is read as before.
A checker `createRevocationChecker` builds resolves a refused entry to revoked and not fresh, so `evaluateDelegationChain`, `verifyRequestDelegation` and `requireDelegation` refuse its chain, the last two as `delegation_revoked`, and `verifyCard` reports its Card as revoked.
`CheqdStatusListResolver` and `StatusList2021Manager.checkStatus` throw `the entry's statusSize is 2, and only an entry of one bit is read`, which `DelegationCredentialVerifier` denies as `status_unresolvable`.
`StatusList2021Manager.updateStatus` throws the same and sets no bit, since the bit at that index is another entry's.
A `statusSize` that is not an integer greater than zero, such as `0`, `-1`, `1.5`, `"2"`, `null` or `[2]`, is refused the same way, with a reason such as `the entry's statusSize ("2") is not an integer greater than zero`.
The hop schema, `DelegationCredentialSchema`, and the Card's entry schema, `BitstringStatusListEntrySchema`, keep `statusSize` and `statusMessage`, so a checker is given the size a hop or a Card states, and reject a `statusSize` that is not an integer greater than zero and a `statusMessage` that is not an array of objects with a string `status` and a string `message`.
They do not check the two further requirements of §2.1, that an entry of more than one bit state a `statusMessage` and that a `statusMessage` have one element for each value the size allows, since every reader refuses such an entry for its size.
On 1.22.0 the hop schema dropped both members, and the Card's entry schema rejected a Card that stated either.
`schemas/kya-os-card.schema.json`, `schemas/card-delegation-credential.json` and `schemas/delegation-credential.json` describe both members.
`withStatusCache` keeps a verdict per `statusSize` as well, so an entry is never answered from the verdict of an entry of another size at the same index.
Issue every credential with an entry of one bit, as `StatusList2021Manager.allocateStatusEntry` does, and re-issue any that states another `statusSize`.
A custom `StatusListResolver` or `BitstringRevocationChecker` is given the entry whole: one that reads the bit at the index should refuse what `acceptEntrySize(status.statusSize)` refuses, before it fetches, and one that reads an entry of several bits where §3.2 places them, for the `message` purpose, is not affected.

#### An `accountabilityVerifier` that returns a value other than a boolean

`verifyCard` takes only a literal `true`, returned bare or as `verified`, as verified, so a truthy value such as `"false"` or `1` now fails the Card's accountability check, and it reads a `fresh` that is present and not a boolean as `false`, which demotes L3 to L2.
Since a verified responsible party is named to the checker as the root of the Card's chain, so that the lists the configuration binds to it count for the Card, SPEC-ENTITY-CARD.md §10.3 states what the verifier must check before it returns `true`: a check of the chain's structure alone, or a stub that always returns `true`, is not enough.

#### A checker built without `verifyStatusList`

It authenticates no list, so it still reads whatever list it is served, as on 1.22.0 (see DEPRECATIONS.md).
Give it `createStatusListProofVerifier`, or a check that resolves `true` only for a proof that verifies under a key the list's `issuer` lists under `assertionMethod`.

#### A custom `StatusListResolver` given to `withKyaOs` or `DelegationCredentialVerifier`

The library reads a list only through it, so a list is held to the credential only as the resolver holds it.
`checkStatus` is now told the credential's issuer; once a list's proof verifies, pass `acceptStatusList(list, statusListExpectationFor(status, context, statusListIssuers))`, with a `statusListIssuers` of your own in the shape above, as `CheqdStatusListResolver` applies the rule to its pin.
`CheqdStatusListResolver` names its `expectedIssuerDid` as the keeper of every URL it reads.

#### A `StatusListResolver` or `RevocationChecker` whose answer is not a boolean

`DelegationCredentialVerifier` takes only a literal `false` from `checkStatus` as not revoked and only a literal `true` as revoked.
Any other answer, such as `undefined`, `null`, `0`, `""`, `"false"` or `{}`, denies the credential with the outcome `status_unresolvable`.
`validateDelegationChain` reads a `RevocationChecker` the same way: a chain passes only on an answer whose `revoked` is `false`, is revoked only when it is `true`, and is refused on any other answer, one that is not an object included.
On 1.22.0 each answer was read by its truthiness, so a credential passed on `undefined`, `null`, `0` or `""`, was revoked on `"false"` or `{}`, and `validateDelegationChain` threw a `TypeError` on an answer of `undefined` or `null`.
An answer's `reason` and `revokedAncestor` are now used only when they are strings.
Each member of a `RevocationChecker`'s answer is read once, and an answer with a member whose getter throws is refused as well, with a reason that names the member, such as `Revocation status of delegation "del-1" could not be read: the revoked member of the revocation checker's answer threw when it was read`; `validateDelegationChain` returns that refusal and does not reject, and the delegation gate answers with it.
`withStatusCache` does not keep an answer that is not a boolean, so the next check asks its resolver again.
`CascadingRevocationManager` reads what its status list's `checkStatus` answers the same way: `isRevoked` reports a delegation as revoked, itself or through the ancestor concerned, when the answer is neither `true` nor `false`, with the reason `Credential status could not be read: the status list resolver's answer (<v>) is neither true nor false`, and does not throw on it; on 1.22.0 it read the answer by its truthiness, so `undefined`, `null`, `0` or `""` left the delegation reading as live.
A resolver or checker written in TypeScript against the library's types already answers a boolean and needs no change; make any other return `true` or `false`, or throw when it cannot tell.

#### A `BitstringRevocationChecker` whose answer is not `{ revoked, fresh }` with literal booleans

This is the checker given to `evaluateRevocationChain` and `evaluateDelegationChain`, to `verifyRequestDelegation` and `requireDelegation` as `checkRevocation`, and to `verifyCard` as `statusListChecker`.
Its answer is read by the reader the delegation side uses, so the rule is the same on both sides.
A hop or a Card passes only on an answer whose `revoked` is the literal `false`, is revoked only when it is the literal `true`, and is fresh only when `fresh` is the literal `true`.
Any other answer, such as `undefined`, `null`, `0`, `{}`, `{ revoked: 0 }`, `{ revoked: "false" }` or one with a member whose getter throws, refuses the hop with a reason that says what was wrong, such as `revocation: hop 0 (list "https://status.example/1", index "7") has a status that could not be read: the revoked member of the revocation checker's answer (of type number) is neither true nor false`.
`verifyRequestDelegation` and `requireDelegation` refuse the call as `delegation_revoked` with that reason.
`verifyCard` reports such a Card as `revocation: { revoked: true, fresh: false, reason }`, where `reason`, a new optional member, says what could not be read; it is `ok: false` at L1, as any revoked Card is.
On 1.22.0 each member was read by its truthiness: a hop or a Card passed on `{}` or `{ revoked: 0 }`, was revoked on `{ revoked: "false" }`, was fresh on any truthy `fresh`, such as `1` or `"false"`, and `evaluateRevocationChain` threw a `TypeError` on `undefined` or `null`.
`RevocationStatus` has a new optional member, `reason`: why the status could not be proven clear.
The checker `createRevocationChecker` builds gives one whenever it fails closed, such as `status-list proof rejected` or the reason `acceptStatusList` gave, and a custom checker may give its own.
`evaluateRevocationChain` appends it to the refusal of a revoked hop, and `verifyCard` reports it as `revocation.reason`, each cut after 256 UTF-16 code units.
Code that compares a verdict of that checker with `{ revoked: true, fresh: false }` exactly must allow for the member.
A checker that `createRevocationChecker` builds, or one written in TypeScript against `RevocationStatus`, already answers two booleans and needs no change; make any other return `{ revoked: true, fresh: false }` when it cannot tell.

### Status-list exports for a custom reader

These are new in `@kya-os/mcp`, `@kya-os/mcp/delegation` and `@kya-os/mcp/card`, for a `StatusListResolver` or checker of your own.

Given a fetched list and a `StatusListExpectation`, the entry's `statusListCredential` and `statusPurpose`, the `keeper` of that URL and `requireId`, `acceptStatusList` returns a `StatusListVerdict`, `{ valid: true }` or `{ valid: false, reason }`.
The list's `issuer` must be `keeper.did`, its `statusPurpose` must include the entry's, as one string unless the list is a `BitstringStatusListCredential` with a `BitstringStatusList` subject, and its `id` must be, byte for byte, the URL it was fetched from.
A list may leave the `id` out only when `requireId` is `false`.
The rule decides by the list's `issuer` and checks no proof, so a custom `StatusListResolver` applies it once the list's proof verifies under a key that `issuer` lists under `assertionMethod`.
`statusListKeeperFor(statusListCredential, context, statusListIssuers)` returns the keeper, `{ did, why }`, by the four rules above, where `why` is `configured-url`, `configured-origin`, `root-credential` or `credential-issuer`; a resolver with one pinned issuer, as `CheqdStatusListResolver` is, names `resolver-issuer`.
It throws the `TypeError` `createRevocationChecker` throws for a `statusListIssuers` it could not apply.
`statusListExpectationFor(entry, context, statusListIssuers)` builds the expectation `acceptStatusList` takes for an entry, as each reader in the library that holds a list to its credential does: the keeper `statusListKeeperFor` names, and `requireId: false` only where the credential's issuer keeps the URL as that issuer, by rule 4 or as the pinned root whose own credential it is, the context pins no other root and `statusListIssuers` names no other issuer.
So a custom `StatusListResolver` passes `acceptStatusList(list, statusListExpectationFor(status, context, statusListIssuers))`.
`acceptEntrySize(statusSize)` returns the same kind of verdict for an entry's `statusSize`: valid when the entry states none or states `1`, and otherwise not, with the reason, for a reader that reads one bit per entry.
All four, with their types, are exported from `@kya-os/mcp`, `@kya-os/mcp/delegation` and `@kya-os/mcp/card`.
`StatusListResolver.checkStatus` and `BitstringRevocationChecker` take a `StatusCheckContext` as an optional second argument: `credentialIssuer`, and for a chain whose root the verifier pins, `trustedRootIssuer` and `trustedRootStatusList`, the URL the root's own credential names.
`withStatusCache` passes it on and caches per context, and `revocationEntriesOf(chain, trustedRootIssuer)` builds it for every hop of a delegation chain, as a `RevocationChainEntry` that carries the hop's `statusPurpose` and its `position` in the chain.
`createRevocationChecker` takes `statusListIssuers`, described under "How to write `statusListIssuers`".
The delegation middleware names only the credential's own issuer to its resolver, even when `trustedRootIssuers` pins the chain's root, so on that path a list the root signed for a re-delegated credential is refused unless the resolver's own configuration binds the list's URL, or its origin, to the root and the list states its `id`.

### Limits on DID resolution and status-list reads

DID resolution and status-list reads refuse inputs over fixed limits, and give up after 5 seconds, or after the time the host sets as `dependencyTimeoutMs`.
A DID may have at most 2,048 UTF-16 code units and a key id at most 4,096, whether a verifier is asked to resolve it or a DID document names it, as its `id` or, in `verificationMethod` and the verification relationships, as a method's `id` or `controller` or a reference to a method; any other identifier in a document, such as its top-level `controller` or an `alsoKnownAs` entry, is held only to the document's limits below.
A DID document may nest at most 64 levels deep and have at most 8,192 members, member names of at most 256 UTF-16 code units, 8,192 entries across `verificationMethod` and the five verification relationships, and 1 MiB of compact JSON.
A did:web response, and a status list read by `CheqdStatusListResolver` or `RuntimeFetchProvider.fetchStatusList`, may have at most 1 MiB decompressed, within the same nesting and member limits; a cheqd resolver response may have at most 4 MiB, 65 levels deep and 131,072 members, room for a DID Resolution Result that lists thousands of resources.
Each read has one 5-second deadline for the fetch and the body, a did:web or status-list read follows at most 3 redirects, and each built-in DID resolver caches at most 128 documents and 8 MiB, evicting the least recently used.
`DelegationCredentialVerifier`, `CheqdStatusListResolver`, `createStatusListProofVerifier`, `createDelegationProofVerifier` and `ProofVerifier` wait at most 5 seconds for any resolver and hold the document it returns to the same limits, and to plain JSON data: a document with a getter on an object member, enumerable or not, a cycle, a class instance or a value JSON cannot hold, such as a function or `NaN`, is refused.
So is a document, or an object inside it, that inherits from anything but `null` or an `Object.prototype`, of this realm or of another such as a `vm` context, so a verifier reads no member, and runs no getter, that an object inherits under a name `Object.prototype` does not have.
A getter on an array element is not refused: it runs, once, and the value it returns is held to the same limits and is the value a verifier reads, or the document is refused when it throws.
A verifier reads its own copy of a custom resolver's document, made as the document is measured: plain objects and arrays that hold each own enumerable data member and each array element by index, each read once.
So nothing else of the returned object reaches a verifier: a member that is not enumerable, which 1.22.0 read, an array's own or inherited `Symbol.iterator` or a method such as `find`, a `Proxy` trap's second answer, or a change made after the document was measured.
`DelegationCredentialVerifier`, `validateDelegationChain`, `verifyRequestDelegation`, `requireDelegation`, `evaluateDelegationChain`, `verifyCard` and `verifyCardProof` give the same 5 seconds to each other dependency the host supplies that they wait on, such as a `StatusListResolver`, a `resolveDelegationChain` or a `RevocationChecker`.
"A dependency that can take longer than 5 seconds to answer", below, lists each and how it is refused.
One dependency of theirs has no deadline from the library: the `verifier` that `validateDelegationChain` is given to verify each credential, since the library's own, `DelegationCredentialVerifier`, bounds each of its steps, and one limit on the whole would refuse a verification whose steps each kept theirs.
A custom one must set its own, and so must a provider no function above calls, such as the nonce cache and the session store of `ProofVerifier` and the middleware.
Anything over a limit is refused, never cut to fit, so check that your DID documents and status lists are within these limits before you upgrade.
SPEC.md §4.4.2 explains each limit.
Every did:web and status-list read also holds its host, and each redirect, to one private-network rule, whatever `FetchProvider` it reads through.
Find your setup below.

#### A custom `FetchProvider` given to the did:web or cheqd resolver, or to `CheqdStatusListResolver`

Its `fetch` must return a `Response` whose `body` is a WHATWG `ReadableStream`.
The readers read the body as a stream and no longer call `json()`, so an adapter or mock that implements only `json()` resolves nothing, and neither does node-fetch v2, whose body is a Node stream.
A body that is not valid UTF-8 is refused, where `json()` replaced the invalid bytes.

#### A `DidCheqdResolver` given `headers`

Each request now sends `Accept: application/did+ld+json`, which asks the cheqd DID resolver for the DID document alone, in place of any `Accept` header the option sets, and the provider's `fetch` receives the headers as a `Headers` object, not the object the option gives.
A `headers` function now runs under the read's 5-second deadline: one that has not answered by then fails that resolution, and the next resolution calls it again.

#### A custom DID resolver: `delegation.didResolver`, a resolver in `didResolvers`, the `didResolver` of `DelegationCredentialVerifier`, `CheqdStatusListResolver`, `createStatusListProofVerifier` or `createDelegationProofVerifier`, or a `FetchProvider.resolveDID` that `ProofVerifier` uses

The document it returns must have an `id` that is a DID, a string that starts with `did:`, of at most 2,048 UTF-16 code units.
Without one it verifies nothing, even when it lists the key.
Its document is checked on every resolution, and the object it returned is neither frozen nor changed.
The verifier copies it as it checks it and reads only the copy, so the resolver need not return a new object each time, and a change it makes to a returned object is seen at the next resolution, not during a verification.
A key the document must publish has to be an own enumerable member, and an array's entries its elements by index, as `JSON.stringify` would write them.

#### A custom `FetchProvider` that reads did:web documents or status lists, such as `delegation.fetchProvider`

Each read now calls its `fetch` with `redirect: "manual"` and follows a redirect itself, refusing a target the private-network rule refuses and a step from https down to http, and sending another origin only the CORS-safelisted request headers and the request's `Cache-Control` and `Pragma`; in a browser, which hides where a redirect leads, it refuses every redirect.
The provider's `fetch` must pass `redirect` on to the request.
One that drops it lets the runtime follow a redirect before the read sees the response: the read then refuses a response that says it was redirected, or names a URL other than the one asked for, but the request has been made.

#### A custom `FetchProvider` whose response names a URL other than the one asked for, such as a gateway, a proxy or a test double that rewrites URLs

Every did:web and status-list read through it is now refused as a redirect the provider followed itself (`Redirect followed by the fetch provider refused`).
Its `fetch` must pass `redirect` on, so that the read follows and checks each redirect, and return a response whose `url` is the URL asked for, or empty, and whose `redirected` is not `true`, such as `new Response(response.body, response)` built from the response it got.
Rebuilding a response after following a redirect itself would hide that redirect from the read.

#### A did:web DID or status list served from a private IP address or a local name, such as `localhost`, as in development

Every did:web read, by the delegation gate, `DidWebResolver`, `createDidWebResolver` or `RuntimeFetchProvider.resolveDID`, and every status-list read, by `CheqdStatusListResolver` or `RuntimeFetchProvider.fetchStatusList`, now refuses a URL whose host is a non-public IP literal or a local name, in any case and with any trailing dots, through any provider.
A local name is a single label, such as `ip6-localhost`, `metadata` or an intranet host's short name, or `localhost`, `localdomain`, `localdomain6`, `local`, `internal` or `home.arpa`, or a name under one of them, such as `localhost.localdomain`, `localhost6.localdomain6`, `printer.local`, `router.home.arpa` or `metadata.google.internal`.
It classifies an address as `SafeFetch` does, so it refuses more than `RuntimeFetchProvider` did, such as an IPv4-mapped, IPv4-translated or NAT64 IPv6 form of a private address, shared address space (100.64.0.0/10), the documentation ranges and multicast.
To read from such a host, give the reader `new RuntimeFetchProvider({ allowPrivateNetworkHosts: true })`, as `delegation.fetchProvider` for the gate, or a custom provider whose `allowPrivateNetworkHosts` member, now declared on `FetchProvider`, is `true`; `RuntimeFetchProvider` now exposes its option as that read-only member.
Only `true` opts in: `RuntimeFetchProvider` no longer reads another truthy value, such as `1` or `'true'`, as `true`.
The rule resolves no name, so it does not refuse any other name whose address is private, such as a public name that points at a loopback address: a verifier needs an egress control that refuses private addresses for that.

#### Code that calls `isBlockedAddress` or `createSafeFetch`

An IPv4-translated IPv6 address (`::ffff:0:0:0/96`) is now classified by the IPv4 address it embeds, as an IPv4-mapped one is, so one that embeds a private address is refused.

#### A did:web or status-list URL whose scheme is not http or https

Every did:web and status-list read now refuses a URL that is not an absolute http or https URL, such as a `data:` or `file:` URL, before any request, whatever `allowPrivateNetworkHosts` says.
`RuntimeFetchProvider.fetchStatusList` read such a URL through the runtime's `fetch`.

#### A DID longer than 2,048 UTF-16 code units, such as a did:key for an ML-DSA-65 or ML-DSA-87 post-quantum key, or a did:peer:2 that lists many keys or services

A verifier now refuses it before asking any resolver, so no credential or proof such a DID issued verifies.
The limit is the reference implementation's, not DID syntax's, and cannot be changed.

#### Code that calls `RuntimeFetchProvider.resolveDID` or `fetchStatusList` directly

Each now applies these limits and its deadline itself, and returns `null` for a document or list over a limit, a read that misses its deadline, or a URL or redirect the private-network rule refuses.
`resolveDID` falls back from a resolver set in `didResolvers` to the built-in did:web or did:key resolver only when the configured one finds no document, not after it returns a document these limits refuse or misses the deadline, and spends one 5-second deadline across both.

#### Code that changes a resolved DID document

`DidWebResolver` and `DidCheqdResolver`, and `RuntimeFetchProvider.resolveDID` through them, return a deeply frozen document, which their cache and concurrent resolutions of the same DID share.
`RuntimeFetchProvider.resolveDID` also returns a deeply frozen document for a resolver set in `didResolvers`: the copy made as that resolver's document was checked, not the object the resolver returned.
Copy it before you change it: assigning to it throws in strict mode.

#### `delegation.trustedRootIssuers`, and the `trustedRootIssuers` of `requireDelegation` and `verifyRequestDelegation`

It must be an array of DIDs, each a string that starts with `did:` and has no white space around it, compared whole with the root's `issuer`.
Creating the middleware or a `requireDelegation` guard with any other value throws a `TypeError` naming the option, `verifyRequestDelegation` rejects with one, and `validateDelegationChain` returns `{ valid: false }` with its reason.
`null` no longer admits every root in the middleware, and a string is no longer searched for the issuer in either.

#### A `delegation.resolveDelegationChain`

For a VC-JWT whose leaf names a parent, it now runs on the leaf's payload before the envelope's signature is checked, so it must treat that payload as unauthenticated, as it already had to for a credential with an embedded proof, whose proof is checked after it runs.
The chain it returns is verified as before.
It now has 5 seconds to return, so a resolver that walks `parentId` one read at a time should finish, or give up, within that time.

#### A dependency that can take longer than 5 seconds to answer

Each call a verifier makes to a dependency the host supplies now has 5 seconds, and one that has not answered by then is refused as below, never thrown, where on 1.22.0 the verification waited without end.
The dependency's own work is not cancelled, so one that reads over a network should bound each read itself, and a later verification asks it again.

| Dependency | Refused as |
| --- | --- |
| `StatusListResolver.checkStatus`, for `DelegationCredentialVerifier`, the shipped `CheqdStatusListResolver` and a resolver wrapped in `withStatusCache` included | the credential denied with the outcome `status_unresolvable` and `Status check error: the status list resolver did not answer within 5 seconds` |
| a custom `signatureVerifier` of `DelegationCredentialVerifier` | `Signature verification error: the signature verifier did not answer within 5 seconds` |
| `resolveDelegationChain`, for `validateDelegationChain` and the delegation middleware | `Failed to resolve delegation chain: the chain resolver did not answer within 5 seconds` |
| `RevocationChecker.isRevoked`, for the same two | `Revocation check failed for delegation "<id>": the revocation checker did not answer within 5 seconds` |
| `resolveDelegationChain` of `verifyRequestDelegation` and `requireDelegation` | the code `delegation_unresolvable` and `delegation chain could not be resolved: the chain resolver did not answer within 5 seconds` |
| `verifyHopProof` of the same two | the code `delegation_invalid` and `hop <n>: the hop proof verifier did not answer within 5 seconds` |
| `checkRevocation` of the same two, and the checker given to `evaluateDelegationChain` or `evaluateRevocationChain` | the code `delegation_revoked`, or a chain that is not ok and not fresh, and `revocation: hop <n> (list "<url>", index "<index>") is unresolvable: the revocation checker did not answer within 5 seconds` |
| `capabilityVerifier`, `accountabilityVerifier` and `attestationVerifier` of `verifyCard` | the claim unverified: no capability verified, the Card not accountable, or that attestation unverified |
| `proofVerifier` of `verifyCard` | the proof unverified, with the reason `the proof verifier did not answer within 5 seconds` |
| `statusListChecker` of `verifyCard` | the Card revoked and not fresh, with the `revocation.reason` `the revocation checker did not answer within 5 seconds` |
| `resolveKey`, `resolveDidKeys` and `consumeNonceIfFresh` of `verifyCardProof` and `requireProof` | the reasons `key_unresolvable`, `did_keys_unresolvable` and `nonce_cache_unavailable`, as when each throws |

The 5 seconds cover the whole call, so a checker built with `createRevocationChecker` has them for its list read and its `verifyStatusList` together, and `CheqdStatusListResolver` for its list read and its DID resolution together.
A dependency that throws is handled as on 1.22.0.

To give a dependency longer, set `dependencyTimeoutMs`, in milliseconds, on the verifier, resolver or provider that waits for it.
It is one option with one name on every entry point below, and its default is 5,000.
It must be a number greater than 0 and at most 2,147,483,647, the longest delay a timer holds, about 24.8 days.
Any other value, such as `0`, a negative number, `NaN`, `Infinity`, a numeric string or `null`, throws a `TypeError` that names the option where the verifier is built, and nothing is converted.

| Entry point | The waits its `dependencyTimeoutMs` sets |
| --- | --- |
| `delegation.dependencyTimeoutMs` of `withKyaOs` and `createKyaOsMiddleware` | every wait of the delegation gate: its DID resolution, a did:web read through the fetch provider it builds, `statusListResolver`, `resolveDelegationChain` and `revocationChecker`; a bad value is refused at startup as `delegation.dependencyTimeoutMs` |
| `DelegationCredentialVerifier` and `createDelegationVerifier` | the DID resolver, a custom `signatureVerifier` and the `StatusListResolver` |
| the dependencies of `validateDelegationChain` | `resolveDelegationChain` and `RevocationChecker.isRevoked`; a bad value returns `{ valid: false }` with its reason, as a bad `trustedRootIssuers` does |
| the dependencies of `verifyRequestDelegation` and `requireDelegation` | `resolveDelegationChain`, `verifyHopProof` and `checkRevocation`; the first rejects with the `TypeError`, the second throws it when the guard is built |
| the context of `evaluateDelegationChain`, and a new third argument of `evaluateRevocationChain`, `{ dependencyTimeoutMs }` | each answer of the revocation checker; each rejects with the `TypeError` |
| the dependencies of `verifyCard` | `capabilityVerifier`, `accountabilityVerifier`, `attestationVerifier`, `proofVerifier` and `statusListChecker`; it rejects with the `TypeError` |
| the dependencies of `verifyCardProof` and `requireProof` | `resolveKey`, `resolveDidKeys` and `consumeNonceIfFresh`; the first rejects with the `TypeError`, the second throws it when the guard is built |
| `createRevocationChecker` | one check, its list read and its `verifyStatusList` together |
| `createDelegationProofVerifier` and `createStatusListProofVerifier` | the DID resolver |
| `DidWebResolver` and `createDidWebResolver` | one read of a did:web document, and how long resolutions of one DID share a pending read |
| `DidCheqdResolver`, `createDidCheqdResolver` and `cheqdResolver` | one resolution: its `headers` function, the request and the body |
| `CheqdStatusListResolver` and `createCheqdStatusListResolver` | the list read, and the resolution of the issuer's DID |
| `RuntimeFetchProvider` | one `resolveDID`, across a configured resolver and the built-in one, and one `fetchStatusList` |
| `ProofVerifier` | `fetchProvider.resolveDID` |

A deadline covers the whole call it is put on, so a dependency that is itself built from one of these needs the option too.
For example, a `verifyCard` given 30,000 still fails a status check after 5 seconds when its `statusListChecker` was built by `createRevocationChecker` without the option, or that checker's `verifyStatusList` resolves a DID through a `DidWebResolver` built without it.
The middleware passes `delegation.dependencyTimeoutMs` to the verifier, the did:web resolver and the fetch provider it builds itself, and to each factory in `didResolvers`, so a resolver that `cheqdResolver(options)` builds waits as long unless its own options set another time.
It does not pass it to an object the host built: a `fetchProvider`, a `didResolver`, a resolver instance in `didResolvers` or a `statusListResolver`, such as a `CheqdStatusListResolver`, each of which takes its own.
A `RuntimeFetchProvider` passes its `dependencyTimeoutMs` to the factories in its `didResolvers` the same way.
A `didResolvers` factory of your own receives it as the `dependencyTimeoutMs` of a new second argument.
A reason states the time that was configured: `did not answer within 30 seconds` for 30,000, and in milliseconds when it is not a whole number of seconds, as in `did not answer within 7500 ms`.
A checker built with `createRevocationChecker` now also has this deadline when it is called directly, where on 1.22.0 it waited without end, and resolves revoked and not fresh when it is missed.
`verifyVcJwtSignature` takes the time for its DID resolver as an optional fifth argument.
`SafeFetch`'s `timeoutMs`, which bounds each hop of its own fetch, is a separate option and is unchanged.

#### A custom `signatureVerifier`, or another dependency, whose verdict is not the boolean its type promises

`DelegationCredentialVerifier` takes the answer of a custom `signatureVerifier` as a verified signature only when it is an object whose `valid` is the literal `true`.
On 1.22.0 `valid` was read by its truthiness, so a credential whose signature did not hold verified on `{ valid: "false" }`, `{ valid: 1 }` or `{ valid: {} }`.
An answer whose `valid` is the literal `false` refuses the credential with the answer's `reason`, when that is a string, as text of at most 256 UTF-16 code units with no control character.
Any other answer refuses it with a reason that starts `The verdict of the signature verifier could not be read`: one that is not an object, one whose `valid` is not a boolean, and one whose `valid` or `reason` throws when read.
`validateDelegationChain` reads the answer of the `verifier` it is given the same way, with a reason that names `the credential verifier`, where on 1.22.0 it passed a credential on any truthy `valid` and threw a `TypeError` on an answer of `undefined` or `null`.
A verifier written in TypeScript against the library's types already answers a boolean and needs no change; make any other return `{ valid: true }` or `{ valid: false, reason }`.
`verifyCard` reads its other seams as it already read `accountabilityVerifier`.
An `accountabilityVerifier` answer that is neither a boolean nor an object, whose `verified` is not a boolean, or that throws when read leaves the Card not accountable with `accountability.reason` saying why, where a member that threw made `verifyCard` throw.
An `attestationVerifier` verifies an attestation only on the literal `true`, where a truthy value such as `"false"` or `1` verified it.
A `proofVerifier` verifies the proof only on an object whose `ok` is the literal `true` and whose `did` is a string, and its `level` is reported only when it is `L3` or `L3-minus`; on the literal `false` the proof is unverified with the `reasons` that are strings, and on any other answer, `undefined` included, with the one reason `proof_verdict_unreadable`, where a truthy `ok` such as `"false"` lifted the Card to L3.
A `capabilityVerifier` must answer an object whose `verified` and `unverified` are arrays of strings, or no capability counts as verified and the Card stays at L1, where `verifyCard` threw a `TypeError` on an answer without a `verified` array; a `fresh` that is present and not the literal `true` reads as `false`, which demotes L3 to L2, where a truthy value such as `"false"` kept L3.
`CheqdStatusListResolver` takes a status list's signature as verified only when its `cryptoProvider.verify` answers the literal `true`, where a truthy value such as `"false"` or `1` verified it.
A nonce cache without `consume()` admits a nonce only when its `has()` answers the literal `false`: any other answer, such as `undefined`, `null` or `0`, now denies the request as a replay and adds nothing, where it admitted the nonce.
The audit verifiers read each boolean a dependency answers the same way, passing only on the literal `true`, where a truthy value such as `"false"`, `1` or `{}` passed.
`AuditArtifactVerifier` and `verifyAuditBundle` take `signatures.verify` so for an entry's, a checkpoint's, an observation's and a bundle's signature, and `verifyAuditBundle` its `verifySupportingAnchor` for an anchor.
`MemoryAuditCheckpointObserver` takes its `verifyCheckpoint` and `verifyConsistency` so, `AuditRecorderService` its `authorizer.authorize` and its `epochTransitionGuard.verifyAndSeal`, and `MemoryAuditEvidenceProvider` its `authorizeAccess`.
`verifyApprovalQuorum`, and the policy gate through it, counts an approver only when `isValidApprovalSignature` answers the literal `true`.
The delegation gate takes a credential's signature as verified only when the middleware's `CryptoProvider.verify` answers the literal `true`; any other answer is refused as `Signature verification failed`.
`verifyOrHints` authorizes an agent only when its `delegationVerifier` answers an object whose `valid` is the literal `true` and whose `delegation` is an object, and hands back a `credential` only when that is an object.
On 1.22.0 it read `valid` and `delegation` by their truthiness, and threw a `TypeError` on an answer of `undefined` or `null`; any answer that is not a verdict now leaves the agent unauthorized with a reason that starts `The verdict of the delegation verifier could not be read`.
`AuthorizationServerRegistry.resolve` skips an adapter only when its `isRequired` answers the literal `false`: on any other answer, such as `undefined`, `null` or `0`, the adapter now runs, where it was skipped.

#### Code that calls `DelegationCredentialVerifier` directly

It now reads a credential's status only once the signature has verified, not alongside it, so a credential whose signature fails causes no status read.
Its result then reports the status as not checked: `checks` has no `statusValid`, where it held the outcome of a status read, and there is no `statusOutcome`.

#### Code that reads `DelegationCheck.vc` on a failure

For a VC-JWT whose envelope does not verify, it now has the `proof: { type: "JwtProof2020", jwt }` marker that the gate adds to a VC-JWT's credential, where it was the embedded credential without one.

#### Code that matches on a failure `reason`

A chain's links, and then its root's `issuer` against `trustedRootIssuers`, are checked before any credential is verified, so a broken link or an untrusted root now gives that reason even when a signature would also fail, and for a VC-JWT the reasons for a malformed chain, a missing `resolveDelegationChain`, `maxChainLength` and root admission come before the envelope's.
An untrusted root reads `Root delegation <id> is issued by "<issuer>", which is not a trusted root issuer`, the issuer quoted as other reasons quote a value.
`Could not resolve issuer DID` is the reason for an issuer DID over its limit, for a VC-JWT as for a credential with an embedded proof, without asking the resolver.
A resolution that misses its deadline fails with a reason that ends `DID resolution deadline exceeded`, and a status-list read with one that ends `Status list fetch deadline exceeded`, or names the limit it exceeded.
Any other dependency that misses it gives a reason that ends `did not answer within 5 seconds`, or within the time `dependencyTimeoutMs` sets, listed under "A dependency that can take longer than 5 seconds to answer".
`ProofVerifier` refuses a DID or key id over its limit with `DID or key identifier exceeds resource limit`, and an empty DID with `DID is empty`.

#### A did:cheqd DID whose unique id is not a UUID or letters and digits

`parseDidCheqd` reads only the unique id cheqd's DID method defines, a UUID or letters and digits, and `DidCheqdResolver` refuses any other DID before a request.
On 1.22.0 it read any unique id without `/`, `?` or `#`, and asked the resolver for it.
`didCheqdToResolverUrl` writes the DID as one path segment, percent-encoded except for its colons, so a DID of the method is written as before.

### Checking a proof against a delegation chain

A response proof can bind the delegation chain a call was decided under, and a verifier that holds the chain checks it.
SPEC.md §7.8 defines the two claims a proof may carry about a delegation, both covered by its signature: `delegationRef`, the reference of the credential the call presented, and `delegationChainDigest`, one digest over each credential of the chain, root to leaf, each taken over what its issuer signed and that signature, so a copy of a credential with other proof metadata, or its signature padded or broken across lines, gives the same value.
Signing either claim from the server is not part of this release: `withKyaOs` sets neither.

Whoever holds the chain checks it by passing `delegationChain` with the request and response that `ProofVerifier.verifyProof` and `verifyProofArtifact` compare.
The proof must then bind that chain, name its last credential, and record a call that was allowed.
A chain given as `null` is none, as an outcome given as `null` is, and one that is not an array, as an untyped caller may pass, is a chain no proof binds.
A refusal is signed too, and binds what the caller presented and its signer examined, which says nothing of whether it is valid: to check one, pass the new `outcome` member (`'denied'`, say) with the chain.
A failure names the comparison in `details`, in the shape of the new `ProofBindingMismatch` type, under two new error codes: `OUTCOME_MISMATCH` for a proof that records another outcome, and `DELEGATION_BINDING_MISMATCH` for one that binds no chain (`delegation-chain-unbound`), binds another (`delegation-chain`), or names another credential than the chain's last (`delegation-ref`).
`CONTENT_BINDING_MISMATCH` stays the code for a request or response that does not match, and now carries `details` as well.
`ProofVerificationErrorCode` gains the two new codes, so a `switch` over it that the compiler checks for exhaustiveness needs a case for each.

`delegationCredentialDigest`, `delegationChainDigest`, `digestDelegationChain` and `signedForm` compute the digests anywhere.
`delegationCredentialId`, `delegationReference` and `delegationRefOf` derive the reference a proof names a credential by.
`signingInput` gives the bytes a credential's signature is checked over, and a value that has no signed form throws `NoSignedFormError`.
They read a credential object as the JSON it stands for: an array's elements whether or not they are enumerable, any other member only when it is, and a member keyed by a symbol leaves it with no signed form.
Each takes the hash it digests with as a `Sha256`: a function from bytes to `sha256:<64 lowercase hex>`, such as a bound `CryptoProvider.hash`.
All of these are exported from the package root and from `@kya-os/mcp/delegation`, and the types `ExpectedContent` and `ProofBindingMismatch` from the root and from `@kya-os/mcp/proof`.
Exported beside them, from the root and from `@kya-os/mcp/delegation`, are the constants `DELEGATION_CREDENTIAL_DIGEST_DOMAIN`, `DELEGATION_CHAIN_DIGEST_DOMAIN` and `MAX_CREDENTIAL_NESTING_DEPTH` (64: how deep the arrays and objects of a credential may nest, SPEC.md §7.8), and the types `ReceivedCredential`, `DelegationChainDigests`, `SignedForm`, `SignedCredential`, `SignedJwt` and `Sha256`.

### Delegation audit events, and how the gate reads a credential

The audit events of the delegation gate's decision say which delegation it decided on, by the reference and the digests of SPEC.md §7.8.
`delegation.rejected` now carries `delegationRef` and `delegationCredentialDigest` in its authorization evidence, where it carried none, and a retry allowed under a stored grant carries those of the delegation the grant was minted from, on `grant.used` and in the context handed to the handler.
`delegation.verified`, `delegation.rejected` and `grant.used` also list `delegationChainDigests`, one digest per credential evaluated.
On a refusal that is what the server had examined when it refused: the ancestors up to the one it stopped at, then the presented credential.
A refusal in which a value a resolver returned could not be read lists none.
`delegationCredentialDigest` is now the digest of SPEC.md §7.8 rather than a hash of the bytes presented, so it no longer changes with proof metadata the issuer did not sign.
The events recorded with the context the gate hands the handler take their evidence from `context.authorization`, and a call the gate refuses after its chain verified, on holder binding or scope, is recorded without the delegation, both as before.
Response proofs are unchanged and carry no delegation claim.
Along with it:

- `delegationRef` has one definition, in SPEC.md §7.8, for the audit trail and for a proof that carries it.
  A refused credential's id is no longer cut to 256 characters.
  An id that is too long is recorded as its `sha256:` digest, so two long ids with the same beginning stay apart.
  So is an id that holds a character that does not print as itself (a control or format character, a bidirectional override or a zero-width space among them, a line or paragraph separator, or a code point that renders as nothing by default, such as a variation selector, as SPEC.md §7.8 lists them), and so is one that holds a surrogate without its pair, hashed over its WTF-8 bytes.
  So is one that is itself written as such a digest, so a reference of that form never stands for an id a caller chose, and one that is the word `unknown`, which the events name a credential that shows no id by.
  A VC-JWT with no credential id is recorded by its `jti`.
  An empty `id` is no id: a credential whose `id` is `""` is recorded by the id of its delegation (`credentialSubject.delegation.id`), where the empty string used to be taken for its id.
  Every other audit reference that holds a character that does not print is now recorded as its digest too.
- A `proofValue` is read one way wherever it is checked, a delegation credential's and a status list's that `CheqdStatusListResolver` reads: its base64 characters in either alphabet, with ASCII whitespace passed over, and `=` passed over at the end.
  One written with those verifies on every runtime, where it used to depend on the decoder underneath.
  One with any other character, with `=` ahead of a base64 character, or of no bytes at all does not.
  A VC-JWT is read as it was: every JWT that verified still verifies, and none that did not now does.
- The gate reads the presented credential, and each value a resolver returns, once, as plain data: the credential when it is presented, and each value the resolver returns, root first, as soon as it is returned and before anything else reads it.
  It checks the value, copies it, and verifies and records the copy, so what it verifies and what it records are one reading, and `resolveDelegationChain` is handed the copy of the presented credential.
  The copy is not frozen, so a resolver that changes it changes what is verified and recorded, and how deep it nests is counted again each time it is read: one nested deeper than 64 levels since is refused with `Unreadable credential content: A credential object nests at most 64 levels deep`.
  Every server does this, whether or not it keeps an audit trail: the verdict on a credential does not turn on what the server records.
  A value that is not plain data is refused wherever in a credential it is, `proof` included: a Proxy, an accessor, a symbol-keyed member, an array element that is not enumerable (a copy leaves it out, and JSON has it), a class instance, a `Map` or any other object that is neither a plain object nor an array, and a function or a symbol.
  In 1.22.0 a presented credential holding one of these made the gate throw, an ancestor holding one at its top level or in its `proof` verified, and so did a Proxy that passes every read through, presented or resolved, wherever it stood.
  All of these are now refused.
  A resolved value that is not shaped as a delegation credential refuses the chain by name.
  The resolver's own copy of the leaf is read like the rest and then set aside, as in 1.22.0, whatever it holds; one that cannot be read now refuses the chain, where 1.22.0 passed over it.
  A resolver that returns more values than `maxChainLength` has the chain refused before any of them is read.
- The arrays and objects of a credential nest at most 64 levels deep (SPEC.md §7.8, `MAX_CREDENTIAL_NESTING_DEPTH`), counted before anything parses, copies or canonicalizes them.
  A credential object nested deeper, in what its issuer signed or in its `proof`, has no signed form, and neither has one that contains itself: presented, it is refused, and returned by a resolver it refuses the chain.
  A VC-JWT whose header or payload nests deeper is not parsed: `parseVCJWT` returns `null` for it, and the gate refuses it.
  The limit used to be the call stack of the runtime, a few thousand levels and different from one runtime to the next, so a credential nested deeper than 64 levels and within that limit verified, and is now refused.
- `ChainValidationResult` gains `evaluated`: the credentials the walk reached, root first, set on a refusal too, and absent when the walk never started.
  `validateDelegationChain` takes `snapshotAncestor`, which a host sets to copy each value the resolver returns, root first and before anything reads it, and to refuse one it will not read.
- A hash provider that fails while a verified delegation is being recorded used to make the gate throw.
  The call is now refused and the fault is logged.
- A presented credential that held a value with no JSON form made the gate throw.
  It now gets a verdict.
  Among what the issuer signed, `undefined`, a bigint, a hole in an array and a `Date` leave the credential with no canonical form, and it is refused.
  In `proof`, which no signature covers, they are passed over in an ancestor, and refuse a presented credential as one the gate cannot encode.
- `ProofVerifier` and `ProofGenerator.verifyProof` read a proof's JWS as SPEC.md §7.4 now says a verifier must: each segment as RFC 7515 §2 writes base64url, of the URL-safe alphabet alone with no white space and no `=`, the header and the payload as UTF-8 that is well formed, and the `x` of the key it is checked with as strictly.
  A proof whose segments or key were written in the base64 alphabet, padded with `=`, with white space inside, or with bytes that are not UTF-8 in its header or payload now fails.
  1.22.0 verified some of these: a segment or an `x` padded to complete its last group, a segment holding two spaces or a line break, and an `x` holding a space.
  A proof this library or a JWS library signed is unaffected.
- The embedded `Ed25519Signature2020` verifier of the delegation gate, and `CheqdStatusListResolver` for a status list's proof, read the key's `x` the same way, and require 32 bytes of it.
  In 1.22.0 they read `x` in either alphabet, padded or not, with white space passed over, and handed the runtime whatever bytes that gave.
  Such an `x` now refuses the credential or the list.

### A VC-JWT whose payload is not well-formed UTF-8

The delegation gate refuses, with `Invalid VC-JWT format`, a VC-JWT whose payload segment is not base64url of well-formed UTF-8 as SPEC.md §7.8 reads it.
On 1.22.0 a byte that is not UTF-8 was read as U+FFFD and the credential was verified.
An issuer that writes its payloads as RFC 7519 has them is not affected.

### Digests and keys to recheck

Two things to check: one if your server uses `wrapWithDelegation`, and one if you hand the verifier keys of your own.

- A consumer that recomputes `authorization.delegationCredentialDigest` from a credential it holds must compute the credential digest of SPEC.md §7.8, a domain-separated SHA-256 over what the issuer signed and the signature, in place of the SHA-256 of the VC-JWT string or of the canonical JSON of the whole credential, `proof` included.
  A digest recorded before the upgrade does not equal one recorded after it for the same credential, and the `delegation.rejected` event and the events of a retry allowed under a stored grant now carry it too.
  It should also expect `delegationRef` to be the `sha256:` digest of an id over 256 code units, of one that holds a character that does not print (SPEC.md §7.8 lists them) or a surrogate without its pair, of one written as a `sha256:` digest and of the id `unknown`, and the `jti` of a VC-JWT whose credential has no `id`.
- A custom DID resolver or key provider that hands the verifier an Ed25519 JWK must write its `x` as RFC 8037 has it: base64url of the URL-safe alphabet alone, with no `=` and no white space, of 32 bytes.
  An `x` in the standard base64 alphabet, padded or holding white space is refused even when it is the same key, for a response proof, a delegation credential's embedded signature and a status list that `CheqdStatusListResolver` reads.

### Conformance suite 1.4.0

The suite adds status-list vectors for the acceptance rule, each with a list whose proof verifies, and has 97 vectors in all.

Six new negative vectors check a revoked credential against a list with its bit unset and a proof that verifies: one another DID issued (`status-list/foreign-issuer-list`), a `suspension` list (`status-list/purpose-mismatch-list`), a StatusList2021 list that states its purposes in an array that includes `revocation` (`status-list/purpose-array-2021-list`), one that states another URL as its `id` (`status-list/id-mismatch-list`), and one that states no `id` from the pinned root of the credential's chain, at the URL the root's own credential names (`status-list/root-no-id-list`), or from an issuer the verifier binds the list's URL to (`status-list/configured-issuer-no-id-list`).
Those two carry the new optional inputs `trustedRootIssuer`, `trustedRootStatusList` and `statusListIssuers`, and a verifier without that configuration refuses their lists for the issuer.
Two new positive vectors check an active credential against its issuer's list re-issued without an `id` (`status-list/no-id-list`) and against its issuer's `BitstringStatusListCredential` for the purposes `suspension` and `revocation` (`status-list/purpose-array-list`), so an implementation that refuses either form fails.
`status-list.json` is regenerated in one run, so its three existing vectors change bytes with the same cases and verdicts, and the other files change only their `version`.
A new file, `status-list-authority.json`, adds nine vectors for the keeper of a list's URL, over one credential, one URL and a clear list that states its `id`.
The pinned root's list must be read at the URL `trustedRootStatusList` says the root's own credential names (`status-list/pinned-root-list`), and refused when that credential names another URL (`status-list/root-list-at-issuer-url`).
The list of a service `statusListIssuers` binds the exact URL to (`status-list/configured-service-list`), or the URL's origin (`status-list/configured-origin-list`), must be read, so an implementation that reads only the credential's own issuer's lists fails.
It must be refused when the bound origin is only a prefix of the URL's host (`status-list/lookalike-origin-list`), when nothing is bound (`status-list/unconfigured-service-list`), and when another URL is (`status-list/service-list-at-unbound-url`).
At a URL bound to the service, the credential's own issuer's list (`status-list/issuer-list-at-bound-url`) and the pinned root's, though its credential names that URL (`status-list/configured-over-root-list`), must be refused.
Four more hold a list without an `id`: it must be read when the credential's own issuer signed it, even if the verifier also pins that issuer as the root (`status-list/owner-root-alias-no-id`) and names the list's URL as the one the root's credential names (`status-list/pinned-root-own-no-id`); the same list must be refused for a delegate's credential whose entry names that URL (`status-list/pinned-root-no-id-for-delegate`), and so must the credential issuer's when the verifier pins another root whose credential names the URL (`status-list/owner-no-id-at-pinned-root-url`).
Five more vectors in that file hold a signed `statusListIndex` that is not a whole decimal string (`status-list/index-suffix`, `status-list/index-fraction`, `status-list/index-space`, `status-list/index-number`), which must be refused, or one that opens with zeros (`status-list/index-leading-zeros`), which must be read.
Three more hold a signed entry that states a `statusSize`: an entry of two bits whose value is set at its own bits while the bit at its index is clear (`status-list/status-size-two-bits`) and one that states `0` (`status-list/status-size-zero`) must be refused, and one that states `1` (`status-list/status-size-one`) must be read from the bit at its index.
The entry of `status-list/status-size-two-bits` states its value, 3, as `revoked` in its `statusMessage`, so an implementation that reads the two bits where Bitstring Status List v1.0 keeps them refuses it as well.
The reference adapter applies `acceptStatusList`, and `conformance/verify.py` checks every status-list vector too.

### SPEC.md §7.8 and conformance suite 1.5.0

SPEC.md §7.8: a response proof binds the delegation chain by digest.
The new optional `ProofMeta` member `delegationChainDigest` is a domain-separated SHA-256 over the digests of every credential the server evaluated, root to leaf, each taken over the credential's signed form: what its issuer's signature covers, and that signature.
It is covered by the proof's own signature.
§7.8 defines both digests, and gives `delegationRef` its one definition: the id a credential shows, or the SHA-256 of an id that is over 256 code units, holds a character that does not print (the control and format characters, the line and paragraph separators and the code points that render as nothing by default, listed by code point) or a surrogate without its pair, reads as a digest, or is the word `unknown`.
An id that is not well-formed Unicode is hashed over its WTF-8 bytes.
A number in a VC-JWT's payload is read whatever its length, and plays no part in the id.
Every JSON text §7.8 reads, a VC-JWT's header and payload and any text a credential object arrives in, is read keeping the last of the members of an object that share a name, as `JSON.parse` keeps it, whatever the parser an implementation uses.
It says how a signature string is read (a VC-JWT's as a JWS segment, a `proofValue` more loosely) and which values have no signed form, and so neither verify nor have a digest: among them a credential object holding a number that is an integer of magnitude above 2^53 - 1 once read as an IEEE 754 binary64 value, whatever the text it was written as.
It bounds how deep the arrays and objects of a credential nest, at 64 levels, counted before anything parses or canonicalizes them: a credential object nested deeper has no signed form, the header or payload of a VC-JWT nested deeper is not read as JSON, and an implementation's own failure to read a value is never reported as the value having no signed form.
Whether a credential verifies and has a digest then does not turn on the call stack of the runtime reading it.
It says what the two members mean on an allowed call and on a refusal, where they describe what was presented and examined and never that it is valid, and what the digest of each kind of refusal covers: the credentials the server examined, and none where a value handed to it for the chain could not be read.
A verifier that holds the chain MUST reject an outcome it does not expect (an allowed call, unless it is checking a refusal), a digest that differs or is absent, and a `delegationRef` that is not the reference of the chain's last credential.
Signing either claim from the server is not part of this release of the reference implementation: its server sets neither `delegationRef` nor `delegationChainDigest`, and its verifier checks both against a chain it is given.
§7.2 and §7.4 list the member, §7.7 uses it, §11.1 adds delegation substitution and a refusal shown as acceptance to the threat model, and Appendix C.4 gives a vector.
Additive: a proof without the member is unchanged.
`schemas/detached-proof.json` admits the member and its `$id` moves to `proof/detached/v1.2.0`.
CONFORMANCE.md adds L3.28, and conformance suite 1.5.0 adds the `signed-proof/delegation-chain-*` and `signed-proof/delegation-ref-*` vectors, which `conformance/verify.py` re-derives in Python.
Among them are credentials at the nesting bound and one level past it, ids at either edge of the control range, one a character longer than the digest form, ids holding a right-to-left override or a zero-width space, four ids each holding a code point that only renders as nothing by default (U+034F, U+3164, U+FE0F and U+E0100), and the id `unknown`, a VC-JWT whose payload holds an integer of 4301 digits, one whose payload holds the credential id twice, a credential object holding 9007199254740993.5, and a credential object whose issuer signed a `__proto__` member.
A verifier built against suite 1.4.0 or earlier fails them until it implements L3.28.

§7.4 now says how a verifier reads a proof's JWS, and it MUST refuse a proof that does not read so: exactly three segments, each base64url as RFC 7515 §2 writes it, with no white space and no `=`; a header whose `alg` is `EdDSA` and whose `kid` is the proof's; an Ed25519 key whose `x` is 32 bytes read the same way; and a signature that verifies over the payload rebuilt from `meta`, and over any other payload segment the JWS carries.
Every claim in `meta` is then held to what was signed, and two verifiers give one verdict on one proof.
§7.8 reads a VC-JWT's segments more loosely, as the JWS libraries that verify a credential read them, and that reading applies there alone.
The 15 `signed-proof/delegation-proof-*` vectors of suite 1.5.0 hold a verifier to it: a signature segment with one or four characters outside base64url, written in the base64 alphabet, holding a line break, or padded with `=`; a fourth segment; a header with a character outside ASCII; `requestHash`, `nonce` or `sessionId` altered after signing; a proof checked against another call than the one it proves; a header that names another algorithm, or another key of the signer's DID; a `meta` whose `did` is not the signer's; and a proof of a request with no `params`, which verifies.
`conformance/verify.py` checks them by a reading of its own, and refuses an Ed25519 key of small order, as the TypeScript reference does.
The reference adapter refuses a signed-proof vector that gives `now` or `skewSeconds` as anything but a number, as `verify.py` does.
`signed-proof.json` is generated whole by one run, its earlier vectors signed again under that run's keys; the other 11 vector files change only their `version`, and the suite has 140 vectors.
