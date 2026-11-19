# Changelog

All notable changes to @kya-os/mcp will be documented here.

Format: https://keepachangelog.com/en/1.0.0/
Versioning: https://semver.org/spec/v2.0.0.html

## [1.26.0] - 2026-11-19

### Upgrading

- **Check how you register delegations with status list entries, and
  catch `StatusEntryUnchangedError` from revocation.** `registerDelegation`
  refuses, as `delegation_malformed`, an entry another registered
  delegation holds, so a subtree can no longer share one entry, and with
  `statusEntryOwners` any entry not allocated to the delegation.
  `revokeDelegation` and `restoreDelegation` throw a
  `StatusEntryUnchangedError`, not the status list manager's error, for an
  entry left unchanged, `StatusListWriteConflictError` among them, and a
  revocation now marks the whole subtree first.
  A graph built without `statusEntryOwners` logs a warning once.
  UPGRADING.md, "A delegation's status entry is the one allocated for it",
  has the steps.
- **Run the journal and observer contracts again, and give the observer
  contract a `fork` fixture.** An observer adapter that does not verify
  each checkpoint's signature now fails the observer contract, and, when
  `fixtures.fork` is given, one that does not verify a larger checkpoint's
  consistency with the one it observed fails it too. Without `fork` that
  check is reported as skipped, with the reason, and does not fail the
  report. A journal adapter whose compare-and-append is not one atomic
  step, or compares only the sequence of the expected head, now fails the
  journal contract. UPGRADING.md, "The audit store contracts fail adapters
  that break what they promise", has the steps.
- **Give the checkpoint builder a `signatures` verifier that resolves the
  recorder's key.** A `CompactJwsAuditSigner` over a private JWK, a
  `KeyObject` or an extractable `CryptoKey` now verifies by default the
  stored entries the recorder and the builder build on under its own key.
  A builder that signs with a key of its own keeps building over the
  recorder's entries as before, trusting them as written, and warns once
  per process for each such key; only `signatures` verifies them. A
  signer over a non-extractable `CryptoKey`, or one of your own without
  `verifier()`, still trusts the journal as written: give both
  `signatures`. UPGRADING.md, "The recorder and the checkpoint builder can
  verify what the journal holds", has the steps.
- **Under `holderBinding: 'enforce'`, a delegation whose subject is a
  did:key of a key other than Ed25519 is refused.** A request proof is
  EdDSA, so such a subject, a P-256 did:key say, can never be bound, and
  the gate took it as it takes a did:web subject: it logged that the
  subject "is not did:key" and ran the tool for whoever held the
  credential, with no proof at all. It is now refused as
  `holder_binding_failed`, with or without a proof, and a session grant
  no longer authorizes such an agent under `enforce`.
  `isHolderBindingApplicable` is true for every did:key, as its
  documentation says, and `assertHolderBinding` answers `unbound` with
  the cause `unsupported_subject_key` for one it cannot bind. UPGRADING.md,
  "Holder binding refuses a did:key subject it cannot bind", has the
  steps.
- **A pinned root's own status list is read on a private host only at that root's own did:web origin.**
  `createRevocationChecker` read the list a pinned root's own credential
  names on any host, a private one included, once that credential's proof
  had verified, so a root pinned from another trust domain could have the
  verifier connect to any private address. It now reads it there only
  when the list is at the https origin, host and port, the root's did:web
  DID names. A list on any other private host, and every list of a
  did:key root, which has no host, is read as a URL a presenter names
  unless `statusListIssuers` binds it: bind it there to keep reading it.
- **A request proof states its delegation, and three kinds of client have
  something to change.** A client that calls `generateRequestProof` with
  the arguments it sends, or `buildCardProof` with a request that holds
  its chain, changes nothing. One that makes the proof first and attaches
  the delegation afterwards makes a proof that states `none` beside a
  delegation: make the proof from what is sent, or pass the credential as
  the new `delegation` input. One that sends no delegation while the
  server retains grants for its agent under more than one passes the one
  it means as `delegation`. One that signs card proofs with a
  `ProofSigner` of its own writes the parameters `sign` now receives as
  its second argument into the protected header. A server sets
  `delegation.requestBinding: 'require'`, or `requestBinding` on the card
  guards, once every client signs with 1.26.0 or later; the default,
  `'prefer'`, accepts a proof that names no credential with one warning
  per process, and 2.0.0 makes `'require'` the default. An enforcement
  point that calls `assertHolderBinding` itself moves to
  `verifyDelegatedCallProof`. UPGRADING.md, "A request proof names the
  delegation it is made for", has the steps, the causes, and what each
  released verifier makes of the new proofs.
- **Status lists take the W3C terms, and an issuer chooses its format.**
  An issuer that sets no new option changes nothing. To issue W3C
  Bitstring Status List v1.0 lists, build `StatusList2021Manager` with
  `format: 'BitstringStatusList'` and a `statusListBaseUrl` no
  StatusList2021 list is stored under, and type a store of your own for
  the lists it then holds, as
  `StatusListStorageProvider<StatusListCredential>`. To bound how long a
  copy of a list is read, set `validityPeriodMs` and call
  `renewStatusList` for each list before its end.
  `RuntimeFetchProvider.fetchStatusList` still answers a
  `StatusList2021Credential` alone. UPGRADING.md, "Status lists take the
  W3C Bitstring Status List terms", has the steps.
- **A chain may be any length, and a check has 30 seconds.** If you
  counted on a carried chain of more than 10 credentials being refused,
  set `maxChainLength: 10`. If one check of a delegation honestly takes
  your dependencies more than 30 seconds, raise `totalTimeoutMs`.
  UPGRADING.md, "A chain may be any length, and a check has 30 seconds",
  has both.

### Added

- **A delegation graph can read whose each status list entry is.**
  `allocateStatusEntry(purpose, { delegationId })` records the entry's
  owner, and `getStatusEntryOwner` and `retireStatusEntry` read and retire
  it, through the optional `StatusEntryOwnerStorageProvider` contract that
  `MemoryStatusListStorage` implements. `DelegationGraphManager` takes the
  manager as `statusEntryOwners`, registers a delegation only with an
  entry allocated to it, retires the entry when it removes the delegation,
  and answers `getStatusEntryClaim`. A graph storage provider can
  implement `getNodeIdsByStatusEntry`, keyed by `statusEntryKey`.
  `StatusEntryUnchangedError` reports each entry a revocation or restore
  left unchanged, with its `events`, and `RevocationEvent` gains
  `statusEntrySharedWith`. UPGRADING.md, "A delegation's status entry is
  the one allocated for it", has the detail.
- **Status-list stores can take a conditional write.** The new
  `ConditionalStatusListStorageProvider` adds `getStatusListWithEtag`,
  which answers a `StoredStatusList`, the list with the etag of the
  write that stored it, and `setStatusListIfMatch`, which stores a list
  only over the one that etag names. `StatusList2021Manager` and
  `createStatusListManager` take the new `maxWriteConflicts` option, how
  many refused writes one change outlasts, 32 by default, and then throw
  `StatusListWriteConflictError`, whose `code` is
  `STATUS_LIST_WRITE_CONFLICT` and which `isStatusListWriteConflict`
  knows from any copy of the package. UPGRADING.md, "Status-list stores
  take a conditional write", has the detail.
- **A delegation hop can commit to its parent credential by its digest.**
  A hop of the Entity Card profile named its parent only by the parent's
  delegate and capability id, so a parent issued again under the id of
  one that was revoked carried every hop signed under the first. A hop
  may now state `credentialSubject.parentCredentialDigest`, the digest
  SPEC.md §7.8 gives the parent credential with its signature.
  `evaluateDelegationChain`, `verifyRequestDelegation` and
  `requireDelegation` check it whenever a hop states it, before any hop
  proof, and refuse a mismatch, or a root that states one, as
  `chain_invalid`; a hop that states none is accepted as before.
  `signDelegationCredential` writes it when given the parent as
  `options.parent`. Version 2.0.0 requires it of every hop but the root.
- **`StatusList2021Manager` issues W3C Bitstring Status List v1.0 lists.**
  Built with `format: 'BitstringStatusList'`, it writes a
  `BitstringStatusListCredential`, a Verifiable Credentials Data Model 2.0
  document that states its window as `validFrom` and `validUntil`, and
  allocates `BitstringStatusListEntry` entries, the entry a card
  delegation credential requires and the manager could not allocate. The
  new option `ttl` is the `credentialSubject.ttl` such a list states: how
  long, in milliseconds, a reader keeps it before it fetches it again,
  which never extends the list past its `validUntil`. A stored list keeps
  the format it was created in, so a manager of either format revokes on
  it and renews it in its own terms, and `allocateStatusEntry` throws a
  `TypeError` for a list of the other format. The manager also throws a
  `TypeError` where it is built for a `ttl` with the StatusList2021 format,
  which has no such member, a `ttl` longer than `validityPeriodMs`, and a
  Bitstring Status List of fewer than 131,072 entries. The new types
  `BitstringStatusListCredential`, `StatusListCredential`,
  `StatusListFormat` and `StatusListEntryOf` are exported. The store
  contracts and `MemoryStatusListStorage` take the type of the lists they
  hold as a type argument, which defaults to `StatusList2021Credential`,
  so a store written for 1.25.0 compiles as it is. StatusList2021 stays
  the default through 1.x.
- **`totalTimeoutMs`: the time one whole check of a delegation chain may
  take.** `verifyRequestDelegation`, `requireDelegation`,
  `evaluateDelegationChain`, `evaluateRevocationChain`,
  `validateDelegationChain` and the middleware's `delegation`
  configuration take it, 30 seconds by default. Each dependency still has
  its own `dependencyTimeoutMs`; this bounds them together, so hosts that
  each answer just in time cannot hold a check open however long the
  chain. A check out of time is refused as `deadline_exceeded`, which is
  transient, and asks nothing more. A check of 10 credentials could wait
  about 100 seconds before.

### Changed

- **The package no longer ships source maps.** Each map pointed at a
  TypeScript source the package does not include, so no debugger could
  show it, and the 262 maps were 0.9 MB of the 4.16 MB 1.25.0 unpacked
  to. The package now unpacks to 3.86 MB in 658 files.
- **A refusal that withholds why now says the operator's log has it.**
  Where a refusal leaves to the log what the verifier's network answered,
  or the words a dependency of yours threw, it now ends with `; the
  verifier's log says why`, which names no cause. The detail a DID
  resolver of your own reports through `lastFailure`, where the refusal
  does not show it, is now logged too. Compare a refusal's `code`, not
  its words; UPGRADING.md, "A refusal says when the operator's log has
  why", lists the reasons that change.
- **A chain a request carries may be any length.**
  `verifyRequestDelegation`, `requireDelegation` and `readDelegationChain`
  refused a carried chain of more than 10 credentials unless
  `maxChainLength` said otherwise. They now put no limit on it, as a
  resolved chain never had one: how far authority is delegated is not the
  verifier's to cap by default (SPEC.md §6.10). Set `maxChainLength: 10`
  to keep the old limit. The order of the check already holds what a long
  chain can make a verifier read: nothing a hop names is read before the
  hops above it verify under a trusted root, and the first failure ends
  the check. UPGRADING.md, "A chain may be any length, and a check has 30
  seconds", has the detail.

### Deprecated

- **`StatusList2021Manager` writes StatusList2021 lists by default only
  through 1.x.** W3C Bitstring Status List v1.0, a Recommendation, succeeds
  StatusList2021, and 2.0.0 makes `format: 'BitstringStatusList'` the
  default. An issuer that means to keep adding to its StatusList2021 lists
  sets `format: 'StatusList2021'`; one that moves gives the manager a
  `statusListBaseUrl` of its own for the new lists, and goes on revoking
  on the old ones through it. DEPRECATIONS.md has the row.
- **`CascadingRevocationOptions.maxDepth` is deprecated** and is removed
  in 2.0.0: a limit on how deep a revocation reaches can only leave a
  delegation live. DEPRECATIONS.md has the row.
- **`DEFAULT_CARRIED_CHAIN_LIMIT` is deprecated** and is removed in
  2.0.0. It is applied to nothing now that a carried chain has no default
  limit; pass `maxChainLength: MAX_DELEGATION_DEPTH` for the limit it
  was. DEPRECATIONS.md has the row.

### Security

- **Two status-list managers over one store no longer lose each other's
  revocations.** `StatusList2021Manager` serialised its read, change, sign
  and write of a list within one manager only, and a store could not tell
  which list a writer had read, so two managers over one store, such as
  two replicas or a manager built per request, could each revoke a
  credential and the second write dropped the first's bit from the signed
  list: a verifier then accepted the revoked credential. A store may now
  implement the optional `ConditionalStatusListStorageProvider`, a write
  that names the list it was made over, and the manager then makes a
  refused write again over the list now stored, after a random wait of at
  most 10 s that grows with each refusal and with how long a try takes,
  up to the new `maxWriteConflicts` option, 32 by default, before it throws
  `StatusListWriteConflictError`, which `isStatusListWriteConflict`
  knows, and stores nothing. `MemoryStatusListStorage` implements it,
  for its subclasses too. A store without it works as before, safely
  with one manager only, and the first write a manager makes to one
  warns once per process. UPGRADING.md, "Status-list stores take a
  conditional write", has the detail.
- **A delegation verdict carries the caveats its chain grants under.**
  `requireDelegation`, `verifyRequestDelegation`, `evaluateDelegationChain`
  and `validateDelegationChain` checked that each hop's caveats narrow its
  parent's, then returned a verdict without them, so a host that trusted the
  verdict never learned that the call was limited, for example by a
  `MaxAmount` of 100, and nothing held the call to the limit. Each verdict now
  carries `caveats`, every limit the chain states at its tightest, the
  earliest hop `validUntil` among them, and lists those the library does not
  interpret apart in `unknownCaveats`. The new `caveatRefusal(verdict, {
  amount, currency })` holds a call to them and answers with a refusal code
  and reason: every caveat applies to every call, so a `MaxAmount` that names
  a currency refuses a call in any other, and it fails closed on a verdict
  that does not pass, one without the lists, and a caveat the host does not
  enforce. A `ValidUntil` that states no date, a `MaxAmount` whose `limit` is
  not a plain non-negative decimal or whose `currency` is not a string, and a
  caveat nested more than 64 levels deep are now refused as
  `delegation_malformed`, so no caveat can run the guard out of stack. A
  `MaxAmount` or `ValidUntil` with a member the library does not know is now
  compared verbatim. The library warns once per process when it passes a
  verdict with a caveat it does not interpret, never from
  `validateDelegationChain`, and a hop's caveats are read in time linear in
  their number. SPEC.md §6.10 states these rules. UPGRADING.md, "A
  delegation verdict carries the caveats it grants under", has the detail.
- **Revoking or restoring a re-delegation no longer changes another
  delegation's status.** `DelegationGraphManager.registerDelegation` stored
  any status list entry it was given, and `CascadingRevocationManager` set
  or cleared that entry's bit, so a host that registered each submitted
  re-delegation with the entry its credential carries let the agent that
  signed it name another delegation's entry, its root's included. The
  cascade now reads the owner the status list manager recorded for each
  entry, and sets or clears an owned entry only for its owner or a
  subtree that holds it; it refuses to clear an entry another registered
  delegation holds; and it walks the whole subtree whatever entry a node
  carries. `StatusList2021Manager.updateStatus` refuses an entry that
  names its list by another spelling. Allocate each entry with
  `allocateStatusEntry(purpose, { delegationId })` and build the graph
  with `{ statusEntryOwners: statusList }` to have registration refuse
  every entry not allocated to the delegation. UPGRADING.md, "A
  delegation's status entry is the one allocated for it", has the detail.
- **A request proof names the delegation it is made for, and a server
  refuses it beside any other.** A holder's request proof covers the tool
  name and the business arguments, and not `_kyaos_delegation`, so a
  party on the path that held another delegation of the same agent, and
  no key, could put it in place of the one the agent chose, or take the
  delegation away so that a grant retained under the other one
  authorized the call, and the call ran and was recorded under that
  delegation. `generateRequestProof` and `buildCardProof` now state the
  delegation the call presents in the proof's JWS protected header,
  which the signature covers: the SPEC.md §7.8 digest of the credential,
  or `none`. A client that passes the arguments it sends changes nothing.
  The delegation gate, `requireDelegation` and `verifyRequestDelegation`
  refuse a proof that names another credential than the one presented,
  and resolve for a call that presents none only a grant of the
  credential its proof names. The new `verifyDelegatedCallProof` does the
  same for an enforcement point of your own, and takes the presented
  credential as a required input, so the check cannot be left out. A
  base profile re-delegation may state its parent's digest, as a card hop
  does, through the issuer's new `parent` option, and where every hop
  states it the proof fixes the whole chain. A verifier that predates the
  header parameter ignores it, so released servers accept the new proofs.
  A proof that names no credential, as a client before 1.26.0 makes it,
  is still accepted, with a warning, until `requestBinding: 'require'` is
  set.
- **An audit record whose key has ended is not valid on the time it
  states.** The verifier checked a recorder, checkpoint or exporter key's
  validity interval against the time the signer wrote into the artifact,
  so whoever still held a key the policy had retired could sign a record
  or an export dated before the retirement, and it read `valid` in every
  integrity dimension. Once the policy no longer lists the key as valid
  at `verifiedAt`, or the verifier has no clock and the key has an end,
  an entry or checkpoint it signed now reads `indeterminate`
  (`AUDIT_KEY_ENDED_UNDATED`) unless evidence its signer does not
  control dates it before the end: the successor epoch's genesis, signed
  by the new key and committing to the old epoch's terminal checkpoint, a
  checkpoint signed by another live key, an observation or supporting
  anchor, or a checkpoint the policy names as the key's or the epoch's
  end. A bundle carries successor geneses in a new optional component,
  `AUDIT_BUNDLE_MEDIA_TYPES.successorGeneses`, and a verifier given
  records outside a bundle takes them in
  `AuditVerificationContext.successorGeneses`, so honest records stay
  `valid` across a rotation. One that dates nothing is reported as
  `AUDIT_SUCCESSOR_GENESIS_MISMATCH`. An export signed by an exporter
  key that has ended reads `indeterminate`, as nothing dates it.
  `verifyAuditBundle` takes a `verifiedAt` clock for the verifier it
  builds. None of this makes a dimension `invalid`.

### Fixed

- **A standard `eddsa-jcs-2022` verifier accepts the delegation hops and
  status lists the library signs.** `signDelegationCredential` and
  `signStatusListCredential` signed the document's `@context` in the
  proof configuration but left it out of the proof, so a verifier that
  follows W3C vc-di-eddsa refused every proof they made. The proof now
  states it, with the same signature as before, which verifiers from
  1.20.0 on accept. `createDelegationProofVerifier` and
  `createStatusListProofVerifier` now accept a standard proof that states
  no `@context`, and still accept the shape 1.22.0 to 1.25.0 issued.
- **The journal provider contract fails a journal whose compare-and-append
  is not atomic.** `evaluateAuditJournalProviderContract` appended one entry
  at a time and offered no stale head but `null`, so a journal that reads
  the head, compares it and then inserts in a second step passed every
  check, and under concurrent submissions the recorder signed several
  entries at one sequence. The contract now issues eight compare-and-append
  calls on one expected head at once and requires exactly one to commit,
  every other to answer `head_conflict` with the head that won or fail
  without committing, and the journal to hold one entry at that sequence.
  It also requires a `head_conflict` naming the actual head for an expected
  head that is no longer the head, so a journal that compares only the
  sequence fails too. AUDITABILITY.md, "Atomic journal contract", has the
  detail.
- **The observer provider contract fails an observer that signs a
  checkpoint it did not check.** `evaluateAuditObserverProviderContract`
  required only that an observer refuse a smaller tree and a different
  checkpoint at the size it observed, so an observer that signed a receipt
  for any larger checkpoint, its signature unchecked and its tree not
  shown to extend the observed one, passed, and would have signed a
  rewritten history. The contract now refuses an observer that accepts a
  checkpoint whose signature does not verify, derived from `first` and
  `next`, and takes a new optional fixture, `fork`: a validly signed,
  larger checkpoint over a history that does not extend `first`, which the
  observer must refuse once it has observed `first`. Without `fork` that
  check is reported with `skipped` set to the reason, a new optional member
  of `AuditProviderContractCheck`, and does not fail the report.
  AUDITABILITY.md, "Atomic journal contract", says how to build it.
- **A recorder and a checkpoint builder no longer sign over an entry the
  recorder never made, when they can verify the journal.** A party that
  can write the journal store, and holds no key, could insert a
  well-formed entry with correct digests and an unsigned receipt:
  `AuditRecorderService` chained the next entry to it,
  `AuditCheckpointBuilder` signed a tree that held it, and the read
  service proved it included in that tree. Both now check such an entry
  with a new optional `signatures` verifier or, given none, with the
  verifier their signer derives from its own key through a new optional
  `AuditSigner.verifier()`, which `CompactJwsAuditSigner` implements for a
  private JWK, a Node.js `KeyObject` (both now accepted) or an extractable
  `CryptoKey`. The recorder chains to a journal head it did not append in
  this process only once the stored entry verifies as one it signed for
  its ledger epoch, and the builder signs a checkpoint only over leaves
  that verify and chain; each refuses with `AUDIT_JOURNAL_FAILURE` naming
  the entry's `sequence` otherwise. A derived verifier checks only entries
  under the signer's own key, so a builder with a key of its own trusts
  the recorder's entries as written, as before, and warns once per process
  for each such key. `createInMemoryReferenceRecorder` passes
  `signatures`. With neither, as for a signer over a non-extractable
  `CryptoKey`, the journal is trusted as written, as before.
- **`AuditCheckpointCoordinator` counts only receipts for the checkpoint it
  published.** It counted whatever its observers and anchors returned, and
  took an anchor's kind from the receipt, so an observer that answered
  with its receipt for an earlier checkpoint, or an anchor declared as one
  kind that answered with a receipt of another kind for an earlier
  checkpoint, met `minimumObservers` and `requiredAnchorKinds`, and
  `onPublished` was told the new checkpoint had its external evidence. An
  observation must now name the published checkpoint's digest, ledger
  epoch and tree size, and an anchor receipt its digest and its provider's
  kind; any other answer is a failed publication for that provider,
  retried like a thrown one.
- **`kya-audit verify` decides the policy constraints that need the present
  time.** It built its verifier without a clock, so under a policy whose
  `keyRevocationMode` is `current` or `both`, and for
  `requiredCheckpointFreshnessMs`, it reported `AUDIT_NOT_EVALUATED` and
  exited 0 for a bundle signed with keys whose validity had ended, or with
  a stale observation. It now verifies at the present time, so such a
  bundle reports `AUDIT_KEY_NOT_CURRENT` or `AUDIT_OBSERVATION_STALE` and
  exits 1.
- **`kya-audit verify` writes no bytes of a bundle to the terminal.** A
  bundle that was not valid JSON was reported with the parser's message,
  which quotes the characters around the error, so a bundle could send
  escape sequences that clear the screen, move the cursor or retitle the
  window to the operator's terminal. The CLI now says `<file> is not valid
  JSON`, names the file in every failure, reports a schema's refusal on
  one line, and writes every character that does not print as U+FFFD.
- **A delegation credential is not accepted before its `issuanceDate`.**
  VC Data Model 1.1 §4.6 makes `issuanceDate` the moment a credential
  becomes valid, but the delegation gate and `DelegationCredentialVerifier`
  read only `constraints.notBefore`, so a credential its issuer dated for
  next month authorized calls today. `isDelegationCredentialNotYetValid`
  now also holds a credential to its `issuanceDate`, with 120 seconds of
  tolerance for the issuer's clock, and refuses it before then as
  `delegation_not_yet_valid`. An `issuanceDate` that is not an RFC 3339
  date-time with its zone counts as not yet valid, as an unreadable
  `notBefore` does.
- **`verifyAuditBundle` answers a bundle with a long component with a
  report, not an exception.** It spread each component's array, and later
  one verdict per checkpoint or observation, into the arguments of a single
  call, so a bundle whose component held a few hundred thousand items made
  it reject with `RangeError`: a stranger could stop a host that verifies
  uploaded bundles, and an honest export of a long ledger in one component
  could not be verified. It now reads and merges those lists without a
  call per item, and answers every such bundle with a report.
- **A did:web DID whose path segment decodes to white space or a control
  character names no URL.** The URL parser removes every tab, line feed and
  carriage return from a URL before it reads it, so
  `did:web:example.com:bob:%2E%09%2E:alice` was resolved from
  `https://example.com/alice/did.json`, a document outside the path the DID
  spells, and `%09` alone was read as an empty segment. `parseDidWeb`,
  `didWebToUrl`, the did:web resolver and the Entity Card's URLs now refuse
  such a segment, as they already refused one for the host.
- **A re-delegation that widens its parent's CRISP budget, or drops or
  changes a constraint the chain walk does not interpret, is refused.** The
  walk compared only scopes, so an agent holding a budget of 100 USD could
  re-delegate with a budget of 1,000,000 USD, or none, and whatever enforced
  the budget of the presented credential enforced that. `validateDelegationChain`
  and the delegation gate now refuse, as `chain_invalid`, a re-delegation
  whose budget is not its parent's and is not narrower: in the same unit, a
  cap no higher, and no window, or a window of the parent's kind at least as
  long. A member of `constraints` or `constraints.crisp` that SPEC.md §6.3
  does not define must be replicated as written. Per-scope `constraints` are
  still reported in `warnings`, as before.
- **A replay bundle that withholds a component by policy is no longer
  reported complete.** The bundle verifier gave a reason, and an
  `indeterminate` scope and evidence completeness, for a component marked
  `redacted`, `disposed` or `unavailable`, but nothing for one marked
  `policy_excluded`, so an exporter could leave out evidence without the
  report saying so. A `policy_excluded` component now gives the new reason
  code `AUDIT_EXPLICITLY_POLICY_EXCLUDED`, as the other three dispositions
  give theirs.
- **A refusal of a re-delegation tells its presenter nothing the chain
  resolver answered, and the presented credential is verified before its
  ancestors.** A caller with no key, who knew only the id of somebody's
  delegation, could present an unsigned credential naming it as parent and
  read the parent's subject DID in the refusal, then present again as that
  DID and learn from the reasons whether each ancestor was expired or
  revoked, at the cost of a verification of every ancestor to the server.
  `validateDelegationChain` and the delegation gate now word a refusal of
  how the presented credential links to its parent from that credential
  alone, and tell the presenter of any other link, or of a resolved root
  that is not trusted, only that its chain is broken or its root not
  trusted, logging what they withhold through `logger.warn`. They verify
  the presented credential first, so one its parent's subject did not sign
  costs no ancestor's verification.
- **A replay bundle carries only what its signed selections cover.** The
  bundle verifier checked the exporter's allowed ledgers against the
  selections the manifest declares, but verified and reported every entry
  in the bundle, whatever ledger it came from. An exporter authorized for
  one ledger could carry a chosen slice of another, and the report called
  the bundle complete. An entry outside every selected range, or a
  checkpoint, observation or Merkle proof of a ledger epoch no selection
  names, now makes scope and evidence completeness `invalid` with the new
  reason code `AUDIT_BUNDLE_CONTENT_OUTSIDE_SELECTION`.
- **`StatusList2021Manager` can state an end on every status list it signs,
  so a copy kept from before a revocation stops being read.** A list that
  states no end is read until its issuer replaces it, and the manager's
  lists stated none and could not, so an old copy with a revoked
  credential's bit clear, served by a cache, a mirror or the credential's
  holder, verified for as long as the issuer's key did. The new option
  `validityPeriodMs`, named for the validity period W3C Bitstring Status
  List v1.0 leaves an issuer to choose, gives every version, as it is
  created, changed or renewed, an end that long after it is signed: the
  `expirationDate` of a `StatusList2021Credential`, or the `validUntil` of
  a `BitstringStatusListCredential`. The new `renewStatusList(statusListId)`
  signs a list again with a new end and the same bits. Renew each list
  before its end: a list past it is refused by every reader, the manager's
  own `checkStatus` included. Without the option nothing changes.
- **A replay bundle meets AAP-3 or AAP-4 only when a checkpoint and an
  observation cover the entries it selects.** The bundle verifier judged
  each checkpoint only against the entries below its tree size, so entries
  past every checkpoint, or of an epoch with none, needed nothing, and any
  valid observation or anchor receipt in the bundle made observation
  integrity valid. A holder of the recorder key could export two
  conflicting continuations of one observed checkpoint, and both passed a
  policy that required AAP-4. Checkpoint integrity is now `indeterminate`
  (`AUDIT_CHECKPOINT_MISSING`) until a checkpoint of each selected ledger
  epoch holds every entry selected, and observation integrity
  `indeterminate` (`AUDIT_OBSERVER_EVIDENCE_MISSING`) until an observation
  names such a checkpoint; AAP-4 also needs a supporting anchor receipt for
  one. A bundle that selects entries past its last checkpoint now reports
  those dimensions `indeterminate` where it reported `valid`.
- **`CascadingRevocationManager` no longer reads a delegation as not revoked
  when the graph cannot read its chain to a root.** `isRevoked` walked
  whatever chain the graph's store returned, so a delegation below a node
  the store did not hold, as a replica not yet sent it or a store that lost
  it reads, was reported live even under a revoked root, and
  `validateDelegation` passed it. `isRevoked` now throws a `RefusalError` of
  code `status_unavailable` for a chain that does not read from a root to
  the delegation asked about, which the chain walk refuses as it refuses a
  status it cannot read, and `validateChain`, which `validateDelegation` now
  reads first, refuses such a chain with a reason that says where it
  breaks. A delegation the graph does not hold at all still reads as not
  revoked. `removeDelegation` now throws, removing nothing, for a
  delegation others are registered under, which it left under a parent the
  graph did not hold; the new `removeDelegation(id, { subtree: true })`
  removes it and every delegation under it, children first, retiring each
  one's entry, and when one cannot be removed keeps every delegation above
  it, removes the rest and throws a `SubtreeRemovalError` that says which. A removed delegation with no status list entry that
  reads as revoked, whose revocation removal erased, now leaves a revoked
  record of its id (`DelegationNode.removed`), which is never restored,
  registered again, nor given children.
- **Verifying a replay bundle costs work in proportion to the bundle.** The
  bundle verifier hashed every checkpoint in the bundle again for each
  checkpoint and observation it checked, and recomputed the Merkle root
  over all covered entries for each checkpoint, whether or not an
  authorized exporter signed the bundle. Doubling the checkpoints in an
  unsigned bundle nearly quadrupled the hashing, so a few megabytes kept a
  verifier busy for minutes. The verifier now indexes key boundaries once
  per bundle, computes every checkpoint root of a ledger epoch in one pass
  over its entries, and looks checkpoints and entries up by key instead of
  scanning for each proof and observation. Reports are unchanged.
- **`requireProof` refuses a `minLevel` it does not know where the guard
  is built.** A level written another way, such as `l3`, `L3 ` or `L4`,
  or a value that is not a string, ranked as no floor at all, so the
  guard passed an `L3-minus` proof under it. It now throws a `TypeError`
  naming the option and the two levels it takes, `L3-minus` and `L3`.
- **A JWS a presenter wrote puts none of its own characters raw into the
  log.** `CryptoService.verifyJWS` logged the engine's JSON parse error
  for a header or payload that is not JSON, which quotes the text around
  the fault, control characters and line breaks included, and logged a
  header's `alg` as written. `parseJWS` now says such a segment is not
  JSON in its own words, the `alg` is quoted, and `base58Decode` quotes a
  character it refuses.
- **A refused delegation chain gives at most 16 reasons.**
  `validateDelegationChain`, and through it `evaluateDelegationChain`,
  `verifyRequestDelegation` and `requireDelegation`, gave one reason for
  every rule a chain broke, so a carried chain whose hops state thousands
  of caveats, signed by nobody, was refused with thousands of reasons.
  Past 16, it now lists the first 15 and says how many more rules the
  chain breaks. The refusal code is the first rule's, as before.
- **A verdict about a status list reaches the presenter only once the list's proof verifies.**
  Whoever presents a status entry chooses the URL it names, so the
  document read there may be any JSON the verifier can reach. The
  status-list checker and `CheqdStatusListResolver` refused such a
  document for its `issuer`, `id` or `statusPurpose` before checking its
  proof, and the refusal, which reaches the presenter through the
  delegation gate and `requireDelegation`, quoted those members. The
  refusal now says only `the status list at "<url>" could not be read or
  checked`, with its code as before, and the operator's log says why,
  with the `statusListIssuers` configuration that would accept a list
  another DID signed. So do a cheqd list proof's stated purpose and
  verification method, and the dates of a list the checker reads without
  `verifyStatusList`. Once a list's proof has verified, a refusal keeps
  its reason. This refines the rule that a refusal tells the presenter
  only what the DID or the URL alone decides, or a deadline.
- **`buildOutboundDelegationHeaders` throws, and signs nothing, for a
  delegation record that is not in force.** It signed a
  `delegation:propagate` proof for whatever record it was given, so a
  server could tell a downstream service it was propagating a delegation
  that was revoked or expired, past its `notAfter`, before its
  `notBefore`, or addressed to another server. It now throws for a record
  whose `status` is not `active`, whose `notAfter` has passed or
  `notBefore` has not, a bound that is no finite number counting as
  either, or whose audience does not admit the forwarding server's DID.
- **A revocation the graph reported done is no longer lost to a
  re-delegation registered under the revoked delegation at the same time.**
  Over a graph store without `registerNodeAtomic`, registering a child read
  the parent and wrote it back whole, so a revocation of the parent stored
  in between, the only record of it for a delegation with no status list
  entry, was overwritten, and both the parent and its new child read as not
  revoked. Every change `DelegationGraphManager` makes to a stored node,
  linking a child, marking a revocation and removing a delegation, now
  takes its turn at that node, shared by every manager over the same
  storage provider object, so a revocation waits for a link under way and
  cascades to the new child. A change waits for its turn at most 10
  seconds: behind a write the store never finishes, it throws a transient
  `RefusalError` of code `deadline_exceeded` naming the node, having changed
  nothing, and a cascading revocation marks the rest of its subtree first,
  so the caller knows to revoke again. Across processes only the store can keep the
  turn: the first link a process makes through a store without
  `registerNodeAtomic` warns once, and `registerNodeAtomic` must change
  nothing of the parent but its `children`.
- **The audit signature verifier checks a JWK's key whatever its `ext`
  member says.** `CompactJwsAuditSignatureVerifier` refuses a small-order
  Ed25519 key, under which one signature verifies every payload, by reading
  the imported key back. It imported a JWK as the JWK's own `ext` member
  asked, so a JWK with `"ext": false` could not be read back and verified
  a forged signature on any entry, checkpoint, observation or bundle
  manifest. It now imports every JWK extractable, so the check always
  runs; a sound key with `"ext": false` verifies as before.
- **A VC-JWT's envelope check refuses a small-order issuer key whatever
  its JWK's `ext` member says.** The check refuses a small-order Ed25519
  key, under which one signature verifies every payload, by reading the
  imported key back. It imported the issuer's `publicKeyJwk` as the JWK's
  own `ext` member asked, so a DID document that published such a key with
  `"ext": false` let a fixed signature verify any VC-JWT the issuer was
  trusted for. The key is now imported extractable, so the check always
  runs; a sound key with `"ext": false` verifies as before.
- **A proof verifier hands back, and acts on, only the meta a signature
  covers.** A proof whose `meta` carried a member the proof schema does
  not name, or an optional claim written as `""`, verified, and code that
  read `proof.meta` after verifying it read that member as if it were
  signed. `ProofVerifier.verifyProof`, `verifyProofArtifact` and
  `verifyProofDetached` still accept such a proof in 1.x, but they act
  only on the meta rebuilt from what the signature covers, and a valid
  result now carries that meta as `meta`: read it, not `proof.meta`. An
  unsigned member is not in it, and an empty optional claim is absent.
  `extractProofFromMeta` and `ProofGenerator.verifyProof` keep only that
  meta too, and `ProofGenerator.generateProof` never writes an unknown
  member or an empty optional claim into the meta, whatever its options
  carry. SPEC.md §7.4 says a verifier MUST NOT return or act on a member no
  signature covers; from 2.0.0 a verifier refuses such a proof.
- **A checkpoint builder no longer checkpoints an entry under another key
  than its epoch's recorder signs with.** A builder that signed with the
  recorder's own key, given no `signatures`, trusted as written any leaf
  that named another key, so a writer of the journal store with no key
  could append an entry naming `did:key:zElsewhere` with a junk receipt
  and have it checkpointed with only a warning. A recorder signs every
  entry of an epoch under one key, so `AuditCheckpointBuilder` now holds
  every leaf to the key the epoch's genesis entry names and refuses any
  other with `AUDIT_JOURNAL_FAILURE`. When the genesis names the builder's
  own key it verifies every leaf; when it names another, it trusts the
  leaves as written, as before, and warns once per process for that key.
- **`verifyAuditBundle` reads a bundle in time that grows with it.** A
  checkpoint over a tree larger than the entries its epoch carries read
  every entry of the epoch, as did each selection and each supporting
  anchor, so a bundle of 4,000 entries and 4,000 such checkpoints took
  about 5 s to verify, and twice as many took four times as long. A
  verifier now counts the inclusion proofs that verify for each
  checkpoint and reads each epoch's entries and selections once. The
  verdicts are unchanged.
- **`kya-audit verify` makes every check of a run at one instant.** It
  read the clock at each check, so a key whose validity ended while the
  run was under way could be current for one check and ended for the
  next. It now reads the clock once per run.
- **Removing a revoked delegation no longer erases its revocation.**
  `removeDelegation` deleted whole a revoked delegation that had a status
  list entry, as if the entry recorded the revocation. When the write of
  its bit had failed, or left the list unchanged, the graph's mark was
  the only record, so once it was removed `isRevoked` answered
  `{ revoked: false }`. A removed delegation that reads as revoked now
  always leaves a revoked record of its id, which refuses the id's
  registration again. One that does not read as revoked is still removed
  whole.
- **A chain refusal writes no presenter text raw to the operator's log.**
  The line the gate logs when it withholds what the chain resolver
  answered cleaned only the withheld half, while the half the presenter
  reads carries the presented credential's `id` and `parentId`, written
  before any signature is checked, so a line break or a bidirectional
  override in either reached the log as written. The whole line is now
  cleaned, and those refusals quote each id, as `Delegation "leaf"
  references parent "middle"`.
- **A re-delegation cannot widen a fixed budget window by lengthening
  it.** The chain walk accepted, under a parent's `fixed` window, a
  child's `fixed` window of any greater length, so a child capped at 100
  per fixed day and a half under a parent capped at 100 per fixed day
  could spend 200 within one parent day. Under a `fixed` window a child
  now states no window, the parent's window length, or a `rolling`
  window at least as long, which the walk now accepts.
- **An Entity Card hop is held to its `issuanceDate` as a start.** The
  hop window read a VC 1.1 `expirationDate` as an end but not an
  `issuanceDate` as a start, so a hop issued for the end of the year and
  stating no `validFrom` was accepted at midyear, while the VC-JWT path
  already refuses a credential before its `issuanceDate`. A hop before
  its `issuanceDate`, held with the clock tolerance, is now refused as
  `delegation_not_yet_valid`. Conformance suite 1.13.0 adds
  `entity-card/hop-issuance-date-future` for it.
- **A delegation is never registered under a parent a racing removal
  left as a revoked record.** `registerDelegation` checked that its
  parent stood before it took the parent's turn, so a registration
  racing `removeDelegation` of a revoked parent linked the child under
  the record the removal left. The parent is now read again in its turn,
  and `MemoryDelegationGraphStorage.registerNodeAtomic` refuses a parent
  stored as removed, as the `registerNodeAtomic` contract now asks of
  every provider.
- **Every Entity Card verifier refuses a malformed `parentCredentialDigest`
  as `chain_invalid`.** `verifyRequestDelegation` and `requireDelegation`
  parsed the member as a digest and refused any other value, `null`
  included, as `delegation_malformed`, while `evaluateDelegationChain`
  refused it as `chain_invalid`, as SPEC.md §6.10 says. Parsing now reads
  the member as any value and leaves its form to the chain rules, so
  every path refuses it as `chain_invalid`. `signDelegationCredential`
  still signs no hop that states one in another form.
- **`StatusList2021Manager` refuses a `validityPeriodMs` past a century
  where it is built.** It took any safe integer, but a period above about
  8.6e15 milliseconds ends a list where no `Date` is, so the manager was
  built and then every list it signed threw, and one far shorter still
  ended a list past the year 9999, which no reader reads as an RFC 3339
  date-time. The option now takes a whole number of milliseconds from 1
  to a century of 365.25 days, 3,155,760,000,000, and throws a `TypeError`
  naming it for any other value.
- **A revocation tells `onRevoke` only of what landed, and a stalled one
  keeps its reports.** When a node's turn did not come, the cascade still
  called `onRevoke` for it, though it had no entry set and was not
  marked, and the transient error it then threw dropped the entries left
  unchanged and the revocations not recorded. `onRevoke` is now told of a
  delegation only once it is marked in the graph or set on its status
  list, and the error is a `RevocationStalledError`, still a
  `RefusalError` of code `deadline_exceeded`, that carries the walk's
  `events`, `stalled`, `unrecorded` and `unchanged`.
- **A checkpoint builder recomputes the digest of the genesis it reads the
  recorder key from.** It took the key from the stored genesis core, while
  only the stored `entryDigest` was compared with the latest checkpoint.
  A writer of the journal store could rewrite the genesis `recorder` to a
  key of its choosing under the same digest, append a leaf under that key,
  and have a builder that shares the recorder's key checkpoint it with one
  warning. `AuditCheckpointBuilder` now recomputes the genesis digest on
  every run, and the digest of each leaf it trusts as written, and refuses
  one whose core is not the one its digest was made from with
  `AUDIT_JOURNAL_FAILURE`.
- **The refusal of an empty resolved chain quotes the ids it names.**
  When the chain resolver answered no ancestors, the reason
  `Delegation <id> references parent <parentId> but the resolved chain is
  empty` held both ids as the presenter wrote them, before any signature
  was checked, so a line break or a bidirectional override reached the
  presenter's reason and whatever logged it. Both are now quoted as JSON
  strings, as every other chain refusal quotes them.
- **A small-order Ed25519 key is refused even when it cannot be read
  back.** Under a key on a point of small order one signature fits every
  message, and every verification path refused such a key only when it
  could export the key's bytes, so a key a resolver imported
  non-extractable passed: the audit signature verifier then accepted one
  fixed signature for any entry, checkpoint or manifest under it. Such a
  key is now checked by what it verifies, one WebCrypto `verify` of a
  fixed probe signature that every small-order key accepts and no other
  key does, asked once per key. A runtime that verifies nothing under a
  small-order key, as Node 24.22.3 does, refuses the probe as it refuses
  every other signature under such a key. A resolver may now import keys
  either way.
- **A recorder and a checkpoint builder whose signer yields no public key
  verify the journal when the signer names its did:key.** With no
  `signatures`, a signer over a non-extractable `CryptoKey`, or one backed
  by a remote key service without `verifier()`, left the journal trusted
  as written, so a party that could write the journal store and held no
  key could have the recorder chain to an entry it never made, and the
  builder checkpoint it. When the signer's `ref` names an Ed25519 did:key,
  the recorder and the builder now derive a verifier from it, once the
  signer's signature over a fixed self-check payload verifies under it,
  and refuse such an entry with `AUDIT_JOURNAL_FAILURE`. A signer that
  names no such key keeps the journal trusted as written, now with a
  warning once per process. No option is added.
- **A bundle of the package no longer carries every locale zod ships.**
  The library imported zod as `import { z } from 'zod'`, and that `z`
  holds the whole of zod, so a bundler kept zod's error messages in
  every language for any app that reached the import. Bundled with
  esbuild and minified, `verifyCardProof` from `@kya-os/mcp/card` came
  to 484 kB, 103 kB gzipped, and `withKyaOs` to 646 kB, 155 kB gzipped;
  they now come to 126 kB, 39 kB gzipped, and 286 kB, 90 kB gzipped.
  Nothing changes for code that uses the package.
- **`CascadingRevocationManager.revokeDelegation` revokes a delegation
  however deep it sits.** It refused, with an `Error`, to revoke one more
  than 100 levels below its root unless the caller passed a larger
  `maxDepth`, so a chain re-delegated that many times left its deepest
  delegations live. A depth limit now applies only when `maxDepth` is set,
  and a `maxDepth` that is not a positive integer throws a `TypeError`
  where 0 meant 100.

### Spec

- **SPEC.md §7.3: for the 1.x line, a verifier MUST accept a tool call's
  `requestHash` over the covered request, the legacy shape `{"method":
  <tool name>, "params": <arguments>}`, or the legacy shape with every
  `_kyaos*` argument removed.** The 1.x reference producers sign a legacy
  shape, so a verifier written from the text alone refused their proofs.
  Producers SHOULD sign the covered request, and 2.0.0 removes the legacy
  shapes. Conformance suite 1.11.0 adds three vectors.
- **SPEC.md §6.6: a status list's `encodedList` is the multibase prefix `u`
  and base64url without padding of the GZIP-compressed bitstring, index 0
  in the most significant bit of the first byte, for StatusList2021 and
  Bitstring Status List lists alike, and a publisher MUST write that
  form.** For the 1.x line a reader MUST also accept the legacy forms the
  reference reads: no `u`, characters of the base64 alphabet, and `=`
  padding. A publisher MUST write at least 131,072 entries, and for the
  1.x line a reader MUST NOT refuse a shorter list. §6.7 bounds an index
  by its list's length rather than by 131,071. 2.0.0 removes the legacy
  forms and refuses a shorter list. Conformance suite 1.12.0 adds four
  vectors, and the Python cross-check now reads the legacy forms.
- **SPEC.md §6.10 and SPEC-ENTITY-CARD.md §10.5: an `eddsa-jcs-2022`
  issuer MUST set `proof.@context` as W3C vc-di-eddsa §3.3.1 does, and a
  verifier MUST verify as §3.3.2 does.** Until 2.0.0 a verifier MUST also
  accept a proof without `proof.@context` whose signed configuration
  includes the document's `@context`, a shape issuers wrote before this
  rule, the reference implementation from 1.22.0 to 1.25.0 among them.
- **SPEC.md §6.10 states how a chain's caveats apply to a call.** Every
  caveat of every hop applies to every call; a `MaxAmount` that names a
  currency permits no call in another, and one that names none limits every
  call whatever its currency; a `MaxAmount` whose `limit` is not a plain
  decimal, or a `ValidUntil` with no date, invalidates the chain; a caveat of
  a known type with a member §6.10 does not define is replicated verbatim, as
  one of an unknown type is; and a verifier that accepts a chain MUST hold
  each call to its caveats or refuse it. SPEC-ENTITY-CARD.md §11.4 adds the
  caveats to what a Verifier holds on success.
- **SPEC-AUDIT-READ §4: an inclusion proof is re-verified with the entry it
  names.** A client verifies that entry's digests and recorder receipt
  signature against the trust policy, as it verifies a `listEntries`
  entry, before it checks the Merkle path, and MUST NOT accept an entry on
  the inclusion proof alone: a checkpoint commits to whatever leaves its
  journal held, so the proof does not show that the recorder made the
  entry.
- **SPEC.md §6.2: a delegation credential's subject `id` MUST be a URL by
  the rule its issuer is held to, and a verifier MUST reject one that is
  not.** The gate held the subject only to being a non-empty string, and
  handed it on as the acting agent's DID, so an agent that re-delegated
  could name a subject holding a line break, which forged a line of the
  operator's log, or a bidirectional control, which showed the audit
  trail and the tool another agent's DID. The basic stage now refuses
  such a credential as `delegation_malformed`, and the gate's log line
  for a subject it defers holder binding for quotes the subject.
- **SPEC.md §6.4: a re-delegation's CRISP budget is no wider than its
  parent's, and a constraint §6.3 does not define is replicated as
  written.** A verifier MUST reject a re-delegation that drops its parent's
  budget, raises its cap, changes its unit, or caps each window where the
  parent caps all time or a longer window, and one that drops or changes a
  member of `constraints` or `constraints.crisp` that §6.3 does not define,
  as §6.10 requires of a caveat.
- **SPEC.md §7.8: a presented credential the server refuses on its own is
  refused before any ancestor is examined.** The digest of such a refusal,
  one whose signature, a VC-JWT envelope's among them, does not verify,
  covers the presented credential alone, where it covered the ancestors
  before it too.
- **SPEC.md §6.6 says how the reference issuer bounds a status list.**
  `StatusList2021Manager` states an end `validityPeriodMs` after it signs
  each version when that option is set, as the list's `validUntil` or, on
  a `StatusList2021Credential`, its `expirationDate`, and
  `renewStatusList` republishes a list with a new end; without the option
  its lists state no end, as before.
- **SPEC.md §8.1: a forwarding server MUST NOT send its session ID
  downstream, and `KYA-OS-Session-Id` carries an anchor of the session for
  the target's host instead.** The delegation gate resolves a grant it
  bound in a session by the session ID alone, and
  `buildOutboundDelegationHeaders` sent that ID to every target as it was,
  so a downstream service, or whatever logged or proxied its headers,
  could call the server's gate in the session as the agent. The header is
  now `sha256:` and the hex SHA-256 of the session ID and the target's
  host under the domain `org.kya-os.outbound.session-anchor.v1`: one value
  for every call of one session to one host, and nothing the target can
  present for the session. The helper's debug line logs the anchor, not
  the ID.
- **SPEC.md §6.5: a server refuses a delegation whose chain its graph cannot
  read to a root.** It refuses it as `status_unavailable`, never as
  standing, removes a delegation only once none is registered under it,
  and keeps a record that a removed delegation with no status list entry
  that reads as revoked is revoked.
- **SPEC.md §6.10: a delegation hop is past its end once any end it
  states has passed, its `expirationDate` and its proof's `expires`
  beside its `validUntil`.** The Entity Card chain rules read only
  `validUntil`, so a hop whose issuer stated its end as the VC 1.1
  `expirationDate`, or as the Data Integrity proof's `expires`, was
  accepted after that end, though its proof covers both. They now refuse
  such a hop as `delegation_expired`, and one whose end is not an RFC
  3339 date-time with its offset as `delegation_malformed`, and a verdict
  carries each end as a `ValidUntil` caveat.
- **Conformance suite 1.13.0 adds thirty-seven vectors, 208 in all, and
  SPEC.md §7.8 defines the delegation a holder's request proof states.** A holder MUST
  state, in the JWS protected header parameter `org.kya-os/delegation`,
  the §7.8 digest of the credential its call presents, or `none`. A
  verifier MUST read the statement only from the header whose signature
  verified, MUST refuse one that is malformed or that names another
  credential than the one presented, MUST authorize a call that presents
  none only under authority retained for the credential stated, and MUST
  refuse a signed `delegationRef` or `delegationChainDigest` of another
  delegation. It SHOULD refuse a proof that names no credential, MAY
  accept one during the transition without reporting the call as bound
  to its delegation, and version 2.0.0 makes the refusal a MUST. §6.2
  gives a base profile re-delegation the optional `parentCredentialDigest`
  §6.10 gives a card hop, which a verifier MUST check when stated and
  2.0.0 requires. Appendix C.5 works a statement through, and
  SPEC-ENTITY-CARD.md §8.4 and §11.4 hold a card proof to the same rule.
  Sixteen `signed-proof/request-binding-*` vectors and five
  `delegation-chain/parent-digest-*` vectors, in two new files generated
  deterministically, hold a verifier to each rule; no vector requires
  accepting a proof that names no credential. `card-proof.json` is signed
  again, since a card proof now carries the statement.
  Of the other sixteen, three `status-list/ttl-*` vectors hold a reader to
  the rule on `ttl` of §6.6, and `delegation-chain` refuses a subject id
  holding a control character and an `issuanceDate` past the tolerance.
  `signed-proof` refuses a request proof that signs the chain of one
  delegation presented beside another, and a refusal whose chain digest
  covers the failing leaf alone. `entity-card` refuses a hop past its
  `expirationDate`, past its proof's `expires`, or before its
  `issuanceDate`, and covers the parent digest: stated and valid, absent,
  stated by a hop presented under a parent reissued under the same id,
  stated by a root, and stated as `null` on a root or a leaf, which
  counts as stated. The Python cross-check reads the new vectors and
  every parent digest, and now tests whether `parentCredentialDigest` is
  present rather than reading `null` as absent.
- **SPEC.md §6.3: a `fixed` budget window counts from the Unix epoch.**
  §6.3 and §6.4 never said where a `fixed` window starts, and a
  re-delegation that states its parent's `fixed` window is narrower only
  when both have the same windows. A `fixed` window's spans now run from
  k × `durationSec` to (k + 1) × `durationSec` seconds after
  1970-01-01T00:00:00Z, not from the credential's own start, and an
  enforcer must count it so. §6.4 says why every other `fixed` length
  under a `fixed` parent is still refused.
- **SPEC.md §6.6 is written in the terms of W3C Bitstring Status List
  v1.0.** The section, now "Status List Revocation", leads with a
  `BitstringStatusListCredential` and its `BitstringStatusListEntry`. A
  publisher SHOULD publish that format and MUST write it as the W3C
  specification requires, MAY publish a `StatusList2021Credential`
  instead, and SHOULD NOT name a list of one format from an entry of the
  other; a verifier MUST read both formats, as before. An issuer SHOULD
  state an end on every version of a list, its `validUntil` or
  `expirationDate`. A list's `ttl` is no part of its window: a verifier
  MUST NOT read a list past its `validUntil` because its `ttl` has not run
  out, and MUST NOT refuse, because of its `ttl`, a list it has just
  fetched inside its window. The reference readers meet both, since they
  do not read `ttl`. `status-list/ttl-list` and `ttl-run-out-list` must
  pass and `ttl-past-end-list` must fail; `status-list-validity.json` is
  generated whole, its earlier vectors signed again with the same cases
  and outcomes.
- **Auditability: a record whose key has ended is undecided until
  evidence dates it.** AUDITABILITY.md now says when a key has ended, that
  an entry or checkpoint it signed is `indeterminate`
  (`AUDIT_KEY_ENDED_UNDATED`) under every key revocation mode unless
  evidence its signer does not control dates it at or before the end,
  and which evidence does: a successor epoch's genesis, verified and
  committing to its predecessor's terminal checkpoint, a checkpoint by
  another live key, an observation by a live observer, a supporting
  anchor, and a checkpoint a policy `validUntilCheckpoint` names, each
  dating the checkpoints whose trees it holds and the entries in them.
  It names the optional replay-bundle component that carries successor
  geneses, `application/vnd.kya-os.audit.successor-geneses.v1+json`, and
  the `AUDIT_SUCCESSOR_GENESIS_MISMATCH` report. SPEC-AUDIT-READ.md §4
  holds a client to the same rule, and says where it reads a successor
  genesis.
- **Entity Card: a carried chain is held by the order and the time of its
  check, not by its length.** SPEC-ENTITY-CARD.md §10.5 rule 2 required a
  Verifier to bound a carried chain's length, which SPEC.md §6.10 says no
  rule of the profile does. It now requires the order of §11.4, under
  which no hop's issuer is resolved before the hops above it verify and
  no status list is read before every hop has, and a bound on the time
  spent on one chain. A Verifier may still bound the length as local
  policy. SPEC.md §4.4.2, §6.4 and §6.10 state the reference
  implementation's 30 seconds.

### Documentation

- **UPGRADING.md opens the notes for this release with "Do I need to do
  anything?"**, which names the two cases that need work, acting on a
  delegated call and writing status lists from more than one process,
  and links each narrower case to its section.

## [1.25.0] - 2026-11-18

### Added

- **`isLostCheckpointRace` tells a benign checkpoint conflict from a
  fork.** It is true only for an `AUDIT_CHECKPOINT_CONFLICT` whose
  `details.reason` is `lost-race`, one of the reasons
  `AUDIT_CHECKPOINT_CONFLICT_REASONS` lists, so a fork, a reason added
  later and a conflict with no reason all read as not benign.
  AUDITABILITY.md, "Checkpoints, observations, and anchors", lists the
  reasons.
- **`buildOutboundDelegationHeaders` sends the delegation credential.**
  Pass the credential, as the VC-JWT its issuer signed, in the new
  `credentialJwt` input, and the helper sends it unchanged as
  `KYA-OS-Delegation-Credential`, the header SPEC.md §8.1 makes
  authoritative. Before, it had no way to send one, so a downstream
  service that follows §8.1 and derives authorization from that header
  could authorize nothing the helper sent. `credentialJwt` is optional,
  so existing calls still type-check: one that omits it warns once per
  process, and one that passes anything but a compact VC-JWT throws a
  `TypeError`. UPGRADING.md, "Send the delegation credential downstream",
  has the detail.

### Security

- **A checkpoint conflict says whether the audit journal forked or another
  signer won the race.** `AuditCheckpointBuilder.createCheckpoint`
  refused a lost race, where another signer stored a checkpoint over the
  same tree first, and a fork, where the journal no longer holds the tree
  of a checkpoint already signed, with the same `AUDIT_CHECKPOINT_CONFLICT`
  and, from 1.17.0, the same `details`, so code that took a conflict with
  a tree size for a lost race took a fork for one. A checkpoint the store
  already held at that size over another tree even had the lost race's
  message. Every `AUDIT_CHECKPOINT_CONFLICT` the builder and
  `MemoryAuditCheckpointObserver` raise now names why in
  `details.reason`, `lost-race` or `fork`, and a checkpoint stored over
  another tree is a `fork` with a message of its own. UPGRADING.md, "A
  checkpoint conflict says whether the journal forked", has the detail.

### Fixed

- **A refusal of an issuer's DID shows the failure the host's own DID
  resolver reports.** When `delegation.didResolver`, or the resolver
  `delegation.didResolvers` configures for the DID's method, found no
  document and said why through `lastFailure`, the gate went on to its own
  did:web resolver, whose failure replaced the host's: a server whose
  resolver read a local name in development, and found the document
  there invalid, refused the DID for a private host the gate's own read
  would not reach. The refusal now shows the failure of the first resolver
  that reported one, as `DIDResolver.lastFailure` documents. The gate
  still asks its own resolvers after the host's, and the presenter sees no
  more than before. UPGRADING.md, "The delegation gate shows the failure
  your DID resolver reports", has the detail.
- **The suite's Python verifier passes on Python 3.9 and 3.10, the oldest
  it supports.** `conformance/verify.py` read a status list's window bound
  with `datetime.fromisoformat`, which before Python 3.11 reads a fraction
  of a second of three or six digits only, so it refused the
  `status-list/offset-window-list` vector, whose bound has nine, and
  reported the run as failed. It now reads a fraction of any length, cut to
  the microsecond, as the TypeScript reference reads it to the
  millisecond. CI runs the verifier on Python 3.9 and on the newest Python.
- **A `delegation.didResolvers` entry that throws is no longer swallowed.**
  The delegation gate caught its error and dropped it: nothing was logged,
  and the DID was refused as `did_unavailable` with no cause, so the log
  said only that the resolver might not serve the DID's method. A
  `RefusalError` it threw lost its code and words. A throw is now answered
  as one of `delegation.didResolver` is: a `RefusalError` is the refusal's
  code and words, and any other error is logged once, naming the entry's
  method, and the DID is refused as `did_unavailable` with none of its
  words. UPGRADING.md, "A `didResolvers` entry that throws is answered as
  `didResolver` is", has the detail.

## [1.24.0] - 2026-11-17

### Added

- **Check delegation hop proofs before reading status.** Pass
  `verifyHopProof` to `evaluateDelegationChain` to verify every hop root to
  leaf after local checks and before any status read. The first proof
  refusal stops the walk, preserving its code and the existing per-answer
  deadline. Omitting the verifier keeps legacy results with one warning per
  process; it becomes required in the next major version. See UPGRADING.md.

### Changed

- **A Card's DID members take only a DID as W3C DID Core writes one, so
  the Card's schema moves to `identity/card/v1.2.0`.** `id`,
  `responsibleParty`, `principal` and an attestation's `subject` and
  `issuer` no longer take a DID URL, such as a key id ending in `#key-1`,
  a character DID Core writes percent-encoded, or an empty last part.
  `v1.1.0` stays published. `EntityCardSchema`, `parseCard` and
  `resolveCard` refuse such a value with a reason that says what is
  wrong; `resolveCard` does so before any request, where it fetched the
  DID document of one such as `did:web:acme.example:a+b`. UPGRADING.md,
  "Each Card DID is a DID as DID Core writes it", has each case.
- **A status-list binding no redirect reaches is said once.** A
  `statusListIssuers` binding written in another form than the URL parser
  writes, such as `https://lists.example:443/list` or a host in upper
  case, still binds a status entry that names it as written, as SPEC.md
  §6.6 reads it, but a redirect is matched as the parser writes the URL it
  resolves to and never reaches it. `RuntimeFetchProvider` and
  `createRevocationChecker` now say so once through `logger.warn` when
  configured, naming the form a redirect reaches, and say once as well of
  a binding no read reaches, one that includes credentials or does not
  parse. See UPGRADING.md.

### Security

- **The cheqd resolver no longer sends its configured headers to any host
  its endpoint redirects to.** `DidCheqdResolver`, `createDidCheqdResolver`
  and `cheqdResolver` let the runtime follow redirects itself, in Node up
  to 20 and to any host, carrying every header the `headers` option sets,
  such as an API key, to wherever they led. The resolver now follows a
  redirect by hand, as did:web and status-list reads do: at most 3, never
  from https down to http, and to an origin other than the resolver's
  with only the CORS-safelisted request headers. The resolver's own host
  may still be private or local, since the operator names it.
  UPGRADING.md, "The cheqd resolver follows a redirect by hand", has the
  detail.
- **A re-delegation under a delegation that grants no scope can no longer
  grant one.** `wrapWithDelegation` runs a tool only for a scope the
  presented delegation states, so a delegation with no scopes, such as an
  identity-only or audience-only grant, runs none. Chain validation read
  such a parent as unrestricted and accepted a re-delegation under it with
  any scope, so a delegate holding that grant from a trusted root could
  sign itself any scope, and the gate ran the tool. `wrapWithDelegation`,
  `validateDelegationChain` and `validateScopeAttenuation` now refuse such
  a re-delegation as `chain_invalid`, at any hop; one that states no scope
  either is still accepted. Every release from 1.2.0 read a parent with no
  scopes this way. It mattered from 1.17.0, on a server that names its
  trusted root issuers, since before then the gate took a root from any
  issuer. Conformance suite 1.6.0 adds a vector for it. UPGRADING.md, "A
  scope under a delegation that grants none", has the detail.
- **A cache TTL that is not a finite number no longer keeps an answer for
  ever.** `withStatusCache`, `DelegationCredentialVerifier`,
  `CheqdStatusListResolver` and the middleware's
  `delegation.verificationCache` read a TTL of `NaN`, as
  `Number(process.env.UNSET)` gives, or `Infinity`, as never expiring, so
  a "not revoked" verdict, a verified status list or a signature result
  was served long after it changed, and a capacity of `NaN` never evicted.
  The did:web and cheqd DID resolvers kept a document for ever under
  `Infinity`. Each TTL must now be a finite number of milliseconds, 0 or
  more, and each capacity a whole number greater than 0, or building the
  verifier or resolver throws a `TypeError` naming the option, as
  `dependencyTimeoutMs` does. An option left out keeps its default. A
  negative TTL and a capacity of 0, which turned a cache off, now throw
  too; set the TTL to 0. UPGRADING.md, "Cache TTL and size options are
  checked when they are set", lists each option.
- **A Card reaches L3 only on a live proof its own DID signed.**
  `verifyCard` lifted a Card to L3 on any valid proof, whatever DID signed
  it, so a caller holding any key could present another Entity's Card at
  L3. It now lifts the level only when the proof's `did` is the Card's
  `id`, compared as `resolveCard` compares a fetched Card's `id` with the
  DID it was resolved for. A Card whose proof another DID signed verifies
  at L2 with the same `ok`, its `proof` still reports that DID, and the
  accountability verifier still receives it as `proofDid`.
  SPEC-ENTITY-CARD.md §9.3, §11.1 and §11.3 state the rule.
- **A status list past its own `validUntil` no longer clears a
  revocation.** A list's proof does not tell its versions apart, so an
  earlier version, signed before a credential was revoked, still
  verifies; until now one past its `validUntil` (or `expirationDate`)
  read `fresh: false` and passed every verifier that did not require
  `fresh`, `requireDelegation` and `verifyCard` among them. Every
  status-list reader in the library, the Card revocation checker,
  `CheqdStatusListResolver`, `StatusList2021Manager` and the conformance
  reference adapter, now reads a list only inside the window it states,
  and refuses one past its end, before its `validFrom` (or
  `issuanceDate`), or with a bound that is not a date as
  `status_unavailable`, which is transient, with a reason that quotes the
  time the list states. A list that states no window is read as before.
  Issuers must republish a list before its `validUntil`. The rule is
  exported as `acceptStatusListValidity` for readers of your own, and
  conformance suite 1.7.0 adds eight vectors for it. UPGRADING.md, "A
  status list outside its validity window is refused", has the detail.
- **Outbound reads fetch what they check, and SafeFetch has one
  deadline.** A did:web DID whose host or path segment still holds a `%`
  after its one percent-decode, such as
  `did:web:example.com:bob:%252E%252E:alice`, now names no URL: the URL
  parser decoded it again, so two DIDs could name one document. The
  private-network rule hands the transport the URL the parser wrote, which
  is the URL it checked, rather than the string it was given, which a
  transport could parse to another host. `createSafeFetch`'s `timeoutMs`
  now covers a whole read, its DNS lookups, every redirect hop and the
  body, and the fetcher takes an optional `{ signal }` that ends the read.
  See UPGRADING.md.
- **The cheqd registrar client no longer sends its headers or a request
  body to any host its registrar redirects to.** `CheqdDidRegistrarClient`
  let the runtime follow redirects itself, in Node up to 20 and to any
  host, carrying the request body and every header the `headers` option
  sets, such as an API key, to wherever they led, and took that host's
  answer as the registrar's. A request now follows only a 307 or 308,
  which keep its method and body, only on the registrar's own origin and
  at most 3 times; a 301, 302 or 303 and a redirect to another origin are
  refused. The registrar's own host may still be private or local, since
  the operator names it. UPGRADING.md, "The cheqd resolver follows a
  redirect by hand", has the detail.
- **`verifyCard` no longer passes a Card whose revocation entry it
  cannot check.** A Card that declares `revocation` was verified
  `ok: true`, its entry ignored, when no `statusListChecker` was given,
  so a revoked Card passed. Such a Card is now refused as
  `configuration_error`, as an accountability or attestation that no
  verifier checks is, and reported revoked and not fresh, with a reason
  that names the missing checker. A Card that declares no `revocation`
  needs no checker. Conformance suite 1.8.0 adds the negative vector
  `entity-card/revocation-unchecked`. UPGRADING.md, "A Card that
  declares a revocation entry needs a checker", has the detail.
- **Status-list remedies bind the list's URL, proofs are canonicalized
  strictly, and decompressors are told the inflation cap.** A keeper
  refusal's `statusListIssuers` line now binds the list's own URL, never
  its origin, which would hand the signer every list there. `eddsa-jcs-2022`
  proofs hash with the package's RFC 8785 canonicalizer, which sorts an
  object with a member named `toJSON` as any other; signatures over plain
  JSON are unchanged, and signing a document with an `undefined` member
  throws. Every status-list reader passes its decompressor
  `{ maxBytes }` so it can stop a decompression bomb while inflating. See
  UPGRADING.md.
- Detached proof key retrieval now requires the signer to list the key under assertionMethod, and CIMD projects only authentication keys for client authentication. Both use the shared method ownership and uniqueness rules. Hand-written DID documents must list each key for its purpose; did:key and buildDidWebDocument are unaffected. See UPGRADING.md, Detached proof and CIMD keys follow their verification relationship.
- **The Card resolver reads a did:web DID as the did:web resolver
  does.** `resolveCard`, `didWebToCardUrl` and `didWebToDidDocUrl` decoded
  a DID's host and path segments with no check, so a dot-segment, an
  encoded separator, a double-encoded `%2E%2E` or userinfo in the host
  could read the DID document and Card another home serves. They now map
  the DID through the did:web resolver's own parser, and a DID that names
  no URL there is refused before any request. See UPGRADING.md.
- **did:web and status-list reads resolve and pin the hosts a presenter
  names.** `RuntimeFetchProvider` now resolves each host before it
  connects, every redirect included, refuses a host with any address that
  is not public, and connects only to the address it checked, so a
  public-looking name such as `did:web:169.254.169.254.nip.io` no longer
  reaches an internal endpoint and a second lookup cannot rebind it. The
  DIDs pinned in `trustedRootIssuers` and the lists `statusListIssuers`
  binds are read wherever they are. A status list, and each of its
  redirects, takes https. See UPGRADING.md.
- **A verified pinned root's status list may be on a private host.**
  `createRevocationChecker` reads the list a pinned root's own credential
  names on any host, still pinned, once that credential's proof has
  verified, and reads the lists `statusListIssuers` binds on any host
  too, deciding each hop, redirects included, on its own URL. A root
  credential whose proof fails or is not checked has its list read as
  one the presenter named, and so does a root no pin names: `verifyCard`
  takes `trustedRootIssuers` for the responsible party it may read so.
  See UPGRADING.md.
- **A proxy that carries the global fetch carries did:web and status-list
  reads again.** Where the global `fetch` sends a request through a
  proxy, under undici's `ProxyAgent`, or its `EnvHttpProxyAgent` such as
  the one Node installs under `NODE_USE_ENV_PROXY`, for a host `NO_PROXY`
  does not name, `RuntimeFetchProvider` reads through it as 1.23.0 did,
  held to the URL alone, and warns once that the proxy must refuse
  private addresses, instead of resolving the host itself and going
  around the proxy. Under any other dispatcher, and for a host `NO_PROXY`
  names, the read is still resolved, checked and pinned. See UPGRADING.md.
- **One failed lookup no longer turns the host check off.** The probe of
  whether the runtime resolves names answers no only where `node:dns` does
  not load or says its `lookup` is not implemented. Any other failure, such
  as a resolver busy for a moment, leaves each read to resolve and check
  its own host, and is asked again. Every fall back to the URL-only rule,
  a provider whose `fetch` is its own included, is logged once.
- **A redirect from a host the operator names is held to the rule.** The
  exemption for a status-list URL `statusListIssuers` binds and for the
  did:web document of a pinned DID covered every redirect of the read, so
  an open redirect on a bound origin reached a private address with no
  lookup. Each request is now decided on its own URL, as SafeFetch decides
  `allowOrigins`, and a redirect to a URL the operator did not name is
  resolved, checked and pinned.
- **Every verifier reads a window's dates as the same instants, and a
  list or hop issued a moment ago is read.** The dates of a status
  list's window and of an Entity Card delegation hop's were read with
  `Date.parse`, which reads a time with no zone, such as
  `2026-11-17T00:00:00`, in the zone of the machine it runs on, so one
  list was read in windows hours apart on two verifiers, and which takes
  forms RFC 3339 does not write. Each is now read as an RFC 3339
  date-time with its time zone, by one parser, and anything else is
  refused by its text alone, the same way everywhere:
  `status_unavailable` for a list, `delegation_malformed` for a hop, and
  expired for a VC 1.1 delegation credential's `expirationDate`. Each
  bound of a list's or a hop's window is now held with a clock
  tolerance, `maxClockSkewMs`, 120 seconds unless set, from 0 to
  600,000 ms, so a list whose `validFrom` an issuer with a clock running
  ahead stamped a moment ago is no longer refused until the verifier's
  clock catches up. Set it on `createRevocationChecker`,
  `CheqdStatusListResolver`, `StatusList2021Manager`, `requireDelegation`
  or a chain's context. Conformance suite 1.10.0 adds four vectors.
  UPGRADING.md, "Dates in a window name one instant, and each bound has
  a clock tolerance", has the detail.
- **Status lists are read over https.** Over http, an on-path party can
  replay an older signed list from before a revocation. A list a presenter
  names, and every redirect, is now read over https alone, under
  `allowPrivateNetworkHosts` and on a private host too. An exact http URL
  the operator binds in `statusListIssuers` is read on any host, by
  `RuntimeFetchProvider` and `createRevocationChecker` alike, and
  `development: true` still reads http from a private or local host. See
  UPGRADING.md, "Hosts a presenter names are resolved and pinned".
- **The pinned connection reads a host as `fetch` did.** It sends the
  `Accept` and `User-Agent` the runtime's `fetch` sends and
  `Accept-Encoding: gzip`, and decodes a gzip body through the package's
  capped decompressor, so the byte cap holds the decoded body. A host that
  serves its JSON gzipped whatever the request asks, as an object store
  does, is read again, and a body in another coding is refused and logged.
  Each pinned request, `SafeFetch`'s included, now has a connection of
  its own: it never reuses a socket `https.globalAgent` keeps alive for
  another request, which may have reached another address, nor goes
  through an agent or `https.request` installed in their place, such as
  a proxy that would resolve the host again. It keeps only the TLS
  settings of `https.globalAgent`, such as a `ca`. See UPGRADING.md.
- **A name that resolves to a private address is coded as one that does not
  resolve.** It was refused as `host_refused`, a verdict, where a name that
  does not resolve is `did_unavailable` or `status_unavailable`, transient,
  so the code told whoever chose the name what the verifier's DNS answered.
  Both are now coded alike, through `RuntimeFetchProvider` and `SafeFetch`,
  and the log says `host_refused` with the name and the address. A refusal
  the URL decides by itself keeps `host_refused`.
- **A proxy agent composed with interceptors is read as any other
  dispatcher.** Where the global dispatcher is undici's `ProxyAgent` or
  `EnvHttpProxyAgent` composed with interceptors, such as
  `interceptors.dns()`, which may resolve the host and connect on their
  own, `RuntimeFetchProvider` resolves, checks and pins the read. Deciding
  whether a proxy carries a read makes no request and opens no
  connection. See UPGRADING.md.
- **No reader sends the credentials in a URL.** A URL that includes a
  user name or a password before its host, such as
  `https://user:secret@host/`, is refused before any request, first or
  as a redirect target, by `RuntimeFetchProvider`'s did:web and status-list
  reads and by `SafeFetch`, as the runtime's `fetch` refuses it. The
  pinned connection sent them to the host as Basic credentials. See
  UPGRADING.md.

### Fixed

- **`validateDelegationChain` refuses, rather than throws, on answers it
  did not expect.** A `resolveDelegationChain` answer that is not an
  array, such as `undefined`, is refused as `runtime_error`. A credential
  verifier that throws is refused as `runtime_error`, or with the code of
  the `RefusalError` it throws, and each verifier call now gets
  `dependencyTimeoutMs` to answer, as the resolver and the revocation
  checker do. A credential whose `constraints.audience` is neither a
  string nor an array is refused as `chain_invalid`, where
  `wrapWithDelegation` refused it as `runtime_error`. A DID whose method only an
  object's prototype holds, such as `did:constructor:x`, no longer reaches
  `Object.prototype` in the delegation gate's resolver or in
  `RuntimeFetchProvider.resolveDID`, and the gate refuses it as
  `did_invalid` where it refused it as `did_unavailable`. In
  `wrapWithDelegation` a credential's DID resolution and status read now
  share one `dependencyTimeoutMs`. See UPGRADING.md.
- **`evaluateDelegationChain` refuses a chain whose revocation checker
  throws or rejects, rather than rejecting itself.** The chain is refused
  with `fresh: false` and the reason `revocation checker threw: status
  unprovable, fail-closed`, coded `status_unavailable`, or with the code
  of a `RefusalError` the checker throws, as `verifyCard` codes it. The
  checker's own words reach the reason only for a `RefusalError`; any
  other error's message goes to the operator's log.
- **A pinned connection tries every address it checked.** It was pinned to
  the first address a host resolved to, so a host with an unreachable
  address first, a dead CDN node or an AAAA record on a host whose IPv6
  egress is broken, was not read, where `fetch` tried the next. Every
  checked address is now handed to the connection, which tries each in
  turn and never one that was not checked.

## [1.23.0] - 2026-11-16

### Upgrading

- **Two things to check: one if your server uses `wrapWithDelegation`,
  and one if you hand the verifier keys of your own.** A consumer that
  recomputes `authorization.delegationCredentialDigest` must compute the
  credential digest of SPEC.md §7.8 in place of a SHA-256 of the bytes
  presented, and a digest recorded before the upgrade does not equal one
  recorded after it for the same credential. A custom DID resolver or
  key provider that hands the verifier an Ed25519 JWK must write its `x`
  as RFC 8037 has it: base64url of the URL-safe alphabet, with no `=`
  and no white space, of 32 bytes. UPGRADING.md, "Digests and keys to
  recheck", has both in full.
- **A status list is now held to the credential it covers, so a status
  check that passed on 1.22.0 can deny.** A reader that verifies a
  list's proof reads the list only from the one keeper of its URL: the
  issuer `statusListIssuers` binds the URL or its origin to, else the
  chain's pinned root when its own credential names the URL, else the
  credential's issuer, and only when the list states its URL as its
  `id`. Bind each list URL another issuer signs in
  `statusListIssuers`, or put the root credential on the root's list
  and pin the root, and re-issue each list with its URL as its `id`. A
  `statusListIndex` must be a string of decimal digits, an entry of
  another `statusPurpose` or of a `statusSize` other than 1 reads as
  revoked, and `verifyCard` takes only a literal `true` from an
  `accountabilityVerifier`. UPGRADING.md, "Status lists held to their
  credential", takes each setup in turn.
- **A delegation credential, status list or delegation hop must be signed
  with a key its issuer's DID document lists under `assertionMethod`.**
  did:key documents, did:web documents built with `buildDidWebDocument`
  and every signer in this package already comply. Before verifiers
  upgrade, any other issuer lists each signing key under
  `assertionMethod`, with its own DID as the method's `controller`,
  states `proofPurpose: assertionMethod`, names its key, and names
  itself by a URL as written. Some did:cheqd documents need a DID
  update. Refusal reasons now quote the values they name, so code that
  matches on their text needs the new wording. UPGRADING.md, "From
  1.22.0", has the steps for each setup and a table of every changed
  reason.
- **DID resolution and status-list reads refuse inputs over fixed limits,
  and give up after 5 seconds.** A DID may have at most 2,048 UTF-16 code
  units, and a DID document, did:web response or status list at most
  1 MiB, within limits on nesting, members and entries; each read has one
  5-second deadline and follows at most 3 redirects. Anything over a
  limit is refused, never cut to fit, so check your DID documents and
  status lists before you upgrade. A did:web DID or status list on a
  private address or a local name is refused unless `development: true`
  admits it in local development, or the `FetchProvider` sets
  `allowPrivateNetworkHosts: true`. A custom `FetchProvider` must pass
  `redirect` on, a custom resolver's document must be plain JSON data
  with a DID as its `id`, and each `trustedRootIssuers` entry must be a
  DID with no white space around it. Some failure reasons changed.
  UPGRADING.md, "Limits on DID resolution and status-list reads", has
  every limit and each setup.
- **A verifier that accepts a delegation must name the issuers it
  trusts.** With no root pinned, a delegation from any issuer is
  accepted, including one an agent signs for itself; 1.22.0 only warned
  at startup on the middleware, and said nothing on the Entity Card
  guards. Outside development, `wrapWithDelegation` now throws while
  `delegation.trustedRootIssuers` is unset, and while neither
  `trustedRootIssuers` nor `resourceOwner` is set, `requireDelegation`
  throws when the guard is built and `verifyRequestDelegation` rejects
  the call. Each error names every fix: set the list to the DIDs allowed
  to grant authority, or on the Card `resourceOwner`; in local
  development, set `development: true`, which the Card guards now take
  too; to accept any issuer anyway, set the new
  `allowAnyRootIssuer: true` (`delegation.allowAnyRootIssuer` on the
  middleware). Either of the last two runs with one warning. A server
  that gates no tool on a delegation needs no setting and is no longer
  warned. An `allowAnyRootIssuer` that is not a boolean, or one set to
  `true` beside a pinned root, throws a `TypeError` when the middleware
  or the guard is created. UPGRADING.md, "A verifier that accepts a
  delegation must name the issuers it trusts", has each setup.

### Added

- **A response proof can bind the delegation chain a call was decided
  under, and a verifier that holds the chain checks it.** SPEC.md §7.8
  defines the two claims a proof may carry, both covered by its
  signature: `delegationRef`, the reference of the credential the call
  presented, and `delegationChainDigest`, one digest over every
  credential of the chain, root to leaf. Whoever holds the chain passes
  `delegationChain` to `ProofVerifier.verifyProof` or
  `verifyProofArtifact`, and `outcome` when checking a refusal. A proof
  that binds another chain or none, or names another credential, fails
  with `DELEGATION_BINDING_MISMATCH`, and one that records another
  outcome with `OUTCOME_MISMATCH`. Signing either claim from the server
  is not part of this release: `withKyaOs` sets neither. UPGRADING.md,
  "Checking a proof against a delegation chain", has the exports and
  each rule.
- **`acceptStatusList` is the status-list acceptance rule the readers that
  verify a list's proof apply, and `statusListKeeperFor` names the one
  issuer whose list is read at a status-list URL.** A custom
  `StatusListResolver` applies the rule, once a list's proof verifies, as
  `acceptStatusList(list, statusListExpectationFor(status, context,
  statusListIssuers))`. `StatusListResolver.checkStatus` and
  `BitstringRevocationChecker` take that `StatusCheckContext` as an
  optional second argument, `withStatusCache` caches per context, and
  `revocationEntriesOf(chain, trustedRootIssuer)` builds it for every hop
  of a chain, with the list URL a pinned root's own credential names.
  `createRevocationChecker` takes `statusListIssuers`, keyed by the DID
  of a status-list issuer, with the URLs and `https:` origins it keeps.
  All are exported from `@kya-os/mcp`, `@kya-os/mcp/delegation` and
  `@kya-os/mcp/card`. The delegation middleware names only the
  credential's own issuer to its resolver, never the pinned root.
  UPGRADING.md, "Status-list exports for a custom reader", has each
  signature and rule.
- **Conformance suite 1.3.0: key-relationship vectors.** Two new vector
  files, `delegation-chain-key-relationship.json` and
  `status-list-key-relationship.json`, put the SPEC.md §6.2 key rule in
  executable form: 3 vectors that verify and 16 that must be rejected,
  among them a key listed only under `authentication` or under no
  relationship, a stated `authentication` purpose, a document or key id
  under another DID, a method naming another `controller`, with no `type`
  or `controller`, or defined twice, and a VC-JWT whose `kid` names the
  `authentication` key or is empty. A `delegation-chain` vector's `leaf`
  may now be a VC-JWT string. CONFORMANCE.md maps L3.9a to them, and
  `npm run conformance:generate:key-relationship` regenerates them. The
  other vector files change only their `version`; the suite has 68 vectors.
- **`dependencyTimeoutMs` sets how long a verifier waits for each
  dependency.** Every wait the DID resource policy bounds used one fixed
  5 seconds: a DID resolution, a status-list read, a chain resolver, a
  revocation checker, a custom signature verifier and each Entity Card
  seam. The delegation middleware (`delegation.dependencyTimeoutMs`),
  `DelegationCredentialVerifier`, `validateDelegationChain`, `verifyCard`,
  `verifyCardProof`, `requireProof`, `verifyRequestDelegation`,
  `requireDelegation`, `createRevocationChecker`, the did:web and cheqd
  resolvers, `CheqdStatusListResolver`, `RuntimeFetchProvider` and
  `ProofVerifier` now take that one option, in milliseconds. It defaults
  to 5,000 and must be a number greater than 0 and at most 2,147,483,647;
  any other value throws a `TypeError` where the verifier is built. A
  reason states the configured time. See UPGRADING.md, "A dependency that
  can take longer than 5 seconds to answer", for each entry point.
- **An accountability verifier can report the status-list URL the root
  credential of a Card's chain names.** `AccountabilityResult` gains an
  optional `rootStatusList`. `verifyCard` passes it to the status checker
  as `trustedRootStatusList`, so a verified responsible party keeps the
  list at that URL for the Card, as a pinned root keeps the list its own
  credential names, and returns it as `accountability.rootStatusList`. It
  is read only beside a literal `verified: true` and only as a non-empty
  string. A verifier that reports none leaves the responsible party only
  the URLs `statusListIssuers` binds to it. SPEC-ENTITY-CARD.md §10.3
  states the rule, and UPGRADING.md, "A Card whose `revocation` list
  another DID issues", says what a verifier returns.
- **Every refusal of a delegation, its chain, its status or an Entity Card
  carries a stable code, and says whether it is transient.** A reason is
  text for people, and its wording changed in this release; branch on the
  code instead. `REFUSAL_CODES` lists 21 codes, exported with
  `RefusalCode`, `isRefusalCode` and `isTransientRefusal` from
  `@kya-os/mcp`, `@kya-os/mcp/delegation` and `@kya-os/mcp/card`. The
  refusals of the delegation and Entity Card verifiers carry `code` and
  `transient`, and a rejection from `verifyRequestDelegation`,
  `requireDelegation` or `readDelegationChain` carries `refusalCode` and
  `transient`, and so does the result of the handshake's `verifyOrHints`,
  as `code` and `transient`, when its delegation verifier refused, or
  threw, which is `runtime_error` unless it threw a `RefusalError`. Four
  codes are transient, `did_unavailable`, `status_unavailable`,
  `deadline_exceeded` and `runtime_error`: the verifier could not decide,
  and the same request may pass later. A refusal that asking again cannot
  lift is not: a DID that can never be resolved, such as a did:key whose
  key does not decode, a did:web DID that names no URL, a did:cheqd DID
  the resolver cannot ask for or a DID of a method none of the delegation
  gate's resolvers serves, a document over the byte cap and an issuer key
  that is not a usable Ed25519 key are `did_invalid`, and a status entry
  whose index is past the end of its list, or that names its list by no
  string, is `delegation_malformed`. A custom signature verifier, chain
  verifier, `revocationChecker`, `BitstringRevocationChecker` or handshake
  `DelegationVerifier` may name a code in its answer, typed `string` where
  a code may come from a variable or JSON, and any dependency may throw a
  `RefusalError` to refuse with a code and words of its own. Every revoked
  answer of the checker `createRevocationChecker` builds, a set bit
  included, now carries `code` and `transient`, so a test that compares
  one exactly must allow for them, and a server that returns a
  `requireDelegation` rejection to its client as it is now sends
  `refusalCode` and `transient` too. The delegation gate of `withKyaOs`
  records the code as `authorization.verificationCode` on
  `delegation.rejected`, and logs it as `{ code, transient }` beside a
  reason it now keeps up to 1,024 UTF-16 code units; under `holderBinding:
  "warn"` its holder-binding warning carries no code and says the call was
  allowed. The gate sends its client no code. UPGRADING.md, "Refusal
  codes", has the catalog.
- **`development: true` reads did:web documents and status lists on
  `localhost`, `*.localhost` names and private IPs, for local
  development.** Set it on `withKyaOs` or `createKyaOsMiddleware`, where
  it holds for every resolver and reader the middleware builds and reaches
  each `didResolvers` factory in its context, or on
  `DidWebResolverOptions`, `CheqdStatusListResolverOptions`,
  `RuntimeFetchProviderOptions` or `SafeFetchOptions`. It admits private
  and local hosts and changes nothing else. It warns once per process,
  throws when what it is set on is built while `NODE_ENV` is `production`,
  and throws a `TypeError` for any value but a boolean. It reads
  `process.env.NODE_ENV` as written, so a bundle in which a bundler has
  put `"production"` in its place refuses it too. To read private hosts in
  production, give the fetch provider `allowPrivateNetworkHosts: true` as
  before. UPGRADING.md, "A did:web DID or status list served from a
  private IP address or a local name, such as `localhost`, as in
  development", says where to set it.
- **A resolver may say why a DID did not resolve, and a refusal is coded
  by it.** `DIDResolver` has a new optional `lastFailure(did)`, which the
  library's did:web, did:key and did:cheqd resolvers and the delegation
  gate's resolver answer, with a `DidResolutionFailure`: a `cause`, one of
  `host_refused`, `deadline_exceeded`, `unavailable`, `too_large` and
  `invalid_document`, and a `detail`. Both types are exported. A verifier
  codes its refusal by the cause. Whoever presents a credential chooses
  its issuer's DID, so `Could not resolve issuer DID: "<did>"`, for a
  VC-JWT as for a credential with an embedded proof, and
  `CheqdStatusListResolver`'s `Could not resolve issuer DID <did>` end
  with the detail in parentheses only where one of the library's resolvers
  decided it from the DID alone, before any request or DNS lookup, such as
  a did:web DID that names a private or local host, or where the deadline
  passed; a host resolver's detail is shown only for a passed deadline.
  Whatever the network answered, such as an HTTP status, a document over
  the byte cap or not JSON, a refused redirect or an address `SafeFetch`
  looked up, goes only to the operator's log, and the refusal's code says
  which kind of failure it was. The delegation gate of `withKyaOs` sends
  the reason to its client. UPGRADING.md, "Changed refusal reasons", has
  the wording.
- **A status resolver that wraps a library checker and passes on only the
  entry keeps the check's context.** Each status read hands its resolver a
  fresh copy of the entry that carries the credential's issuer and the
  pinned root under `Symbol.for('@kya-os/mcp/status-check-context')`, and
  the checker `createRevocationChecker` builds and `withStatusCache` read
  it when they are given no second argument. A checker that gets neither
  refuses the entry with a reason that says a wrapping resolver must pass
  its second argument on. UPGRADING.md, "A custom `StatusListResolver`
  given to `withKyaOs` or `DelegationCredentialVerifier`", has the detail.

### Changed

- **The audit events of the delegation gate's decision say which
  delegation it decided on, by the reference and the digests of SPEC.md
  §7.8.** `delegation.rejected` and a retry under a stored grant now
  carry `delegationRef` and `delegationCredentialDigest`, and
  `delegation.verified`, `delegation.rejected` and `grant.used` list
  `delegationChainDigests`, one per credential evaluated.
  `delegationCredentialDigest` is the §7.8 digest, no longer a hash of
  the bytes presented. The gate reads a presented credential, and each
  value a resolver returns, once, as plain data, and a credential may
  nest at most 64 levels. `ProofVerifier`, the gate and
  `CheqdStatusListResolver` read a JWS segment and a key's `x` as
  RFC 7515 section 2 writes base64url, with no padding and no white
  space. Some refusal reasons changed. UPGRADING.md, "Delegation audit
  events, and how the gate reads a credential", lists every change.
- **A Bitstring Status List may state its `statusPurpose` as an array.**
  Bitstring Status List v1.0 §2.2 lets a `BitstringStatusListCredential`
  whose subject's `type` is `BitstringStatusList` declare one or more
  purposes. `createRevocationChecker` and
  `StatusList2021Manager.checkStatus` now read such a list when its
  purpose array includes the purpose being checked, where they rejected
  any array before. Every other list, a StatusList2021 list included,
  states one string, as Verifiable Credentials Status List v2021 §2.2
  requires, and is still rejected when it states an array, now with a
  reason that says so. `CheqdStatusListResolver` reads StatusList2021
  lists alone, so it still rejects every array. A list with no purpose,
  an empty array, or a purpose that is not a string is still rejected.
  `CheqdStatusListResolver` applies the shared rule before it checks a
  list's signature, and refuses a list's issuer and purpose with the
  rule's reasons.
- **A status-list refusal quotes at most 64 characters of a value the
  list, the entry or the credential states.** The messages
  `acceptStatusList` gives, the refusals of an entry's `statusPurpose`
  and of a `statusListIndex`, and the message
  `evaluateRevocationChain` gives for a refused hop quote such a value
  as the delegation verifier's reasons do, so each is one line of
  well-formed text. On 1.22.0 they quoted the value whole, and two of
  them threw a `TypeError` on a parsed object whose `toString` member
  is a string, where `evaluateRevocationChain` and
  `evaluateDelegationChain` now return their verdict. A refusal of a
  list's issuer names the keeper of the list's URL and why it keeps
  it, and a refused hop is named by its position in its chain, the
  root being 0. UPGRADING.md, "Changed refusal reasons", has each
  message before and after.
- **The `DIDDocument` type lists all five verification relationships.**
  It had `authentication` and `assertionMethod` only, and now also has
  `keyAgreement`, `capabilityInvocation` and `capabilityDelegation`, each
  optional and of the same shape: methods listed by id or embedded
  (Controlled Identifiers v1.0 §2.3). Nothing changes at run time.
- **A delegation credential's issuer must be a URL as it is written.** The
  `basic` stage of `DelegationCredentialVerifier`, which
  `prepareVcJwtCredential` runs for a VC-JWT, refuses an `issuer`, an
  issuer object's `id` or a VC-JWT's `iss` that the WHATWG URL parser does
  not parse, such as `acme` or `#key-1`, or that has white space at
  either end or holds a control or format character, U+2028, U+2029, a
  character that renders as nothing by default or a lone surrogate
  anywhere (SPEC.md §6.2), by one fixed list of code points that every
  runtime shares. Such a credential was refused
  later, when its issuer did not resolve, unless a custom `DIDResolver`
  resolved it. `credentialIssuerDid`, and every reader of a credential's
  issuer in `DelegationCredentialVerifier` and `CheqdStatusListResolver`,
  takes the `id` of an object only, never of an array.
- **`CheqdStatusListResolver` refuses a status list whose proof names its
  key by anything but a non-empty string.** Such a proof was read as
  naming no key, and the list was checked with each of the issuer's keys;
  it now fails as the delegation verifier fails such a proof.
- **A refused status entry says why.** The checker
  `createRevocationChecker` builds answered every entry it could not
  prove clear with `{ revoked: true, fresh: false }` and kept the cause
  to itself, so a refused hop read only `is revoked or unresolvable`.
  `RevocationStatus` has a new optional `reason`, which that checker
  fills whenever it fails closed: the entry's purpose or size, the
  fetch, the list's issuer, purpose or `id`, its proof, or its bits.
  `evaluateRevocationChain` appends a checker's reason to the hop's
  refusal after a colon, so `evaluateDelegationChain`,
  `verifyRequestDelegation` and `requireDelegation` carry it, and
  `verifyCard` reports it as `revocation.reason`. The checker's reason
  is at most 512 UTF-16 code units, `CHECKER_REASON_LENGTH`, and those
  readers keep up to 640 of a reason, with control characters replaced.
  Code that compares that checker's verdict with `{ revoked: true,
  fresh: false }` exactly, or matches a refused hop's whole text, must
  allow for the reason. UPGRADING.md, "Changed refusal reasons", has
  the wording.
- **The two delegation credential schemas move to new `$id`s.**
  `schemas/card-delegation-credential.json` is now
  `delegation/credential/v1.2.0` and `schemas/delegation-credential.json`
  is now `delegation/credential/v1.0.1`, since each rejects a `statusSize`
  or `statusMessage` that the schema published at its old `$id` accepts,
  and `v1.2.0` also requires `DelegationCredential` in `type`. A
  published `$id` keeps its bytes unless a change only widens it, so
  schema.kya-os.org serves the new versions beside the old ones, which
  do not change. The Card's schema only gains the two members and keeps
  `identity/card/v1.1.0`. A test now fails when a schema changes under
  an `$id` that is published with other bytes.
- **The refusal of a private or local host names the settings that admit
  it, and no refusal names an address or a redirect target the network
  gave.** A did:web or status-list read refused for its host now says
  `Request to "<host>" refused: a private or local host. In local
  development, set development: true; to read private hosts in production,
  give the fetch provider allowPrivateNetworkHosts: true.`, and a redirect
  to such a host `Redirect to a private or local host refused. In local
  development, ...`, naming no host. `createSafeFetch` refuses a
  non-public IP literal, IPv4 or IPv6, and `localhost` or a name under it,
  before any lookup, as `safe-fetch: refusing host "<host>", a private or
  local host: ...`, coded `host_refused`, where such a host failed as a
  lookup error or was refused once looked up, and a body over its cap as
  too large whether or not its length was declared. It refuses any other
  host that resolves to a non-public address as `safe-fetch: refusing host
  "<host>", which resolves to a non-public address: in local development,
  set development: true; to read a host you own in production, list each
  origin you own in SafeFetch's allowOrigins`, where it named the address,
  and a redirect to another origin as `safe-fetch: cross-origin redirect
  from <origin> blocked`, where it named the target; the log keeps both.
  Code that matches on these texts needs the new wording. UPGRADING.md,
  "Changed refusal reasons", has each.
- **A custom `FetchProvider` need not return a stream body.** The did:web
  and status-list readers read a body that is a WHATWG `ReadableStream` as
  it streams, and any other response, such as one from node-fetch v2 or
  from `createSafeFetch`, through its `text()`, else its `json()`, under
  the same deadline, byte cap and JSON limits. Only a response with none
  of these is refused, with a reason that says what a provider must
  return. `SafeFetchResponse` has a new optional `text()`, which
  `createSafeFetch` answers. UPGRADING.md, "A custom `FetchProvider` given
  to the did:web or cheqd resolver, or to `CheqdStatusListResolver`", has
  the detail.
- **A status list refused for its signer says which `statusListIssuers`
  line would accept it.** When the checker refuses a list another DID
  signed, its reason ends with that configuration as a condition only the
  operator can judge, such as `; if "<signer>" signs this issuer's lists,
  name it in statusListIssuers: { "<signer>": ["<origin>"] }`, or says
  where to name the signer when the line cannot be printed whole within
  the checker's 512 UTF-16 code units, `CHECKER_REASON_LENGTH`, exported
  from `@kya-os/mcp/card`, and says neither when that does not fit. No cut
  of a reason falls inside such a remedy, so a reason carries it whole or
  not at all. The chain walk, `verifyCard` and the `Status check error` of
  `DelegationCredentialVerifier` keep up to 640 UTF-16 code units of a
  resolver's or checker's reason, and so does the chain walk of a
  `RevocationChecker`'s, so a wrapper may add 128 of its own; the chain
  walk keeps a credential verifier's reason up to 1,024, and the
  delegation gate of `withKyaOs` logs up to 1,024. The reason the gate
  sends its client is cut after 256 and so carries no remedy.
  `requireDelegation` sends its client a status checker's reason in
  `error.reasons`, now up to 640 UTF-16 code units, and a hop proof
  verifier's `RefusalError` up to 512, where each was a short fixed text.
  UPGRADING.md, "How to write `statusListIssuers`", has each form.
- **`statusListIssuers` refuses a binding it would not read as meant.** A
  binding is an exact URL, compared byte for byte, or an `https:` origin
  with nothing after it, as SPEC.md §6.6 says. `createRevocationChecker`,
  `statusListKeeperFor` and `statusListExpectationFor` now throw a
  `TypeError` that names the fix for an origin followed by `/`, an origin
  whose host has an upper-case letter, and any other binding that ends in
  `/`, each of which would be read as an exact URL that no list names.
  Each fix names the origin to bind, or, where no binding can hold a list
  whose own URL ends in `/`, says to change that list's URL. UPGRADING.md,
  "How to write `statusListIssuers`", has each fix.

### Security

- **A `__proto__` member with a primitive or `null` value is now part of
  what a credential's signature is checked against.**
  `wrapWithDelegation` checked an embedded-proof credential's signature
  over a copy of it built by assignment. Assigning a string, a number, a
  boolean or `null` to `__proto__` adds no member, so a member of that
  name with such a value was left out of what was checked: a holder
  could add one to a credential an issuer had signed and it still
  verified. A `__proto__` member holding an object or an array was
  already refused. Nothing in this library reads the member, so what
  was exposed is code that is handed the verified credential and does.
  The signature is now checked over every member but `proof`, read the
  same way the chain digest of SPEC.md §7.8 reads them, so such a
  credential is refused, and one whose issuer did sign a `__proto__`
  member verifies where it used to fail.
- **`createRevocationChecker` no longer accepts a status list from whoever
  signed it.** Given `verifyStatusList`, it checked a list's proof against
  the DID the list named as its issuer, and never compared that DID with
  the credential the entry belongs to, so whoever could serve the list
  could sign one of their own with the bit cleared, and a revoked
  credential read as active. The list's `issuer` must now be the one
  keeper of the URL the entry names, which the checker decides before
  it fetches: the issuer its configuration binds the URL to, else the
  chain's pinned root when its own credential names the URL, else the
  credential's issuer. This affected `evaluateDelegationChain` and
  `verifyCard` from 1.20.0, and `verifyRequestDelegation` and
  `requireDelegation` from 1.22.0. `CheqdStatusListResolver` was not
  affected. A deployment whose lists are served only by their issuer,
  from a host and over a transport no one else controls, was not
  exposed; others should upgrade.
- **A status list a trusted issuer signed is no longer read at another
  of that issuer's list URLs.** `CheqdStatusListResolver` from 1.14.0,
  and `createRevocationChecker` given `verifyStatusList` from 1.20.0,
  never compared a list's `id` with the URL it was fetched from, so
  whoever could serve a list could serve, in its place, another list
  the same issuer signed with the credential's bit clear. Both now
  require a list's `id` to be, byte for byte, that URL, except that
  the checker still reads a list with no `id` from the credential's
  own issuer where the verifier pins no other root and its
  configuration names no other issuer. A deployment whose lists are
  served only by their issuer, from a host and over a transport no one
  else controls, was not exposed; others should upgrade.
- **A delegation credential, status list or delegation hop no longer
  verifies with a key its issuer's DID document does not list under
  `assertionMethod`.** `DelegationCredentialVerifier`,
  `CheqdStatusListResolver`, `createStatusListProofVerifier` and
  `createDelegationProofVerifier` took any key the document published, so
  the holder of a key listed for another purpose or none, such as an
  `authentication` key on a less protected device, or of a third party's
  key the document defines, could sign a delegation the gate ran a tool
  for, a status list that cleared a revocation, or a hop
  `verifyRequestDelegation` accepted. The first was affected in every
  release, from 1.9.0 for VC-JWTs, and the others from 1.14.0, 1.20.0 and
  1.22.0. A verifier is unaffected when every issuer it trusts lists each
  key it publishes under `assertionMethod`, as did:key documents do;
  others should upgrade.
- **A delegation or a request proof can no longer make its verifier fetch
  and parse a DID document or status list of any size, or wait for one
  without end.** The did:web and cheqd DID resolvers,
  `CheqdStatusListResolver` and `RuntimeFetchProvider.fetchStatusList`
  read a whole response with no size limit or deadline, and the resolvers'
  caches had no limit, so a caller of a gated tool or of `ProofVerifier`
  could name a DID or a status list served without end.
  `trustedRootIssuers` did not stop this: the gate resolved an issuer
  before it refused the root, and read a status list whether or not its
  signature verified. These reads are now bounded (see Upgrading); the
  gate admits a root before any resolution, and reads a status list only
  after the signature verifies. Affected: the gate from 1.2.0;
  `RuntimeFetchProvider`, and so `ProofVerifier`, from 1.4.0;
  `DidCheqdResolver` from 1.9.0; `CheqdStatusListResolver` from 1.14.0.
  Every verifier that resolves a DID or a status list a counterparty names
  should upgrade.
- **Through a provider that passes `redirect` on, a delegation or a
  request proof can no longer make its verifier send a request to a
  non-public IP literal or a local name; names are not resolved.** The
  delegation gate, `DidWebResolver` and `createDidWebResolver` read a
  did:web document from any host and let the runtime follow its redirects,
  `CheqdStatusListResolver` left the check to its provider, and
  `RuntimeFetchProvider` missed some private IP forms and every name, so a
  DID or status list could have a request sent to the cloud metadata
  address, `localhost`, or a host that redirects there. Every such read
  now holds its host, and each redirect it follows by hand, to one
  private-network rule; a public name whose address is private is still
  admitted. Affected: the gate, `DidWebResolver` and
  `createDidWebResolver` from 1.2.0; `RuntimeFetchProvider` from 1.4.0;
  `CheqdStatusListResolver` from 1.14.0. A verifier whose every request
  passes an egress control that refuses private addresses, loopback
  included, is not exposed; others should upgrade.
- **`SafeFetch` no longer admits an IPv4-translated IPv6 form of a private
  address.** `createSafeFetch` and `isBlockedAddress`, which the Entity
  Card's reads go through, classified an address in `::ffff:0:0:0/96` (RFC
  2765) as public, so a host that resolved to the translated form of a
  private address, such as `::ffff:0:7f00:1` for 127.0.0.1, was connected
  to. They now classify it by the IPv4 address it embeds, as they do an
  IPv4-mapped address. This affected 1.9.0 through 1.22.0. Such an address
  reaches the private host only through a stateless IP/ICMP translator on
  the verifier's network: a deployment with one should upgrade, and others
  are not exposed.
- **A did:cheqd DID no longer chooses the path the cheqd resolver is
  asked for.** `parseDidCheqd` read any unique id without `/`, `?` or
  `#`, and `didCheqdToResolverUrl` wrote the DID into the URL as it
  stood. A URL parser reads `\` as `/`, so a DID such as
  `did:cheqd:mainnet:x\..\..\admin`, named by a delegation or a request
  proof, made the resolver send the operator's headers to another path
  of the configured resolver's host. This affected 1.9.0 through
  1.22.0. A unique id is now a UUID or letters and digits, as cheqd's
  DID method defines it, any other DID is refused before a request, and
  the URL holds the DID as one encoded path segment, in a `{did}`
  template too.
- **A revocation answer that is not a boolean no longer passes a
  credential.** `DelegationCredentialVerifier` read what a
  `StatusListResolver` answered by its truthiness, and
  `validateDelegationChain` read a `RevocationChecker` the same way, so a
  custom resolver or checker that answered `undefined`, `null`, `0` or
  `""`, as untyped code or a fault can, let a revoked credential through,
  and `validateDelegationChain` threw on `undefined` or `null`. Only a
  literal `false` now passes and only a literal `true` revokes; any other
  answer denies the credential, as `status_unresolvable` from the status
  check, with a reason that says the status could not be read. 1.22.0
  read both this way. The shipped resolvers and
  `CascadingRevocationManager` answer booleans and were not affected.
  UPGRADING.md, "A `StatusListResolver` or `RevocationChecker` whose
  answer is not a boolean", has the reasons and what to change.
- **A root delegation must name the DID that signed it as its
  `issuerDid`.** SPEC.md §2 defines the Responsible Party as the
  `issuerDid` of the root credential, while the gate attributes a call to
  the root's verified signer, the credential's `issuer`. A root in which
  the two differed was accepted with a logged warning, so the code and
  the specification could name different DIDs for one call.
  `validateDelegationChain` and the delegation gate now refuse such a
  root before resolving any DID, with a reason that quotes both, so the
  two are one DID in every accepted chain. The warning is removed.
  Credentials from `DelegationCredentialIssuer` or `wrapDelegationAsVC`
  are unaffected: both write the two from one value. UPGRADING.md, "The
  Responsible Party of a delegated call", has the reason text and what
  an issuer that set them apart must do.
- **A dependency that never answers can no longer hold a delegation
  verification open.** `DelegationCredentialVerifier` waited without a
  deadline on a `StatusListResolver` and on a custom signature verifier,
  and `validateDelegationChain`, which the delegation gate runs, on
  `resolveDelegationChain` and a `RevocationChecker`, so a stalled status
  service, chain store or revocation graph kept a gated call waiting
  without end, where a DID resolver was given 5 seconds. Each call now
  has the same 5 seconds, and one that has not answered by then is
  refused: the credential as `status_unresolvable`, the signature as
  unverified, the chain as unresolved, the revocation check as failed. A
  dependency that can take longer, such as one that makes several reads
  in a row, now fails where it was slow. UPGRADING.md, "A dependency that
  can take longer than 5 seconds to answer", has each reason.
- **A tool argument named `__proto__` stays an argument, and no longer
  becomes the prototype of the arguments a handler receives.** The gates
  copied a call's arguments, without its `_kyaos*` control arguments, by
  assigning each member to a new object, which turns an own `__proto__`
  member into the copy's prototype. A handler behind `withPolicyGate`
  used on its own then read members the approved call never stated, and
  the approval's request hash did not cover them; the delegation gate
  with holder binding off or in `warn` did the same. A host that passes
  `JSON.parse` output to a wrapper was exposed; the MCP SDK's request
  schema drops the member first. Every such copy is now one function,
  `withoutControlArgs`, exported from `@kya-os/mcp`, which keeps
  the member a member. UPGRADING.md, "Arguments named `__proto__`",
  says what a handler sees.
- **A seam that never answers can no longer hold an Entity Card
  verification open.** `verifyRequestDelegation` and `requireDelegation`
  waited without a deadline on `resolveDelegationChain`, `verifyHopProof`
  and `checkRevocation`, `evaluateDelegationChain` on its revocation
  checker, `verifyCard` on its capability, accountability, attestation
  and proof verifiers and its `statusListChecker`, and `verifyCardProof`
  on `resolveKey`, `resolveDidKeys` and `consumeNonceIfFresh`. Each call
  now has 5 seconds, and one that has not answered by then is refused as
  that verifier refuses a seam that fails: `delegation_unresolvable`,
  `delegation_invalid` or `delegation_revoked`, a claim left unverified,
  the Card revoked, or the proof reason the seam has when it throws. A
  seam that can take longer now fails where it was slow. UPGRADING.md, "A
  dependency that can take longer than 5 seconds to answer", lists each.
- **The delegation gate names the verified root issuer as the
  Responsible Party, never a `controller` a credential states.** SPEC.md
  §2 defines the Responsible Party as the root issuer of the chain. The
  gate took it from the presented credential's `controller`, which that
  credential's own issuer writes, so a delegate that re-delegated could
  have a call attributed to any DID in the handler's context, the
  `delegation.verified`, `authorization.approved` and `grant.used` audit
  events, and the stored grant. This affected every release with
  `wrapWithDelegation`. The context's `responsibleParty` and
  `principal.responsibleParty` are now the root issuer the chain walk
  verified, and are always present. A grant stores it as
  `responsibleParty` and no longer sets `userDid`. A `withPolicyGate`
  that no `wrapWithDelegation` precedes verifies no delegation, and no
  longer gives its engine a Responsible Party at all. UPGRADING.md, "The
  Responsible Party of a delegated call", says what a handler, engine or
  audit consumer that read the old value must change.
- **A custom signature verifier's verdict counts only as a literal
  `true`.** `DelegationCredentialVerifier` read the `valid` of a custom
  `signatureVerifier`'s answer by its truthiness, so a credential whose
  signature did not hold verified when the verifier answered
  `{ valid: "false" }`, `{ valid: 1 }` or `{ valid: {} }`. Only an object
  whose `valid` is the literal `true` now verifies. Any other answer, one
  that is not an object or whose `valid` or `reason` throws when read
  included, leaves the signature unverified with a reason that says the
  verdict could not be read, and nothing throws. `validateDelegationChain`
  reads the `verifier` it is given by the same rule, where it threw a
  `TypeError` on `undefined` or `null`. A verifier typed against the
  library already answers a boolean. See UPGRADING.md, "A custom
  `signatureVerifier`, or another dependency, whose verdict is not the
  boolean its type promises".
- **`verifyCard` reads each seam's verdict as the literal its type
  promises.** Only the accountability verdict was read strictly. An
  `attestationVerifier` that answered a truthy value such as `"false"`
  verified the attestation, a `proofVerifier` whose `ok` was truthy
  lifted the Card to L3, a `capabilityVerifier` whose `fresh` was truthy
  kept L3, and one that answered no `verified` array made `verifyCard`
  throw. An attestation now verifies only on the literal `true`, a proof
  only on an object whose `ok` is `true` and whose `did` is a string,
  and a capability check counts only when `verified` and `unverified`
  are arrays of strings, with a `fresh` other than `true` read as
  `false`. Any other answer leaves the claim unverified, the proof with
  the reason `proof_verdict_unreadable` and the accountability check with
  an `accountability.reason`, and nothing throws. A seam typed
  against the library needs no change. See UPGRADING.md, "A custom
  `signatureVerifier`, or another dependency, whose verdict is not the
  boolean its type promises".
- **A Card or chain revocation checker whose answer is not a literal
  boolean no longer passes a credential.** `evaluateRevocationChain`,
  `evaluateDelegationChain`, `verifyRequestDelegation`,
  `requireDelegation` and `verifyCard` read a
  `BitstringRevocationChecker`'s `revoked` and `fresh` by their
  truthiness, so a custom checker that answered `{}` or `{ revoked: 0 }`
  let a revoked hop or Card through, and `"false"` revoked one. They now
  share one reader with the delegation side: only a literal `revoked:
  false` passes, only a literal `true` revokes, only a literal `fresh:
  true` is fresh, and any other answer, one whose getter throws
  included, refuses the hop with a reason that says what could not be
  read. `validateDelegationChain` returns that refusal where it rejected
  on a throwing getter. 1.22.0 read the Card side this way. The checker
  `createRevocationChecker` builds answers booleans and was not
  affected. `CascadingRevocationManager` reads its status list's answer
  the same way. UPGRADING.md, "A `BitstringRevocationChecker` whose
  answer is not `{ revoked, fresh }` with literal booleans", has the
  detail.
- **A crypto provider's and a nonce cache's answers count only as the
  literal they promise.** `CheqdStatusListResolver` read the answer of
  its `cryptoProvider.verify` by its truthiness, so a provider that
  answered `"false"` or `1` verified a status list's signature; it now
  verifies only on the literal `true`, as `ProofVerifier` already read
  its own. A nonce cache without `consume()` is asked `has()` and then
  `add()`, and a `has()` that answered `undefined`, `null`, `0` or `""`
  admitted the nonce; only the literal `false` now does, and any other
  answer denies the request as a replay and adds nothing. A provider or
  cache typed against the library already answers a boolean and needs no
  change. See UPGRADING.md, "A custom `signatureVerifier`, or another
  dependency, whose verdict is not the boolean its type promises".
- **A resolved DID document can no longer hand a verifier a member it
  inherits.** The walk that holds a custom resolver's document to the
  DID limits measures each object's own members, and admitted an object
  whose prototype was built by hand to pass for another realm's
  `Object.prototype`: one with a `constructor` named `Object`. A getter
  for `verificationMethod` or `assertionMethod` on that prototype was
  never measured, and the key lookup then read it. The walk now also
  refuses a prototype that has any member name `Object.prototype` lacks,
  so the document is refused before a getter on it runs, and a verifier
  reads only what was measured. A document that is a plain object, of
  this realm or another, is read as before. See UPGRADING.md, "Limits on
  DID resolution and status-list reads".
- **A verifier reads its own copy of a custom resolver's DID document.**
  The walk that holds such a document to the DID limits read each array
  by index, and the key lookup and `ProofVerifier` then iterated the same
  arrays, so an array with its own or an inherited `Symbol.iterator`, a
  replaced `find`, a getter on an index or a `Proxy` could hand a
  verifier a verification method that was never measured, as could a
  member that is not enumerable or a change made after the walk. The
  walk now copies what it measures, each own enumerable data member and
  each element by index, read once, into frozen plain objects and
  arrays, and every verifier reads that copy. The resolver's own object
  is left as it was. `RuntimeFetchProvider.resolveDID` returns the frozen
  copy for a resolver set in `didResolvers`. See UPGRADING.md, "Limits on
  DID resolution and status-list reads".
- **Every boolean a host's dependency answers is read as a literal.** The
  audit verifiers read `signatures.verify`, `verifySupportingAnchor`,
  `verifyCheckpoint`, `verifyConsistency`, `authorizer.authorize`,
  `epochTransitionGuard.verifyAndSeal` and `authorizeAccess` by their
  truthiness, and so did `verifyApprovalQuorum` its signature check, so
  an answer such as `"false"`, `1` or `{}` verified a signature, admitted
  a submission or released evidence. Each now passes only on the literal
  `true`. `verifyOrHints` authorizes only on a `delegationVerifier`
  answer whose `valid` is the literal `true` and whose `delegation` is an
  object, and does not throw on `undefined` or `null`. The delegation
  gate reads its `CryptoProvider.verify` the same way, and
  `AuthorizationServerRegistry.resolve` skips an adapter only when
  `isRequired` answers the literal `false`. Dependencies typed against
  the library need no change. See UPGRADING.md, "A custom
  `signatureVerifier`, or another dependency, whose verdict is not the
  boolean its type promises".
- **A status entry of more than one bit is no longer read from another
  entry's bit.** W3C Bitstring Status List v1.0 §2.1 lets an entry
  state `statusSize`, and §3.2 reads its status at `statusListIndex`
  times `statusSize`. Every reader read the one bit at
  the index, and the hop schema dropped the member, so an entry of two
  bits at index 7 was read from bit 7, which is entry 3's: a revoked
  credential could pass, and a live one be refused. The checker
  `createRevocationChecker` builds, `CheqdStatusListResolver` and
  `StatusList2021Manager` now refuse, before any fetch, every entry
  whose `statusSize` is not 1, through one exported rule,
  `acceptEntrySize`; an entry that states none is read as before. The
  hop and Card entry schemas keep `statusSize` and `statusMessage` and
  reject a malformed one. Conformance suite 1.4.0 gains three vectors
  for it. 1.22.0 has the defect. UPGRADING.md, "A `credentialStatus`,
  or a Card's `revocation` entry, that states a `statusSize`", has the
  detail.
- **A refusal no longer tells whoever presented a credential what the
  verifier's network answered, or what a dependency of the host's threw.**
  The presenter chooses the DIDs and status-list URLs a verifier reads,
  and their hosts may be internal ones. A reason now says why a DID or a
  status list could not be read only where the DID or the URL alone
  decided it, before any request or DNS lookup, as for a private or local
  host it names, or where the deadline passed. Otherwise it reads `Could
  not resolve issuer DID: "<did>"` or `the status list at "<url>" could
  not be read or checked`, and an HTTP status, the text of a body that is
  not JSON, a byte cap, a redirect target or a transport's error, which
  1.22.0 quoted, goes to the operator's log; the refusal's code still says
  which kind of failure it was. A DID resolver, signature verifier, chain
  resolver, revocation checker, status-list resolver or proof verifier the
  host supplies that throws still refuses, with a reason such as
  `Signature verification error: the signature could not be checked` or
  `Failed to resolve delegation chain: the chain resolver failed`, and its
  words reach only the log, as do a handshake delegation verifier's, whose
  challenge says `the delegation verifier failed`. To refuse in its own
  words, it throws a `RefusalError`, now exported from `@kya-os/mcp`,
  `@kya-os/mcp/delegation` and `@kya-os/mcp/card`, whose code and message
  reach the refusal. A verdict on a list that was read keeps its reason,
  the `statusListIssuers` remedy included. UPGRADING.md, "Changed refusal
  reasons", has each wording.

### Fixed

- **The delegation gate signs a refusal whose reason quotes text that is
  not well-formed.** `wrapWithDelegation` writes a refusal's reason with
  `sanitizeForMessage`, which cut it after 256 UTF-16 code units, possibly
  inside a surrogate pair, and kept a lone surrogate that a caller wrote
  in a VC-JWT's `kid` or a delegation id. A response proof signs the
  reason in RFC 8785 form, which refuses both, so such a refusal was sent
  without its proof. `sanitizeForMessage` now writes well-formed text, for
  that reason and every other: the cut falls before a pair it would split,
  and a lone surrogate reads as U+FFFD, as do DEL, the C1 controls,
  U+2028, U+2029, format characters such as bidirectional controls, and
  characters that render as nothing, which could make a reason or log
  line read otherwise than it is written.
- **The delegation gate sends a signed refusal for a delegation holding a
  value RFC 8785 cannot encode**: a lone surrogate, an integer of
  magnitude 2^53 or more, or a number beyond the double range. A
  credential's Data Integrity `proof` is outside its signature, so anyone
  holding a validly signed credential could put one there, and the gate
  threw a `TypeError` and ran nothing. A VC-JWT holding one in a value the
  gate hands on, its credential's, subject's or delegation's `id`, its
  delegation's `controller`, `parentId` or `scopes`, or the `scopes` of
  its `constraints`, could run the tool, or in some cases with an audit
  store make the gate throw. The gate now checks all of a credential with
  a Data Integrity proof, and those values of a VC-JWT, before holder
  binding and scope, and refuses as `delegation_invalid`, with a response
  proof in a session; a session grant whose credential holds one
  authorizes no call.
  The credential is never altered to make it encode.
- **A `statusListIndex` must be a non-negative decimal string.** The
  conformance reference adapter read the index with
  `parseInt`, so an entry stating `7junk`, `7.5` or `7` after a space read
  bit 7, where the library's status-list readers refuse each. Those
  readers converted an index that is not a string, so the number `7` or
  the array `["7"]` read bit 7, where `conformance/verify.py` refuses
  both; they now refuse it too. Conformance suite 1.4.0 adds a negative
  vector for each, `status-list/index-suffix`,
  `status-list/index-fraction`, `status-list/index-space` and
  `status-list/index-number`, and a positive one,
  `status-list/index-leading-zeros`, whose index opens with 4,300 zeros
  and names the bit its value names.
- **The delegation gate refuses a VC-JWT whose payload is not base64url
  of well-formed UTF-8.** The gate read a VC-JWT's claims with a decoder
  that repairs a byte that is not UTF-8, and SPEC.md §7.8 reads the id a
  credential is recorded by from the payload as it stands, so such a
  VC-JWT, signed by its issuer, ran the tool and was recorded in the
  audit trail and the handler's context under no `delegationRef`. It is
  now refused with `Invalid VC-JWT format`, as §7.8 says of a payload
  that is not read, and every VC-JWT the gate acts on is recorded by
  the id it acted on. `readsVcJwtClaims` is exported for a verifier of
  its own that wants the same check.
- **A tool result with a member named `__proto__` is proven under the
  envelope profile.** The envelope profile hashes a result without its
  top-level `_meta`, and made that copy by assigning each member to a
  new object, which turns an own `__proto__` member into the copy's
  prototype. Canonicalization then refused the copy, so the result was
  returned with no proof and `_meta.proofError` set: a tool, or whatever
  supplied its data, could make any of its answers unprovable. The copy
  is now made by the function that copies a request's params without
  `_meta`, which keeps the member a member, so the result is proven and
  `responseHash` covers the member. The body profile is unchanged.
  UPGRADING.md, "Arguments named `__proto__`", says what a verifier on
  1.22.0 does with such a proof.
- **A re-delegation's `prefix` scope is no longer accepted as narrower
  than its parent's `path-prefix` scope.** Chain validation proved a
  child `prefix` scope such as `notes/` to be inside a parent
  `path-prefix` scope `notes`. A `path-prefix` matches no value with a
  dot segment, and a `prefix` matches any value that starts with its
  base, so the child granted `notes/../admin`, which its parent did
  not. Only a tool registered with such a `scopeId` was reachable this
  way. `matcherContains` now proves no `prefix` inside a `path-prefix`,
  so such a re-delegation is refused. Write the child's scope as a
  `path-prefix`, which is still proven inside its parent. A `path-prefix`
  also refuses a percent-encoded dot segment (`%2e`, in either case) as
  the `.` or `..` it encodes, in a value and in a pattern, so
  `notes/%2e%2e/x` no longer matches `notes`. UPGRADING.md, "A `prefix`
  scope under a `path-prefix` parent", has both changes.
- **A `path-prefix` scope refuses a percent-encoded separator.** A
  `path-prefix` refuses a `.` or `..` segment, written as itself or as
  `%2e`, because a consumer that decodes and normalizes the path would
  resolve it outside the grant. It split the path on a literal `/` or
  `\` only, so `notes/..%2fsecrets/x.md` and `notes/..%5csecrets/x.md`
  matched a scope `notes`, and such a consumer would read
  `secrets/x.md`. A value or a pattern that holds `%2f` or `%5c`, in
  either case and anywhere in it, now matches nothing, and
  `matcherContains` proves no re-delegation inside or through such a
  pattern. Nothing else is decoded: `notes/a%20b.md` and a doubly
  encoded `%252f` still match, and the `exact`, `prefix` and `regex`
  matchers compare the text as written. A resource whose name holds an
  encoded separator needs an `exact` scope. UPGRADING.md, "A `prefix`
  scope under a `path-prefix` parent", has the detail.

### Spec

- **SPEC.md §7.8: a response proof binds the delegation chain by
  digest.** The new optional `ProofMeta` member `delegationChainDigest`
  is a domain-separated SHA-256 over the digests of every credential the
  server evaluated, root to leaf, each taken over the credential's signed
  form: what its issuer's signature covers, and that signature. §7.8
  defines both digests, gives `delegationRef` its one definition, bounds
  a credential's nesting at 64 levels, and says how a credential's JSON
  is read. §7.4 says how a verifier reads a proof's JWS: base64url as
  RFC 7515 section 2 writes it. CONFORMANCE.md adds L3.28, suite 1.5.0
  has 140 vectors, and `conformance/verify.py` re-derives them in Python.
  UPGRADING.md, "SPEC.md §7.8 and conformance suite 1.5.0", has the full
  text of the change and the vectors.
- **SPEC.md §6.6: every status-list URL has one keeper, and conformance
  suite 1.4.0 tests it.** A list's proof shows only who signed it, and
  its `id` binds it to a URL but not the URL to a signer. A verifier
  MUST decide, before any fetch, the one issuer whose list it reads at
  the URL a status entry names: the issuer its configuration binds that
  URL or its `https:` origin to, else the pinned root of the chain when
  the root's own credential names the URL, else the credential's
  issuer. The list's `statusPurpose` must include the entry's, and its
  `id` must be its URL, byte for byte, unless the credential's issuer
  alone keeps any URL. An entry whose `statusSize` is not 1 MUST be
  rejected under the `revocation` or `suspension` purpose. SPEC.md
  §6.10, SPEC-ENTITY-CARD.md §4.1, §10.3 and Appendix B, and
  CONFORMANCE.md L3.11 say the same. The suite gains 29 vectors, 97 in
  all. UPGRADING.md, "Conformance suite 1.4.0", lists them.
- **SPEC.md §6.2 and §6.10 and SPEC-ENTITY-CARD.md §10.5: a proof
  verifies only with a key its issuer's DID document lists under
  `assertionMethod`**, by reference or embedded, in a conforming method
  defined once, with an id under the issuer's DID and the issuer as its
  `controller` (Controlled Identifiers v1.0 §3.3). §6.2 also rejects a
  stated `proofPurpose` other than `assertionMethod`, an empty or
  non-string `kid` or `verificationMethod`, and an issuer or VC-JWT `iss`
  that is not a URL as written, and lets a VC-JWT with no `kid` be checked
  with the first `assertionMethod` entry alone. §11.5 says how to rotate
  keys under these rules. SPEC.md adds the CID, VC Data Model 2.0 and URL
  Standard references and cites VC-JOSE-COSE; SPEC-ENTITY-CARD.md adds CID.
- **SPEC.md §6.4: a root delegation's `issuerDid` MUST equal the `issuer`
  of its credential**, and a verifier MUST reject a chain whose root names
  any other DID. §2 names the root's `issuerDid` as the Responsible Party,
  and nothing said it had to be the DID that signed.
- **SPEC.md §6.3: a `path-prefix` scope matches no path with a dot
  segment or an encoded separator.** A verifier MUST NOT match a
  `path-prefix` value or pattern that has a `.` or `..` segment, written
  literally or as `%2e`, or that holds `%2f` or `%5c`, and MUST NOT take a
  `prefix` scope as contained in a `path-prefix` scope. The reference
  implementation already refused each; the specification did not say so.
- **SPEC.md §6.6: a verifier SHOULD refuse a `statusListIssuers` binding
  that is almost always a mistake.** That is an origin followed by `/`, an
  origin with an upper-case letter in its host, and any other binding that
  ends in `/`; how a binding is read is unchanged. The standalone
  conformance harness refuses the same bindings. §4.4.2 now says a reader
  reads a response with no WHATWG stream body through its `text()` or
  `json()` under the same limits, and that `development: true` admits
  private and local hosts and throws while `NODE_ENV` is `production`.

### Documentation

- **`adopters/` holds small apps that use the packed package as adopters
  do.** Each installs the tarball `npm pack` builds, imports only the
  public entry points, and shows one integration: `createSafeFetch` as a
  `FetchProvider`, a `StatusListResolver` around
  `createRevocationChecker`, did:web on `*.localhost` with `development:
  true`, a status list another DID signs under `statusListIssuers`, and
  `withKyaOs` with its defaults. Three also check the refusal codes an
  adopter branches on. `pnpm test:adopters` runs them, and CI runs them on
  every pull request.

## [1.22.0] - 2026-11-10

### Added

- **A request can carry its delegation chain, so a server can verify an
  agent acting for another organization without a lookup.** Put the chain
  in `_meta['org.kya-os/delegation-chain']` with `toDelegationChainMeta`.
  `verifyRequestDelegation`, and the `requireDelegation` guard that runs
  after `requireProof`, verify it in a fixed order: chain rules, the leaf
  delegate equal to the caller's proof DID, trusted roots, every hop's
  signature, the invoked action, then live revocation. With no chain in
  the request they verify one resolved by reference instead. A carried
  chain is bounded to 10 credentials by default. Hops are signed and
  checked with `signDelegationCredential` and
  `createDelegationProofVerifier` (`eddsa-jcs-2022`), and status lists can
  be signed with `signStatusListCredential`. Run
  `npm run example:chain-by-value` to see it end to end.

### Changed

- **Chain validation now reports a re-delegation that is wider than its
  parent.** SPEC.md §6.4 says "Scope constraints MUST be equal to or
  narrower than parent's constraints", and the chain walk has only
  compared scopes. A child that expires after its parent, names an
  audience its parent does not, or does not repeat the per-scope
  `constraints` of the parent scopes that cover it still validates, and
  each of these now comes back in `ChainValidationResult.warnings` and is
  logged by the middleware, once an hour per message. No verdict changes.
  The new `attenuationWarnings(parent, child)` export returns the same
  list, so an issuer can check a credential before minting it. These are
  candidates for rejection at a future major (see DEPRECATIONS.md), so
  issuers that see the warning should narrow what they mint.

### Spec

- **SPEC-ENTITY-CARD.md §10.5 and §11.4: a request may carry its
  delegation chain.** The new `_meta` key `org.kya-os/delegation-chain`
  holds the chain, root to leaf. A server that finds it verifies it and
  never falls back to a lookup. The chain binds to the request through the
  leaf join rather than `requestHash`, every hop carries an
  `eddsa-jcs-2022` proof by its own issuer, and revocation is read live as
  for a resolved chain. §11.4 fixes the verification order, Appendix D.5
  lists the gate codes, and §12.11 covers an on-path party replacing a
  carried chain. SPEC-MCP-EXTENSION.md §2 and §7.1 and SPEC.md §6.10 point
  to the new section.

## [1.21.3] - 2026-11-06

### Security

- **A `path-prefix` scope no longer matches a path with a `.` or `..`
  segment.** `matchScope` compared the raw string, so a grant for
  `notes/` matched `notes/../secrets/plan.md`, and a consumer that
  normalized the path afterwards read or wrote outside the grant. A value
  or pattern with a dot segment, split on `/` or `\`, now matches
  nothing, and `matcherContains` proves no containment through one.
  Dots inside a name (`notes/v1.2/`, `notes/.env`) still match. This
  affected 1.16.0 through 1.21.2. Consumers that already reject
  dot segments before the check are unaffected; others should upgrade.

### Fixed

- **`examples/revoked` no longer sends users to the retired cheqd testnet
  faucet.** `npm run gen:accounts` printed `https://testnet-faucet.cheqd.io`,
  which is now behind a cheqd-only login, and a Discord channel. The script,
  the example README, `.env.example` and the zero-balance error in
  `check:b` now point to the cheqd testnet faucet in cheqd Studio:
  https://docs.cheqd.io/product/network/tools/testnet-faucet. Examples only;
  no change to the package.

## [1.21.2] - 2026-10-27

### Security

- **`kya-audit verify` reported success without verifying when installed
  with npm.** npm links a package bin into `node_modules/.bin` as a
  symlink, and the CLI decided whether it was the entry point by matching
  the file name in `process.argv[1]` against `audit/cli.js`. Started
  through that link it matched nothing, so on macOS and Linux
  `npx kya-audit` and `kya-audit` printed nothing and exited 0 for every
  input, including a tampered bundle it never read. A pipeline that gated
  on the exit status therefore passed any bundle. This affected 1.11.0
  through 1.21.1. Running `node dist/audit/cli.js` directly and installs
  made with pnpm were not affected. The CLI now compares the resolved
  paths of `argv[1]` and its own module. Re-run any verification whose
  result rested on an exit 0 from an npm-installed `kya-audit`.

## [1.21.1] - 2026-10-22

### Fixed

- **Signed denials and challenges now verify when the call carried other
  KYA-OS control arguments.** A delegation-gate denial (an invalid, revoked
  or insufficient delegation, or a failed holder binding) hashed its request
  with only `_kyaos_delegation` removed, so a call that also carried
  `_kyaos_proof` or `_kyaos_approvals` got a proof whose `requestHash` matched
  no shape a client or auditor holds. A `needs_authorization` challenge to a
  call that sent `_kyaos_delegation: null` together with another control
  argument had the same fault, and so did a policy-gate denial or
  re-challenge on a resume that carried a custom `approvalsArgKey`. Outcome
  proofs now hash the request as SPEC §7.3 describes, with every `_kyaos*`
  argument removed. Proofs issued before this fix stay unverifiable.
- **An approved call on a resume with a custom `approvalsArgKey` now
  verifies.** The policy gate removed that key from the arguments it handed
  its handler, so a handler wrapped in `wrapWithProof` signed a request the
  client never sent. The gate now removes only the `_kyaos*` arguments: a
  custom key outside that prefix reaches the handler as the ordinary
  argument SPEC §7.3 classifies it as. A gate built with a custom
  `approvalsArgKey` logs a warning saying so, and that a `_kyaos`-prefixed
  custom key does not survive `wrapWithDelegation`.

## [1.21.0] - 2026-10-21

### Upgrading

- **A status-list manager given a compressor that does not GZIP now throws
  instead of publishing.** Status-list readers accept only GZIP, so such a
  list read as revoked for every credential it covered. A decompressor that
  hands back its input unchanged now makes every read throw, where it read
  the GZIP header as status bits. Drop the compressor and decompressor
  arguments to use the shipped codec, or pass `statusListGzipCodec`. A list
  already stored without GZIP, such as one published with the pass-through
  pair the status-list example used, can no longer be read or updated:
  reissue it, and the credentials it covers, with the codec.

### Added

- **`statusListGzipCodec`, a GZIP codec for status lists.** One object is
  both the `CompressionFunction` and the `DecompressionFunction` that
  `StatusList2021Manager` and `BitstringManager` take. It loads `node:zlib`
  on first use, so a bundle that injects its own codec does not pull it in,
  and bounds inflation to the 16 MiB status-list cap. The Entity Card
  revocation checker uses it as its default `decompress`.
- **The compressor and decompressor of `StatusList2021Manager`,
  `createStatusListManager`, `BitstringManager` (its constructor, `decode`
  and `fromSetBits`) and `isIndexSet` are optional** and default to
  `statusListGzipCodec`.

### Fixed

- **`StatusList2021Manager` could publish status lists that every other
  reader took as revoked.** The manager required a compressor and
  decompressor, the package shipped none, and its example passed a pair that
  did not compress, so the lists it published were not GZIP and the Entity
  Card revocation checker reported every entry revoked. Publishing now
  refuses a list that is not GZIP, and the example uses the shipped codec.
- **A pass-through decompressor read revoked entries as live.** Reading a
  GZIP list without inflating it took the GZIP header as status bits, which
  left the first three entries clear whatever the issuer had set. Reading a
  payload that is not GZIP, or one the decompressor returns unchanged, now
  throws, on the delegation and Entity Card paths alike. Fixes #254.

## [1.20.0] - 2026-10-13

1.19.0 was tagged but never published to npm; its changes (listed under
1.19.0 below) ship to npm for the first time in this release.

### Upgrading — BREAKING without an open KYA-OS transport

- **Every response proof is now made where the KYA-OS transport sends the
  result, under the default body profile as under the envelope profile, and
  the wrappers refuse to run without one.** While no KYA-OS transport is open
  for the middleware, `wrapWithProof`, `wrapWithDelegation`, `withPolicyGate`
  and `proveOutcome` throw on entry, before they record or run anything, with
  an error that names `withKyaOs` and `createKyaOsTransport`. A transport
  counts as open from `start()` until it closes, by `close()` or by its own
  `onclose`. Once a KYA-OS transport has been created for a middleware, every
  wrapper result must go out through one. Before, the proofs were signed in
  the handler, and they did not verify on 2026-07-28 (envelope) or after an
  SDK reshaped `content` (body). Find your setup:
  - **`withKyaOs(server, …)` before `server.connect()`, `proofAllTools` left
    on:** nothing to change.
  - **The low-level `Server` API with `createKyaOsMiddleware`:** connect
    through the KYA-OS transport, as this repository's examples now do:

    ```ts
    await server.connect(createKyaOsTransport(transport, kyaos)); // was server.connect(transport)
    ```

    The transport proves and audits every tool's result, as `withKyaOs`
    does, including tools you registered without a wrapper, which went out
    unproven on 1.19.0. List any to leave unproven in its third argument,
    which adds to the always-excluded `_kyaos` and `_kyaos_handshake`.
  - **A script, walkthrough or test that calls a wrapped handler directly:**
    serve it in process, and read the result a client would receive:

    ```ts
    const local = serveInProcess(kyaos);
    const checkout = local.tool('checkout', kyaos.wrapWithDelegation('checkout', consent, handler));
    const result = await checkout({ item: 'laptop' }); // proved
    await local.close();
    ```
  - **`withKyaOs` with `proofAllTools: false`:** it wraps no transport, so
    the wrappers refuse. Leave it on and list the tools to leave unproven in
    `excludeTools`.
  - **`withKyaOs` called after `connect()`:** the connected transport is not
    wrapped; call `withKyaOs` first.
  - **Code that reads the proof inside the handler:** the result
    `proveOutcome` or a wrapper returns no longer carries one, under either
    profile. Return it from the handler; the transport adds the proof.
  - **Results delivered later, such as MCP task results:** a result is
    proved the first time the same middleware sends it, within
    `pendingProofTtlMs` (default five minutes, at most 2147483647) of the
    handler returning. Raise it for task results fetched later; a later or
    repeated send goes out with `proofError` (see below).

### Added

- **The Entity Card revocation checker can verify a status list's proof.**
  `createRevocationChecker` fetched a Bitstring status list and read its bits
  without checking the list's proof, which Bitstring Status List v1.0 requires
  (§3.2, step 4). Whoever could serve or alter the list could clear a
  revocation. It now takes an optional `verifyStatusList`: a list it rejects,
  by returning anything but `true` or by throwing, resolves to revoked and not
  fresh, like any other unreadable list. `createStatusListProofVerifier({
  didResolver })` is a ready verifier for `DataIntegrityProof` /
  `eddsa-jcs-2022` lists. It finds the key that `proof.verificationMethod`
  names in the issuer's DID document, requires that method to belong to the
  list's `issuer`, and accepts relative method ids and `publicKeyJwk` or
  `publicKeyMultibase` keys. It verifies a status list published by
  builders.kya-os.org, signed by an independent implementation. Without
  `verifyStatusList` the checker behaves as before. The option becomes
  required in 2.0, and SPEC.md §6.10 states the requirement.
- **`createKyaOsTransport` is exported from `@kya-os/mcp`,** next to
  `createKyaOsMiddleware`, for servers on the low-level `Server` API, which
  now connect through it. It was only on `@kya-os/mcp/middleware`. Its
  `Transport` type declares the callbacks as methods, so an SDK 1 or SDK 2
  transport is accepted, and the wrapper connects to either SDK's server,
  without a cast.
- **`serveInProcess(kyaos)` calls wrapped handlers outside an MCP server.**
  `local.tool(name, handler)` answers as a server would, through a KYA-OS
  transport, so the result carries its proof; `local.close()` closes the
  transport. It replaces the examples' own helper.
- **`pendingProofTtlMs`** on `KyaOsConfig` and `WithKyaOsOptions`: how long a
  wrapper's result may wait to be sent before its proof is given up (default
  300000, five minutes; at most 2147483647, about 24.8 days, the longest timer
  a JavaScript runtime keeps). Memory stays bounded by the caps on waiting
  proofs.

### Changed

- **Envelope-profile proofs are made at the transport, over the result as it
  is sent.** On the 2026-07-28 revision, MCP SDK 2 adds `resultType:
  'complete'` to a tool result after the handler returns it. An
  envelope-profile proof made in the handler, by `proveOutcome`,
  `wrapWithProof` or either gate, did not cover that member, so the client's
  check of the result it received failed. Under the envelope profile these
  paths now leave the proof to the `withKyaOs` transport, or one built with
  `createKyaOsTransport`, which makes it in `send()`, after the SDK has
  finished the result. The proof covers exactly the result the client
  receives, on 2025-11-25 and on 2026-07-28, with SDK 1 or SDK 2. This
  supersedes the 1.19.0 advice to set `resultType: 'complete'` on a result
  before proving it under the envelope profile: that is no longer needed, and
  a result that sets it is proved as sent.
  - What a proof claims stays in the middleware. The result carries only a
    private one-time id, redeemed only on a result that also carries the
    middleware's stamp, and the session is read again when the proof is made,
    which takes its audience from it. A result naming no waiting proof, or
    one whose session is gone by then, goes out without a proof and with
    `_meta.proofError`, as does an outcome whose proof fails at send.
  - A waiting proof holds the request's hash, computed when the call was
    recorded, never the arguments, so a waiting proof is small however large
    they were, and later changes to the arguments cannot reach what is
    signed. Arguments that cannot be hashed fail the proof in the handler
    (`proofError`, `proof.rejected` with `PROOF_GENERATION_FAILED`).
  - The claims, `_meta` keys and audit events are the ones the handler-side
    proof had. For a result that is sent, the audit events are recorded in
    the same order as before: an allowed call's `tool.call.started` in the
    handler, then `proof.generated` and `tool.call.completed` at send.
  - A result the SDK never sends (a cancelled call, or an SDK 1 result
    replaced after an `outputSchema` check) is closed in the audit trail with
    `proof.rejected` under the new code `PROOF_NOT_SENT`. An allowed call
    then records `tool.call.failed` with the reason `RESULT_NOT_SENT`, never
    `tool.call.completed`, since its client did not get the result. An
    outcome's terminal events were recorded in the handler. This happens five
    minutes after the handler returned; when the last KYA-OS transport for
    the middleware closes; or, oldest first, when 10,000 proofs are waiting
    or they hold about 16 MB of audit context.
- **Body-profile proofs are made at the transport too, so neither profile
  signs in the handler.** The MCP SDK also changes `content` after the
  handler returns. SDK 2, on both revisions, appends a text item when
  `structuredContent` is not an object and `content` has none. Both SDKs fill
  in `content: []` when a handler leaves it out. A body-profile proof made in
  the handler did not cover the appended item, so it failed verification, and
  over a missing `content` it could not be made at all. The body profile now
  takes the same path as the envelope profile above: the claims stay in the
  middleware by request hash, and the transport makes the proof in `send()`
  over the result as sent, with the same claims, `_meta` keys and audit
  events, recorded in the same order. `_meta` keeps its place among the
  result's members. Where the SDK does not reshape the result, the output is
  byte-identical to 1.19.0. An outcome proof that fails now also says so in
  `_meta.proofError`, as an allowed call's already did.
- **A result is proved once, within the window.** A stamped result whose
  pending proof is no longer waiting, because its window passed, it was
  evicted, or it was already sent (a task result fetched again), goes out
  with `proofError`, and the audit trail records `proof.rejected` with the
  new code `PROOF_EXPIRED`, with the call's audit context when it is still
  known. That record of closed proofs is bounded too: 10,000 entries and
  about 4 MB, oldest first, holding no context over 16 KB.
- **`createKyaOsTransport`'s `exclude` adds to the protocol tools.** The
  third argument replaced the default `["_kyaos", "_kyaos_handshake"]`, so a
  caller passing its own list had the protocol tools' results proved. It now
  adds to them, as `excludeTools` does in `withKyaOs`; the protocol tools
  are always excluded.

### Security

- **SDK 2's per-tool OAuth scope challenges were bypassed under `withKyaOs`
  in earlier versions.** SDK 2's `McpServer.connect()` installs
  the `scopeChallenge` enforcement of `registerTool` only on a transport
  that has `setScopeChallengeResolver`, and the KYA-OS transport did not
  pass that member through. A tool registered with, for example,
  `scopeChallenge: requireScopes('payments:write')` therefore ran, and was
  even proved, for a token without that scope. The caller should have
  received a 403. This affected 1.19.0 and earlier:
  - `withKyaOs` with a server's own `WebStandardStreamableHTTPServerTransport`;
  - `createMcpHandler` serving a client that negotiates 2025-11-25.

  At 2026-07-28, `createMcpHandler` enforces the challenge at its entry, before
  the transport. The transport now passes the resolver through, and every
  other transport member either SDK feature-detects or reads is passed
  through too.
- **The private members could leave in a message that is not a result, and
  a copied stamp and id could make the transport sign chosen content.** The
  transport removed the lifecycle stamp and pending-proof id only from
  `result`. A tool that logged a wrapped result in a notification therefore
  sent both to the client. A tool that relays caller-controlled `_meta` into
  its own result could then redeem them, and the client got a server-signed
  proof over content of its choosing, verifying as the wrapped call's
  response. With envelope-profile proofs at the transport this was possible
  before this release; with the body profile there too, in this release
  before the fix. Now:
  - every outgoing message is cleaned at any depth: its `params`,
    `result` and `error.data`;
  - a waiting proof whose id is found anywhere other than its own result is
    closed, so nothing can redeem it;
  - on the answer to a `tools/call` the transport tracked, a pending proof
    left for a different tool is not redeemed. The answer goes out unproven,
    and the audit trail records `proof.rejected` with the new code
    `PROOF_TOOL_MISMATCH`.

### Fixed

- **The proof wrappers no longer change the result a handler returns.**
  `wrapWithProof` set its `_meta` members (the pending-proof id, the
  lifecycle stamp, `proofError`, the audit marker) on the handler's own
  object, and its audit-degraded path set `isError: true` on it. A handler
  that returned one object from every call, a module-level constant or a
  cached result, found those members on it, and a later call could go out
  with an earlier call's `isError` and audit marker; a frozen result made the
  wrapper throw. Every member now goes on a shallow copy of the result with a
  new `_meta`, in `wrapWithProof` and in the outcome path behind the gates
  and `proveOutcome`, and the handler's object and its `_meta` are never
  changed. What the client receives is otherwise the same. Closes #249.

- **The KYA-OS transport passes the SDK's request context through.** It
  dropped the second argument of `onmessage` and of `send`, and did not
  expose the inner transport's `sessionId`, `setProtocolVersion`,
  `setSupportedProtocolVersions` or `hasPerRequestStream`. Under `withKyaOs`,
  tools lost the request's `sessionId`, `authInfo` and `requestInfo` (SDK 1)
  and `ctx.http.authInfo` (SDK 2, both revisions); SDK 1 task stores stopped
  separating tasks by session; and notifications a tool sent during a call
  lost their `relatedRequestId`, so on Streamable HTTP they missed the
  request's stream. All of these now pass through unchanged. Closes #248.
- **The proof's scope is the call's, as the wrapper received it.**
  `wrapWithProof` read `context.scopeId` and the audit context after the
  handler ran, so a handler could change the scope a proof claims by changing
  the context object it was handed. They are now read before the handler
  runs.
- **Private members never reach the wire from a nested result.** A wrapped
  result a handler placed inside its own result, in `structuredContent` for
  example, carried the lifecycle stamp and the pending-proof id to the
  client. They are now removed at any depth: the walk is iterative, with no
  depth limit. A wrapped result serialized into a string, a text item for
  example, cannot be cleaned that way. Such a result is sent without a
  proof and with `proofError`, recorded as `proof.rejected` with the new
  code `PRIVATE_MEMBER_IN_RESULT`. Every waiting proof whose id appears in
  that string is closed, so it cannot be redeemed.

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
