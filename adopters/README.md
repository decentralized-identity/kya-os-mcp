# Adopter apps

These are small apps that use `@kya-os/mcp` the way adopters do: installed from the packed package, through its public exports only, combining its parts as real integrations combine them.
The library's own tests and examples import its source, so they cannot see a break that only shows once the package is installed and its parts are put together.

## Run

```sh
pnpm test:adopters
```

The runner builds the library, packs it with `npm pack` into a fresh temporary directory, and installs the tarball into a new project there, with TypeScript at the repository's version.
It type-checks and compiles the fixtures with the strict settings in `tsconfig.json`, runs each with plain `node`, prints a summary, and removes the directory.
It exits 1 when a fixture fails or has a type error.
`--keep` keeps the directory, `--no-build` packs the `dist/` already built, and naming fixtures runs only those, as in `pnpm test:adopters localhost-development`.
A run reads the npm registry for the project's install, and no other network.

## Fixtures

Each fixture in `fixtures/` issues everything it verifies with the library's public API, so it also shows that what the library issues, the library verifies.
`fixtures/shared/` holds what they share: keys and DID documents, credentials, status lists, an in-memory network, and the case runner.
A fixture prints `PASS <fixture>: <what it showed>`, or one `FAIL <fixture>: <case>: <why>` line for each case that failed, and then exits 1.

| Fixture | The integration it uses |
| --- | --- |
| `safe-fetch-provider` | A `FetchProvider` whose `fetch` returns what `createSafeFetch` returns, given to `createDidWebResolver`. |
| `wrapped-status-checker` | The adopter's own `StatusListResolver` around `createRevocationChecker`, passing on only the status entry. |
| `localhost-development` | did:web documents on `*.localhost` names, read with `development: true`, which production refuses. |
| `separate-status-signer` | A status list signed by a DID other than the credential's issuer, trusted through `statusListIssuers`. |
| `with-kya-os-defaults` | `withKyaOs` with its defaults, called in process through `serveInProcess`, under a pinned root. |
| `trusted-root-issuers` | `withKyaOs` with a tool gated on a delegation: `delegation.trustedRootIssuers`, `development: true` and `delegation.allowAnyRootIssuer: true`, and the refusal when none is set. |
| `proofs-before-status` | `evaluateDelegationChain` with `verifyHopProof`: signed chains pass, while an edited hop is refused before the status checker or fetch runs. |
| `proof-key-relationships` | A builder-generated did:web document still verifies detached proofs and projects CIMD keys; authentication-only keys cannot verify proofs, and assertion-only keys cannot authenticate clients. |
| `card-root-issuers` | `requireDelegation` from `@kya-os/mcp/card`: `trustedRootIssuers`, `development: true` and `allowAnyRootIssuer: true`, and the refusal when nothing pins the root. |
| `expired-status-list` | `requireDelegation` and `verifyCard` with `createRevocationChecker` and `createStatusListProofVerifier`: a signed list past its `validUntil` or before its `validFrom` is refused as `status_unavailable`, while one in its window, or stating no end, is read. |
| `card-revocation-checker` | `verifyCard` with and without a `statusListChecker` built from `createRevocationChecker`: a Card that declares a revocation entry is refused as `configuration_error` when no checker is given, and a Card that declares none needs no checker. |
| `window-dates` | `createRevocationChecker`, `CheqdStatusListResolver` and `requireDelegation` over `RuntimeFetchProvider` and SafeFetch: a list or hop bound with no time zone, or not RFC 3339, is refused alike under `TZ=UTC` and `TZ=America/Chicago`, and one a few seconds outside its window is read within the clock tolerance. |
| `checkpoint-conflicts` | An on-demand checkpoint endpoint over `AuditRecorderService` and `AuditCheckpointBuilder`, with two signer processes sharing one checkpoint store: it answers success for a lost race and failure for a forked journal, told apart by `isLostCheckpointRace`. |
| `status-entry-owners` | `DelegationGraphManager` built with `statusEntryOwners`, over entries from `allocateStatusEntry(purpose, { delegationId })`, and `CascadingRevocationManager`: a re-delegation carrying another's entry is refused, a pre-upgrade row with one is revoked in the graph alone through a caught `StatusEntryUnchangedError`, and a removed delegation's entry stays retired, while one removed as revoked keeps its id revoked. |
| `status-list-replicas` | Two issuing replicas, each with its own `StatusList2021Manager`, over the adopter's own status-list table that implements `ConditionalStatusListStorageProvider` with etags from a sequence that never resets: revocations made at the same moment all reach the published list after at least one refused write, a write refused every time throws an error `isStatusListWriteConflict` knows, and the same table without the conditional write loses one and warns once. |
| `request-proof-binding` | `withKyaOs` with `delegation.holderBinding: 'enforce'` and a client that signs with `generateRequestProof` from the arguments it sends: the proof names the delegation among them, so another delegation of the agent put in its place is refused with no further setting; the `delegation` input names one attached after signing; a proof that names none, as an earlier client makes it, runs under the default and is refused under `delegation.requestBinding: 'require'`. |

A case whose name starts with `control:` checks the setup the other cases rely on, so a failure beside a passing control is the library's, not the fixture's.

## Released verifiers

```sh
pnpm test:released-verifiers
```

A request proof states the delegation its call presents in its JWS protected header (SPEC.md §7.8), and a server that has not upgraded must go on verifying the proofs an upgraded client signs.
This measures that against the verifiers themselves.
It builds and packs the library, installs the tarball and each released version into projects of their own in a fresh temporary directory, makes session request proofs and card proofs with this version, and has every installed version verify four of each: one made without the statement, as the control, one as the generator signs it, and that one with its statement swapped for another digest and stripped after signing.
A verifier must give the proof as signed the verdict it gives the control, and refuse a statement changed after signing, since the header is part of what is signed.
It prints one table for each kind of proof and exits 1 when a verdict is not the expected one.
With no version named it measures 1.11.0, 1.16.0, 1.22.0 and 1.25.0; name others to measure those, as in `pnpm test:released-verifiers 1.23.0 1.24.0`.
`--keep` and `--no-build` are as above.
The control for a card proof is signed by a signer that leaves the statement out, so the run prints the warning such a signer gets.

A run installs published versions from the npm registry, so it is a measurement to run by hand before a release that changes what a proof carries, and is no part of `pnpm test` or of CI.
`UPGRADING.md` records the results for the release that added the statement.

## Adding a fixture

Add one `.ts` file to `fixtures/`, import only from `@kya-os/mcp` and its public entry points, and end it with `runCases` from `shared/cases.ts`.
A package a fixture needs beside the library goes in `runner/project.mjs`, at the version the repository installs.
