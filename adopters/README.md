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
| `card-root-issuers` | `requireDelegation` from `@kya-os/mcp/card`: `trustedRootIssuers`, `development: true` and `allowAnyRootIssuer: true`, and the refusal when nothing pins the root. |

A case whose name starts with `control:` checks the setup the other cases rely on, so a failure beside a passing control is the library's, not the fixture's.

## Adding a fixture

Add one `.ts` file to `fixtures/`, import only from `@kya-os/mcp` and its public entry points, and end it with `runCases` from `shared/cases.ts`.
A package a fixture needs beside the library goes in `runner/project.mjs`, at the version the repository installs.
