# Contributing to @kya-os/mcp

Thank you for your interest in contributing to `@kya-os/mcp` — the reference implementation of the KYA-OS (Know Your Agent Operating System) protocol for Model Context Protocol servers, submitted to the [DIF Trusted AI Agents Working Group (TAAWG)](https://identity.foundation/working-groups/trusted-agents.html). KYA-OS is the agent identity, authorization, and observability protocol; this package binds its primitives into MCP.

All contributions are welcome: bug fixes, protocol clarifications, new examples, test improvements, and documentation.

---

## DIF Membership

Contributing to this repository requires [**DIF Membership**](https://identity.foundation/join). DIF (the Decentralized Identity Foundation) is the standards body where the KYA-OS protocol is being developed and ratified; membership is the licensing-and-IPR vehicle that lets your contributions land in a DIF-owned spec without ambiguity. Please join at <https://identity.foundation/join> before opening a pull request.

---

## Developer Certificate of Origin (DCO)

**Every commit must include a sign-off trailer:**

```
Signed-off-by: Your Name <your@email.com>
```

Add this automatically with:

```bash
git commit -s -m "your commit message"
```

Commits without a DCO sign-off will not be merged.

---

## Getting Started

```bash
git clone https://github.com/decentralized-identity/kya-os-mcp.git
cd kya-os-mcp
npm install
npm test
npx tsx examples/node-server/server.ts
npx tsx examples/outbound-delegation/demo.ts
```

---

## Branch Naming

| Prefix | Use                                 |
| ------ | ----------------------------------- |
| feat/  | New features or protocol extensions |
| fix/   | Bug fixes                           |
| docs/  | Documentation only                  |
| test/  | Test additions or improvements      |
| chore/ | Tooling, CI, dependency updates     |

---

## Code Style

- TypeScript strict mode — no any types
- No console.log — use the logger from src/logging/index.ts
- .js extension on all imports (ESM)
- DID-METHOD resolvers (`DIDResolver` impls — e.g. `src/delegation/did-web-resolver.ts`) return null on failure and log at debug level: a failed method must degrade gracefully so another resolver can be tried
- The card resolve/verify surface (`src/card/resolve.ts` — `resolveCard`) is the EXCEPTION: it fails CLOSED, throwing a reasoned `Error` on any failure. A silently-null card risks a fail-OPEN integrator that reads "no card = allow"; a loud throw forces explicit handling. See `resolveCard`'s docstring for the throw contract
- Run npm run lint before pushing

---

## Pull Request Process

1. Fork and create a branch from main
2. Make changes with DCO-signed commits (git commit -s)
3. Ensure all tests pass: npm test
4. Note relevant SPEC.md sections if your change affects the protocol
5. Add a changelog entry if your change affects the package (see Changelog below)
6. Open a PR against main and fill out the PR template

---

## Changelog

CHANGELOG.md is generated from the files in `.changes/`, so do not edit it directly.
A pull request that changes the package (`src/` outside tests, or `schemas/`) adds an entry:

```
npm run changie -- new
```

Pick the kind, then write the entry as it should read in CHANGELOG.md: a bold lead sentence saying what changed for a user, then what was wrong or what is new, and what to do about it.
Wrap lines at about 76 columns; continuation lines are indented for you.
The entry lands in `.changes/unreleased/` as a small YAML file, which you can also write or edit by hand.

| Kind | For | Version bump |
| --- | --- | --- |
| Upgrading | Steps a user must take when they upgrade | minor |
| Added | New features and exports | minor |
| Changed | Changes to existing behavior | minor |
| Deprecated | Features scheduled for removal | minor |
| Removed | Features removed | major |
| Security | Fixes to a security weakness | patch |
| Fixed | Bug fixes | patch |
| Spec | Normative changes to SPEC.md or another SPEC-*.md | minor |
| Documentation | Other documentation a user relies on, such as guides and examples | patch |

A change with no effect a user can see, such as a refactor, takes the `no-changelog` label instead.
CI checks both rules, and that CHANGELOG.md matches `.changes/`.

### Releasing

1. On a `chore/release-X.Y.Z` branch, run `npm run changie -- batch auto` (or `batch X.Y.Z` to choose the version), then `npm run changie -- merge`.
   `batch` moves the unreleased entries into `.changes/X.Y.Z.md`, and `merge` regenerates CHANGELOG.md and sets the version in `package.json` and `package-lock.json`.
2. Commit the result as `chore(release): X.Y.Z` with `git commit -s` and open a PR.
3. After it merges, tag `vX.Y.Z` on the merge commit, run `npm publish` from the tag, and create the GitHub release: `gh release create vX.Y.Z --title vX.Y.Z --notes-file <(tail -n +3 .changes/X.Y.Z.md)`.

---

## Spec Changes

Protocol changes should be discussed in DIF TAAWG before implementation. Open an issue first.

---

## Reporting Security Issues

Do NOT open public GitHub issues for security vulnerabilities. See SECURITY.md.

