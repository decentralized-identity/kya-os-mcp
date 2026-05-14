# Contributing to @kya-os/mcp

Thank you for your interest in contributing to `@kya-os/mcp` — the reference implementation of MCP-I, the identity surface of KYA-OS (Know Your Agent Operating System), submitted to the [DIF Trust and Authorization for AI Agents Working Group (TAAWG)](https://identity.foundation/working-groups/agent-and-authorization.html). KYA-OS is the umbrella protocol for agent identity, authorization, and observability; MCP-I binds those primitives to Model Context Protocol servers.

All contributions are welcome: bug fixes, protocol clarifications, new examples, test improvements, and documentation.

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
git clone https://github.com/modelcontextprotocol-identity/mcp-i-core.git
cd mcp-i-core
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
- No thrown errors in resolvers — return null on failure, log at debug level
- Run npm run lint before pushing

---

## Pull Request Process

1. Fork and create a branch from main
2. Make changes with DCO-signed commits (git commit -s)
3. Ensure all tests pass: npm test
4. Note relevant SPEC.md sections if your change affects the protocol
5. Update CHANGELOG.md under [Unreleased]
6. Open a PR against main and fill out the PR template

---

## Spec Changes

Protocol changes should be discussed in DIF TAAWG before implementation. Open an issue first.

---

## Reporting Security Issues

Do NOT open public GitHub issues for security vulnerabilities. See SECURITY.md.

---

## Code of Conduct

This project follows the Contributor Covenant Code of Conduct. See CODE_OF_CONDUCT.md.
