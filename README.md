<p align="center">
  <a href="https://kya-os.ai">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://kya-os.ai/mcp/images/logo-mark_white.svg">
      <img alt="" src="https://kya-os.ai/mcp/images/logo-mark_black.svg" width="64">
    </picture>
  </a>
</p>

<p align="center">
  <strong>KYA-OS: agent identity, delegation, and proof. This repo is the MCP binding.</strong>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@kya-os/mcp"><img src="https://img.shields.io/npm/v/@kya-os/mcp" alt="npm"></a>
  <a href="https://kya-os.ai/mcp"><img src="https://img.shields.io/badge/spec-KYA--OS-blue" alt="spec"></a>
  <a href="https://identity.foundation/working-groups/agent-and-authorization.html"><img src="https://img.shields.io/badge/DIF-TAAWG-purple" alt="DIF TAAWG"></a>
  <a href="./LICENSE"><img src="https://img.shields.io/github/license/decentralized-identity/kya-os-mcp" alt="license"></a>
</p>

---

## What KYA-OS is

**KYA-OS** (Know Your Agent Operating System) is an identity, authority, and accountability layer that other agent-facing protocols adopt, so that any time an agent acts you can verify *who* called (agent identity), *under what authority* (delegation chain rooted at a Responsible Party, plus consent where required), and *what they did* (signed proofs composing into audit trails).

The shape of the contribution is roughly analogous to TLS. TLS is not a transport, it is a security layer that transports adopt. KYA-OS is not a transport or a runtime, it is an identity and accountability layer that host protocols embed.

Three jobs, six primitives:

- **Identity.** Every agent and every server holds a Decentralized Identifier (`did:key`, `did:web`): a stable, cryptographically-controlled identifier that the agent can prove it owns, and that credentials can be issued against. Without this, there is nothing to bind authority to or hold accountable.
- **Authority.** W3C Verifiable Credentials carrying scoped, revocable delegation chains rooted at a Responsible Party. Per-tool consent gating for actions that require explicit human approval.
- **Accountability.** Detached JWS proofs over canonicalized request/response hashes, composing into tamper-evident audit trails. Invisible to the LLM, verifiable by anyone holding the agent's DID.

> **Note on the name.** This protocol was previously known as **MCP-Identity** / **MCP-I**. The rename to KYA-OS reflects the protocol's binding-agnostic scope. See the [`[Unreleased]` entry in `CHANGELOG.md`](./CHANGELOG.md#unreleased) for the full rationale.

## What this repo is

`@kya-os/mcp` is the **MCP binding** of KYA-OS, the reference implementation for [Model Context Protocol](https://modelcontextprotocol.io) servers, and the first binding to ship.

KYA-OS primitives are intended to embed in three kinds of host surface:

1. **Transport bindings.** Wire protocols an agent's calls ride over (e.g. MCP, HTTPS, gRPC, SMTP).
2. **Runtime bindings.** Agent harnesses where the loop runs and tool invocations can be wrapped uniformly.
3. **Manifest / assertion embeddings.** Host formats that already carry signed assertions, where a KYA-OS proof can serve as one assertion type (e.g. C2PA-track content provenance manifests).

The MCP binding ships first because MCP is the most concentrated agent-to-tool RPC surface today. Additional bindings will be specified in the working group as they reach consensus.

The KYA-OS protocol itself is defined in [`SPEC.md`](./SPEC.md). Binding-specific behavior is called out so future bindings can diverge cleanly where they need to.

```
npm install @kya-os/mcp
```

---

## Migrate any MCP server in 2 lines

**Before**, a standard MCP server with no identity or proofs:

```typescript
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

const server = new McpServer({ name: 'my-server', version: '1.0.0' });

server.registerTool('greet', { description: 'Say hello' }, async (args) => ({
  content: [{ type: 'text', text: `Hello, ${args.name}!` }],
}));
```

**After**, every tool response now carries a signed cryptographic proof:

```typescript
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { withKyaOs, NodeCryptoProvider } from '@kya-os/mcp';  // +1 line

const server = new McpServer({ name: 'my-server', version: '1.0.0' });
await withKyaOs(server, { crypto: new NodeCryptoProvider() }); // +1 line

server.registerTool('greet', { description: 'Say hello' }, async (args) => ({
  content: [{ type: 'text', text: `Hello, ${args.name}!` }],
}));
```

That's it. `withKyaOs` auto-generates an Ed25519 identity, registers the `_kyaos` protocol tool, and wraps the transport so every tool response includes a detached JWS proof in `_meta`. Invisible to the LLM, verifiable by anyone.

> See the full working example: [examples/context7-with-kya-os](./examples/context7-with-kya-os/), a real MCP server (Context7) migrated with exactly 2 lines of code.

---

## Protect tools with human consent

Some tools shouldn't run without a human saying "yes." KYA-OS adds per-tool authorization using W3C Verifiable Credentials:

```typescript
const checkout = kyaos.wrapWithDelegation(
  'checkout',
  { scopeId: 'cart:write', consentUrl: 'https://example.com/consent' },
  kyaos.wrapWithProof('checkout', async (args) => ({
    content: [{ type: 'text', text: `Order placed: ${args.item}` }],
  })),
);
```

When an agent calls `checkout` without a delegation credential, it gets back a `needs_authorization` response with a consent URL. The human approves, a scoped credential is issued, and the agent retries, now authorized.

> Try it yourself: [examples/consent-basic](./examples/consent-basic/) walks through the full consent flow end-to-end.

---

## See it in action

```bash
git clone https://github.com/decentralized-identity/kya-os-mcp.git
cd kya-os-mcp && npm install
bash scripts/demo.sh
```

This starts all example servers and opens [MCP Inspector](https://github.com/modelcontextprotocol/inspector). Connect to any server, call a tool, and inspect the proof in `_meta`:

| Port | Example | What it demonstrates |
|------|---------|---------------------|
| 3001 | [node-server](./examples/node-server/) | Proofs + restricted tools (low-level API) |
| 3002 | [consent-basic](./examples/consent-basic/) | Human consent flow with built-in UI |
| 3003 | [consent-full](./examples/consent-full/) | Production consent UI ([@kya-os/consent](https://www.npmjs.com/package/@kya-os/consent)) |
| 3004 | [context7-with-kya-os](./examples/context7-with-kya-os/) | 2-line migration of a real MCP server |

Also available: [outbound-delegation](./examples/outbound-delegation/) (gateway pattern), [verify-proof](./examples/verify-proof/) (standalone verification), [statuslist](./examples/statuslist/) (revocation lifecycle).

---

## What's under the hood

| Capability | How it works |
|-----------|-------------|
| **Cryptographic identity** | Ed25519 key pairs, `did:key` and `did:web` resolution |
| **Signed proofs** | Detached JWS over JCS-canonicalized request/response hashes |
| **Delegation credentials** | W3C Verifiable Credentials with scope constraints, rooted at a Responsible Party |
| **Revocation** | StatusList2021 bitstring with cascading revocation |
| **Replay prevention** | Nonce-based handshake with timestamp skew validation |
| **Extensible** | Bring your own KMS, HSM, nonce cache (Redis, DynamoDB, KV), or DID method |

### Multi-instance deployments

The in-memory defaults are **single-process only**. For a load-balanced /
multi-instance deployment, inject a durable Redis / Durable Object / DB-backed
implementation for **every** runtime-state seam — the nonce cache
(`NonceCacheProvider`) together with the consent stores (`GrantStore`,
`PendingFlowStore`, `SessionStore`) — so replay protection, grants, pending OAuth
flows, and sessions are shared across instances and survive restarts.

---

## Links

- [Spec](./SPEC.md) | [Changelog](./CHANGELOG.md) | [DIF TAAWG](https://identity.foundation/working-groups/agent-and-authorization.html) | [npm](https://www.npmjs.com/package/@kya-os/mcp)
- [CONTRIBUTING.md](./CONTRIBUTING.md) | [CONFORMANCE.md](./CONFORMANCE.md) | [SECURITY.md](./SECURITY.md) | [GOVERNANCE.md](./GOVERNANCE.md)

## License

MIT
