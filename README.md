<p align="center">
  <a href="https://modelcontextprotocol-identity.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://modelcontextprotocol-identity.io/images/logo-mark_white.svg">
      <img alt="" src="https://modelcontextprotocol-identity.io/images/logo-mark_black.svg" width="64">
    </picture>
  </a>
</p>

<p align="center">
  <strong>Identity, delegation, and proof for the Model Context Protocol.</strong>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@kya-os/mcp"><img src="https://img.shields.io/npm/v/@kya-os/mcp" alt="npm"></a>
  <a href="https://modelcontextprotocol-identity.io"><img src="https://img.shields.io/badge/spec-modelcontextprotocol--identity.io-blue" alt="spec"></a>
  <a href="https://identity.foundation/working-groups/agent-and-authorization.html"><img src="https://img.shields.io/badge/DIF-TAAWG-purple" alt="DIF TAAWG"></a>
  <a href="./LICENSE"><img src="https://img.shields.io/github/license/modelcontextprotocol-identity/mcp-i-core" alt="license"></a>
</p>

<p align="center">
  <em><code>@kya-os/mcp</code> is the reference implementation of the <strong>KYA-OS</strong> (Know Your Agent Operating System) protocol for Model Context Protocol servers — binding KYA-OS's identity, delegation, and proof primitives into MCP. KYA-OS is the agent identity, authorization, and observability protocol.</em>
</p>

---

AI agents call tools on your behalf. But today, there's no way to know *who* called, *whether they were allowed to*, or *what actually happened*. `@kya-os/mcp` fixes that for Model Context Protocol servers.

- **Every server gets a cryptographic identity** (DID) — no accounts, no API keys, no central registry
- **Every tool call gets a signed proof** — a tamper-evident receipt the agent can't forge or deny
- **Protected tools require human consent** — per-tool authorization via W3C Delegation Credentials
- **The AI never knows** — identity, proofs, and consent happen transparently in the protocol layer

```
npm install @kya-os/mcp
```

---

## Migrate Any MCP Server in 2 Lines

**Before** — a standard MCP server with no identity or proofs:

```typescript
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

const server = new McpServer({ name: 'my-server', version: '1.0.0' });

server.registerTool('greet', { description: 'Say hello' }, async (args) => ({
  content: [{ type: 'text', text: `Hello, ${args.name}!` }],
}));
```

**After** — every tool response now carries a signed cryptographic proof:

```typescript
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { withMCPI, NodeCryptoProvider } from '@kya-os/mcp';  // +1 line

const server = new McpServer({ name: 'my-server', version: '1.0.0' });
await withMCPI(server, { crypto: new NodeCryptoProvider() }); // +1 line

server.registerTool('greet', { description: 'Say hello' }, async (args) => ({
  content: [{ type: 'text', text: `Hello, ${args.name}!` }],
}));
```

That's it. `withMCPI` auto-generates an Ed25519 identity, registers the `_mcpi` protocol tool, and wraps the transport so every tool response includes a detached JWS proof in `_meta` — invisible to the LLM, verifiable by anyone.

> See the full working example: [examples/context7-with-mcpi](./examples/context7-with-mcpi/) — a real MCP server (Context7) migrated with exactly 2 lines of code.

---

## Protect Tools with Human Consent

Some tools shouldn't run without a human saying "yes." KYA-OS MCP adds per-tool authorization using W3C Verifiable Credentials:

```typescript
const checkout = mcpi.wrapWithDelegation(
  'checkout',
  { scopeId: 'cart:write', consentUrl: 'https://example.com/consent' },
  mcpi.wrapWithProof('checkout', async (args) => ({
    content: [{ type: 'text', text: `Order placed: ${args.item}` }],
  })),
);
```

When an agent calls `checkout` without a delegation credential, it gets back a `needs_authorization` response with a consent URL. The human approves, a scoped credential is issued, and the agent retries — now authorized.

> Try it yourself: [examples/consent-basic](./examples/consent-basic/) walks through the full consent flow end-to-end.

---

## See It in Action

```bash
git clone https://github.com/modelcontextprotocol-identity/mcp-i-core.git
cd mcp-i-core && npm install
bash scripts/demo.sh
```

This starts all example servers and opens [MCP Inspector](https://github.com/modelcontextprotocol/inspector). Connect to any server, call a tool, and inspect the proof in `_meta`:

| Port | Example | What it demonstrates |
|------|---------|---------------------|
| 3001 | [node-server](./examples/node-server/) | Proofs + restricted tools (low-level API) |
| 3002 | [consent-basic](./examples/consent-basic/) | Human consent flow with built-in UI |
| 3003 | [consent-full](./examples/consent-full/) | Production consent UI ([@kya-os/consent](https://www.npmjs.com/package/@kya-os/consent)) |
| 3004 | [context7-with-mcpi](./examples/context7-with-mcpi/) | 2-line migration of a real MCP server |

Also available: [outbound-delegation](./examples/outbound-delegation/) (gateway pattern), [verify-proof](./examples/verify-proof/) (standalone verification), [statuslist](./examples/statuslist/) (revocation lifecycle).

---

## What's Under the Hood

| Capability | How it works |
|-----------|-------------|
| **Cryptographic identity** | Ed25519 key pairs, `did:key` and `did:web` resolution |
| **Signed proofs** | Detached JWS over JCS-canonicalized request/response hashes |
| **Delegation credentials** | W3C Verifiable Credentials with scope constraints |
| **Revocation** | StatusList2021 bitstring with cascading revocation |
| **Replay prevention** | Nonce-based handshake with timestamp skew validation |
| **Extensible** | Bring your own KMS, HSM, nonce cache (Redis, DynamoDB, KV), or DID method |

---

## Links

- [Spec](https://modelcontextprotocol-identity.io) | [DIF TAAWG](https://identity.foundation/working-groups/agent-and-authorization.html) | [npm](https://www.npmjs.com/package/@kya-os/mcp)
- [CONTRIBUTING.md](./CONTRIBUTING.md) | [CONFORMANCE.md](./CONFORMANCE.md) | [SECURITY.md](./SECURITY.md) | [GOVERNANCE.md](./GOVERNANCE.md)

## License

MIT
