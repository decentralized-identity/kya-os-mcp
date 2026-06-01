# authz-inspector

An MCP Inspector–ready demo of the `@kya-os/mcp/authz` authorization-server
seam. One protected tool, `read_vault`, is gated by the OAuth adapter: calling
it unauthorized returns a `needs_authorization` challenge (authorize URL,
scopes, resume token); supplying the returned authorization code completes the
flow and the tool runs.

The authorization logic is the tested seam — `GenericOidcAdapter` +
`AuthorizationServerRegistry` from `@kya-os/mcp/authz`. This example is only the
thin MCP shell over it. The token exchange is backed by an in-memory provider,
so the demo is **deterministic and runs with no external identity provider or
network**.

## Run it with MCP Inspector

Each command below is **a single command** — it starts the demo server *and*
opens [MCP Inspector](https://github.com/modelcontextprotocol/inspector)
connected to it. You do not need a server running first.

**Over stdio** (Inspector launches the server as a child process):

```bash
# From the repo root
pnpm install
npm run example:authz-inspector
```

**Over the modern Streamable HTTP `/mcp` transport** (starts the `/mcp` server
on `http://localhost:3030/mcp`, waits for it to be ready, then opens Inspector
already pointed at it):

```bash
# From the repo root
npm run example:authz-inspector:http
```

Either way, once Inspector is open:

1. **List tools** — you'll see `read_vault`.
2. **Call `read_vault`** with no arguments — the response is the
   `needs_authorization` challenge: an authorize URL (with mandatory `S256`
   PKCE), the requested scopes, and a `resume_token`.
3. **Re-call `read_vault`** with:
   - `resume_token`: the value from step 2
   - `state`: `demo-state`
   - `authorization_code`: `demo-auth-code`  *(what the in-memory provider accepts)*
4. The tool returns the vault contents — authorization verified.

The `read_vault` tool and the `needs_authorization` flow are identical across
both transports — only the wire differs.

## Run a server only (no Inspector)

If you want just the server — for example to point your own MCP client at it:

```bash
# stdio
npm run example:authz-inspector:stdio:server   # equivalently: npx tsx examples/authz-inspector/src/stdio.ts

# Streamable HTTP — serves http://localhost:3030/mcp
npm run example:authz-inspector:http:server
```

Both transports are exercised by the test suite — `__tests__/server.test.ts`
(stdio, via an in-memory client) and `__tests__/http-transport.test.ts` (the
`/mcp` transport, via the SDK's Streamable HTTP client).

## How it maps to the seam

| Step | Seam element |
|------|--------------|
| Tool is protected | `ToolProtection` with an `oauth` `AuthorizationRequirement` |
| Resolve the adapter for the tool | `AuthorizationServerRegistry.resolve()` |
| Produce the challenge | `GenericOidcAdapter.initiateFlow()` → `needs_authorization` |
| Verify the returned code | `GenericOidcAdapter.verifyAuthorization()` → `VerifyDelegationResult` |

A live identity provider plugs in by swapping the adapter's injected `fetchImpl`
for a real token endpoint — the server shell does not change. Vendor adapters
bind the same `AuthorizationServerAdapter` port downstream.

## Tests

```bash
cd examples/authz-inspector && npm test
```

Drives the server over an in-memory MCP client transport (the same protocol
Inspector speaks) and asserts the challenge, the authorized read, and
fail-closed behavior on a state mismatch.
