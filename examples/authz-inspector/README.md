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

The two transports differ in one meaningful way — **whether the authorize URL
is a real page you can open**:

### Over HTTP — a real, clickable authorization flow

The HTTP entrypoint co-hosts a genuine OAuth 2.1 + PKCE authorization server, so
the authorize URL is a live page. Once Inspector is open (connected to
`http://localhost:3030/mcp`):

1. **List tools** → you'll see `read_vault`.
2. **Call `read_vault`** with no arguments → the challenge comes back with a real
   `http://localhost:3030/authorize?...` URL (mandatory `S256` PKCE, RFC 8707
   `resource`), the scopes, and a `resume_token`.
3. **Open that authorize URL in your browser** → a consent page → click
   **Approve**. It redirects to `/callback?code=...&state=demo-state`, which
   shows the **authorization code**.
4. **Re-call `read_vault`** with `authorization_code` = the code from step 3,
   `resume_token` = step 2's value, `state` = `demo-state`. The server runs the
   PKCE code exchange against its own `/token` endpoint → the vault reads.

### Over stdio — the same flow, deterministic (no page to visit)

stdio uses the in-memory provider (there is no HTTP server to host a page), so
step 3 is skipped: the challenge shows the real OAuth request shape, and you use
the fixed code `demo-auth-code` directly in step 4. Same `read_vault` tool, same
`needs_authorization` challenge — only the provider differs.

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
