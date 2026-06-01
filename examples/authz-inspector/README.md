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

```bash
# From the repo root
pnpm install
npm run example:authz-inspector
```

That launches [MCP Inspector](https://github.com/modelcontextprotocol/inspector)
against the demo server over stdio. Then, in Inspector:

1. **List tools** — you'll see `read_vault`.
2. **Call `read_vault`** with no arguments — the response is the
   `needs_authorization` challenge: an authorize URL (with mandatory `S256`
   PKCE), the requested scopes, and a `resume_token`.
3. **Re-call `read_vault`** with:
   - `resume_token`: the value from step 2
   - `state`: `demo-state`
   - `authorization_code`: `demo-auth-code`  *(what the in-memory provider accepts)*
4. The tool returns the vault contents — authorization verified.

## Run the server directly (without Inspector)

```bash
npx tsx examples/authz-inspector/src/stdio.ts
```

## Run over the modern Streamable HTTP `/mcp` transport

The demo also serves the modern MCP transport, so it works the same way in a
deployed `/mcp` setup as it does over stdio:

```bash
# From the repo root
npm run example:authz-inspector:http
# → serves http://localhost:3030/mcp
```

Point MCP Inspector (or any Streamable-HTTP MCP client) at
`http://localhost:3030/mcp`. The same `read_vault` tool and the same
`needs_authorization` challenge flow apply — only the transport differs. Both
transports are exercised by the test suite (`__tests__/http-transport.test.ts`
drives the server through the SDK's Streamable HTTP client).

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
