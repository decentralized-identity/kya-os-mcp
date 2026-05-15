# `@kya-os/mcp` Example Server

A minimal MCP server demonstrating cryptographic identity, proof generation, and tool protection.

## Quick Start

From the **repository root** (`kya-os-mcp/`):

```bash
# Install dependencies
pnpm install

# Start the server (SSE on port 3001)
npx tsx examples/node-server/server.ts
```

Then open **MCP Inspector** and connect:
- **Transport Type:** SSE
- **URL:** `http://localhost:3001/sse`

## Demo Walkthrough

Once connected in the Inspector, go to **Tools** and try the following:

### Call `greet` (open tool with proof)

Call `greet` with:

```json
{
  "name": "DIF"
}
```

The response includes:
- **Tool result:** `Hello, DIF!`
- **`_meta.proof`** — a detached Ed25519 proof containing:
  - `jws` — compact JWS signature over the canonical payload
  - `meta.did` — agent DID that signed it
  - `meta.kid` — key identifier
  - `meta.requestHash` / `meta.responseHash` — SHA-256 hashes of the canonical request/response
  - `meta.sessionId` — session binding
  - `meta.nonce` — replay protection
  - `meta.ts` — signature timestamp

> Sessions are created automatically — no manual handshake step needed.
> In production, MCP-I-aware clients handle the handshake transparently.

### Call `restricted_greet` (protected tool)

Call `restricted_greet` with:

```json
{
  "name": "Agent"
}
```

The server returns an `MCPI_NEEDS_AUTHORIZATION` error with:
- `scopeId` — the required delegation scope (`greeting:restricted`)
- `consentUrl` — where the user approves the delegation
- `architecture` — a 5-step explanation of the consent/delegation flow

This demonstrates how protected tools work in production:
1. Agent calls restricted tool
2. Server returns `MCPI_NEEDS_AUTHORIZATION` with consent URL
3. User approves delegation at the consent URL
4. A Verifiable Credential (delegation) is issued
5. Agent presents the delegation credential on the next call

## Alternative: Stdio Transport

For use with `npx @modelcontextprotocol/inspector` auto-connect:

```bash
npx @modelcontextprotocol/inspector npx tsx examples/node-server/server.ts --stdio
```

Or run the server directly on stdio:

```bash
npx tsx examples/node-server/server.ts --stdio
```

## Verifying Proofs

Copy the proof JSON from the `_meta` response and verify it:

```bash
echo '<proof-json>' | npx tsx examples/verify-proof/verify.ts
```

## Architecture

```
Client (Inspector)          Server (this example)
      |                            |
      |-- greet ------------------>|  Auto-session created (or reused)
      |                            |  Tool executes
      |                            |  ProofGenerator signs (request, response, session)
      |<-- result + _meta.proof ---|  Detached JWS over canonical payload
      |                            |
      |-- restricted_greet ------->|  Tool protection check
      |<-- NEEDS_AUTHORIZATION ----|  Returns scopeId + consentUrl + architecture
      |                            |
```

## Tools

| Tool | Description |
|------|-------------|
| `greet` | Returns a greeting with a detached Ed25519 proof via `_meta` |
| `restricted_greet` | Protected tool — returns `MCPI_NEEDS_AUTHORIZATION` with delegation instructions |
