# consent-basic

Human-in-the-loop consent flow for `@kya-os/mcp`. An AI agent calls a protected tool, the human approves via a consent page, and the agent retries with a signed delegation credential.

```
Agent calls checkout → needs_authorization → Human approves → Agent retries with VC → Tool executes
```

## Quick Start

```bash
# 1. Generate a persistent identity (optional — ephemeral if skipped)
npm run generate-identity

# 2. Start the server (MCP + consent server, shared identity)
npm start

# 3. Connect via MCP Inspector
npx @modelcontextprotocol/inspector
# → Connect to http://localhost:3002/sse
```

## What's Inside

| File | Purpose |
|------|---------|
| `src/server.ts` | MCP server with `browse` (public) and `checkout` (protected) tools |
| `src/consent-server.ts` | HTTP consent page + VC issuance endpoint |
| `src/delegation-issuer.ts` | Shared factory for creating a `DelegationCredentialIssuer` from identity config |
| `scripts/generate-identity.ts` | Persist a DID to `.mcpi/identity.json` so it survives restarts |
| `public/consent.html` | Consent UI served during the authorization flow |

## Testing the Consent Flow

1. **Call `browse`** with `{ "category": "electronics" }` — works immediately, proof attached
2. **Call `checkout`** with `{ "item": "laptop" }` — returns `needs_authorization` with a consent link
3. **Open the consent URL** in your browser and click **Approve**
4. **Retry `checkout`** with the same arguments — the delegation is applied automatically
5. Order confirmed — proof attached to response

## Spec Coverage

| Section | What's demonstrated |
|---------|-------------------|
| §4 Delegation | W3C VC issuance, scope constraints, expiry |
| §5 Proof | Detached JWS proof on every tool response |
| §6 Authorization | `needs_authorization` → consent → delegation verification |

## Persistent Identity

This example generates ephemeral keys by default. To persist across restarts:

```bash
npm run generate-identity
```

This writes a `did:key` identity to `.mcpi/identity.json`. The server loads it automatically on startup.
