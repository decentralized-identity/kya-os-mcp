# consent-full

Same `@kya-os/mcp` consent flow as [consent-basic](../consent-basic/) — but the consent page is rendered by [`@kya-os/consent`](https://www.npmjs.com/package/@kya-os/consent). One `generateConsentShell()` call replaces 200+ lines of hand-rolled HTML with a production-grade consent UI: multi-mode auth, configurable branding, loading skeleton, and no-JS fallback.

## Quick Start

```bash
# From the repo root
pnpm install
npx tsx examples/consent-full/src/server.ts
```

Then connect with [MCP Inspector](https://github.com/modelcontextprotocol/inspector):

```bash
npx @modelcontextprotocol/inspector
# → Connect to http://localhost:3002/sse
```

1. Call `checkout` — get a consent link
2. Open the link — see the `<mcp-consent>` UI
3. Approve — delegation issued, stored via resume_token
4. Retry `checkout` — delegation auto-applied, tool executes

## Architecture

This example runs **two servers**:

| Server | Port | Purpose |
|--------|------|---------|
| MCP server (`server.ts`) | 3002 | Hosts tools, verifies delegations, attaches proofs |
| Consent server (`consent-server.ts`) | 3001 | Renders consent UI via `@kya-os/consent`, issues VCs |

**`consent-server.ts` is the showcase** — it demonstrates `@kya-os/consent`'s template system, auth modes, and branding. `server.ts` is MCP infrastructure, identical in structure to consent-basic.

### Why the low-level Server API?

This example uses `createKyaOsMiddleware` with the SDK's low-level `Server` class instead of the 2-line `withKyaOs(server, { crypto })` pattern ([see context7-with-kya-os](../context7-with-kya-os/) for that). The reason: delegation-protected tools receive `_kyaos_delegation` as a tool argument. `McpServer.registerTool` validates args against zod schemas and strips unknown keys — so the delegation VC is silently dropped before the handler sees it. The low-level `Server` API passes args through without schema validation, which delegation requires.

If your server doesn't need delegation (just proofs + handshake), use `withKyaOs` — it's 2 lines.

## What's Different from consent-basic?

| | consent-basic | consent-full |
|---|---|---|
| **Consent UI** | Hand-rolled HTML + vanilla JS | `@kya-os/consent` web component |
| **Auth modes** | Consent-only | Consent-only (default) + credentials via `AUTH_MODE` |
| **Branding** | Hardcoded dark theme | Configurable via `BRAND_COLOR` / `COMPANY_NAME` |
| **Loading UX** | None | Skeleton loader + no-JS fallback |
| **Approval format** | JSON POST to `/approve` | FormData POST to `/consent/approve` |
| **HTML template** | `public/consent.html` (215 lines) | `generateConsentShell()` (zero template files) |

## Configuration

| Env var | Default | Description |
|---------|---------|-------------|
| `AUTH_MODE` | `consent-only` | Auth mode: `consent-only` or `credentials` |
| `BRAND_COLOR` | `#2563EB` | Primary brand color (hex) |
| `COMPANY_NAME` | `KYA-OS Demo` | Company name shown on consent page |
| `PORT` | `3002` | MCP server HTTP port |
| `CONSENT_PORT` | `3001` | Consent server HTTP port |

### Credentials mode

```bash
AUTH_MODE=credentials npx tsx examples/consent-full/src/server.ts
```

The consent page shows a username/password form. Demo credentials: `demo` / `demo123`.

### OAuth (production)

`@kya-os/consent` supports 8 auth modes including OAuth, magic-link, OTP, passkey, and IDV. This example demonstrates consent-only and credentials. For OAuth integration in production, see the [`@kya-os/consent` documentation](https://www.npmjs.com/package/@kya-os/consent).

## File Structure

| File | Purpose |
|------|---------|
| `src/consent-server.ts` | **The showcase** — consent page via `@kya-os/consent`, VC issuance |
| `src/server.ts` | MCP server infrastructure — tools, delegation, transports |
| `src/delegation-issuer.ts` | DelegationCredentialIssuer factory |
| `scripts/generate-identity.ts` | Persistent Ed25519 DID identity |

## Persistent Identity

```bash
npx tsx examples/consent-full/scripts/generate-identity.ts
```

Generates `.kya-os/identity.json` — the DID survives server restarts. Without it, the server creates an ephemeral identity on each start.

## Tests

```bash
cd examples/consent-full
npx vitest run
```

Coverage: delegation issuance, consent page rendering, VC structure, scope enforcement, proof generation, and full E2E consent flow.
