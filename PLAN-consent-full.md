# Plan: consent-branded Example

## Summary

Add `examples/consent-branded/` — the same MCP-I consent flow as consent-basic, but using `@kya-os/consent` for the consent page. Demonstrates branded UI, multi-mode auth (consent-only by default, credentials via env var), config resolution, and production-grade HTML with loading skeleton and no-JS fallback. The example justifies `@kya-os/consent` by showing the DX leap: less code in the consent server, richer UI, configurable auth modes — all from a single `generateInlineConsentShell()` call.

## Decision Log

| Decision | Options Considered | Choice | Rationale |
|----------|-------------------|--------|-----------|
| Consent rendering | (A) generateConsentShell + serve bundle, (B) generateInlineConsentShell, (C) SSR templates | B — inline shell | Self-contained: no separate bundle route needed. Single HTML response. Ideal for an example — zero infra. |
| Code sharing with consent-basic | (A) Copy files, (B) Import from consent-basic, (C) Shared module | A — copy | Examples in a protocol repo should be self-contained and independently readable. 60 lines of delegation-issuer.ts isn't worth the coupling. |
| Default auth mode | consent-only | consent-only | Works with zero config. No credentials endpoint to build, no OAuth app to register. |
| Second auth mode | (A) credentials, (B) magic-link, (C) OTP | A — credentials | Simplest to implement locally (username/password validation). No external services. Shows the 3-step flow and AUTH_MODE_TO_PROVIDER_TYPE mapping. |
| Tool names | (A) Same as consent-basic, (B) Different domain | A — same (browse/checkout) | Makes the comparison obvious. "Same protocol flow, better consent UX." |
| Approval endpoint path | (A) /approve, (B) /consent/approve | B — /consent/approve | The `<mcp-consent>` component hardcodes `${serverUrl}/consent/approve`. Must match. |
| Approval payload format | (A) JSON, (B) FormData | B — FormData | The `<mcp-consent>` component sends FormData, not JSON. Server must parse multipart/form-data or urlencoded. |

## Known Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| `<mcp-consent>` bundle too large for inline | Low | Med | Check bundle size. If >500KB, fall back to serving from a /consent.js route. |
| FormData parsing in Node.js http module | Med | Med | Node 20+ supports `Request` with FormData. Use URLSearchParams fallback if needed. |
| `@kya-os/consent` bundle may have browser-only Lit dependencies that fail on import in Node | Med | High | Only import types and `generateInlineConsentShell` + `CONSENT_BUNDLE` from the package. Avoid importing Lit components server-side. |
| Credentials mode needs a validate endpoint | Low | Low | Simple in-memory check (hardcoded demo user). Not a real auth system — just shows the flow. |

## Milestones

### Milestone 1: Scaffold

**Goal:** Project structure, dependencies, config files.
**Files:** `examples/consent-branded/package.json`, `tsconfig.json`, `.gitignore`
**Dependencies:** None

#### Changes

- `package.json`: name `@kya-os/example-consent-branded`, add `@kya-os/consent` as dependency alongside `@modelcontextprotocol/sdk`
- `tsconfig.json`: same as consent-basic
- `.gitignore`: same as consent-basic (`.mcpi/`, `node_modules/`, `dist/`)

### Milestone 2: Consent Server with @kya-os/consent

**Goal:** Replace hand-rolled HTML with `generateInlineConsentShell()`. This is the core flex — the consent server shrinks because @kya-os/consent handles all rendering, branding, loading states, and no-JS fallback.
**Files:** `examples/consent-branded/src/consent-server.ts`
**Dependencies:** Milestone 1

#### Changes

The consent server has two routes:

**GET /consent** — generates branded HTML via @kya-os/consent:
- Read `AUTH_MODE` env var (default: `consent-only`)
- Build `ConsentConfig` with branding (custom colors, company name)
- Call `generateInlineConsentShell()` with config, tool, scopes, agentDid from query params
- `serverUrl` points to the consent server itself (so `<mcp-consent>` posts back to us)
- Return the HTML

**POST /consent/approve** — parse FormData from `<mcp-consent>` component:
- The component sends FormData (not JSON) to `${serverUrl}/consent/approve`
- Extract: `tool`, `scopes` (JSON string), `agent_did`, `session_id`
- Issue delegation VC (same as consent-basic)
- Store in DelegationStore if resume_token present
- Return JSON `{ success: true, delegation_id, delegation_token }`

Key difference from consent-basic: no `consent.html` template file. No template variable replacement. The entire consent UI comes from the package.

### Milestone 3: MCP Server + Delegation Infra

**Goal:** MCP server with browse/checkout tools, transports, identity management.
**Files:** `examples/consent-branded/src/server.ts`, `examples/consent-branded/src/delegation-issuer.ts`, `examples/consent-branded/scripts/generate-identity.ts`
**Dependencies:** Milestone 2

#### Changes

- `delegation-issuer.ts`: Copy from consent-basic (60 lines, self-contained factory)
- `generate-identity.ts`: Copy from consent-basic (identity persistence script)
- `server.ts`: Same architecture as consent-basic:
  - DelegationStore class
  - formatAsConsentLink() wrapper
  - createBrandedMcpServer() factory (browse + checkout tools)
  - createMcpiMiddleware() identity loader
  - Transport setup (stdio, SSE, streamable HTTP)
  - Standalone entry point creates shared DelegationStore, passes to both servers

### Milestone 4: Tests

**Goal:** Test coverage matching consent-basic (delegation, consent server, MCP server, E2E).
**Files:** `examples/consent-branded/__tests__/*.test.ts`
**Dependencies:** Milestones 2, 3

#### Changes

Adapt consent-basic test patterns:
- `delegation-issuer.test.ts` — copy verbatim (same factory)
- `consent-server.test.ts` — update for new endpoint path (`/consent/approve`), FormData parsing, branded HTML assertions
- `server.test.ts` — same tool tests (browse/checkout), same delegation verification
- `e2e.test.ts` — full cycle with branded consent server

### Milestone 5: README + Root README

**Goal:** Document the example, explain the DX comparison with consent-basic.
**Files:** `examples/consent-branded/README.md`, `README.md` (root — add to examples table)
**Dependencies:** Milestones 1-4

#### Changes

- `README.md` (example): Quick start, what's different from consent-basic, config options (AUTH_MODE, BRAND_COLOR, COMPANY_NAME), file table
- `README.md` (root): Add row to examples table: `consent-branded` — Same flow as consent-basic but using @kya-os/consent for branded multi-mode consent pages.

## Testing Strategy

1. Unit: delegation-issuer factory produces valid VCs
2. Integration: consent server serves branded HTML, issues VCs on FormData POST
3. Integration: MCP server tools (public/protected), delegation verification, proof
4. E2E: full flow — tool call → needs_authorization → consent page → approve → retry → success
5. Manual: start servers, connect Inspector, verify branded consent page renders in browser

## Rollback Plan

Single feature branch. If anything breaks, the example is self-contained — delete `examples/consent-branded/` and revert the README table row.
