# `org.kya-os/decentralized-authority` as an opt-in module for the MCP TypeScript SDK v2

Scoping spike, design doc only.
No implementation, no pushes, no PRs.
Date: 2026-07-28.

Sources: the SPEC-MCP-EXTENSION.md binding in the kya-os-mcp tree, its shipped reference logic (`src/extension/settings.ts`, `declaration.ts`, `gate.ts`, `conformance/vectors/negotiation.json`, on the repository `main` branch and shipping in the next release), and a fresh read of the official TypeScript SDK v2 described below.

---

## 1. Which SDK ref was read

Clone: `github.com/modelcontextprotocol/typescript-sdk`, branch `main`, commit `cc4b41617ce3601b1290d67216ea0b194a3cd9ac` ("Version Packages (#2555)").
This commit is the peeled target of every `@modelcontextprotocol/*@2.0.0` tag (`client@2.0.0`, `server@2.0.0`, `core@2.0.0`, `node@2.0.0`, `server-legacy@2.0.0`, `express@2.0.0`, `fastify@2.0.0`, `hono@2.0.0`, `codemod@2.0.0`).
So the tree read is exactly the v2.0.0 release line.

npm state at read time: v2 is a monorepo split into scoped packages.
`@modelcontextprotocol/server` and `@modelcontextprotocol/client` went `2.0.0-beta.1` (2026-06-30) through `2.0.0-beta.5` (2026-07-21), then `2.0.0` published 2026-07-27T23:55Z and now carries dist-tag `latest`.
The legacy monolith `@modelcontextprotocol/sdk` stays at `1.30.0` and is not the v2 line.
File citations below are repo-relative paths in the typescript-sdk tree, all read at commit `cc4b416`.

A structural note that shapes the whole design: v2 implements the MCP `2026-07-28` revision exactly as SPEC-MCP-EXTENSION.md assumes.
Stateless core, per-request `_meta` envelope, mandatory `server/discover`, `-32021` as a first-class protocol error, and `extensions` maps on both capability shapes.
There is no SDK "extensions framework" API beyond those generic surfaces, and that turns out to be enough.

---

## 2. Investigation answers

### 2a. Client capabilities envelope and the `extensions` map

Representation.
`ClientCapabilities.extensions?: { [key: string]: JSONObject }` is in the spec types at `packages/core-internal/src/types/spec.types.2026-07-28.ts:771-781`, with the server twin at `:868-878`.
The zod wire schemas admit it on the 2026-07-28 era (`packages/core-internal/src/wire/rev2026-07-28/buildSchemas.ts:276`, `:300`, `:647`, `:657`) and, importantly, also on the 2025-11-25 era (`packages/core-internal/src/wire/rev2025-11-25/buildSchemas.ts:408`, `:494`), which matches SPEC-MCP-EXTENSION §3.1's initialize-era carriage rule.

Sending.
On a modern-era connection the `Client` stamps the reserved envelope keys onto every outgoing request and notification via the protected seam `_outboundMetaEnvelope()` (`packages/client/src/client/client.ts:700-712`), which passes `clientCapabilities: this._capabilities` to the era codec.
The codec builds the object with `CLIENT_CAPABILITIES_META_KEY = "io.modelcontextprotocol/clientCapabilities"` at `packages/core-internal/src/wire/rev2026-07-28/codec.ts:129-137`.
`Protocol._envelopeOutbound` merges it under `params._meta` with user-supplied `_meta` keys spread last, so user keys win (`packages/core-internal/src/shared/protocol.ts:675-685`).
The connect-time `server/discover` probe carries the same envelope (`packages/client/src/client/versionNegotiation.ts:372`).

Contributing entries.
Two public paths, no third: constructor option `ClientOptions.capabilities` (`client.ts:187`, stored at `:637`) and `client.registerCapabilities(caps)` (`client.ts:789-796`, before connect only).
Both go through `mergeCapabilities` (`protocol.ts:1881-1896`), which merges one level deep, so `{ extensions: { "org.kya-os/decentralized-authority": {...} } }` merges into an existing `extensions` map without clobbering other extension ids.

Is there a dedicated public extensions API (register/declare hooks)?
No.
There is no `registerExtension`-style hook anywhere in the v2 surface, and the docs tree has no extensions page (the only docs mention of extension methods is `docs/advanced/custom-methods.md`).
The generic surfaces above are the API, and they are sufficient for declaration.

### 2b. Server contribution to `server/discover` `capabilities.extensions`

`ServerOptions.capabilities` seeds `Server._capabilities` (`packages/server/src/server/server.ts:319`); `server.registerCapabilities(caps)` (`server.ts:443-457`, public, before connect only) merges through the same `mergeCapabilities`.
`McpServer` forwards its `ServerOptions` verbatim (`packages/server/src/server/mcp.ts:118`) and exposes the low-level instance as `public readonly server: Server` (`mcp.ts:70`), so both API levels can declare.

The `server/discover` handler is installed by the serving entries (`installModernOnlyHandlers`, `server.ts:239-241`, called from `createMcpHandler.ts:772` and the stdio entry) or at construction when a modern revision is configured (`server.ts:345-347`).
It answers with `capabilities: discoverAdvertisedCapabilities(this.getCapabilities())` (`_ondiscover`, `server.ts:932-940`), and `discoverAdvertisedCapabilities` is a shallow copy that passes `extensions` through untouched (`server.ts:1331-1332`).
Conclusion: `registerCapabilities({ extensions: { [id]: settings } })` on the factory-fresh instance is all it takes; the declaration then appears in every `server/discover` result, including the discover probe instance `createMcpHandler` builds from the same factory (`createMcpHandler.ts:82-83`).

### 2c. Server-side pre-handler interception and protocol-level errors

There is no public protocol-level middleware.
What v2 calls "middleware" is (i) client-side `fetch` wrapping (`docs/clients/middleware.md:6`) and (ii) HTTP framework adapters (`packages/middleware/{express,fastify,hono,node}`).
The dispatch-adjacent hooks that do exist are all `protected` or internal:

- `Protocol._wrapHandler` (`protocol.ts:1749-1754`), subclass-only wrapping of registered handlers.
- `Protocol._shouldDropInbound` (`protocol.ts:650-652`), subclass-only drop consult.
- The HTTP entry's pre-dispatch capability gate (`createMcpHandler.ts:700-703`) evaluates `requiredClientCapabilitiesForRequest` against `REQUIRED_CLIENT_CAPABILITIES_BY_METHOD`, but that table is a module-scoped constant that is empty today (`packages/core-internal/src/shared/clientCapabilityRequirements.ts:42`), not per-instance extensible.
- `ServerOptions.requestState.verify` (`server.ts:191`) is a real public verify hook, but scoped to multi-round-trip request state, not general requests.

The seam that IS public and sufficient: the `Transport` interface plus the fact that every serving entry connects the factory product through its public `connect` method.

- `Transport` is a public exported type (`packages/core-internal/src/exports/public/index.ts:66`, re-exported by both `@modelcontextprotocol/server` (`packages/server/src/index.ts:109`) and `@modelcontextprotocol/client` (`packages/client/src/index.ts:117`)).
- The modern HTTP path calls `await server.connect(transport)` on the factory product (`packages/server/src/server/invoke.ts:66`).
- The legacy stateless path does the same (`createMcpHandler.ts:329`), and stdio does too (`packages/server/src/server/serveStdio.ts:531`).
- `McpServer.connect` simply delegates (`mcp.ts:148-149`).

So a factory wrapper can decorate the product's public `connect` to interpose a gate transport.
The gate sees every inbound `JSONRPCRequest` as raw wire bytes, before the dispatch layer's lift mutates anything.
That raw view matters twice over: dispatch lifts the reserved `_meta` envelope keys and the MRTR retry members out of `params` before handlers run (`liftWireOnlyMaterial`, `protocol.ts:211-251`), and spec-path handlers receive zod-parsed params (`protocol.ts:1701-1719`), so only the transport boundary can recompute the KYA-OS `requestHash` over the exact received `{ method, params }` minus `params._meta` (SPEC-ENTITY-CARD §8.3).
To reject, the gate writes a `JSONRPCErrorResponse` directly via the inner transport's `send`, which is byte-for-byte what the dispatch layer's own `sendErrorResponse` does (`protocol.ts:953-960`).

Handler-level context access also exists for anyone who prefers wrapping individual handlers: `ctx.mcpReq._meta` carries the non-reserved keys (the KYA-OS proof key survives the lift; `protocol.ts:1057`, contract at `:348-352`) and `ctx.mcpReq.envelope` carries the lifted reserved keys including the client capabilities declaration (`protocol.ts:1058`, type at `:355-363`).

HTTP status for `-32021`.
The per-request HTTP transport maps an error response with code `-32021` to HTTP `400` even when it is produced after the dispatch window opens, as a documented spec-mandated exception (`packages/server/src/server/perRequestTransport.ts:266-296`, special case at `:290`; status table `LADDER_ERROR_HTTP_STATUS` at `packages/core-internal/src/shared/inboundClassification.ts:383-390`; `httpStatusForErrorCode` at `:410-415`).
So a gate-emitted or handler-thrown `-32021` gets the spec's `400` with zero extra work, and in-band `-31000` proof-gate errors correctly stay on HTTP `200`.

### 2d. Client-side `_meta` read/write

Per-request write, explicit: every request params type includes `_meta` (`RequestMetaSchema` is `z.looseObject`, `buildSchemas.ts:146`), `callTool(params, ...)` takes `CallToolRequest['params']` verbatim (`client.ts:2317`), and user `_meta` wins over the auto-envelope (`protocol.ts:672-684`).
So `client.callTool({ name, arguments, _meta: { "org.kya-os/request-proof": proof } })` works today.

Per-request write, transparent: decorate the client `Transport` the developer already constructs and passes to `client.connect(transport)`.
`transport.send` sees the final outgoing `JSONRPCRequest` (envelope already merged), and since `requestHash` excludes `params._meta` by design, minting the proof there and injecting it under `_meta` is hash-safe by construction (SPEC-MCP-EXTENSION §6 item 2).
`send` returns a promise, so async signing (including non-extractable `CryptoKey` signers) fits.
A pleasant consequence: multi-round-trip auto-fulfilment retries (`client.ts:717-750`) re-enter `transport.send` as new wire requests, so each retry gets a fresh, correctly bound proof with no special handling, matching SPEC-MCP-EXTENSION §7.3's "retry is a new request" posture.

Reading results: result schemas keep `_meta` (`_meta: z.optional(z.looseObject({}))`, `buildSchemas.ts:365`, `:375`), and the 2026 decode returns the body verbatim minus only the `resultType` discriminator (`rev2026-07-28/codec.ts:253-256`).
Since KYA-OS `responseHash` excludes `_meta` and never covers `resultType` (SPEC-MCP-EXTENSION §6), response-proof verification can run either on the decoded result or, more robustly, on the raw response inside the same transport decorator before the SDK decodes it.

Reading errors: an inbound error response becomes `ProtocolError.fromError(code, message, data)` (`protocol.ts:1213`).
One sharp edge found: the `-32021` branch of `fromError` (`packages/core-internal/src/types/errors.ts:93-102`) reconstructs `MissingRequiredClientCapabilityError` from `data.requiredCapabilities` alone and drops sibling members at `:100`.
If `data` carries `{ reason, extension }` without `requiredCapabilities`, exactly the SPEC-MCP-EXTENSION §4.2 shape, the branch does not match and the error falls through to the generic path (`errors.ts:105`) with `data` preserved verbatim.
So the spec-exact error shape survives SDK client reconstruction intact, and clients can dispatch on `error.data.reason` as §5.2 requires.
(The final core spec makes `data.requiredCapabilities` a MUST on `-32021`, so the module emits it alongside `reason`/`extension`. That routes stock SDK clients into the typed subclass, which drops the sibling members at `errors.ts:100` - so the client module reads the raw wire error at its transport decorator, before `fromError` runs, and the one-line upstream fix preserving extra data members is the named companion ask in the maintainer summary rather than an optional nicety.)

### 2e. Protocol error modeling for `-32021` with a `data` payload

`ProtocolError` is a public class with a `(code, message, data)` constructor (`errors.ts:19-54`), and `MissingRequiredClientCapabilityError` subclasses it with `ProtocolErrorCode.MissingRequiredClientCapability = -32021` (`errors.ts:207-226`; enum at `packages/core-internal/src/types/enums.ts:30`; spec constant `MISSING_REQUIRED_CLIENT_CAPABILITY = -32021` at `spec.types.2026-07-28.ts:449`; data interface at `types.ts:783`).
All of it is public API re-exported by both role packages (`exports/public/index.ts:106-111`).
A handler-thrown error keeps its integer `code` and its `data` verbatim on the wire (`protocol.ts:1141-1151`), and `encodeErrorCode` is identity for `-32021` on both eras (`rev2026-07-28/codec.ts:271`, `rev2025-11-25/codec.ts:141`).
So an extension can emit `-32021` with `data: { reason: "extension_not_declared", extension: "org.kya-os/decentralized-authority" }` from a wrapped handler or mint the response directly at the transport gate; both produce the SPEC-MCP-EXTENSION §4.2 wire shape, and on HTTP both get status `400` (see 2c).

---

## 3. Minimal module design

### 3.1 Shape and naming

One new package, no SDK core changes: working name `@kya-os/mcp-sdk` (subpaths `/server` and `/client`), delivered for the SEP as a prototype branch of the official SDK adding `packages/extension-decentralized-authority` with identical code.
The module is a thin binding: all extension logic in `@kya-os/mcp` (on `main`, shipping in the next release: `src/extension/settings.ts`: id, meta-key and code constants, settings schema, `buildExtensionsEntry`; `src/extension/declaration.ts`: `readExtensionDeclaration` with the stateless and initialize carriages; `src/extension/gate.ts`: `requireExtension`, `missingRequiredCapabilityError`, `proofGateToJsonRpcError`; verification primitives in `src/card/`) is imported, not duplicated.

### 3.2 Public API sketch

```ts
// ---- server (wraps the factory; works for createMcpHandler, serveStdio, and hand-wired connect) ----
import { withDecentralizedAuthority } from '@kya-os/mcp-sdk/server';

const handler = createMcpHandler(
    withDecentralizedAuthority(myFactory, {
        settings: { version: '1.0.0', proofProfiles: ['org.kya-os/proof.v1'], didMethods: ['did:key', 'did:web'] },
        required: true,                      // -32021 + { reason: 'extension_not_declared' } for undeclared clients
        verifier,                            // proof verifier from @kya-os/mcp (fail-closed order, SPEC-ENTITY-CARD §11.2)
        nonceStore,                          // shared across per-request instances (module default: in-memory, documented caveat)
        gate: { exempt: ['server/discover', 'ping'] }   // discovery is never gated (SPEC-MCP-EXTENSION §4.2)
    })
);

// ---- client (declare + transparently attach proofs) ----
import { decentralizedAuthority } from '@kya-os/mcp-sdk/client';

const da = decentralizedAuthority({ signer, delegationRef });    // signer may hold a non-extractable CryptoKey
const client = new Client(info, { capabilities: da.capabilities });   // or da.register(client) pre-connect
await client.connect(da.transport(new StreamableHTTPClientTransport(url)));
```

### 3.3 How each piece lands on the SDK surfaces found in §2

Server declaration: the factory wrapper calls `product.server.registerCapabilities({ extensions: buildExtensionsEntry(settings) })` on every fresh instance, pre-connect (the entries call the factory per request, per connection, and per discover probe, so the advertisement is always present in `server/discover`).
Server gate: the wrapper replaces the product's public `connect` with `t => originalConnect(gateTransport(t, opts))`.
The gate transport delegates the `Transport` contract and intercepts inbound requests: it reads the declaration from `_meta["io.modelcontextprotocol/clientCapabilities"].extensions` (or, on a 2025-era `initialize`, from `params.capabilities.extensions`) via `readExtensionDeclaration`, answers required-mode absence with the §4.2 `-32021` error object written straight to `innerTransport.send` (HTTP 400 comes free, `perRequestTransport.ts:290`), runs the proof gate on gated methods over the raw `{ method, params }`, maps failures through `proofGateToJsonRpcError` (`-31000`, `data.reason` in `proof_missing | proof_invalid | proof_level_insufficient`), and forwards clean traffic to the protocol's `onmessage` untouched.
Malformed declarations are treated as absent (fail closed, SPEC-MCP-EXTENSION §3.2), matching the `negotiation/malformed-*` vectors.

Client declaration: `da.capabilities` / `da.register(client)` use the constructor option or `registerCapabilities`; the SDK then carries the declaration on every request automatically via `_outboundMetaEnvelope`, including the discover probe.
Client proofs: `da.transport(t)` decorates `send` to mint `org.kya-os/proof.v1` over the final wire request (minus `_meta`) and inject it under `_meta`; it also verifies response proofs from `_meta["org.kya-os/response-proof"]` on the way back, before the SDK decode, and surfaces `needs_authorization` challenges per SPEC.md §9.

Optional mode, unaware peers, and disabled-by-default all hold by construction: a server not wrapped and a client not decorated are byte-identical to stock v2, and a wrapped server with `required: false` passes undeclared traffic through untouched.

### 3.4 Crypto and verification: peer dependency, not vendored

Peer dependencies: `@modelcontextprotocol/server` / `@modelcontextprotocol/client` at `>=2.0.0 <3`, and `@kya-os/mcp` at the first minor carrying the extension module for settings/declaration/gate logic and the `src/card/` verification primitives (DID resolution, delegation chains, status lists, JCS hashing, jose 6).
Vendoring is rejected: the verification stack is security-sensitive and already audited once, the conformance harness pins it, and duplicating it would fork the fail-closed order.
The SDK core gains zero dependencies because the SDK core gains zero code.

### 3.5 Diff to SDK core

Zero core changes required.
Every needed seam is public API at `cc4b416`: capability `extensions` maps on both roles, `registerCapabilities` on both roles, the auto-emitted client envelope, the `Transport` interface plus entry-side `connect(product)` dispatch, verbatim `code`/`data` pass-through for thrown protocol errors, and the `-32021` to HTTP 400 mapping.
One named companion ask, not a blocker (the client module reads raw wire errors, §2d): one line in `ProtocolError.fromError` (`errors.ts:100`) to preserve extra `-32021` data members alongside `requiredCapabilities`, so stock SDK clients keep the extension dispatch code. One optional nicety: (2) a per-instance hook behind `REQUIRED_CLIENT_CAPABILITIES_BY_METHOD` (`clientCapabilityRequirements.ts:42`) so required-extension gating could ride the entry's own pre-dispatch rung instead of a transport decorator.
If maintainers prefer the hook route for an official extensions story, that is the exact PR to name; the module works without it.

---

## 4. Effort estimate (person-days)

Scenario A is the real one: the hooks exist (verified in §2).
Scenario B is the counterfactual if the seams had been missing (no public `Transport` decoration path, no `registerCapabilities`), requiring an upstream hook PR first.

| Work item | A: hooks exist (actual) | B: hooks missing (counterfactual) |
|---|---|---|
| Module (server wrapper, client wrapper, settings/declaration/gate binding over `@kya-os/mcp`) | 3-4 | 5-7 (includes writing the core hook PR itself) |
| Tests (port the 8 `negotiation.json` vectors + proof-gate vectors against real `Client`/`Server` over `InMemoryTransport`, `createMcpHandler` HTTP-status assertions incl. the 400, stdio path, 2025-era initialize carriage) | 3-4 | 4-5 |
| Docs (README, worked example, SEP prototype note for the maintainers) | 1-2 | 2 |
| **Total** | **7-10** | **11-14 plus upstream review latency on the hook PR** |

---

## 5. Maintainer-facing summary (Discord-ready)

> **Prototype: `org.kya-os/decentralized-authority` as an opt-in extension module on SDK v2, zero core changes.**
>
> We (DIF-hosted KYA-OS project) have an Extensions Track SEP in the works for `org.kya-os/decentralized-authority`: verifiable agent identity, delegation chains, and per-request holder-of-key proofs for MCP.
> Per the extensions docs, an Extensions Track SEP needs a reference implementation in an official SDK before review, so we scoped exactly what that takes on `typescript-sdk@cc4b416` (the 2.0.0 line) and want to sanity-check the approach with you before building the prototype branch.
>
> The short version: **v2 already exposes everything we need, and the module touches no core code.**
> Declaration rides the existing `capabilities.extensions` maps (client side auto-carried in the per-request `_meta` envelope, server side surfaced by `server/discover` via `registerCapabilities`).
> The proof is one namespaced `_meta` key on requests.
> Enforcement is a `Transport` decorator installed by wrapping the user's `McpServerFactory`, so `createMcpHandler`, `serveStdio`, and hand-wired `connect` all work unchanged; required mode answers undeclared clients with core `-32021` (`data.reason: "extension_not_declared"`), and your per-request transport already maps that to the spec's HTTP 400.
> No new tools, no new methods, no new error codes, no new SDK dependencies.
>
> **Disabled by default, by construction**: nothing activates unless a developer explicitly wraps their factory (server) or transport (client); unwrapped paths are byte-identical to stock v2, and an unaware peer talking to an optional-mode server gets plain core MCP.
> **Conformance is already testable**: the extension ships with a cross-language conformance-vector suite (negotiation vectors covering declared/absent/malformed/required/initialize-era cases, plus proof vectors), and the crypto/verification core is a peer dependency on `@kya-os/mcp`, live on npm with implementations shipping in two languages.
> The prototype branch would add one `packages/` module plus tests that run the vectors against the real `Client`/`Server` over `InMemoryTransport`.
> One small core ask (not a blocker): preserving extra `-32021` `data` members in `ProtocolError.fromError`, so typed reconstruction keeps the extension dispatch code the final spec has ride alongside the mandated `requiredCapabilities`. One optional nicety: a per-instance hook on the pre-dispatch capability gate.
> Estimated effort on our side: about 7-10 person-days including tests and docs.
> Would a draft PR against a fork be the right next step, or do you prefer prototype modules proposed as a `packages/` addition directly?

---

## 6. Open items and risks

1. `registerCapabilities` throws after connect on both roles; the module must document that client registration happens before `connect` (the factory wrapper is inherently pre-connect on the server side).
2. The gate must never gate `server/discover` or `ping` (discovery deadlock otherwise); the default exempt list encodes the normative exemption of SPEC-MCP-EXTENSION §4.2.
3. Nonce replay containment needs a store that outlives per-request factory instances; the module takes a `nonceStore` option with an in-memory default and the SPEC-MCP-EXTENSION §10 item 4 multi-replica caveat in the README.
4. The stdio entry also builds a discarded discover-probe instance from the same factory; the wrapper is idempotent per instance so this is free, but tests should pin it.
5. On 2025-era traffic the declaration arrives via `initialize` `params.capabilities.extensions`; the gate transport reads both carriages through `readExtensionDeclaration` and must normalize them into one internal declaration (SPEC-MCP-EXTENSION §3.1), with the `negotiation/legacy-initialize-required` vector as the pin.
6. Emit the `-32021` `data` payload with the core-mandated `requiredCapabilities` plus `{ reason, extension }`; the client module reads the raw wire error at the transport decorator (before `fromError` reconstruction), and the upstream `fromError` one-liner is the named companion ask (see §2d).
