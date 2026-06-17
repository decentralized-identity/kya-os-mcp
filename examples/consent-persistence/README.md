# Durable Consent Persistence

Proves that KYA-OS consent **survives restarts and resolves across load-balanced
instances** — the agent never has to re-paste its delegation after the user has
approved once.

This is the fix for the *"consent doesn't persist after the user grants the
consent URL"* bug, demonstrated end-to-end. Unlike
[`consent-basic`](../consent-basic), there is **no per-example `DelegationStore`
Map** — the no-paste retry comes from the package's own grant resolution over a
durable, process-external store.

It uses **holder-of-key** (`holderBinding: 'enforce'`) as the cross-instance
mechanism: the agent presents a per-request `_kyaos_proof` proving possession of
its key, and the retry resolves an **agent-anchored** grant via `getByAgent` with
**no shared server session**. That is what lets the no-paste promise hold over a
stateless HTTP transport — a session-based approach (`getBySession`) would need
the client to thread a sessionId, which the stateless transport does not.

## What's Inside

| File | Shows | How it proves the fix |
|------|-------|-----------------------|
| `src/file-grant-store.ts` | A `GrantStore` persisting approved grants to a JSON file. | The same process-external store both instances read. |
| `src/file-pending-flow-store.ts` | A `PendingFlowStore` persisting OAuth/OIDC PKCE state to a JSON file. | Lets the OAuth callback complete on the *other* instance. |
| `src/instance.ts` | The shared identity + stores, the per-instance KYA-OS middleware factory (`holderBinding: 'enforce'`, `grantStore` injected), and `mintCheckoutProof()` (the agent's per-request holder-of-key proof). | Demonstrates the package's own holder-of-key retry resolution, not an example hack. |
| `src/approve.ts` | Issues the delegation VC and **binds an agent-anchored grant** into the shared store. | Approval is written to durable storage. |
| `src/consent-server.ts` | Consent page → `POST /approve` calls `approve()`. | The HTTP approval write path. |
| `src/server.ts` | Two MCP instances (ports A/B) + the consent server, sharing one identity and one file-backed `grantStore` + `pendingFlowStore`. | A running two-instance deployment. |
| `scripts/scenario-cross-instance.ts` | Approve, retry on a separate instance with a holder-of-key proof → succeeds, no re-paste (+ a PKCE pending flow consumed cross-instance). | Direct proof of cross-instance consent persistence. |
| `scripts/scenario-restart.ts` | Approve, then a brand-new instance with empty memory retries with a fresh proof → succeeds from the file store. | Direct proof of restart survival. |

## How it works

1. The agent calls the protected `checkout` tool with a per-request
   `_kyaos_proof` but no delegation. The middleware returns `needs_authorization`
   with a consent link.
2. The user approves at the consent page. `approve()` mints the delegation VC and
   **binds a durable, agent-anchored grant** (`agentDid` + scopes, no sessionId)
   into the shared file-backed `GrantStore`.
3. The agent retries `checkout` — **on any instance, or after a restart** — with a
   fresh `_kyaos_proof` and no delegation. The middleware re-proves possession of
   the agent's key (holder-of-key) and resolves the grant from the shared store
   via `getByAgent`, then runs the tool. **No re-paste, no shared session.**

A call that omits the proof cannot resolve the agent grant (confused-deputy
guard), so it is re-challenged.

Swapping the file stores for Redis / a Durable Object / Postgres behind the same
`GrantStore` / `PendingFlowStore` interfaces makes this production-ready — the
server code does not change. For a real multi-instance deployment, swap the
**nonce cache** (`NonceCacheProvider`) and the `SessionStore` off their
in-memory defaults the same way: the in-memory implementations are single-process
only, so replay protection and sessions must also use a durable, shared backing.

> This example sets `emitLegacyProofKey: false` so the Inspector shows a single
> clean `org.kya-os/proof` key. The library default is `true` (it also mirrors
> the proof under legacy bare `proof`) for back-compat with pre-1.1 clients.

> **Consent UI:** this example uses the basic shared consent page, not the
> `@kya-os/consent` component (which consent-full and node-server use). That
> component's approval response must carry a delegation token, but this
> holder-of-key flow issues none — approval binds an agent-anchored grant and
> the agent re-proves possession per request. The basic page renders that
> token-less `{ approved: true }` outcome cleanly; it's the honest holder-of-key
> exception.

> The grant is the durable *authority*, anchored to the agent DID and re-proven
> per request by the holder-of-key proof. The session-bearer path (`getBySession`)
> is the alternative when an agent has no key, but it resolves on sessionId
> possession alone (so the sessionId is load-bearing) and needs the client to
> thread that id — which a stateless HTTP transport does not. Holder-of-key is
> the robust cross-instance choice and what this example uses.

## Testing

```bash
# 0. (optional) persist a shared identity so the DID survives restarts
npm run generate-identity

# 1. Cross-instance: approve on A, retry on B with no re-paste
npm run scenario:cross-instance

# 2. Restart survival: approve, restart, retry from the file store
npm run scenario:restart
```

Both scripts are headless and deterministic, printing `PASS`/`FAIL` per check and
exiting non-zero on failure.

### Interactive (two live instances)

```bash
npm start
# → consent page + instance A (/mcp on PORT_A) + instance B (/mcp on PORT_B)
```

Drive it with the MCP Inspector (`pnpm demo` from the repo root includes this
example): call `checkout` on instance A (with a `_kyaos_proof` in the args),
approve at the consent page, then call `checkout` on instance B with a fresh
`_kyaos_proof` — it succeeds without re-pasting the delegation. Minting that
proof is what a KYA-OS-aware client does automatically; the scenario scripts
above are the deterministic, runnable demonstration.
