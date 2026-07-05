# Embedded Agent — holder-of-key, in-process

The **recommended** way for an agent you *own* to be a KYA-OS holder-of-key agent:
it embeds `@kya-os/mcp`, holds its own key, and **signs its own per-request proof
in-process**. No proxy, no shared session, no re-pasted credential.

This is the counterpart to the **proxy** pattern (e.g. a `kya-os-inspector`-style
adapter), which exists only for *generic clients you cannot modify*. When you
control the agent, you **embed** — it is simpler and strictly more secure (the key
never leaves the agent's process).

```
[ your agent ]                          [ KYA-OS server ]
  imports @kya-os/mcp                     holderBinding: 'enforce'
  mints _kyaos_proof in-process  ───▶     verifies the proof, resolves the
  (no proxy in between)                    agent-anchored grant via getByAgent
```

## The one move

On every call the agent does exactly this — and nothing else:

```ts
import { generateRequestProof } from '@kya-os/mcp';

const proof = await generateRequestProof({
  identity,             // the agent's own DID + signing key
  crypto,
  toolName: 'checkout',
  args,                 // bound into the proof — tamper-evident
  audience: serverDid,  // who it is addressed to (a distinct party)
});
// → call checkout({ ...args, _kyaos_proof: proof })
```

A fresh CSPRNG nonce per call makes every proof replay-safe. That is the whole
client half of holder binding (KYA-OS spec §11.8).

## Run it

```bash
npm run build                          # examples import the built @kya-os/mcp
npm run example:embedded-agent         # narrated walkthrough
# terse CI form:  npx tsx examples/embedded-agent/walkthrough.ts --quiet
```

It runs as a **narrated walkthrough** by default — printing the real `_kyaos_proof`
(its `nonce`, `requestHash`, `audience`), the server's challenge, and a *fresh nonce
per call* so replay-safety is visible. Pass `--quiet` (or `QUIET=1`) for the terse
PASS/FAIL form — headless + deterministic, non-zero exit on failure (a CI gate).

It stands up a holder-of-key server, creates an agent with its **own, distinct**
identity, and runs the full no-paste loop:

| Step | Result |
|------|--------|
| 1. Agent signs its own proof in-process and calls `checkout` with no grant | → `needs_authorization` |
| 2. Approve once (binds an agent-anchored grant) | — |
| 3. Agent retries with a **fresh** in-process proof (new nonce) | → **success**, no re-paste, no session |
| 4. A call with **no** proof | → re-challenged (confused-deputy guard) |

## Why this is the low-friction path

For an agent you own, adopting KYA-OS is *embed the SDK + sign your calls* — the
agent's footprint is one function (`generateRequestProof`) per call. The server's
holder-of-key resolution (`getByAgent`) and the grant's durability are the
package's job, not yours. That is the honest answer to "is KYA-OS a nuisance to
adopt?": for an owned agent, no — it is additive and small.

## Embedded vs. proxy

| | **Embedded** (this example) | **Proxy** (`kya-os-inspector`) |
|---|---|---|
| Who holds the key | the agent itself | a co-located proxy |
| Use when | you **own** / can modify the agent | a generic client you **can't** modify |
| Security | key never leaves the agent | a signing oracle — keep it loopback-only |
| The move | embed the SDK, sign in-process | inject the proof from the outside |

Embed whenever you can; proxy only when you must.
