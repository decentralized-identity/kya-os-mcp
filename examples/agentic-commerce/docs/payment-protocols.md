# One authority gate, multiple commerce paths

The merchant applies the same published KYA delegation verifier, current revocation check, holder proof, signed consent evidence, GS1 product scope, CHF cap, and required decision audit before invoking a payment handler.
Changing the checkout or payment protocol does not grant additional authority.
The existing order-only demonstration remains the default, with payments disabled.
Set `COMMERCE_PAYMENTS=1` to expose payment tool arguments, discovery and checkout endpoints.
When disabled, payment arguments are refused explicitly and never converted into an unpaid order.

x402 supplies payment negotiation and payment evidence over HTTP or MCP.
UCP supplies discovery, checkout operations and payment-handler negotiation; UCP is not itself a payment rail.
This example pins UCP `2026-08-25` and advertises checkout plus the candidate `org.kya-os.delegation` extension and `org.kya-os.x402` / `org.kya-os.sandbox-token` payment handlers.
Those KYA names describe this implementation, not ratified UCP extensions, W3C Recommendations, or AP2 mandates.
The merchant implements a single catalog line with whole-item quantities and server-owned CHF prices; shipping, tax, billing changes, arbitrary totals and unimplemented checkout features are refused rather than ignored.
Catalog orders are demonstration records and are not fulfilled.

See the primary [x402 v2 specification](https://github.com/x402-foundation/x402/blob/main/specs/x402-specification-v2.md), its [HTTP transport](https://github.com/x402-foundation/x402/blob/main/specs/transports-v2/http.md) and [MCP transport](https://github.com/x402-foundation/x402/blob/main/specs/transports-v2/mcp.md), and the pinned [UCP checkout specification](https://ucp.dev/2026-08-25/specification/shopping/checkout/) and [UCP overview](https://ucp.dev/2026-08-25/specification/overview/).

## Rehearsal configuration

Use the normal setup and start commands from the example directory:

```bash
npm ci
npm run setup
COMMERCE_PAYMENTS=1 PAYMENT_MODE=sandbox npm run demo
```

The default x402 sandbox verifies genuine EIP-712/EIP-3009 signatures without contacting a chain or facilitator.
Its receipt says `simulated`, carries no blockchain transaction hash, and moves no funds.
The agent creates a separate sandbox EVM wallet in its private state directory; its Ed25519 KYA holder key remains separate.
The sandbox-token handler validates a merchant-issued token bound to the exact reviewed checkout and also moves no funds.
It does not represent a card network, bank, Google Pay, AP2, or an external payment processor.

The catalog and delegation remain denominated in CHF.
`X402_ATOMIC_UNITS_PER_CHF_CENT=10000` is a fixed workshop quote: CHF 39.80 becomes 39.800000 test USDC.
This is an artificial conversion, not a live CHF/USD market rate.
The merchant binds the conversion, asset, network, recipient, amount and expiry to the checkout terms; the agent verifies those values against its configured policy before signing.
UCP's review page displays the exact quantity, price, selected handler and conversion before confirmation.
Changing the terms invalidates that confirmation.

| Configuration | Behavior |
|---|---|
| `COMMERCE_PAYMENTS` | `0` or unset preserves the original workshop flow; `1` enables the optional payment integration. Set it on the merchant/gateway process and refresh Claude's tool connection after changing it. |
| `PAYMENT_MODE=sandbox` | Default; signature verification and simulated settlement only. |
| `PAYMENT_MODE=testnet` | Optional Base Sepolia USDC settlement through the configured implementation's facilitator. |
| `X402_PAY_TO` | Required nonzero EVM recipient address in testnet; leave unset for the sandbox default. |
| `X402_ATOMIC_UNITS_PER_CHF_CENT` | Positive integer quote rate; merchant and agent must agree. |
| `AGENT_EVM_PRIVATE_KEY` | Dedicated `0x`-prefixed 32-byte private key, required for testnet; keep in secret configuration, never Claude or Git. |
| `MERCHANT_ORIGIN` | Public origin used for checkout discovery, review URLs, payment resources and the agent platform profile; defaults to localhost. |
| `UCP_PLATFORM_PROFILES` | Optional comma-separated allowlist of additional platform profile URLs. |

Testnet is restricted to `eip155:84532` and Base Sepolia USDC at `0x036CbD53842c5426634e7929541eC2318f3dCF7e`.
The test wallet needs test USDC, and the facilitator/network must be reachable.
No mainnet path exists.
Stop the demo, supply the testnet settings in the ignored environment file or deployment secrets, then restart and prepare a new checkout whose review discloses testnet mode.
Do not reuse an earlier sandbox quote after changing payment mode or pricing.
The automated payment acceptance tests run in sandbox; passing those tests does not establish that a live testnet payment has settled.

## Claude run of show

Connect Claude to the existing `/agent/mcp` gateway and keep the merchant decision and event log projected.
The model supplies business arguments; the gateway handles KYA credentials, request proofs, payment signatures and durable retries.
Use the original order-only consent and revocation flow first.
The following additions assume the operator has enabled `COMMERCE_PAYMENTS=1` and started the server in sandbox mode.

### x402 after the same delegation

Send:

> Use only the connected place_order tool. Order product "risotto", quantity 2, payment_protocol "x402". This is the configured sandbox demonstration, with a CHF 39.80 order under the CHF 50.00 grant. If human consent is required, show its authorizationUrl and stop. After I approve, resume the same purchase. Preserve any checkout_id. Do not create another checkout or payment if the result is unresolved.

For a consent continuation, send:

> I approved the grant. Resume that same risotto purchase with quantity 2 and payment_protocol "x402". Reuse the checkout_id if one was returned.

Explain the two checks: the KYA grant establishes authority to place this order, and the x402 signature supplies separate payment evidence.
A valid payment signature alone cannot authorize another GTIN, exceed the CHF cap or override revocation.
The sandbox result must explicitly say that no funds moved.

### UCP with either handler

Send:

> Use only place_order with product "risotto", quantity 2, payment_protocol "ucp", payment_method "x402". Show any human consent URL or checkout continue_url and stop for me. Do not confirm the checkout on my behalf. Retain the checkout_id and resume only after I say I reviewed the exact terms. If settlement is unresolved, stop and retain the same checkout.

Approve the reusable grant if required, then review and explicitly confirm the merchant's exact checkout page.
The review is a human UI handoff, not an AP2 mandate or a separate WebAuthn assertion.
It does not place the order or submit payment; the subsequent agent completion still runs the merchant's current KYA checks.
Then send:

> I reviewed and confirmed that checkout. Call place_order again with product "risotto", quantity 2, payment_protocol "ucp", payment_method "x402", and the same checkout_id you returned.

To demonstrate the second handler, create a separate purchase by repeating the UCP prompt with `payment_method "sandbox-token"`.
Keep the quantity, scope and cap unchanged so the audience can see that the authority checks are the same.
Revoke the grant and ask for a new in-scope purchase through either protocol to show refusal before settlement.
Reusing a completed checkout displays its existing outcome, so it is not the demonstration of a new revoked action.

## Wire surfaces

The gateway still exposes `browse_catalog` and `place_order` over stateless Streamable HTTP.
With `COMMERCE_PAYMENTS=1`, the latter adds `payment_protocol` (`order-only`, `x402`, `ucp`), `payment_method` (`x402`, `sandbox-token`) and `checkout_id` for continuations.
There is no stdio dependency.

For native MCP x402, call the merchant's `place_order` with normal KYA arguments plus `checkout: { id, protocol: "x402" }`.
After the shared authority gate passes, the payment challenge contains x402 v2 `PaymentRequired` in `structuredContent` and sets `isError: true` as specified by the MCP transport.
The retry binds `{ id, protocol: "x402", termsDigest }` in its fresh holder proof and carries the payment payload in `params._meta["x402/payment"]`.
Settlement evidence is returned in `_meta["x402/payment-response"]`, alongside the signed merchant content.
The gateway performs this exchange for Claude.

| HTTP surface | Contract |
|---|---|
| `POST /payments/x402` | JSON body is the canonical `place_order` arguments, including `_kyaos_delegation`, `_kyaos_proof` and checkout intent. |
| HTTP 402 challenge | `PAYMENT-REQUIRED` contains base64 JSON x402 `PaymentRequired`; the JSON body repeats it. |
| Payment retry | `PAYMENT-SIGNATURE` contains base64 JSON `PaymentPayload`; use a fresh KYA request proof for the same checkout. |
| Settlement response | `PAYMENT-RESPONSE` carries base64 JSON settlement evidence; `KYA-Response` carries the merchant proof metadata. |
| Unresolved settlement | HTTP 202 with `SETTLEMENT_PENDING`; it is not a successful order. |

UCP discovery is at `/.well-known/ucp`; the built-in agent profile is `/agent/.well-known/ucp`.
The five REST operations are:

| Operation | Method and path |
|---|---|
| Create | `POST /ucp/checkout-sessions` |
| Get | `GET /ucp/checkout-sessions/:id` |
| Update | `PUT /ucp/checkout-sessions/:id` |
| Complete | `POST /ucp/checkout-sessions/:id/complete` |
| Cancel | `POST /ucp/checkout-sessions/:id/cancel` |

Send `UCP-Agent: profile="<allowlisted platform profile URL>"`, `Request-Id`, and an `Idempotency-Key` on writes.
Each operation also carries this example's `X-KYA-Request`: base64 JSON `{ body, proof }` signed as `ucp.<operation>` over exactly `{ id: <checkout ID or null>, body: <HTTP JSON body or {}>, idempotencyKey: <write key or null>, profile: <platform profile URL> }`.
The proof binds the configured merchant audience and a fresh holder nonce.
Complete additionally carries `X-KYA-Order`: base64 JSON `{ args }`, where `args` contains the canonical product, quantity, `{ id, protocol: "ucp", termsDigest }` checkout, delegation and `place_order` holder proof.
These headers are the example's KYA binding, not reserved UCP core fields.

Create/update uses one `line_items` entry and `kya: { rail: "x402" | "sandbox-token" }`.
Complete selects handler ID `kya_x402` or `kya_sandbox_token` in `payment.instruments[0]` and supplies its matching credential payload or token.
The checkout's public `kya` member exposes canonical intent, the payment quote, pricing and the merchant's signed completion/challenge result; it does not echo payment credentials.
`POST /payments/sandbox/tokenize` requires a fresh `payment.tokenize` holder proof over `{ id }` and an already confirmed, owned sandbox-token checkout.
Human review uses `/checkout/:id?token=...`; confirmation binds that token and exact terms digest.

## Origins and deployment state

x402 and UCP are mounted on the existing merchant listener; they do not require another deployment or domain.
A separate Responsible Party authorization domain continues to issue grants, serve passkeys and publish the status list through the existing HTTP boundaries.
Configure its `RP_ORIGIN`, `RP_DID`, `RP_KID`, `RP_DID_MIRROR_URL`, `STATUS_LIST_URL`, Google origin and WebAuthn settings as for the existing hosted consent flow.
Set `MERCHANT_ORIGIN` to the externally reachable HTTPS merchant origin so checkout and profile URLs match the agent's pinned origin.
The merchant automatically allows its own `/agent/.well-known/ucp` profile and only fetches additional explicitly configured platform URLs; redirects are refused.

Use one merchant and one RP replica for this reference deployment.
The commerce journal combines an in-process queue with a shared-volume lock held throughout settlement and atomic durable writes, so overlapping merchant processes on the same volume cannot submit the same checkout twice.
The lock heartbeats every two seconds, becomes stale after 15 seconds if a process dies, and waits at most 20 seconds for acquisition.
A compromised lock terminates its worker; recovering a stale lock preserves any unresolved settlement record.
This file-backed lock does not coordinate independent volumes or provide a distributed database, and the RP's SDK nonce cache remains process-local.
Persist the merchant commerce journal, the agent's wallet and attempt state, and the RP's consent, credential, status-list and authenticator storage.
The local listener and signing gateway retain their loopback protections: public-origin settings alone do not expose or authenticate a public Claude connector.
Use the existing deployment's authenticated ingress/gateway and protect operator actions; this change does not add public multi-user gateway authentication.

## Durable state and recovery

| State | Default path | Purpose |
|---|---|---|
| Merchant commerce journal | `var/merchant/commerce.json` | Immutable checkout terms, payment attempts, request idempotency and committed order results. |
| Agent attempts | `var/agent/commerce.json` | Checkout IDs, payment payloads, UCP operation keys and recovery status. |
| Sandbox payment wallet | `var/agent/payment-wallet.json` | Agent-owned EVM signing key; private state, never an export artifact. |
| Reusable agent grant | `var/agent/state.json` | RP credential and pending consent pickup, separate from payment attempts. |

`DEMO_VAR_DIR` relocates these application state directories to persistent storage.
`DEMO_DATA_DIR` relocates authenticator storage.
Set these paths in the deployment environment or the ignored `.env.local`/`.env` file; configuration loads before storage paths are initialized, and existing process variables take precedence.
`DEMO_ENV_FILE` selects a different environment file when separating the merchant and RP configuration.
Grant reset and setup preserve commerce and wallet files; deleting them can remove the information needed to prevent a duplicate payment.
Merchant audit bundles remain separate from the durable payment journal and retain their existing advertised audit profile.

The agent persists the payment authorization before network submission and reuses it after a lost response.
The merchant persists a settling intent before calling the payment handler and the resulting order before returning success.
Repeated completion of the same committed checkout returns the original order instead of charging again.
Completed UCP retries retain the historical order body and receive a fresh merchant proof for the authenticated holder's request.
Historical receipt recovery checks checkout ownership without requiring a still-current delegation or submitting another payment.
Durable checkout and payment identities provide this settlement protection across restarts.
Transport proof nonces still use process-local caches; neither those caches nor the original order-only tool claim durable business idempotency.
UCP idempotency keys retain operation results for at least 24 hours; a different body or intent under the same key is rejected.
A new attempt after a definitive consent/policy refusal uses a new operation key; an uncertain transport result retains the prior key and payment payload.

`SETTLEMENT_PENDING` or UCP `complete_in_progress` means the outcome is unknown.
Keep the same checkout ID and original authorization; do not generate another payment nonce, create another checkout, erase the journal or reset the wallet to retry.
Reconcile the recorded payment authorization with the facilitator/chain outcome before any manual recovery.
There is no automatic reconciliation worker or force-retry switch in this example.

An explicit retry of an unresolved `checkout_id` checks its recorded status without authorizing or submitting another payment.
The quoted x402 resource, `GET /payments/checkouts/:id`, serves this recovery path for either checkout protocol.
Send `X-KYA-Request` containing base64-encoded `SignedMessage("payment.status", { id })` with a fresh holder proof addressed to the merchant.
The merchant checks the exact request and stored checkout owner, then returns `SignedMessage("payment.status.result", { id, state, protocol, termsDigest, requestNonce, result? })` addressed to that holder.
The agent verifies the merchant signature, request nonce and its saved checkout terms before displaying the result.
Only a settled checkout includes its historical result; private review tokens, token hashes and internal payment nonce reservations are omitted.
This lookup requires no active delegation and invokes no authorization, tokenization or settlement callback, so old receipts remain retrievable after revocation.
For a settled order with pending completion audit evidence, the status lookup retries that retained evidence and marks its delivery durably.
Already-delivered evidence and unresolved payments trigger no audit callback.
Audit delivery is at least once if its acknowledgement is lost; the retained checkout and order identifiers provide stable correlation, and replaying evidence never repeats the payment.
Missing or replayed proofs return HTTP 401, and an unknown checkout or different holder returns HTTP 404.
UCP order permalinks use the protected checkout review URL and display the recorded order without another confirmation form.

## Validation

Run from the example directory:

```bash
npm test
npm run typecheck
npx vitest run tests/payment-e2e.test.ts tests/rail-authorization.test.ts tests/commerce-payments.test.ts tests/commerce-ucp-backend.test.ts tests/ucp.test.ts tests/x402.test.ts tests/agent-commerce.test.ts
```

The fixtures use real KYA holder proofs and x402 typed-data signatures with isolated state and simulated settlement.
They cover shared authorization refusals before payment, exact amount/checkout binding, duplicate completion, restart recovery, pending settlement, UCP negotiation and official schema fixtures, protected human review, and credential-redaction boundaries.
Live Base Sepolia settlement requires a separate funded testnet rehearsal.
