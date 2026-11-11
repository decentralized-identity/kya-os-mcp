# Three parties, three keys, explicit protocol boundaries

The merchant authorizes from the RP-signed delegation, the agent’s fresh holder proof, and the RP’s signed revocation list.
Its consent evidence is carried inside the signed credential.
It does not open the RP’s flow store or require the RP to write an agent credential file.

## Exchange

1. The agent calls merchant `/mcp` with a fresh `place_order` proof bound to that merchant.
2. The merchant verifies the proof, then posts a merchant-signed request to RP `/consent/requests`.
   This envelope contains the grant terms and the original agent request and proof.
   The RP independently verifies both signers, audiences, request hashes, freshness and replay state before creating its private flow.
3. The RP returns a signed challenge reply bound to the merchant request nonce.
   The merchant returns the usual signed MCP `needs_authorization` challenge.
   The agent verifies its URL bindings before showing it to the human.
4. The RP validates the human’s selected scopes and, when configured, the account-bound passkey assertion.
   It issues a credential to its own archive and records consent approval and issuance under its own audit signing key.
5. The agent posts to `/consent/pickup`, proving possession of its key with a fresh proof bound to the RP, resume token and merchant audience.
   The RP delivers the approved credential in a signed reply bound to that exact request nonce.
   A fresh authenticated pickup may repeat after a lost response.
   The ten-minute challenge deadline limits pending human decisions; it does not expire an already approved grant's delivery.
   The agent verifies the reply and consent binding before saving its own credential.
6. The agent retries any order within the approved grant, attaching the credential and a fresh holder proof.
   The resume token stays in the RP consent/pickup exchange and is not an order parameter.
   The merchant verifies the signed consent attestation, scope, cap and current revocation status.
   A successful receipt carries the same consent reference.

The RP request and pickup endpoints are an **example HTTP binding** using the published `@kya-os/mcp` request-proof primitives.
They are not proposed as new standardized MCP methods.
The merchant remains a stateless Streamable HTTP MCP server using the published package.
Pending grants, keys, credentials and replay caches are application state, separate from MCP transport sessions.

## What the credential attests

Every approval, including the default local click approval, adds the following profile to `credentialSubject.delegation.metadata.consent`:

```json
{
  "profile": "urn:kya-os:example:agentic-commerce:consent:v1",
  "consentRef": "sha256:<hash of the consent token>",
  "approvedAt": "<approval timestamp>",
  "agentDid": "<credential subject>",
  "audience": "<merchant DID>",
  "scopes": ["<selected GS1 product class>"],
  "cap": { "maxAmount": "50.00", "currency": "CHF", "per": "order" },
  "validHours": 48,
  "authentication": "rp-local-approval"
}
```

The authentication method becomes `webauthn` or `google+webauthn` when that ceremony was verified.
The existing `demoConsent` extension additionally carries the public account and authenticator references for the named-account presentation.
Raw Google subject, email, provider tokens and authenticator credential IDs remain at the RP.

A valid RP signature without the consent attestation is insufficient for this example.
An attestation that disagrees with the actual credential’s subject, audience, scope, cap or expiry is refused at the consent gate.
Changing signed metadata without re-signing fails credential verification.

This is an RP attestation about a human decision.
The merchant trusts that issuer to report its ceremony honestly; it does not independently authenticate the human or receive their Google token.
The projector labels the relationship as RP-attested.
The grant authorizes a product class and per-order limit, not a particular quantity, a recurring purchase or a payment.

## Evidence ownership

| Recorder | Events it can attest | Correlation |
| --- | --- | --- |
| RP | Human consent approved or denied, credential issued, authority revoked | Consent reference inside the issued credential |
| Merchant | Challenge requested, RP credential/consent verified, order approved or refused, signed receipt | The verified credential’s consent reference |

The RP’s public DID is recorded as a public DID.
The merchant does not import RP events into its own ledger or claim it observed the account login.
The RP’s witness receipt on a merchant checkpoint means it observed that checkpoint; it does not certify the merchant’s account-authentication claims.

The grant panel links `/api/rp/audit/ledger` and `/api/rp/audit/bundle` on the RP origin.
`POST /api/rp/audit/export` produces the RP’s bundle, public verification keys, policy and a deliberately edited bundle.
The merchant’s existing audit controls and export endpoint continue to operate on the merchant ledger.
Both exports are checked with the published SDK verifier and the independent Python verifier.

Both journals advertise AAP-1 because their live journals are in memory.
The RP retains its own source events and replays them with their original event IDs and occurrence times into a new epoch after restart.
RP exports are saved under `var/rp/audit/<epoch>/`.
These are reviewable snapshots, not a claim of production-grade transactional audit durability.

## Storage and rehearsal boundary

| Party | Private state under its own `DEMO_VAR_DIR` |
| --- | --- |
| RP | `rp/consent/flows.json`, `rp/credentials/`, RP account and authenticator state, signed status list, RP audit exports |
| Agent | `agent/state.json`, containing its pending verified challenge and delivered grant |
| Merchant | `audit/` exports; live request-proof replay cache in memory |

`npm run demo` deliberately co-hosts the workshop’s single configured agent gateway and merchant and uses a common local configuration file.
That convenience is not process, filesystem-permission or multi-user isolation.
Separate deployments supply role-specific environment configuration and storage roots; `DEMO_ENV_FILE` can replace the local shared environment-file default.
The acceptance test supplies each process only its own private key.
The gateway serializes its own grant transitions across concurrent HTTP connections; multiple gateway replicas would need shared coordination and replay storage.
The merchant has no consent-use store; its authorization relies on the signed consent attestation and fresh holder proof.
An exact request-proof replay is refused, while a new proof represents a new order attempt.
Lost responses do not disable a grant and are not automatically retried.
Transaction idempotency and reconciliation of an uncertain purchase outcome remain outside this example.

The read-only RP delegation endpoint remains a public projector artifact in this local demonstration.
The delegation is holder-bound, not a bearer secret; presenting it still requires the agent key.
The agent’s operational delivery path is authenticated pickup.
Presenter reset and revocation endpoints remain local demo controls, not a production hosting authentication design.

Existing grants from the previous shared-file implementation are not silently migrated.
Start a new human approval to obtain the signed consent profile and agent-owned credential.
Legacy issuance filenames still reserve their status-list indices so new grants cannot accidentally reuse old revocation bits.

## Reproducible checks

```bash
npm test -- --run tests/party-boundaries.test.ts tests/consent-protocol.test.ts tests/consent-security.test.ts
npm test
npm run typecheck
npm run test:webauthn:browser
npm run test:google:browser
```

The process-boundary test runs separate RP and merchant processes and an independent agent with separate storage roots.
It verifies authenticated challenge creation, rejection of wrong parties and replayed proofs, approval, late and repeated HTTP delivery, changed in-scope orders, tampered metadata refusal, recovery after a lost order response, separate ledger signers, shared consent references, and live revocation.
After delivery it deliberately makes the RP flow file unreadable and confirms that a new order still succeeds.
It also verifies the RP’s honest and edited bundles independently with the SDK and Python.
The Google browser test uses a fictional locally signed identity-token fixture and a Chromium virtual FIDO2 authenticator, not a live Google login or a physical key.
