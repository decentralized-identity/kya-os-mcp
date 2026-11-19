# Chain by value

A merchant's MCP server verifies an agent acting for a company it cannot query.
The agent carries its whole delegation chain in the request, so the merchant needs no access to the company's delegation registry.

```bash
npm run example:chain-by-value
```

## The setup

- **Acme** is the Responsible Party.
  It delegates `orders.place` and `orders.read`, up to 500 USD, to its procurement agent.
- The **procurement agent** re-delegates `orders.place`, up to 100 USD, to a checkout worker.
  It signs that hop with its own key and asks no one, because Acme's hop already names it as the delegate.
  It hands the SDK Acme's hop as the parent, so the hop states that credential's digest and holds under it alone.
- The **merchant** (`did:web:merchant.example`) runs `requireProof` and then `requireDelegation` on every call to `orders.place`.
  It prices each order from its own price list, 30 USD an item, and holds that price to the limits the grant carries.
  It knows Acme's DID and trusts it as a customer.
  It can fetch Acme's public revocation list, but Acme's delegation registry refuses it.

Every party has a real Ed25519 `did:key`.
Both hops and Acme's Bitstring Status List are signed with `eddsa-jcs-2022` through the SDK.
Only the network is in memory.

## The seven calls

| Call | What the merchant sees | Answer |
| --- | --- | --- |
| 1. By reference | Only the worker's request proof, so it asks Acme's registry for the chain | `403 delegation_unresolvable` |
| 2. Chain carried | The chain in `_meta["org.kya-os/delegation-chain"]` beside the proof, for 2 items, 60 USD | `200`, Acme recomputed as the Responsible Party |
| 3. Over the limit | The same chain, for 8 items, 240 USD, inside Acme's 500 but over the worker's 100 | `403 insufficient_scope`: the grant carries the worker's limit |
| 4. Understated amount | The same chain, for 1,000 items the worker says cost 60 USD | `403 insufficient_scope`: the price list says 30,000 USD |
| 5. Edited hop | The worker raised its limit from 100 to 400, still inside Acme's 500 | `403 delegation_invalid`: the agent's signature no longer verifies |
| 6. Chain replayed | Another agent sends the worker's chain with a valid proof of its own | `403 delegation_invalid`: the leaf names the worker, not this caller |
| 7. Root revoked | Acme set the root's bit in its status list; the chain is byte for byte the one from call 2 | `403 delegation_revoked` |

Call 3 shows that a verified chain still limits the call.
The guard checks that each hop's caveats narrow its parent's, but it never sees the order's amount, so the merchant holds the order to the limit the grant carries, with `caveatRefusal`.
Call 4 shows where that amount comes from: the merchant's own price list, never an amount the caller states.
Call 5 shows that attenuation alone is not enough: the edited hop still narrows its parent, and only the signature catches it.
Call 7 shows that carrying a chain does not freeze it, since every hop's status is read live.

## Wiring it into a server

```ts
import {
  caveatRefusal,
  createDelegationProofVerifier,
  createRevocationChecker,
  createStatusListProofVerifier,
  requireDelegation,
  requireProof,
} from '@kya-os/mcp/card';

const proofGuard = requireProof({ resolveKey, resolveDidKeys, expectedAudience: SERVER_DID, consumeNonceIfFresh });
const delegationGuard = requireDelegation({
  resource: SERVER_DID,
  trustedRootIssuers: [ACME_DID],
  verifyHopProof: createDelegationProofVerifier({ didResolver }),
  checkRevocation: createRevocationChecker({
    fetch: safeFetch,
    verifyStatusList: createStatusListProofVerifier({ didResolver }),
  }),
});

const proof = await proofGuard(request, meta);
if (!proof.ok) return { status: proof.status, error: proof.error };
const authority = await delegationGuard({ meta, proofDid: proof.did, action: request.params.name });
// refusalCode and transient say why, for your logs; the client needs only the status and the error.
if (!authority.ok) return { status: authority.status, error: authority.error };
// authority.responsibleParty is the root issuer, recomputed from the chain.
// The order costs what your own records say, never what the caller says: the arguments are the caller's.
const order = priceOf(request.params.arguments); // (args: unknown) => { amount: '60.00', currency: 'USD' } | undefined
if (order === undefined) return { status: 400, error: { code: 'invalid_order', message: 'unknown item or quantity' } };
// authority.caveats holds the chain's limits at their tightest, such as the lowest MaxAmount.
// Every one applies to the order: caveatRefusal holds it to each.
const refusal = caveatRefusal(authority, order);
if (refusal !== undefined) return { status: 403, error: { code: refusal.code, message: refusal.reason } };
```

`priceOf` is yours: [walkthrough.ts](./walkthrough.ts) reads the item and quantity from the arguments and prices them from the merchant's list, so a caller that understates the amount gains nothing.
The library holds the call to each `ValidUntil` caveat when it reads the chain, but a `MaxAmount` limits a value only your server sees.
`caveatRefusal`, from `@kya-os/mcp/card`, compares the amount with every `MaxAmount` in `authority.caveats`, as an exact decimal.
A `MaxAmount` that names a currency also requires the call to be in that currency, and one that names none limits the amount whatever its currency, so limits in two currencies permit no call.
It reads each `ValidUntil` again at the time of the call, the chain's own expiry among them, so a grant you keep for later is still held to it.
It answers with a refusal `code`, such as `insufficient_scope` for an amount over a limit or `delegation_expired`, beside its `reason`.
It refuses a call under a caveat of a type the library does not know, listed in `authority.unknownCaveats`, unless you name its type in `enforcedTypes` and enforce it yourself.
It refuses a `MaxAmount` or `ValidUntil` that states a member the library does not interpret, such as `per`, whatever you name.
It also refuses a verdict that does not pass, and a grant without `caveats` or `unknownCaveats`, as a test double or a cached grant may be, rather than read it as unlimited.

On the calling side, `toDelegationChainMeta(chain)` builds the `_meta` member to send beside the request proof.

## Evaluate the chain on its own

When checking a chain outside a request, pass the same verifier to `evaluateDelegationChain`.
It runs local checks, then every hop proof, then status; the first failed proof prevents every status read.
The request guard above additionally binds the leaf to the caller and checks the action.

```ts
import {
  createDelegationProofVerifier,
  createRevocationChecker,
  createStatusListProofVerifier,
  evaluateDelegationChain,
} from '@kya-os/mcp/card';

const checkRevocation = createRevocationChecker({
  fetch: safeFetch,
  verifyStatusList: createStatusListProofVerifier({ didResolver }),
});
const authority = await evaluateDelegationChain(chain, checkRevocation, {
  resource: SERVER_DID,
  resourceOwner: ACME_DID,
  verifyHopProof: createDelegationProofVerifier({ didResolver }),
});
```

The rules are in [SPEC-ENTITY-CARD.md](../../SPEC-ENTITY-CARD.md) §10.5 (carrying the chain), §11.4 (the verification order), §12.11 (substitution), and Appendix D.5 (the gate codes).
