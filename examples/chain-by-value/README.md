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
- The **merchant** (`did:web:merchant.example`) runs `requireProof` and then `requireDelegation` on every call to `orders.place`, and holds each order to the limits the grant carries.
  It knows Acme's DID and trusts it as a customer.
  It can fetch Acme's public revocation list, but Acme's delegation registry refuses it.

Every party has a real Ed25519 `did:key`.
Both hops and Acme's Bitstring Status List are signed with `eddsa-jcs-2022` through the SDK.
Only the network is in memory.

## The six calls

| Call | What the merchant sees | Answer |
| --- | --- | --- |
| 1. By reference | Only the worker's request proof, so it asks Acme's registry for the chain | `403 delegation_unresolvable` |
| 2. Chain carried | The chain in `_meta["org.kya-os/delegation-chain"]` beside the proof, for an order of 60 USD | `200`, Acme recomputed as the Responsible Party |
| 3. Over the limit | The same chain, for an order of 240 USD, inside Acme's 500 but over the worker's 100 | `403 limit_exceeded`: the grant carries the worker's limit |
| 4. Edited hop | The worker raised its limit from 100 to 400, still inside Acme's 500 | `403 delegation_invalid`: the agent's signature no longer verifies |
| 5. Chain replayed | Another agent sends the worker's chain with a valid proof of its own | `403 delegation_invalid`: the leaf names the worker, not this caller |
| 6. Root revoked | Acme set the root's bit in its status list; the chain is byte for byte the one from call 2 | `403 delegation_revoked` |

Call 3 shows that a verified chain still limits the call.
The guard checks that each hop's caveats narrow its parent's, but it never sees the order's amount, so the merchant holds the order to the limit the grant carries, with `caveatRefusal`.
Call 4 shows that attenuation alone is not enough: the edited hop still narrows its parent, and only the signature catches it.
Call 6 shows that carrying a chain does not freeze it, since every hop's status is read live.

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
// authority.caveats holds the chain's limits at their tightest, such as the lowest MaxAmount.
// Every one applies to the call: caveatRefusal holds the order to each.
const { amount, currency } = request.params.arguments;
const overLimit = caveatRefusal(authority, { amount, currency });
if (overLimit !== undefined) return { status: 403, error: { code: 'limit_exceeded', message: overLimit } };
```

The library holds the call to each `ValidUntil` caveat itself, but a `MaxAmount` limits a value only your server sees.
`caveatRefusal`, from `@kya-os/mcp/card`, compares the amount with every `MaxAmount` in `authority.caveats`, as an exact decimal.
A `MaxAmount` that names a currency also requires the call to be in that currency, and one that names none limits the amount whatever its currency, so limits in two currencies permit no call.
It refuses a call under a caveat the library does not interpret, listed in `authority.unknownCaveats`, unless you name its type in `enforcedTypes` and enforce it yourself.
It also refuses a grant without `caveats` or `unknownCaveats`, as a test double or a cached grant may be, rather than read it as unlimited.

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
