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
- The **merchant** (`did:web:merchant.example`) runs `requireProof` and then `requireDelegation` on every call to `orders.place`.
  It knows Acme's DID and trusts it as a customer.
  It can fetch Acme's public revocation list, but Acme's delegation registry refuses it.

Every party has a real Ed25519 `did:key`.
Both hops and Acme's Bitstring Status List are signed with `eddsa-jcs-2022` through the SDK.
Only the network is in memory.

## The five calls

| Call | What the merchant sees | Answer |
| --- | --- | --- |
| 1. By reference | Only the worker's request proof, so it asks Acme's registry for the chain | `403 delegation_unresolvable` |
| 2. Chain carried | The chain in `_meta["org.kya-os/delegation-chain"]` beside the proof | `200`, Acme recomputed as the Responsible Party |
| 3. Edited hop | The worker raised its limit from 100 to 400, still inside Acme's 500 | `403 delegation_invalid`: the agent's signature no longer verifies |
| 4. Chain replayed | Another agent sends the worker's chain with a valid proof of its own | `403 delegation_invalid`: the leaf names the worker, not this caller |
| 5. Root revoked | Acme set the root's bit in its status list; the chain is byte for byte the one from call 2 | `403 delegation_revoked` |

Call 3 shows that attenuation alone is not enough: the edited hop still narrows its parent, and only the signature catches it.
Call 5 shows that carrying a chain does not freeze it, since every hop's status is read live.

## Wiring it into a server

```ts
import {
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
if (!proof.ok) return proof;
const authority = await delegationGuard({ meta, proofDid: proof.did, action: request.params.name });
if (!authority.ok) return authority;
// authority.responsibleParty is the root issuer, recomputed from the chain.
```

On the calling side, `toDelegationChainMeta(chain)` builds the `_meta` member to send beside the request proof.

The rules are in [SPEC-ENTITY-CARD.md](../../SPEC-ENTITY-CARD.md) §10.5 (carrying the chain), §11.4 (the verification order), §12.11 (substitution), and Appendix D.5 (the gate codes).
