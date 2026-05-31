# `@kya-os/mcp` Proof Verification

Verifies a DetachedProof JSON using did:key resolution, and demonstrates
content binding (anti-MITM).

## Files

- `verify.ts` — CLI that verifies a single DetachedProof (signature, replay, skew).
- `anti-mitm-demo.ts` — self-contained demo: a signed `needs_authorization`
  challenge whose `authorizationUrl` is detected as tampered when swapped.

Both wire `ProofVerifier` from the package's shipped providers —
`NodeCryptoProvider`, `SystemClockProvider`, `RuntimeFetchProvider`, and
`MemoryNonceCacheProvider` — so nothing is hand-rolled.

## Verify a proof

```bash
# From a file
npx tsx examples/verify-proof/verify.ts proof.json

# From stdin
echo '{"jws":"...","meta":{...}}' | npx tsx examples/verify-proof/verify.ts

# Or via the package script
pnpm example:verify-proof proof.json
```

It parses the proof, resolves the signer DID, verifies the Ed25519 JWS
signature, checks the nonce against replay, checks timestamp skew (5 min), and
prints `VALID` / `INVALID` (exit 1 on failure).

## Anti-MITM content binding

```bash
npx tsx examples/verify-proof/anti-mitm-demo.ts
# or
pnpm example:anti-mitm
```

A resource server answers an unauthorized tool call with a `needs_authorization`
challenge that embeds a consent URL, and signs a proof binding a `responseHash`
over that challenge content. The verifier opts into content binding by passing
the received request/response:

```ts
verifier.verifyProof(proof, jwk, { request, response });
```

The demo shows three outcomes:

1. **genuine content** → `VALID` — the client received exactly what was signed.
2. **MITM-swapped URL** → `REJECTED: CONTENT_BINDING_MISMATCH` — an in-path
   intermediary swapped the `authorizationUrl`; the signature is still valid, but
   the recomputed `responseHash` no longer matches.
3. **response not supplied** → `REJECTED: CONTENT_BINDING_MISMATCH` — fail-closed:
   a `responseHash`-bound proof verified without its response is rejected, not
   waved through.

The signature alone proves the proof is *authentic*; only recomputing the hash
over the received content proves it *matches what was signed*.
