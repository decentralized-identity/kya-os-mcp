# `@kya-os/mcp` Proof Verification

Verifies a DetachedProof JSON using did:key resolution.

## Usage

```bash
# From a file
npx tsx examples/verify-proof/verify.ts proof.json

# From stdin
echo '{"jws":"...","meta":{...}}' | npx tsx examples/verify-proof/verify.ts
```

## What It Does

1. Parses the DetachedProof JSON (JWS + metadata)
2. Resolves the DID in the proof metadata to extract the public key
3. Verifies the JWS signature using Ed25519
4. Checks timestamp freshness (within 5-minute skew)
5. Prints the verification result
