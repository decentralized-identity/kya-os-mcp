# cheqd DID Linkage and DLR Publishing Example

This example shows the explicit operator flow for cheqd integration. It does
not run as part of normal MCP proof generation.

It demonstrates:

- resolving `did:cheqd` only when a resolver URL is configured
- updating the cheqd DID Document with a reciprocal `did:web` `alsoKnownAs`
  reference
- signing registrar payloads locally with Ed25519
- publishing one DID-Linked Resource for each supported KYA artifact type
- keeping private key material out of registrar request bodies and logs

## Prerequisites

Use testnet first. The default registrar URL below is the cheqd staging
testnet registrar. For mainnet, run or contract against your own fee-payer
registrar deployment.

Required environment variables:

| Variable | Description |
| --- | --- |
| `CHEQD_DID` | Existing `did:cheqd:testnet:*` controlled by your key |
| `CHEQD_DID_WEB` | Reciprocal `did:web:*` alias to add to the cheqd DID Document |
| `CHEQD_KID` | Verification method id, for example `${CHEQD_DID}#key-1` |
| `CHEQD_PRIVATE_KEY_BASE64` | Base64 Ed25519 private key seed used only by the local signer |
| `CHEQD_REGISTRAR_URL` | Optional. Defaults to `https://did-registrar-staging.cheqd.net/1.0` |
| `CHEQD_RESOLVER_URL` | Optional. Defaults to `https://resolver.cheqd.net` |

Do not paste production keys into shell history. In production, prefer a signer
hook backed by your KMS or HSM.

## Run

```bash
npm run build
npx tsx examples/cheqd-dlr/operator-flow.ts
# or
npm run example:cheqd-dlr
```

The script performs real testnet writes:

1. Resolves the existing `did:cheqd` DID Document.
2. Adds `CHEQD_DID_WEB` to `alsoKnownAs` if missing.
3. Publishes:
   - `CapabilityManifest`
   - `ConformanceManifest`
   - `AccessHashManifest`
   - `TrustConfigManifest`
4. Prints only public DID, resource id, artifact type, and content hash values.

## Notes

- `did:web` remains the canonical identity unless the operator explicitly opts
  into reciprocal cheqd linkage.
- DLRs are for durable manifests. Do not write raw tool-call logs, high-volume
  runtime events, or normal proof events to cheqd.
- DLR "updates" are new resource versions under the same resource name/type, not
  overwrites of previous content.
