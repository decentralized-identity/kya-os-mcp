# did:cheqd and DID-Linked Resources

> Integration reference for the opt-in `@kya-os/mcp/cheqd` module. See [Integrations](../../../README.md#integrations) in the main README for how to enable it.

`did:cheqd` support is additive and opt-in. Existing `did:key` and `did:web`
flows remain unchanged, and operators can keep `did:web` as their canonical
identifier while linking to a cheqd DID over time.

### Resolver configuration

```typescript
import { RuntimeFetchProvider, withKyaOs, NodeCryptoProvider } from '@kya-os/mcp';
import { cheqdResolver } from '@kya-os/mcp/cheqd';

const crypto = new NodeCryptoProvider();
const fetchProvider = new RuntimeFetchProvider();
const didResolvers = {
  cheqd: cheqdResolver({ resolverUrl: 'https://resolver.cheqd.net' }),
};

await withKyaOs(server, {
  crypto,
  delegation: {
    fetchProvider,
    didResolvers,
  },
});
```

`did:cheqd` is resolved only when a resolver for the `cheqd` DID method is
explicitly supplied. The core middleware and fetch provider use the generic
`didResolvers` registry; cheqd-specific URL/cache/header options live in the
`cheqdResolver()` factory from `@kya-os/mcp/cheqd`.
`RuntimeFetchProvider` accepts the same registry when it is used directly by a
standalone verifier or operator script.
Unsupported methods, malformed DIDs, fetch failures, invalid JSON, malformed DID
Documents, and DID id mismatches fail closed by returning `null`. The resolver
accepts both raw DID Documents and Universal Resolver-style DID Resolution
Results (`{ didDocument: ... }`).

### Registrar writes

Registrar writes are explicit operator/admin actions. The package exposes
`CheqdDidRegistrarClient` for cheqd DID Registrar `/create`, `/update`, and
`/{did}/create-resource` flows, using cheqd's client-managed-secret pattern:
the registrar returns a serialized payload, your signer signs it, and the
signature is submitted back. Private keys are not sent to the registrar.

```typescript
import {
  CheqdDidRegistrarClient,
  createLocalEd25519CheqdRegistrarSigner,
} from '@kya-os/mcp/cheqd';
import {
  NodeCryptoProvider,
} from '@kya-os/mcp';

const crypto = new NodeCryptoProvider();
const registrar = new CheqdDidRegistrarClient({
  registrarUrl: 'https://did-registrar-staging.cheqd.net/1.0',
  fetchProvider,
  // Optional static or async auth headers for private registrar deployments.
  // headers: async () => ({ Authorization: `Bearer ${token}` }),
});

const signer = createLocalEd25519CheqdRegistrarSigner({
  cryptoProvider: crypto,
  privateKey: process.env.CHEQD_DID_PRIVATE_KEY_BASE64!,
  verificationMethodId: 'did:cheqd:testnet:...#key-1',
  signatureEncoding: 'base64url',
});
```

For mainnet, run or contract against your own fee-payer registrar deployment and
provide the signer hook from your KMS/HSM boundary. The local Ed25519 helper is
for simple controlled deployments and tests; it still signs locally and sends
only signatures to the registrar.

Runtime proof generation does not perform registrar writes. Create/update/DLR
publishing should be triggered by an explicit operator workflow, deployment
step, or admin tool.

### Issuer signing keys

`CheqdStatusListResolver`, like the package's delegation credential verifiers, checks an issuer's signature only with a key that the issuer's DID document lists under `assertionMethod` (SPEC.md §6.2).
It uses the key the list's `proof.verificationMethod` names.
When the proof names no key, it uses only the first entry the issuer's DID document lists under `assertionMethod`, and refuses the list when that entry does not name a key SPEC.md §6.2 accepts; it does not try later entries.
A proof whose `verificationMethod` is empty names no usable key, and the list is refused.
To sign with a key listed after the first, name it in `proof.verificationMethod`.
A key listed only under `authentication` verifies neither a status list nor a delegation credential.

`createDidPayload` in `@cheqd/sdk` lists the keys only under `authentication` in every release from 1.2.6 through 5.3.2, and under both `authentication` and `assertionMethod` from 5.3.3.
The cheqd DID registrar's `/did-document` helper builds its document with `createDidPayload`, and locks 5.3.2 or earlier in every registrar release before 2.7.1, and 5.3.7 or later from 2.7.1.
A cheqd DID created from a payload or a hand-built document that lists its key only under `authentication` needs a DID update that adds the key under `assertionMethod`.
Earlier releases of this package accepted any key the document published, so make the update before the verifiers of that issuer's credentials and status lists upgrade:

```typescript
import { createDidCheqdResolver } from '@kya-os/mcp/cheqd';

const issuerDid = 'did:cheqd:testnet:...';
const keyId = `${issuerDid}#key-1`;
const resolver = createDidCheqdResolver(fetchProvider, {
  resolverUrl: 'https://resolver.cheqd.net',
});
const current = await resolver.resolve(issuerDid);
if (!current) {
  throw new Error(`Could not resolve ${issuerDid}`);
}

await registrar.updateDid({
  did: issuerDid,
  didDocument: {
    ...current,
    assertionMethod: [...(current.assertionMethod ?? []), keyId],
  },
  signer,
  verificationMethodId: keyId,
});
```

### DID linkage

For `did:web` <-> `did:cheqd` binding, publish reciprocal `alsoKnownAs` values
and verify both DID Documents with `verifyDidLinkage()`. `buildDidWebDocument`
can include the `did:cheqd` reference on the `did:web` side, while
`updateCheqdAlsoKnownAs()` updates the cheqd side through the registrar.

```typescript
import { verifyDidLinkage } from '@kya-os/mcp';
import { updateCheqdAlsoKnownAs } from '@kya-os/mcp/cheqd';

await updateCheqdAlsoKnownAs({
  didWeb: 'did:web:agent.example.com',
  didCheqd: 'did:cheqd:testnet:...',
  resolver: cheqdResolver,
  registrar,
  signer,
  verificationMethodId: 'did:cheqd:testnet:...#key-1',
});

const linkage = verifyDidLinkage({
  primaryDid: 'did:web:agent.example.com',
  secondaryDid: 'did:cheqd:testnet:...',
  primaryDidDocument: didWebDocument,
  secondaryDidDocument: didCheqdDocument,
});
```

### DID-Linked Resource helpers

DID-Linked Resource helpers are intended for durable manifests only. Supported
artifact types are:

- `CapabilityManifest`
- `ConformanceManifest`
- `AccessHashManifest`
- `TrustConfigManifest`

`prepareCheqdDlrResource()` validates the artifact, canonicalizes its `content`
with JSON Canonicalization Scheme, computes its `sha256:<64 hex>` content
hash, and returns a registrar resource body. A `contentHash` supplied on the
artifact must equal the computed one, or the call throws. Updates are modeled
as new resource versions under the same resource `name` and `type`; prior resources are
not overwritten. Do not write high-volume tool calls, raw operational logs, or
normal runtime proof events to cheqd; keep those in your normal audit/hash
stores.

```typescript
import { prepareCheqdDlrResource } from '@kya-os/mcp/cheqd';

const prepared = await prepareCheqdDlrResource({
  type: 'TrustConfigManifest',
  subjectDid: 'did:cheqd:testnet:...',
  name: 'agent-trust-config',
  resourceType: 'TrustConfigManifest',
  version: '2026-06-01',
  content: {
    acceptedDidMethods: ['did:web', 'did:key', 'did:cheqd'],
    requiredLinkage: { type: 'alsoKnownAs', bidirectional: true },
  },
}, crypto);

await registrar.createResource({
  did: 'did:cheqd:testnet:...',
  resource: prepared.resource,
  signer,
  verificationMethodId: 'did:cheqd:testnet:...#key-1',
});
```

See [examples/cheqd-dlr](../../../examples/cheqd-dlr/) for a complete operator flow.

### Live cheqd registrar E2E tests

Live registrar coverage is opt-in because it performs real writes to cheqd
testnet. The default endpoint is the cheqd-published testnet staging registrar;
override it only with another testnet registrar. The live test creates a testnet
DID, adds a realistic `did:web` alias via `alsoKnownAs`, then publishes one
resource for each supported KYA DLR artifact type.

```powershell
$env:KYA_OS_CHEQD_E2E = '1'
npm run test:e2e:cheqd:testnet
Remove-Item Env:\KYA_OS_CHEQD_E2E
```

Optional environment variables:

| Variable | Default |
| --- | --- |
| `KYA_OS_CHEQD_TESTNET_REGISTRAR_URL` | `https://did-registrar-staging.cheqd.net/1.0` |
| `KYA_OS_CHEQD_TESTNET_RESOLVER_URL` | `https://resolver.cheqd.net` |
| `KYA_OS_CHEQD_E2E_TIMEOUT_MS` | `180000` |

Out of scope for this package: replacing `did:web` as the canonical identity,
writing runtime proof events on-chain, KYC/KYB issuance, reputation VC snapshot
publication, status-list backend hosting, and external registry changes.
