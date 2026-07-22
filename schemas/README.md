# KYA-OS JSON Schemas

This directory contains JSON Schema definitions for the core KYA-OS (Model Context Protocol - Identity) protocol messages.

## Schemas

| Schema | Description |
|--------|-------------|
| [handshake-request.json](./handshake-request.json) | Client-initiated session establishment request |
| [handshake-response.json](./handshake-response.json) | Server response with session context |
| [delegation-credential.json](./delegation-credential.json) | W3C Verifiable Credential for delegations (legacy VC 1.0 shape) |
| [card-delegation-credential.json](./card-delegation-credential.json) | W3C VC 2.0 + ZCAP-LD delegation profile (Entity Card) |
| [detached-proof.json](./detached-proof.json) | Cryptographic proof for tool request/response |
| [kya-os-card.schema.json](./kya-os-card.schema.json) | Typed KYA-OS Entity Card |
| [well-known-mcpi.json](./well-known-mcpi.json) | Service discovery document |
| [audit-event.schema.json](./audit-event.schema.json) | Strict, privacy-minimal producer audit event core |
| [audit-entry.schema.json](./audit-entry.schema.json) | Recorder-assigned chained entry core |
| [audit-receipt.schema.json](./audit-receipt.schema.json) | Signed append-receipt core |
| [audit-checkpoint.schema.json](./audit-checkpoint.schema.json) | RFC 9162 signed-checkpoint core |
| [audit-bundle-manifest.schema.json](./audit-bundle-manifest.schema.json) | Signed replay-bundle inventory and scope core |
| [audit-observation.schema.json](./audit-observation.schema.json) | Independently signed checkpoint observation receipt |
| [audit-anchor-receipt.schema.json](./audit-anchor-receipt.schema.json) | Supporting WORM, RFC 3161, or SCITT receipt |
| [audit-inclusion-proof.schema.json](./audit-inclusion-proof.schema.json) | RFC 9162 inclusion proof |
| [audit-consistency-proof.schema.json](./audit-consistency-proof.schema.json) | RFC 9162 consistency proof |
| [audit-verification-report.schema.json](./audit-verification-report.schema.json) | Multi-dimensional offline verification result |
| [audit-verification-policy.schema.json](./audit-verification-policy.schema.json) | Out-of-band recorder, observer, anchor, and exporter trust policy |

## Usage

### Validation with Node.js (Ajv)

```javascript
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import handshakeRequestSchema from './schemas/handshake-request.json';

const ajv = new Ajv({ strict: true });
addFormats(ajv);

const validate = ajv.compile(handshakeRequestSchema);

const request = {
  nonce: 'k7Hy9mNpQrStUvWxYz01Aa',
  audience: 'did:web:example.com',
  timestamp: Math.floor(Date.now() / 1000),
  agentDid: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
};

if (validate(request)) {
  console.log('Valid handshake request');
} else {
  console.error('Validation errors:', validate.errors);
}
```

### Validation with Python (jsonschema)

```python
import json
from jsonschema import validate, ValidationError

with open('schemas/handshake-request.json') as f:
    schema = json.load(f)

request = {
    "nonce": "k7Hy9mNpQrStUvWxYz01Aa",
    "audience": "did:web:example.com",
    "timestamp": 1710268800
}

try:
    validate(instance=request, schema=schema)
    print("Valid handshake request")
except ValidationError as e:
    print(f"Validation error: {e.message}")
```

### Schema References

All schemas use JSON Schema draft 2020-12 and are published at:

```
https://schema.kya-os.org/v1/protocol/{family}/{resource}/v1.0.0
```

Schemas can reference each other using `$ref`. For example, the delegation credential schema references shared definitions for constraints and proof structures.

### Audit semantic keywords

Two audit schemas use required KYA-OS semantic keywords for invariants that
JSON Schema draft 2020-12 cannot express with its standard vocabulary:

- `kyaOrderedDecimalRange` compares two canonical decimal-string properties;
- `kyaUniqueProperty` requires unique values for one property across an array.

Audit validators MUST implement these keywords rather than treating them as
annotations. The TypeScript/Ajv parity suite in
`src/audit/__tests__/schema-parity.test.ts` is the executable reference.

## Protocol Flow

```
┌────────┐                          ┌────────┐
│ Client │                          │ Server │
└───┬────┘                          └───┬────┘
    │                                   │
    │  GET /.well-known/mcp                │
    │──────────────────────────────────>│
    │  (well-known-kyaos.json)           │
    │<──────────────────────────────────│
    │                                   │
    │  POST /handshake                  │
    │  (handshake-request.json)         │
    │──────────────────────────────────>│
    │  (handshake-response.json)        │
    │<──────────────────────────────────│
    │                                   │
    │  POST /tools/{method}             │
    │  + X-Session-Id header            │
    │──────────────────────────────────>│
    │  Response + detached-proof.json   │
    │<──────────────────────────────────│
    │                                   │
```

## Specification Reference

These schemas implement types defined in the [KYA-OS Specification](../SPEC.md):

- **Handshake**: SPEC.md §4.5–4.9
- **Delegation Credentials**: SPEC.md §4.1–4.2
- **Detached Proofs**: SPEC.md §5
- **Discovery**: SPEC.md §14 (Transport Binding)
- **Auditability**: [AUDITABILITY.md](../AUDITABILITY.md)

## Contributing

When modifying schemas:

1. Ensure backward compatibility or increment the schema version
2. Update the `examples` array with valid instances
3. Run validation tests against the examples
4. Update this README if adding new schemas
