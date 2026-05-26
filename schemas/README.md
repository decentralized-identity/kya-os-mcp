# KYA-OS JSON Schemas

This directory contains JSON Schema definitions for the core KYA-OS (Model Context Protocol - Identity) protocol messages.

## Schemas

| Schema | Description |
|--------|-------------|
| [handshake-request.json](./handshake-request.json) | Client-initiated session establishment request |
| [handshake-response.json](./handshake-response.json) | Server response with session context |
| [delegation-credential.json](./delegation-credential.json) | W3C Verifiable Credential for delegations |
| [detached-proof.json](./detached-proof.json) | Cryptographic proof for tool request/response |
| [well-known-kyaos.json](./well-known-kyaos.json) | Service discovery document |

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
https://schema.kya-os.ai/xmcp-i/{category}/{schema-name}.v1.0.0.json
```

Schemas can reference each other using `$ref`. For example, the delegation credential schema references shared definitions for constraints and proof structures.

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

## Contributing

When modifying schemas:

1. Ensure backward compatibility or increment the schema version
2. Update the `examples` array with valid instances
3. Run validation tests against the examples
4. Update this README if adding new schemas
