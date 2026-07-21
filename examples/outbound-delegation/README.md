# Outbound Delegation Propagation Example

This example demonstrates KYA-OS §7 (Outbound Delegation Propagation) — how an MCP server forwards delegation context when calling downstream services.

## The Scenario

```
Agent → [MCP Server A] → [MCP Server B / REST API]
                ↑
         Forwards delegation headers
         so Server B knows who authorized this
```

When an MCP server (Server A) needs to call a downstream service (Server B or a REST API) on behalf of an agent, it forwards the delegation context as HTTP headers. This allows Server B to verify the original agent's delegation without trusting Server A blindly.

## Why This Matters

Without outbound delegation propagation:
- Server B only sees Server A making the request
- Server B has no way to verify who originally authorized the action
- The audit trail is broken — there's no cryptographic proof linking back to the agent

With outbound delegation propagation:
- Server B receives the original agent's DID and delegation chain
- Server B can verify the delegation proof JWT (signature check)
- The audit trail remains intact across service boundaries

## The Headers

| Header | Description | Example |
|--------|-------------|---------|
| `KYA-OS-Agent-DID` | The original agent's DID | `did:key:z6Mk...` |
| `KYA-OS-Delegation-Chain` | The delegation chain ID (vcId of the root delegation) | `urn:uuid:abc-123` |
| `KYA-OS-Session-Id` | The current KYA-OS session ID | `kyaos_xyz789` |
| `KYA-OS-Delegation-Proof` | Signed JWT proving the delegation is being forwarded | `eyJhbGciOiJFZERTQS...` |

## The Delegation Proof JWT

The `KYA-OS-Delegation-Proof` header contains a signed JWT with these claims:

```json
{
  "iss": "did:key:z6Mk...",           // Server A's DID (the forwarder)
  "sub": "did:key:z6Mn...",           // Original agent's DID
  "aud": "downstream-api.example.com", // Target hostname
  "iat": 1234567890,                   // Issued at (Unix timestamp)
  "exp": 1234567950,                   // Expires in 60 seconds
  "jti": "uuid-...",                   // Unique ID (prevents replay)
  "scope": "delegation:propagate"      // Fixed scope for propagation
}
```

## How Server B Verifies

Server B should:

1. **Extract the JWT** from `KYA-OS-Delegation-Proof`
2. **Verify the signature** using the public key from the `iss` DID (Server A)
3. **Check timing**: `iat` should be recent, `exp` should not have passed
4. **Check audience**: `aud` should match Server B's hostname
5. **Check scope**: should be `delegation:propagate`
6. **Match DIDs**: `sub` should match `KYA-OS-Agent-DID` header

If all checks pass, Server B knows:
- Server A is legitimately forwarding this request
- The original agent is identified by `KYA-OS-Agent-DID`
- The delegation chain in `KYA-OS-Delegation-Chain` can be fetched and verified

## Running the Demo

```bash
npx tsx examples/outbound-delegation/demo.ts
```

The demo:
1. Creates two identities: Server A and an Agent (both did:key)
2. Issues a delegation from Server A to the Agent
3. Simulates Server A receiving a tool call from the Agent
4. Calls `buildOutboundDelegationHeaders()` to produce headers
5. Prints the headers and decoded JWT claims
6. Shows what Server B would verify

## Usage in Your Code

```typescript
import { buildOutboundDelegationHeaders } from '@kya-os/mcp';

// When making an outbound request on behalf of an agent...
const headers = await buildOutboundDelegationHeaders({
  session,           // The current SessionContext
  delegation,        // The DelegationRecord for this agent
  serverIdentity: {
    did: serverDid,
    kid: serverKid,
    privateKey: serverPrivateKey,
  },
  targetUrl: 'https://downstream-api.example.com/resource',
});

// Attach headers to your HTTP request
const response = await fetch(targetUrl, {
  method: 'POST',
  headers: {
    ...headers,
    'Content-Type': 'application/json',
  },
  body: JSON.stringify(payload),
});
```

## Related Spec

- KYA-OS §7 — Outbound Delegation Propagation
- [kya-os.org/mcp](https://kya-os.org/mcp)
