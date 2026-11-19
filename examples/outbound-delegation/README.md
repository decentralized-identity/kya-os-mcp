# Outbound Delegation Propagation Example

This example demonstrates KYA-OS §8 (Outbound Delegation Propagation): how an MCP server forwards delegation context when calling downstream services, and how the downstream service authorizes the call from the delegation credential.

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
- Server B receives the delegation credential, signed by its issuer, and the original agent's DID
- Server B derives the granted scopes from the credential and verifies the delegation proof JWT
- The audit trail remains intact across service boundaries

## The Headers

| Header | Description | Example |
|--------|-------------|---------|
| `KYA-OS-Delegation-Credential` | The delegation credential as a VC-JWT, which Server B derives authorization from (§8.1) | `eyJhbGciOiJFZERTQS...` |
| `KYA-OS-Agent-DID` | The original agent's DID | `did:key:z6Mk...` |
| `KYA-OS-Delegation-Chain` | The delegation chain ID (vcId of the root delegation); advisory, never read for a decision | `urn:uuid:abc-123` |
| `KYA-OS-Session-Id` | An anchor of the current KYA-OS session for this target's host, never the session ID, which the session's grants answer to | `sha256:6f1c...` |
| `KYA-OS-Delegation-Proof` | Signed JWT proving the delegation is being forwarded | `eyJhbGciOiJFZERTQS...` |

`buildOutboundDelegationHeaders()` sends `KYA-OS-Delegation-Credential` when you pass the credential as `credentialJwt`.
Without it, a service that follows §8.1 can authorize nothing, and the first call in a process that omits it logs a warning.
The header carries a VC-JWT: the credential the agent presented in that form, a grant's `credentialJwt`, or one the issuer signs as the demo does.

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

Server B derives authorization from the credential:

1. **Verify the credential** in `KYA-OS-Delegation-Credential` with `DelegationCredentialVerifier.verifyDelegationJwt()`: its issuer's signature, its expiry and its revocation status
2. **Match DIDs**: the credential's subject should be the `KYA-OS-Agent-DID` header
3. **Check scope**: the scope the call needs should be one the credential grants, as `scopeSatisfies()` decides

It also checks the `KYA-OS-Delegation-Proof` JWT:

1. **Verify the signature** using the public key from the `iss` DID (Server A)
2. **Check timing**: `iat` should be recent, `exp` should not have passed
3. **Check audience**: `aud` should match Server B's hostname
4. **Check scope**: should be `delegation:propagate`
5. **Match DIDs**: `sub` should match `KYA-OS-Agent-DID` header

Server B never reads `KYA-OS-Delegation-Chain` for a decision, and ignores it when it disagrees with the credential.

## Running the Demo

```bash
npx tsx --tsconfig tsconfig.examples.json examples/outbound-delegation/demo.ts
```

The demo:
1. Creates two identities: Server A and an Agent (both did:key)
2. Issues a delegation from Server A to the Agent, and the same credential as a VC-JWT
3. Simulates Server A receiving a tool call from the Agent
4. Calls `buildOutboundDelegationHeaders()` with the credential to produce headers
5. Prints the headers and decoded JWT claims
6. Has Server B verify the credential and authorize the call from it, and exits 1 if it cannot

## Usage in Your Code

```typescript
import { buildOutboundDelegationHeaders } from '@kya-os/mcp';

// When making an outbound request on behalf of an agent...
const headers = await buildOutboundDelegationHeaders({
  session,           // The current SessionContext
  delegation,        // The DelegationRecord for this agent
  credentialJwt,     // The delegation credential as a VC-JWT
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

- KYA-OS §8: Outbound Delegation Propagation
- [kya-os.org/mcp](https://kya-os.org/mcp)
