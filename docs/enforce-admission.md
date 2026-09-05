# Enforce admission integration

The native Card guard is exported as `requireDelegatedInvocation` from `@kya-os/mcp/card`.
It composes the existing request-proof verifier and delegation-chain evaluator with mandatory credential-signature, revocation and resource-policy adapters.
It is an admission primitive; installing this package alone does not enable it on a managed tool.

## Handler contract

1. Select the resource owner, canonical resource and action from trusted tool/route configuration.
2. Pass the actual JSON-RPC `{ method, params }` request, with the incoming `params._meta` provided as the metadata argument.
3. Load the original signed delegation chain from the presentation or the existing grant store.
4. Supply an authoritative DID resolver, issuer assertion-method signature verifier, authenticated status-list reader and shared atomic nonce store.
5. Implement `authorizeInvocation` to bind authenticated consent to the resource account and evaluate every caveat against the operation, including unknown-caveat rejection.
6. Invoke the business handler only when the guard returns `ok: true`.

The guard requires a proof on every request, signatures on all chain hops, the configured root issuer, a constant resource target, attenuation, validity, matching leaf holder, permitted action and fresh revocation status for every credential.
The stricter live-status requirement is this guard's admission policy, not a claim that every protocol credential is required to publish a status list.
It returns the actual root issuer as `responsibleParty` and the verified request signer as `leafInvoker`.
A human identifier inside a host-signed credential is not a human signature.

The mandatory adapters must fail closed.
Do not supply callbacks that return `true` merely because a credential parses or came from a cache.
Signature verification must verify the original document, cryptosuite and issuer's assertion authority.
Revocation lookup must authenticate the status-list credential, not just read its bitstring.
All adapters that fetch remote data must use trusted discovery and SSRF-safe fetching.

Stored-grant retries must reload and recheck the chain; the guard never caches an allow decision.
A token's `cnf.jkt` belongs to its authenticated request context and must not be shared across users in a long-lived guard.
For per-request token confirmation, create the guard with those verified token facts for that request while sharing the underlying nonce store.
Proof admission is not transaction deduplication: mutations still need application idempotency.

## Legacy profile migration

`wrapWithDelegation` uses the separate legacy `_kyaos_proof` profile.
With `holderBinding: "enforce"`, stored session grants no longer substitute for a fresh holder proof.
Unsupported subjects, including `did:web` in this legacy profile, are rejected.
Existing `off` and `warn` compatibility modes remain available for deliberate migration.
Named DID clients should use a supported native proof profile and authoritative DID resolution.

The native Card chain and legacy VC-JWT are different credential formats.
Do not cast or decode one into the other and claim signature verification succeeded.
The managed runtime's issuer, guard, storage adapter and installed bundle still require coordinated qualification before enabling this guard on a customer tool.

## Evidence and remaining integration

The invocation tests use real Ed25519 request proofs and exercise mandatory adapter composition, scope/resource/holder denial, saved-chain revocation, failed account policy and concurrent replay rejection.
Credential-signature and status-provider callbacks are test doubles in that suite; these tests do not qualify a production issuer or hosted status-list service.
The wider package test suite exercises the existing proof and chain primitives.
Managed runtime wiring, authenticated account policy, issuer/provider qualification and installed deployment acceptance remain separate release gates.
