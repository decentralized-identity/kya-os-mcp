# Deferred breaking changes

Internal maintenance ledger.
Every entry here is a compatibility affordance the codebase carries deliberately: current releases are fully backward compatible, and each affordance can only be removed (or a default flipped) in a major release, whenever one is undertaken.
Nothing in this file is a schedule or a commitment to any release.

When adding a compatibility affordance elsewhere in the codebase, add a row here in the same change; when a major release is eventually planned, this file is the checklist of candidates to deprecate or remove.

| Affordance carried today | Action at a future major | Where it lives |
|---|---|---|
| Response-proof profile default is body-only `responseHash` coverage; the envelope profile is opt-in via `responseProofProfile` | Consider flipping the default emit profile to envelope coverage (older verifiers reject envelope-profile proofs, so this is breaking for un-upgraded clients); body-profile verification support itself can remain indefinitely | `src/middleware/with-kya-os.ts` (default resolution), `src/middleware/with-kya-os.config-types.ts` (`responseProofProfile`), SPEC.md §7.3 |
| Legacy bare `_meta.proof` response-proof mirror is emitted by default (`emitLegacyProofKey`) and read-accepted | Stop emitting the mirror; drop read acceptance | `src/proof/generator.ts` (`LEGACY_PROOF_META_KEY`), `src/middleware/with-kya-os.config-types.ts` (`emitLegacyProofKey`), SPEC.md §7.6 |
| Legacy namespaced response-proof key `org.kya-os/proof` is read-accepted (canonical: `org.kya-os/response-proof`) | Drop read acceptance of the legacy key | `src/proof/generator.ts` (`LEGACY_NAMESPACED_PROOF_META_KEY`), SPEC-MCP-EXTENSION.md §2, SPEC-ENTITY-CARD.md Appendix |
| Legacy request-proof carrier key and `prf` value `org.kya-os/proof@1` are accepted (canonical: `org.kya-os/request-proof` carrying `org.kya-os/proof.v1`) | Drop acceptance of the legacy key and legacy `prf` value | `src/card/proof/types.ts` (`LEGACY_CARD_PROOF_META_KEY`), `src/card/schema.ts` (`LEGACY_PROOF_PROFILE_ID`), `src/card/middleware.ts`, SPEC-ENTITY-CARD.md §8.1 |
| `revocation.ts` alias exports duplicating identically named exports | Remove the alias | `src/card/revocation.ts` |
| Producers hash a tool call's `requestHash` over the legacy `{method: <tool name>, params: <arguments>}` shape; verifiers also accept the SPEC §7.3 covered `tools/call` request | Producers switch to the SPEC §7.3 shape in 2.0.0; verifiers accept both until then | `src/proof/covered-request.ts` (`alternateRequestShapes`), `src/proof/generator.ts` (`acceptedRequestHashes`), `src/middleware/with-kya-os.session.ts`, `src/middleware/with-kya-os.policy-gate.ts`, `src/delegation/holder-binding.ts` (`toHolderBindingRequest`), SPEC.md §7.3 |
| `DelegationChainContext.maxDepth` is kept, deprecated, as an alias for `maxChainLength`, which wins when both are set | Remove the alias | `src/card/delegation.ts` |
| `ProofVerifier.verifyProofDetached` is kept, deprecated; the payload it takes must equal the one `verifyProof` rebuilds from `meta` | Remove the method | `src/proof/verifier.ts` |
| Session-bound proof era coexists with the self-contained card-proof era on distinct `_meta` keys | Expected deprecation of the session profile in favor of the self-contained profile | SPEC-MCP-EXTENSION.md §12 |
| `withPolicyGate` and `proveOutcome` are optional members of `KyaOsMiddleware`, so structural implementers and mocks written before them still type-check; `createKyaOsMiddleware` always provides both | Make both required | `src/middleware/with-kya-os.types.ts` (`KyaOsMiddleware`) |
| The delegation gate's default `needs_authorization` challenge carries no `isError`, while the policy gate's step-up result carries `isError: true` (pinned by a test) | Consider defaulting the challenge to `isError: true`, which changes the result for clients that treat an error result as a failure | `src/middleware/with-kya-os.delegation-verify.ts` (`buildNeedsAuthorizationChallenge`), `src/middleware/__tests__/challenge-format.test.ts` |
