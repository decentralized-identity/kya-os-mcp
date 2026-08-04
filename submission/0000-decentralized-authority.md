<!-- SPDX-License-Identifier: Apache-2.0 -->

# SEP-0000: Decentralized Authority Extension

| | |
|---|---|
| **Title** | Decentralized Authority: agent identity, delegated authority, and per-request proof-of-possession as an MCP extension |
| **Author** | Dylan Hobbs (@h0bb5) |
| **Sponsor** | None (seeking sponsor) |
| **Status** | proposal |
| **Type** | Extensions Track |
| **Extension id** | `org.kya-os/decentralized-authority` (see Rationale for the identifier-and-governance path on acceptance) |
| **Created** | 2026-07-28 |
| **PR** | 0000 (placeholder; file renamed to the PR number on filing) |
| **Associated group** | To be secured before filing: an MCP-side interest group (candidate paths: the authorization-extensions orbit, or a new agent-identity IG formed per the SEP guidelines). External standards home: DIF Trusted AI Agents Working Group (TAAWG) |
| **Extension maintainers** | Dylan Hobbs (@h0bb5); at least one additional maintainer from outside the KYA-OS project, to be named with the associated group |
| **Filing gates** | This draft does not file until three gates close: the official-SDK reference module (design complete, fork branch pending), the associated group, and a sponsor |

## Abstract

MCP's `2026-07-28` authorization stack answers which *user* authorized which *client* (core OAuth) and how an *enterprise* governs a session (the Enterprise-Managed Authorization extension).
No layer answers which *agent* is acting, under what verifiable delegated authority, with proof a third party can check later.
This SEP proposes an Extensions Track extension, `org.kya-os/decentralized-authority`, that adds exactly that layer: agent identity as a W3C DID, authority as a Verifiable Credential delegation chain with per-hop attenuation and revocation, and a self-contained per-request holder-of-key proof carried in `_meta`.
Every artifact verifies locally from signatures, with no round trip to a central authorization service; the default DID methods are `did:key` and `did:web`, and no distributed ledger is required or referenced.
The extension is strictly additive: no tools, no new methods, no sessions, no use of the `Authorization` header.
It is negotiated through the standard `extensions` capability map, degrades gracefully for unaware peers, and rejects undeclared clients in required mode using core `-32021`.
The wire binding is one short document; the underlying protocol is specified externally as a DIF TAAWG work item, with the implementation evidence described in Reference Implementation.

## Motivation

Three demand signals, all inside this venue:

1. `ext-auth` [issue #13](https://github.com/modelcontextprotocol/ext-auth/issues/13) asks how a downstream API can distinguish a request executed directly by a human from one executed by an autonomous agent acting on the user's behalf, today indistinguishable because the agent fully impersonates the user.
2. In [Discussion #804](https://github.com/modelcontextprotocol/modelcontextprotocol/discussions/804), a gateway-based authorization proposal, a commenter proposes the composing alternative: agents carrying signed delegation chains that any server verifies locally, with the gateway issuing delegation proofs rather than terminating trust.
   This extension specifies that alternative and composes with the gateway pattern rather than replacing it.
3. The [project roadmap's](https://modelcontextprotocol.io/development/roadmap) Enterprise Readiness priority calls for "end-to-end visibility into what a client requested and what a server did" and proposals for "gateway and proxy patterns", noting "much of the output will likely land as extensions".
   The non-repudiable per-request proof artifact is a direct mechanism for that audit-trail deliverable, and the outbound header registry is a direct mechanism for authorization propagation through gateways.

The operator need behind these signals: organizations deploying fleets of agents need delegated authority that is attributable (which agent, on whose authority), auditable after the fact by parties who were not present, and revocable without redeploying the fleet, across organizational boundaries where no shared authorization server exists.
The need is sharpest in regulated sectors such as healthcare, government, and financial services, where operators must evidence who authorized an action and what was done long after the session that did it has ended.
Non-repudiable per-request proofs and self-contained delegation chains are mechanisms for exactly those obligations, proposed here as an optional extension rather than as operator-specific infrastructure.

The `2026-07-28` revision hardened user-level OAuth, and `ext-auth` covers enterprise session governance and workload client credentials.
None of these establish agent-level identity, delegation semantics beyond token passing, or per-request proof a third party can re-verify after the fact.
This extension specifies that layer and composes with the existing ones: CIMD is its on-ramp, sender-constrained tokens fuse with its proofs via `cnf.jkt`, and EMA remains the enterprise session layer beside it.

## Specification

The complete wire binding is the accompanying extension specification ([`decentralized-authority.md`](./decentralized-authority.md), Apache-2.0), which defers normatively to the externally governed KYA-OS Protocol Specification and Entity Card profile.
Summary of the entire surface:

- **Negotiation**: a settings object (`version`, `proofProfiles`, `didMethods`, `required`) under `capabilities.extensions["org.kya-os/decentralized-authority"]`, carried per-request in `_meta["io.modelcontextprotocol/clientCapabilities"]` and in `server/discover` results; `{}` means supported with defaults.
- **Required mode**: servers with `required: true` reject undeclared clients with core `-32021`, carrying the core schema's `requiredCapabilities` member plus `error.data.reason: "extension_not_declared"`; optional servers degrade to core behavior, and `server/discover` is never gated so discovery stays reachable.
- **Request proof**: a self-contained holder-of-key proof under `_meta["org.kya-os/request-proof"]` (the role-named carrier of the `org.kya-os/proof.v1` profile), hash-bound to the request with `params._meta` excluded, audience-bound, nonce-fresh, 60-second lifetime, verified fail-closed.
- **Authority**: W3C VC delegation chains with subset-only attenuation, continuity, depth caps, and status-list revocation; referenced from proofs, never asserted.
- **Consent**: a signed challenge result whose proof binds the authorization URL against substitution.
- **Gateway propagation**: the `KYA-OS-*` outbound header registry with authoritative-versus-advisory trust tiers, plus body-free routing on the core `Mcp-Method`/`Mcp-Name` headers.
- **Errors**: no new numeric codes anywhere; snake_case reason codes ride `error.data.reason`.

## Rationale

**Why DID/VC rails rather than composing DPoP, Workload Identity Federation, and RFC 8693 token exchange.**
Comparison, including rows where the OAuth stack is stronger:

| Capability | DPoP + WIF + RFC 8693 | This extension |
|---|---|---|
| Per-request proof-of-possession | Yes, HTTP-bound (`htm`/`htu`) | Yes, bound to the JSON-RPC operation; composes with DPoP via `cnf.jkt` |
| Transport coverage | HTTP-only; undefined over stdio | Identical over stdio and Streamable HTTP (MCP is dual-transport) |
| Enterprise IdP maturity | Stronger | Conceded; a cost this proposal accepts |
| Verification without an AS round trip | No; validity and exchange are AS-mediated | Yes; local, from public keys |
| Cross-domain portability | Pairwise federation configuration per domain pair | The chain carries its own authority |
| Delegation with per-hop narrowing | Standardized nesting (RFC 8693 `act`); attenuation is AS policy, not verifier-checkable | Subset-only attenuation enforced by any verifier |
| Post-hoc third-party verifiability | Signed tokens verify while AS key history is retained; no self-contained grant chain | Chain and proof verify from the artifacts alone |
| Revocation staleness | Token lifetime | Status-cache TTL; a knob, not a solution, for both |
| Library ubiquity | Stronger | Conceded |

SEP-1932 (DPoP) and SEP-1933 (Workload Identity Federation) are in flight in this venue and address the token and workload layers; this extension composes with both via the `cnf.jkt` sender-constraint (Entity Card §8.6, §8.8) and never competes for the `Authorization` header.
Local verification and portable chains are the decentralization property the identifier names.

**Design inputs.**
The delegation model applies object-capability discipline rather than novel invention: authority flows only by explicit grant, every hop may only attenuate (subset-only actions, monotone caveats, narrowing validity; KYA-OS Spec §6.10), and an invocation must designate the specific resource it exercises (§6.4.1), the classic remedy to the confused deputy.
The credential shape profiles W3C ZCAP-LD capabilities carried as Verifiable Credentials, with revocation-as-delegable-permission recorded as future work in the governing specification (§6.5.1), a pattern familiar from UCAN.
The alternative authorization models in the table above were design inputs rather than foils: the `cnf.jkt` fusion exists precisely because RFC 9449's sender-constraint semantics were worth adopting wherever an authorization server supplies them.

**Identifier and governance on acceptance.**
As drafted, this is a vendor-prefixed extension whose normative core is externally governed, which SEP-2133 does not yet define a track for.
The proposed resolution, stated head-on: the intended entry path is `experimental-ext-` incubation with the associated interest group; on graduation through this SEP, the MCP binding document transfers to extension-repository governance under an `io.modelcontextprotocol` identifier, with MCP core maintainers holding ultimate authority over the binding, while the underlying KYA-OS specifications remain externally governed, the way EMA's profiled token machinery remains at the IETF.
The `org.kya-os/*` namespace then survives as the `_meta` key namespace of the underlying proof profile; core expects official extensions to define keys under `io.modelcontextprotocol/`, so whether those keys also re-point on graduation is an adoption-time decision the configurable `proofMetaKey` (KYA-OS Spec §7.6) leaves open.
One distinction is owed precision: the underlying specifications are DIF TAAWG work items under ratification review, not yet ratified standards; the SEP's claims rest on the published documents and shipped implementations, not on that pending status.
Stewardship is active rather than nominal: the TAAWG task force meets weekly, working-group review has already changed the specification (the proof-key separation and the exact request-hash canonicalization were external review findings, resolved in the 1.11.0 release), and the conformance suite gates every change in CI.
The identifier was settled in DIF TAAWG discussion (2026-07-28); it was chosen because "authority" covers identity, delegation, proof, and audit together, where "delegation" alone did not.

## Backward Compatibility

Strictly additive.
Unaware peers get core MCP end to end; discovery projections degrade to fetches, never failures; `2025-11-25` peers carry the declaration as an additive initialize-era member.
No core behavior, method, or schema changes.

## Reference Implementation

- **[`@kya-os/mcp`](https://www.npmjs.com/package/@kya-os/mcp) (TypeScript, npm)**: proof generation and fail-closed verification, delegation-chain evaluation, and discovery emitters (published 1.11.0); the negotiation module and `-32021` admission guard are on the repository's `main` branch, shipping in the next release.
- **[`kya-os-verify`](https://pypi.org/project/kya-os-verify/) 0.2.0 (Python, PyPI, beta)**: an independent, stdlib-only verify-side implementation, re-verifying the TypeScript-minted vectors in CI (cross-language JCS and Ed25519 parity, one-directional today).
- **[Conformance vectors](https://github.com/decentralized-identity/kya-os-mcp/tree/main/conformance/vectors)**: a 44-vector machine-readable suite, including 8 negotiation vectors covering declared, absent, malformed, empty-object, initialize-era, and discovery-exemption cases against optional and required servers, with the [stdlib Python verifier](https://github.com/decentralized-identity/kya-os-mcp/blob/main/conformance/verify.py) as the second implementation for the proof and audit vector categories.
- **Live deployment**: [poc.kya-os.ai](https://poc.kya-os.ai) (guided walkthrough) against [demo-mcp.kya-os.ai](https://demo-mcp.kya-os.ai/provenance), demonstrating the underlying protocol stack: DID-anchored identity, per-request proofs, live revocation, and tamper and replay rejection against the shipped verifier.
- **Official SDK (the Extensions Track review gate)**: an opt-in, disabled-by-default module for the TypeScript SDK v2 line, designed against the v2.0.0 release at a pinned commit.
  Every seam the module needs is a public v2 API (capability registration on both roles, `server/discover` passthrough, transport decoration for the admission gate, per-request `_meta` access, and `-32021` with a preserved `data` payload), so the module requires **zero SDK core changes**.
  The accompanying design note ([`sdk-v2-module-design.md`](./sdk-v2-module-design.md)) specifies the API, gate placement, carriage normalization, and a 7-10 person-day estimate.
  The fork-branch prototype is a filing gate: per SEP-2133 this SEP is pre-review until it exists, and it is sequenced before filing, not after.

A conformance scenario and the SEP-2484 traceability file will be prepared from the existing vector suite during review.

## Security Implications

The extension's security analysis lives in the governing specifications and is summarized in the extension document's Security Considerations.
The SEP-relevant points: capability declarations are unauthenticated `_meta` and are handled fail-closed (stripped equals absent, never accepted as authenticated); replay prevention is honestly scoped (stateless proof construction, stateful verification, with the same multi-replica bound DPoP's `jti` tracking carries); discovery fetches are mandatorily SSRF-hardened; and privacy is addressed with pairwise-DID support and a claim-minimal card, with no globally stable identifier required for conformance.
The threat model is enumerated rather than asserted: the governing specifications carry per-threat tables with mitigations and named residual risks (KYA-OS Spec §11.1; Entity Card §12.10), the conformance suite's negative vectors are those attacks in executable form (tampered bodies and signatures, wrong audiences, expired windows, kid-to-did forgeries, absent replay seams, malformed and stripped declarations), and the public walkthrough demonstrates tamper, replay, stolen-key, and live-revocation handling against the shipped verifier.
