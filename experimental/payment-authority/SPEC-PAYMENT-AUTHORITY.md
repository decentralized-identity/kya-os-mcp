# KYA-OS Payment Authority Profile: Core Authority

- **Status:** Experimental Working Group discussion draft; not ratified.
  Identifiers and schema URLs in this document are drafts (section 6) and
  are not deployed.
- **Profile:** `org.kya-os/payments.v1`
- **MCP extension:** `org.kya-os/payment-authority`
- **Depends on:** `org.kya-os/decentralized-authority`
- **Date:** 2026-10-20
- **Scope:** the payment intent, authorization, constraints caveat, and outcome
  artifacts; their digests; money; identifiers; evidence references; and MCP
  extension negotiation.
- **Out of scope:** request binding, the processing algorithm, idempotency and
  recovery, rail adapters, approval evidence formats, and the envelopes that
  carry an artifact across a trust boundary (section 8.5). These are defined
  by a separate execution profile, in preparation, which this document calls
  **the execution profile**.

This folder holds the profile's machine-readable artifacts: seven JSON Schema
files — `payment-intent.schema.json`, `payment-authorization.schema.json`,
`payment-constraints.schema.json`, `payment-outcome.schema.json`,
`payment-extension-settings.schema.json`, `payment-profile-meta.schema.json`,
and `payment-profile-vocabulary.schema.json` — and the Core Authority vector
corpus, `vectors/payment-authority-vectors.json`, with its verifier,
`vectors/verify_vectors.py` (section 15.1).

This profile is unrelated to, and claims no compatibility with, ACP's
independently defined Delegate Payment API. Namespace placement under a DIF or
MCP registry remains a Working Group decision (see Open Working Group
decisions).

## 1. Abstract

This profile binds a KYA-OS delegation and holder-of-key request proof to exact
economic intent for a named payer, a deterministic authorization decision, and
durable payment outcome evidence. Executing a payment, idempotently, is the
subject of the execution profile.

It is deliberately **not a payment rail, checkout protocol, wallet, credential
format, or settlement network**. A commerce protocol such as UCP or ACP can
construct a checkout. AP2 or another mandate format can supply user-intent
evidence. x402, a card processor, a bank rail, or another adapter can authorize
or settle value. KYA-OS answers the orthogonal questions:

1. Which agent is acting?
2. Which accountable party delegated the action, and which party pays?
3. Does the current delegation permit this payee, resource, action, amount, and
   time window?
4. Is the caller proving possession of the delegated key for this exact
   request?
5. Which immutable intent, authorization decision, and payment outcome can be
   audited later?

This separation lets implementations add payment rails without giving each rail
a new identity and delegation model.

This draft does not claim that payment intent, mandates, delegation, spending
limits, or receipts are individually novel. Its proposed contribution is their
composition with multi-hop organizational delegation (up to this profile's
ten-hop limit, section 8.4), live status and revocation, accountable-party
attribution, binding to the exact request digest, and rail-neutral outcome
evidence.

## 2. Design goals

The profile is designed to be:

- **Rail neutral.** Protocol, method, handler, scheme, network, transfer
  method, payment flow, asset, and transport identifiers are distinct.
- **Commerce neutral.** UCP, ACP, direct x402, and application-specific checkout
  flows can all bind the same payment artifacts.
- **Fail closed.** Unknown critical extensions, unevaluable caveats, stale
  authority, changed terms, ambiguous money, and unresolved settlement never
  silently degrade, and a settlement read before the rail's own final state
  says so wherever it leaves the Executor (section 8.3).
- **Deterministic.** Whatever proposes the business inputs, deterministic code
  verifies identity, delegation, approval, constraints, signatures,
  idempotency, and settlement state.
- **Developer friendly.** Application code handles normalized intent and
  outcome objects. Rail adapters encapsulate wallets, credentials, signatures,
  gas, facilitator APIs, and native payloads.
- **Auditable without leaking credentials.** Public records carry digests and
  safe references, not card data, private keys, bearer tokens, or payment
  payloads.
- **Additive to the base protocol, with named exceptions.** Existing KYA
  Entity Cards, delegations, request proofs, revocation, and audit machinery
  are unchanged, and a delegation that carries no payment caveat behaves exactly
  as before. The profile depends on the five base amendments it proposes to
  the Working Group in `BASE-AMENDMENTS.md` (open decision 10):
  profile-defined caveat narrowing (SPEC.md §6.10, section 8.4.3), the
  description of a payment chain's root issuer (sections 4.1, 8.1, and 8.2),
  the
  reading of the SPEC.md §11.6 per-hop audience rule for VC 2.0 + ZCAP chains
  (on which the verification of every multi-hop chain, section 8.4.6, step 8,
  and the execution profile's request binding rely), the
  registration of its `_meta` keys (section 11.1), and authenticated,
  time-bounded status reads (section 14, item 19). All five are additive in
  behaviour (`BASE-AMENDMENTS.md` item 3 is a reading of the SPEC.md §11.6
  requirement that non-root credentials carry an `audience` constraint, not
  an addition to it), except that the proposed status reading makes a
  validity window's end exclusive, so a status list is stale at the exact
  instant of its `validUntil`. The profile also reads, as
  exclusive ends that no clock skew extends, a request proof's `expires`
  wherever it bounds payment authority (sections 7.1 and 8.2), which
  SPEC-ENTITY-CARD Appendix D.1 counts as `expired` only once
  `expires < now - skew`, where `skew` is the base's request-proof skew
  (section 7.1), and a delegation credential's `validUntil` and a
  `ValidUntil` caveat's `date` (section 8.4.6, step 5), which the base chain
  verifier accepts at that exact instant: a payment decided at or after such
  an end is refused (`proof_invalid` or `payment_delegation_invalid`).
  Answering `proof_invalid` for a request proof that the base still counts as
  unexpired, from its `expires` through `expires` plus that request-proof
  skew, is a profile
  extension of that base reason, which SPEC-ENTITY-CARD Appendix D.2 defines
  for a proof that did not verify (section 13). No ratified specification
  text is changed. A base verifier that does not
  implement the profile treats the payment caveat as unknown and accepts only
  verbatim re-delegation, so a chain whose payment caveat narrows is
  verifiable only by profile-aware verifiers, for every action it grants.
  (Informative: payment authority is therefore best issued in dedicated chains
  whose `allowedAction` contains only payment actions, section 8.4.)
- **Executor-scoped in version 1.** A payment chain authorizes payments at one
  Executor's protected resource; open-world, multi-Executor delegation is open
  decision 9.

## 3. Non-goals

This profile does not:

- define catalog, cart, tax, shipping, order, refund, or dispute APIs, or
  authorize refunds and reversals (value moving from payee to payer);
- replace UCP, ACP, AP2, x402, W3C Payment Request, or payment processors;
- make a KYA delegation into money or prove that funds exist;
- make a payment signature into permission to buy a resource;
- promise globally exactly-once settlement;
- place payment credentials, wallet keys, or sensitive rail payloads in KYA
  credentials, MCP context, or audit logs;
- standardize foreign signed artifacts by parsing and reserializing them; or
- require a blockchain, blind signatures, or any single signature algorithm.

## 4. Layered model

```text
 commerce lifecycle      UCP | ACP | direct application checkout
          │
 user-intent evidence    AP2 | human approval | policy credential
          │
 KYA authority           identity → delegation → current status → holder proof
          │
 payment profile         exact intent → authorization binding → durable outcome
          │
 rail adapter            x402 | card | bank | wallet | closed-loop credits
          │
 transport               MCP (normative in v1) | HTTP | A2A | browser surface
```

No layer silently stands in for another. In particular:

- AP2 is authorization evidence, not a settlement rail.
- x402 is payment negotiation/verification/settlement, not a general commerce
  lifecycle or delegated-authority system.
- MCP and A2A are transports, not payment guarantees.
- A base `MaxAmount` caveat is a per-request ceiling.

This document defines the payment-profile layer's artifacts and their
negotiation. The rail-adapter layer, and the binding of the artifacts to a
transport request, are defined by the execution profile.

### 4.1 Parties and roles

The profile uses these party terms exactly; each is derived from verified
material, never accepted from the caller. The Executor's authentication of the
request derives the actor and the caller from the request proof, and the
payee's admissibility from the intent; the Authority Verifier derives the
principal, the responsible party, and the approval subject from the chain and
the evidence it verifies, and checks the payer against them:

| Term | Meaning | Derived from |
| --- | --- | --- |
| `actor` | The agent performing the request | the DID proven by the request proof, which MUST equal the delegate of the chain's leaf credential |
| `principal` | The immediate delegator of the actor | the issuer of the leaf delegation credential |
| `responsibleParty` | The accountable party for the payment authority | the issuer of the root delegation credential (SPEC-ENTITY-CARD §10.2) |
| `payer` | The party whose funding source is debited | the intent's `payer`, which MUST equal `responsibleParty` |
| `caller` | The authenticated party whose idempotency namespace a key lives in | the proof DID (the actor), which the Executor's authentication derives with the idempotency scope |
| `payee` | The party that receives value | the intent's `payee`, whose `id` MUST be one of the payees the Executor serves: those its deployment configures, by default only the payee whose `id` is the `tenant` of its idempotency scope (section 8.2), checked before step 1 of section 8.4.6 (section 14, item 22) |
| approval `subject` | The person or party who approved, as the authenticated issuer of the approval evidence asserts | verified approval evidence only; the Authority Verifier does not authenticate the subject itself (section 8.2) |

(Informative: the execution profile also requires the rail terms an Executor
accepts to pay exactly the intent's `payee`.)

A credential's **delegate** is the base's: its `credentialSubject.invoker`, or
its `credentialSubject.controller` when it names no invoker (SPEC.md §6.10).
The **delegates of a chain** are the actor and the delegate of every credential
in it. The **issuer** of a credential, a delegation credential or a status-list
credential, is the identifier its `issuer` member names: the member itself
when it is a string, and its `id` when it is an object, the two forms the base
delegation credential admits. Every comparison this profile makes with an
issuer (the principal, the responsible party and the payer, a credential whose
delegate is its own issuer, an accepted payer, and a status list's issuer,
section 14, item 19) uses that identifier.

Authority-bearing roles are DIDs in v1. A DID-Linked Resource (DLR) is a resource
controlled by a DID, not a party identity; it can anchor status lists, policy, or
batched audit commitments but is never required and never identifies a role. An
OAuth client identified by Client ID Metadata (CIMD) is software, not a person;
an OAuth or OIDC login proves authentication, not economic approval.

### 4.2 Conformance roles

An implementation declares one or more roles; conformance to one role does not
imply conformance to another. Each role's duties in request processing,
idempotency, recovery, and answering are defined by the execution profile; the
role descriptions below state what bears on the artifacts of this document:

- **Agent/Client:** constructs the immutable intent, or receives it from the
  party that constructed it. An intent that names no presenter is shared; a
  client that constructs an intent for one agent names that agent as its
  presenter (section 8.1).
- **Authority Verifier:** for a request the Executor authenticated, verifies
  the delegation chain, every caveat, current status, constraint attenuation,
  approval evidence, payer, and exact intent, in the order of
  section 8.4.6; it alone may produce the authority facts that a Payment
  Authorization records (section 8.2), and
  it names every delegate of the chain so no delegate's approval is accepted
  (section 8.2). It MUST register the
  `org.kya-os/payment-constraints` narrowing relation with its base chain
  verifier. It does not authenticate the request: the Executor does, once.
- **Gateway/Intermediary:** either forwards proof-covered bytes unchanged or
  authenticates the request itself, as the execution profile requires of an
  Executor, acts as a new Authority Verifier, and issues a separately
  authenticated Payment Authorization. Rewriting a request never preserves the
  original end-to-end authorization implicitly. A Gateway/Intermediary that
  issues its own Payment Authorization conforms as an Authority Verifier for
  that authorization, and as a Payee/Executor where it executes the payment;
  the role has no test group of its own (section 15). One that only forwards
  proof-covered bytes has no Core Authority duty.
- **Payee/Executor:** authenticates each request exactly once — verifies its
  KYA request proof and consumes its nonce — performs durable idempotency,
  makes the checks that the request and the intent alone decide, before step 1
  of section 8.4.6 (the intent's audience, payee, presenter against the DID of
  the request proof it authenticated, `createdAt`, expiry, and extensions, and
  that proof's `expires`), bounds every authorization by that proof's
  `expires`, and, under the execution profile, executes the payment and
  records its outcomes. An Executor MUST use what its authentication of a
  request established only for that same request: it accepts from an Authority
  Verifier only facts that name the digest of that request and the
  holder-proof digest (section 10) of the request proof it verified, and lets
  one request back at most one authority decision.
- **Evidence Consumer:** verifies artifacts, their digests, and outcome
  streams (section 8.3), and, under the Portable Evidence tier, envelopes,
  producer authority, authorization to retrieve evidence, and retention
  policy, without assuming it can execute a payment.

The party that issues approval evidence is a role of the execution profile,
which defines it with the approval evidence formats and their tests. This
document uses only what a verified approval yields: the approval facts that
intent evaluation reads and the approval a Payment Authorization records
(section 8.2).

A delegator — the payer, or a delegate that re-delegates — issues the payment
constraints caveat inside its delegation credential, under the base delegation
rules (SPEC.md §6.10). This document defines what a well-formed caveat is and
how it attenuates (section 8.4); the Authority Verifier's checks decide whether
one is accepted. Issuing a caveat is not a separate conformance role: the
`constraints` and `narrowing` vectors (section 15.1) state the results an
issuer's caveats are held to.

### 4.3 Conformance tiers

The profile is divided so that interoperability additions do not enlarge the
mandatory authority core:

1. **Core Authority:** the union of the duties that section 4.2 assigns each
   role over the artifacts of this document. An implementation meets this
   tier for the roles it claims, and no role has to produce what section 4.2
   assigns to another. Every role validates each artifact it accepts
   (section 8.7) and applies the digests (section 10), money (section 7),
   identifiers (section 6), and evidence references (section 9) to it. In
   addition, the Agent/Client constructs or receives the Payment Intent
   (section 8.1) and declares its side of the MCP extension negotiation
   (section 11); the Authority Verifier verifies the chain, its payment
   constraints caveats and every other caveat, the approval evidence, the
   payer, and the intent by the attenuation, caveat, and intent-evaluation
   rules, in the verification order (section 8.4), and alone produces the
   authority facts that a Payment Authorization records (section 8.2); the
   Payee/Executor makes the checks that precede that order (section 8.4.6)
   and serves the negotiation (section 11); and
   the Evidence Consumer verifies Payment Authorizations and Payment
   Outcomes, their digests, and an outcome stream by the seven stream checks
   of section 8.3. This tier is
   REQUIRED for profile conformance, for each role an implementation claims.
   It produces no Payment Outcome. It defines no approval evidence format
   (section 8.2), so a Core-only Authority Verifier, which implements none,
   can never authorize a payment whose effective constraints require approval
   for it.
2. **Execution:** request and response binding, durable idempotency, rail
   execution, and producing Payment Outcomes (when each state is recorded,
   when a failure names a `basis`, and when an outcome carries `correction`
   or `finality`; section 8.3). A **payment effect** is any step that can move value at a
   rail. This tier is REQUIRED for an implementation that creates payment
   effects. Its processing rules are defined by the execution profile.
3. **Portable Evidence:** signed outcome streams, the envelopes that carry a
   Payment Authorization or a Payment Outcome across a trust boundary
   (section 8.5), retrieval, retention, and dispute evidence. This tier is
   OPTIONAL unless outcomes cross a trust boundary. Its envelopes and its
   tests are defined by the execution profile.
4. **Interop:** UCP, ACP, AP2/Verifiable Intent, x402, card, bank, or other
   mappings. Each mapping is independently optional; its requirements and
   tests are the execution profile's (section 12).

Execution requires a verified Entity Card request proof (SPEC-ENTITY-CARD §8)
at proof assurance `L3-minus` or `L3` (SPEC-ENTITY-CARD §9), a verified
delegation chain, and a live (fresh) status read of every delegation in the
chain. Every credential in a
payment chain MUST carry a status entry whose `statusPurpose` is `revocation`
(section 8.4), so that every hop is independently and finally revocable. A
bearer-only, unproven, or stale-status request MUST NOT create a payment
effect. Version 1 defines the normative binding for MCP (section 11 and the
execution profile); HTTP and A2A bindings are informative (section 12.10).

## 5. Normative language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when,
and only when, they appear in all capitals, as shown here.

Sections 1 to 3, the layered model that opens section 4, examples, and text
marked informative are informative; the rest of this document is normative.
An algorithm (the attenuation rules of section 8.4.2, the rule tables of
sections 8.4.4 and 8.4.5, and the verification order of section 8.4.6)
carries the force of the requirement that introduces it, and an
implementation MAY realize it by any means that gives the same results.

## 6. Identifiers

Each identifier below has only the meaning the table gives it. The party that
produces an artifact MUST NOT use one of these identifiers to carry the meaning
of another row, and a party that reads one MUST NOT read it as another row's
identifier: for example, a `handlerId` never stands for a `methodId`, and a
request or correlation id never deduplicates an effect.

| Identifier | Meaning |
| --- | --- |
| `commerce.id` | Commerce protocol, such as UCP. |
| `payment.protocol.id` | Rail protocol, such as x402. |
| `payment.protocol.specDigest` | The `sha256:` digest of the specification the protocol locator serves, when `id` is an HTTP(S) locator (below). |
| `methodId` | W3C Payment Method Identifier or explicitly namespaced equivalent. |
| `handlerId` | Commerce/payment handler selected for the checkout. |
| `scheme` | Protocol-specific execution scheme, such as an x402 scheme. |
| `network` | Network identifier; CAIP-2 SHOULD be used for chain-specific rails. |
| `transferMethod` | How the rail authorizes or moves value for the scheme on the network, such as an x402 `assetTransferMethod`. |
| `paymentFlow` | When the rail settles relative to the purchase, such as an x402 `paymentFlow`. |
| `redeemableByOthers` | The credential policy an intent signs: present when a credential others can redeem may pay it (section 8.1). |
| `fundingAccount` | The account every credential for an intent debits, as its rail mapping spells accounts; required with `redeemableByOthers` (section 8.1). |
| `asset` | ISO 4217, CAIP-19, or `uri` asset identifier (section 7). |
| `intentId` | Application-generated stable id for one immutable payment intent. |
| `payer` | DID of the accountable responsible party whose funding source is debited. |
| `presenter` | DID of the one agent that may present an intent; an intent without it is shared. |
| idempotency `key` | Effect-deduplication key, bound to one request digest. |
| request/correlation id | Observability only; never assumed to prevent effects. |

The party that constructs an intent MUST record in `commerce.version` and
`payment.protocol.version` the exact version, as its protocol spells it, of
the commerce protocol and of the rail protocol that the payment uses, never a
normalized or lower one, and a party that compares one of them with another
version compares the two as exact strings, as rule `intent.rail` of
section 8.4.4 does. A mismatch is an explicit error, never permission to
downgrade. Payment-artifact versions (each artifact's `schema` and `profile`,
and the payment caveat's `version`) and critical-extension versions are
likewise matched exactly, never by compatibility (sections 8 and 8.4, and
check V5 of section 8.7); the MCP extension settings instead follow the base
extension's additive versioning (section 11).

An HTTP(S) commerce or payment protocol locator MUST carry `specDigest`, which
the party that records it computes as SHA-256 over the octets the locator
serves for the specification (the HTTP response content, any content coding
removed), with no canonicalization and no domain separation (section 10). No
rule of this document fetches a locator or recomputes its `specDigest`: every
party compares `specDigest` values as exact strings (section 8.4.2, rules 2
and 4; rule `intent.rail`, section 8.4.4; and the binding of an outcome
stream, section 8.3). The locator SHOULD itself be immutable (a
commit-pinned raw file URL, or a dated release URL whose publisher commits never
to change it), because a digest of a mutable page cannot be re-derived later. A
stable non-HTTP registry identifier MAY omit `specDigest`.

**Draft identifiers.** Every identifier this profile defines is a draft that
may change before ratification: the profile `org.kya-os/payments.v1`, the MCP
extension `org.kya-os/payment-authority` and its settings version `1.0.0`, the
caveat type `org.kya-os/payment-constraints` and its version `1.0.0`, the
`org.kya-os.payments.*.v1` digest domains (section 10), the `_meta` keys of
section 11.1, the schema URLs, and the vocabulary URI. The schema URLs are the
`$id` of each schema in this folder:
`https://schema.kya-os.org/experimental/payment-authority/2026-09-22/`
followed by `intent` (section 8.1), `authorization` (section 8.2), `outcome`
(section 8.3), `constraints` (section 8.4), `mcp-extension-settings` (the
extension settings of section 11, in
`payment-extension-settings.schema.json`), `meta` (the profile meta-schema,
section 8.6), or `vocabulary/semantic-validation/schema` (the vocabulary's
meta-schema, `payment-profile-vocabulary.schema.json`); the vocabulary URI is
that prefix followed by `vocabulary/semantic-validation` (section 8.6). None
of them is stable: ratification may keep or replace each of them, and always
replaces the schema URLs and the vocabulary URI with new immutable versioned
identifiers, as section 8.1 states for the intent's. The execution profile
lists the draft identifiers it defines, those of its approval evidence formats
and of its answer proof among them.

## 7. Money representation

Floating point MUST NOT be used for value-bearing fields.

```json
{
  "asset": { "namespace": "iso4217", "id": "CHF" },
  "coefficient": "3980",
  "scale": 2
}
```

The value is `coefficient × 10^-scale`. `coefficient` is a canonical
non-negative integer string of at most 78 digits with no sign, leading zero,
decimal point, exponent, or separator; the only zero encoding is `"0"`. `scale`
is an integer from 0 through 255. Amounts compare by exact value across scales;
`{"coefficient":"10", "scale":0}` and `{"coefficient":"1000","scale":2}` are
equal.

The unit is the asset's whole unit in every namespace: the ISO 4217 major unit
(CHF 39.80 is `3980` at scale 2), one whole token for a CAIP-19 fungible asset
(44.5 USDC is `44500000` at scale 6), and the unit its defining specification
names for a `uri` asset. (Informative: converting an amount to rail-native base
units is the rail adapter's work under the execution profile, which refuses an
amount the asset's decimals cannot represent exactly, after removing trailing
zeros, rather than rounding it.)

Where this profile hashes a set of amounts it has normalized (effective
payment constraints, section 8.4), each amount is first reduced to its
**minimal scale**: trailing zero digits are removed from the coefficient while
`scale > 0`, and zero is always `{"coefficient":"0","scale":0}`. Equal
quantities therefore produce identical canonical bytes. Signed artifacts such
as the Payment Intent keep the exact representation their signer produced.

A zero business amount is structurally representable but version 1 defines no
zero-value operation profile, so the Authority Verifier MUST deny every
zero-value intent:
one whose business amount is zero, and one that states a zero
`settlementAmount` (rules `intent.nonZeroAmount` and
`intent.nonZeroSettlement`, section 8.4.4), so zero never stands for an
unspecified or later-selected amount.

The **effective settlement amount** is `payment.settlementAmount` when present,
else the business `amount`. It is the exact native amount a rail may move for
the intent, excluding payer-borne fees. **Payer-borne fees** are amounts charged
to the funding source in addition to the effective settlement amount; fees
borne by the payee (for example a merchant discount rate) are outside the
payer's authority and are not reported to it.

Asset namespaces are:

- `iso4217`: exactly three uppercase letters;
- `caip19`: a CAIP-19 asset identifier; or
- `uri`: an identifier defined by another specification, which matches the
  URI pattern of section 8.6, a coarse filter rather than the RFC 3986
  syntax.

In this profile's artifacts, asset identifiers compare as exact,
case-sensitive strings and are never normalized. Each deployment uses one
spelling per asset in them — for a CAIP-19
`eip155` token, the EIP-55 checksummed address its rail reports — and an amount
spelled differently from its delegation's limit does not match it and is
denied.

The business amount and settlement amount are separate. A conversion
(section 8.4.4), such as a CHF checkout paid in USDC, keeps both in the intent,
the business `amount` and `payment.settlementAmount`, and binds the quote that
converts one into the other by `quoteDigest` (section 8.1). This profile does
not define exchange-rate discovery.

Rail-native signed bytes stay outside the core artifacts, which reference them
by digest (section 9). A normalized amount never replaces the bytes that were
actually signed.

A payee's `accountDigest`, in an intent or in a payment caveat's `payees`, is
produced by the construction its `accountDigestMethod` names:
`opaque-token-sha256` (SHA-256 of a high-entropy rail token), `hmac-sha256` (a
keyed commitment to the account identifier), or `issuer-attestation-sha256`
(SHA-256 of an issuer-signed opaque account identifier). The party that
produces the commitment MUST NOT use an unkeyed digest of a PAN, IBAN,
routing/account pair, wallet address drawn from a small allowlist, or another
low-entropy identifier. This is the producer's obligation alone: a digest does
not reveal its construction, so no consumer can detect a violation from the
artifact. Which key or issuer a commitment uses, and how a party that checks
an account learns it, are defined by the execution profile's rail adapter
rules.

### 7.1 Time normalization

Payment artifacts use integer Unix epoch milliseconds from 0 through 2^53 − 1.
Base proof timestamps in seconds are multiplied by 1,000 with checked integer
arithmetic. An RFC 3339 bound is accepted only as `YYYY-MM-DDTHH:MM:SS[.fff]`
(ASCII digits only) followed by `Z` or a `±HH:MM` offset, matched in full, and
the lowercase `t` and `z` that RFC 3339 §5.6 permits are accepted. The
fraction has at most three digits, the hour field is at most 23, the minute
field at most 59, the second field at most 59, and an offset is at most 23
hours and 59 minutes. A party that reads a bound MUST refuse one whose
calendar date does not exist, one that names a leap second, one with
sub-millisecond precision, one before the Unix epoch, and any other bound that
cannot be represented without loss. Starts are inclusive and expiries are
exclusive. The authorization expiry is computed only after normalization and
is the minimum of all applicable bounds. Clock-skew policy MAY decide proof
freshness but MUST NOT extend the expiry of an intent, a delegation, an
approval, or a status list, and MUST NOT extend a request proof's `expires`
where it bounds an authorization (section 8.2). The execution profile applies
the same rule to the expiries it reads from the rail, a quote's among them.

One verification uses one **decision clock**: a single epoch-millisecond value
against which proof freshness, delegation validity, caveat bounds, status
freshness, approval expiry, and every expiry bound are all evaluated. An
implementation MUST NOT evaluate parts of one decision against different
clocks; in particular the authority decision for an authenticated request runs
at the instant of its authentication.

The profile defines one clock skew of its own, 60 seconds, for the timestamps
of its artifacts, and assumes that the clocks of the parties differ by less
than it. It applies this 60-second skew to an intent's `createdAt`: the
Executor MUST refuse, with `payment_request_invalid`, a request whose intent's
`createdAt` is more than 60 seconds after the decision time, before step 1 of
section 8.4.6. It applies it too to the `created` of a credential's or a
status list's proof (section 8.4.6, step 3). The 60-second skew never extends
an expiry.

The skew a request proof is checked with, the request-proof skew, is not this
one but the base's (SPEC-ENTITY-CARD §8.2). Wherever a request proof's
`expires` bounds payment authority, this profile reads it as an exclusive end
that no skew extends: the Executor MUST refuse, with `proof_invalid` and
before step 1 of section 8.4.6, a payment request whose decision time is at
or after the `expires` of its request proof, although SPEC-ENTITY-CARD
Appendix D.1 counts that proof as `expired` only once `expires < now - skew`.
Answering `proof_invalid` for a proof that the base still counts as
unexpired, from its `expires` through `expires` plus the request-proof skew,
is a profile extension of that base reason, which SPEC-ENTITY-CARD
Appendix D.2 defines for a proof that did not verify (section 13). The other
bounds of request-proof freshness for a payment request, such as how long
before the decision a proof may have been created, are defined by the
execution profile.

A rail is not a party: a
check against a rail uses the rail's own time in a final rail state, never a
party's clock.

The decision clock governs one verification. Execution steps after it read the
clock again, as the execution profile defines; the re-evaluation that precedes
a payment effect (section 8.4.4) evaluates at such a later reading, never at
the decision time.

Status freshness is judged at the decision clock too: a status list counts as
live only as section 14, item 19, states, at the decision time. A `ttl` is the
`ttl` member of the list's `credentialSubject`, in milliseconds as Bitstring
Status List v1.0 defines it, and is never parsed as a timestamp: it is valid
only as an integer from 1 through 2^53 − 1, and its end is the list's
`validFrom`, or its `issuanceDate` when it declares no `validFrom`, plus
`ttl`, summed exactly (an end beyond 2^53 − 1 is after every decision time).
A list whose `ttl` is not valid, or that declares a `ttl` and neither start,
is stale.

## 8. Core artifacts

Each artifact of this section is a JSON object. Appendix A lists every member
its schema admits, with that member's syntax; the subsections below define
what each member means. In the intent, the authorization, and the outcome,
`schema` is the constant identifier of its schema and `profile` is
`org.kya-os/payments.v1`; the payment caveat carries neither member and is
identified by its `type` and `version` (section 8.4). In every artifact,
times are epoch milliseconds (section 7.1), amounts those of section 7, and
digests the `sha256:` strings of section 10.

**Extensions.** The intent, the authorization, and the outcome can carry
`extensions`: a map of at most 64 entries, each keyed by an extension
identifier of 1 to 256 code points that the schemas' extension-identifier
pattern admits in one of two forms: a URI, which matches the URI pattern of
section 8.6; or a reverse-DNS name, two or more labels joined by `.`, each of
lowercase ASCII letters, digits, and `-` and neither starting nor ending with
`-`, followed by any number of segments, each a `/` or a `.` and then one or
more ASCII letters of either case, digits, `.`, `_`, `~`, or `-`. Like the URI
pattern, this is a coarse filter: it admits, for example, `org.example.UPPER`
and `org.example/../..`. The party that defines an extension SHOULD name it by
an RFC 3986 absolute URI, or by a reverse-DNS name under a domain it controls
whose path segments each follow a `/`. Each entry has `version`, the exact
version its data follows; `critical`, whether a receiver without a handler
for that exact version MUST refuse the artifact (check V5, section 8.7);
`data`, a canonical value (section 10) within the bounds of section 14,
item 6; and, optionally, `schema`, an identifier of the schema of `data` that
matches the URI pattern of section 8.6. The artifact's digest covers every
extension, understood or not.

### 8.1 Payment Intent

`PaymentIntentV1` contains the exact economic terms that KYA authority is being
used to execute. Its schema is:

`https://schema.kya-os.org/experimental/payment-authority/2026-09-22/intent`

The date-bearing experimental identifier is deliberately non-stable; the date
names the experimental draft series, not a revision. It is never copied into
the stable schema publication tree. Ratification requires a new immutable
versioned identifier; publication does not mutate this draft id.

Its members are:

- `intentId`, the identifier the application assigns to this one immutable
  intent (section 6);
- `createdAt`, the time the client created the intent, and `expiresAt`, the
  end of its validity (exclusive, section 7.1), which is after `createdAt`;
- `audience`, the Executor's DID: the audience of the request proofs; and
  `action`, the exact KYA action the payment exercises;
- `payee`, the party that receives value: its `id`, and optionally an account
  commitment, `accountDigest` together with the `accountDigestMethod` that
  produced it (section 7);
- `payer` and the optional `presenter` (below);
- `amount`, the business amount (section 7);
- `resources`, the purchased resources: 1 to 256, each an `id` naming the
  resource and a `digest` committing to its immutable terms (for example a
  checkout snapshot), no two with the same `id`;
- `commerce`, optional: the commerce protocol's `id` and exact `version`, its
  `specDigest` (section 6), and optionally the commerce `sessionId` (for
  example a checkout id) and `artifactDigest`, the digest of the commerce
  artifact the terms come from;
- `payment`, the selection: `protocol`, the rail protocol's `id`, exact
  `version`, and `specDigest` (section 6); the optional `methodId`,
  `handlerId`, `scheme`, `network`, `transferMethod`, and `paymentFlow`, each
  the identifier of section 6 of that name; and the optional
  `redeemableByOthers`, `fundingAccount`, `settlementAmount` (section 7), and
  `quoteDigest` (below);
- `purpose`, optional: text for display only, which no rule evaluates; and
- `extensions`, optional (section 8): any critical extension data needed to
  evaluate the intent.

The selection's `transferMethod`, `paymentFlow`, `redeemableByOthers`, and
`fundingAccount` are signed terms for the rail credential that pays the
intent, which the execution profile defines and checks against them.
`transferMethod` and
`paymentFlow` name the rail mechanism. `redeemableByOthers`, the literal
`true` when present, signs the credential policy: a rail credential others can
redeem may pay the intent, and every credential that pays it commits to it;
absent, no such credential may pay it. `fundingAccount` names the account
every credential for the intent debits, as the rail mapping spells accounts.
(Informative: which of these terms a rail mapping needs, and how it spells an
account, are the execution profile's adapter rules; section 12.5 describes
them for x402.) An
intent that signs `redeemableByOthers` MUST sign its `fundingAccount` and MUST
name its `presenter` (below). (Informative: one account and one agent then
stand behind every credential for the intent, and from these signed terms the
execution profile fixes one single-use redemption slot that every such
credential consumes, so the rail redeems at most one of them, whoever holds or
presents it.)

`presenter`, when present, is the DID of the one agent that may present the
intent: an Executor MUST refuse a request whose request proof names another
DID (`payment_intent_mismatch`), before any chain resolution or status read.
An intent that names no presenter is **shared**: any agent the payer
authorizes may present it. The party that constructs an intent for one agent
MUST name that agent as its `presenter`, so that no other agent can present
it. If a `settlementAmount` is present, `quoteDigest` is REQUIRED: it is the
`sha256:` digest (section 10) of the quote that binds the conversion, which
rule `intent.quote` (section 8.4.4) compares, as an exact string, with the
verified quote's `digest`, so the conversion cannot be substituted
independently of the intent. (Informative: how a rail adapter derives a
quote's digest from the rail's quote bytes is the execution profile's adapter
rule; section 12.5 describes the one x402 case in which the rail's own bytes
are the quote.) Without a conversion no rule of
this document reads `quoteDigest`; it can then commit to other rail bytes,
such as the rail's payment requirements, which the execution profile matches.

`payer`, the DID of the party whose funding source is debited, MUST equal the
root issuer (section 4.1), the responsible party, of the verified delegation
chain (section 8.4.6, step 9). An intent therefore names who pays: a party
holding its own valid authority cannot authorize, reserve, or block another
payer's intent by replaying its bytes.

The party that constructs an intent MUST NOT place in it private keys or
seeds, card PAN/CVV or bank credentials, bearer tokens, AP2 disclosure
material the verifier does not require, x402 payment payloads, or processor
secrets. This is the producer's obligation alone: such material can sit in
`purpose` or in extension data like any other text, so no consumer can detect
it from the artifact.

Example (digests are illustrative):

```json
{
  "schema": "https://schema.kya-os.org/experimental/payment-authority/2026-09-22/intent",
  "profile": "org.kya-os/payments.v1",
  "intentId": "urn:uuid:11111111-1111-4111-8111-111111111111",
  "createdAt": 1789952400000,
  "expiresAt": 1789952460000,
  "audience": "did:web:merchant.example",
  "action": "payments.transfer",
  "payee": {
    "id": "did:web:merchant.example",
    "accountDigest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    "accountDigestMethod": "issuer-attestation-sha256"
  },
  "payer": "did:web:company.example",
  "presenter": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "amount": {
    "asset": { "namespace": "iso4217", "id": "CHF" },
    "coefficient": "3980",
    "scale": 2
  },
  "resources": [
    {
      "id": "https://merchant.example/checkouts/checkout-1",
      "digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222"
    }
  ],
  "commerce": {
    "id": "https://ucp.dev/2026-08-25/specification/overview/",
    "version": "2026-08-25",
    "specDigest": "sha256:5555555555555555555555555555555555555555555555555555555555555555",
    "sessionId": "checkout-1",
    "artifactDigest": "sha256:3333333333333333333333333333333333333333333333333333333333333333"
  },
  "payment": {
    "protocol": {
      "id": "https://raw.githubusercontent.com/x402-foundation/x402/71eb9a55e081e7b81ba3046d0bd17c3eb9c7bf81/specs/x402-specification-v2.md",
      "version": "2",
      "specDigest": "sha256:6666666666666666666666666666666666666666666666666666666666666666"
    },
    "handlerId": "org.example.x402",
    "scheme": "exact",
    "network": "eip155:84532",
    "transferMethod": "eip3009",
    "paymentFlow": "authorization",
    "redeemableByOthers": true,
    "fundingAccount": "eip155:84532:0x857b06519E91e3A54538791bDbb0E22373e36b66",
    "settlementAmount": {
      "asset": {
        "namespace": "caip19",
        "id": "eip155:84532/erc20:0x036CbD53842c5426634e7929541eC2318f3dCF7e"
      },
      "coefficient": "44500000",
      "scale": 6
    },
    "quoteDigest": "sha256:4444444444444444444444444444444444444444444444444444444444444444"
  }
}
```

### 8.2 Payment Authorization Binding

`PaymentAuthorizationV1` is a deterministic verification record. It binds one
verified KYA authority context to one intent digest and one request digest. It
is **not** a rail credential and cannot move funds.

Its schema is:

`https://schema.kya-os.org/experimental/payment-authority/2026-09-22/authorization`

Its members are:

- `authorizationId`, an identifier the party that creates the record assigns
  to it, unique among the records that party creates;
- `intentDigest`, the digest of the exact Payment Intent (section 10);
- `decision`, always `authorized`: a refusal creates no Payment Authorization;
- `verifier`, the stable identity of the deterministic verifier that decided;
- `actor`, `principal`, and `responsibleParty` (section 4.1), and `audience`
  and `action`, the intent's, as verified;
- `delegation`: `credentialRef`, the `id` of the leaf credential's
  `credentialSubject` (the capability it grants, not the credential's own
  `id`); `chainDigests`, the root-to-leaf credential digests (section 10), at
  most ten (section 8.4); `credentialDigest`, the leaf credential's digest,
  which the producer MUST record as the last entry of `chainDigests`; and
  `delegates`, the delegates of the chain (section 4.1), each named once: the
  actor and each intermediate delegate (the delegate of a credential nearer
  the root than the leaf), at most ten, since the actor is the leaf
  credential's delegate. The actor comes first, then the delegate of each
  credential from the root to the leaf, each at its first appearance. The
  producer MUST record `delegates` whenever it records an approval, so that
  anyone holding the record can re-check the no-self-approval rule;
- `holderProof`: its `profile`, the request-proof profile that the verified
  request proof names in its `prf` member (`org.kya-os/proof.v1` for the
  Entity Card request proof, SPEC-ENTITY-CARD §8), and its `digest`, the
  holder-proof digest of that proof (section 10);
- `effectiveConstraintsDigest`, the digest of the effective payment
  constraints (section 8.4.2), and `decisionTrace`, the privacy-minimal
  decision trace of the authorized decision, 1 to 512 entries in the entries
  and order of section 8.4.4, each a stable rule identifier (`rule`), its
  `result`, `pass` or `deferred`, and, for an attenuation rule, its `hop`.
  `deferred` marks a rule whose inputs are rail facts not yet verified when
  authority is decided (`intent.quote` for a converted intent, and
  `intent.fees`); no payment effect follows until the whole intent
  evaluation, run again with them, passes (section 8.4.4). A deferred rule is
  never recorded as passed;
- `approval`, optional: the verified approval (**Recorded approval**, below);
- `idempotency`, the idempotency binding (below), whose `requestDigest` is the
  digest of the exact proof-covered request from which the intent was
  extracted;
- `evidence`, references to external evidence such as AP2 mandates
  (section 9);
- `createdAt`, the decision time (section 7.1) of the verification that
  decided, and `expiresAt`, the authorization expiry (below), which is after
  `createdAt` and, when an approval is recorded, not after its `expiresAt`;
  and
- `extensions`, optional (section 8).

**Payment argument.** A payment request carries, covered by its request
proof, one object, the **payment argument**, from which this document reads
only the Payment Intent (section 8.1), the client's idempotency key (`key`,
below), the `delegationDigest` (section 10), and, when presented, the
approval evidence (below). (Informative: the payment argument, its schema,
and where in a request it travels are defined by the execution profile; its
members are `profile`, the literal `org.kya-os/payments.v1`, `intent`,
`idempotencyKey`, `delegationDigest`, and, optionally, `approvalEvidence`.)

**Idempotency binding.** `idempotency` has exactly these four members, each
established for the request the authorization binds; only the key comes from
the client:

- `key`: the payment argument's `idempotencyKey`, 1 to 256 code points
  with no CR, LF, or U+0000;
- `phase`: the execution phase, which the operation fixes. Version 1 defines
  single-phase execution only, so `phase` is always `execute`: one operation
  authorizes and settles one attempt;
- `scope`: the namespace the key lives in, exactly `org.kya-os/payments.v1:`
  followed by `JCS({tenant, caller, operation})` (section 10), at most 2,048
  code points. `tenant` is the payee's namespace at the Executor (for example
  its DID), `caller` the authenticated caller (section 4.1), and `operation`
  the operation identifier, for an MCP `tools/call` exactly `tools/call#<name>`
  with the tool name (1 to 256 code points, without `#`, CR, or LF). Each
  member is non-empty and has no CR or LF, `tenant` and `caller` have at most
  512 code points each, and all three come from the Executor's authentication
  of the request, never from the caller. The Executor MUST refuse
  (`payment_request_invalid`) a request whose caller identifier or scope
  exceeds its limit; and
- `requestDigest`: the request digest of section 10.

The schemas check only these members' types and lengths, the value of
`phase`, and the digest pattern of `requestDigest`; the scope is never
presented, since the Executor's authentication derives it. (Informative: the
execution profile checks the key's character rule when it parses the payment
argument.) How an Executor uses the binding to
deduplicate effects is defined by the execution profile.

**Approval modes.** A mode states what the approval's issuer attests about how
it approved:

- `human-present` — the issuer authenticated a person, showed them the terms
  of the intent whose digest the evidence carries (the payee, the business
  amount, the effective settlement amount and asset when a conversion
  applies, and the intent's expiry), and the person approved during that
  interaction;
- `human-not-present` — the issuer approved under a person's earlier recorded
  instruction, without the person reviewing this intent; and
- `standing-policy` — the issuer's automated policy approved the intent, and no
  person took part.

Each approval evidence format (below) derives the mode from what the evidence
itself attests about the intent whose digest it carries, and never reports a
mode the evidence does not establish. (Informative: AP2's
human-present and human-not-present flows correspond to `human-present` and
`human-not-present`; a profiled AP2 or Verifiable Intent verifier documents its
exact mapping, and accepts a mandate or presentation only when it carries the
intent digest. Payer-borne fees are not part of the intent; the payer's own
delegation bounds them, section 8.4.4, and open decision 11 asks whether an
approval should bind them too.)

**Approval evidence formats** are defined by the execution profile, the
profile's native approval statement among them. Each format fixes its evidence
`type` and `format`, its signature and binding rules, how the issuer, mode,
subject, and expiry are derived from the verified evidence, and where the
evidence itself carries the digest of the intent it approves, which every
format places in the evidence (below). Verifying evidence under its format
yields a **verified approval**, an object with the members of the
authorization schema's `approval` member (Appendix A.2; **Recorded approval**,
below), which the Authority Verifier then checks (below). This
document defines what the Authority Verifier checks of a verified approval,
how it is recorded in the Payment Authorization (`approval`, below), and the
**approval facts** that intent evaluation reads: an object with at
least `mode` and `issuer`, the mode and issuer of the verified approval, whose
other members are ignored (section 8.4.4). Version 1 defines no
format for AP2 mandates or Verifiable Intent (open decision 12); an Authority
Verifier that accepts them documents its own mapping and states it in its
conformance claim as an extension, outside Core Authority conformance.

**Approval evidence.** Approval evidence travels with the request, covered by
its request proof, as the `approvalEvidence` member of the payment argument
(above): an object whose `type` and `format` name the approval evidence
format it follows and whose `value` is a string holding the exact evidence. (Informative: the execution
profile's schema of the payment argument bounds them: a `type` of 1 to 2,048
code points and a `format` of 1 to 256 code points, neither with CR or LF,
and a `value` of 1 to 65,536 UTF-8 bytes.) An approval exists only as
evidence presented there, never as a record a verifier recalls. The Authority
Verifier verifies it in deterministic code under the rules of its format,
derives `mode`, `issuer`, `subject`, and expiry from the verified evidence
(never from the caller), and records an approval only when all of these hold:

- the evidence authenticates its `issuer`. A `subject` is what that
  authenticated issuer asserts about who approved; the Authority Verifier does
  not authenticate the subject itself, and `bindingEvidenceDigest` is an audit
  reference to the evidence the issuer relied on (for example the ID Token of
  the person's login), which the Authority Verifier does not verify;
- the evidence itself carries the intent digest (section 10) of this exact
  intent, and the verifier records that digest as the approval's
  `intentDigest`. Evidence that carries only terms the intent commits to,
  such as a checkout digest, binds no intent: the payer, the presenter, the
  expiry, the `intentId`, and the payment selection lie outside every
  resource and commerce digest, so such evidence would fit every intent that
  reuses those terms;
- `evidenceDigest` is `sha256:` followed by the lowercase hex of SHA-256 over
  the UTF-8 bytes of the `approvalEvidence.value` string, with no
  canonicalization and no domain separation (section 10), computed by the
  verifier, never taken from the evidence or the caller; and
- the evidence has not expired at the decision time.

The Authority Verifier MUST refuse (`payment_approval_invalid`) evidence
that its format refuses or that fails one of these, and evidence whose `type`
and `format` name no format it implements, so one that implements none
refuses every presented `approvalEvidence`. It gives the evidence verifier
the effective `requireApproval` of the verified chain, and MUST refuse a
verified approval whose `intentDigest` is not exactly the intent digest it
computed, or whose `evidenceDigest` is not exactly the evidence digest it
computed (above). It MUST also refuse (`payment_approval_invalid`) a verified
approval that the authorization schema's `approval` member does not admit
(Appendix A.2), such as one whose `issuer` has no scheme, and so does not
match the URI pattern of section 8.6, or whose `profile` is longer than 256
code points, so evidence whose `type` is longer than 256 code points is never
recorded.

**Recorded approval.** A Payment Authorization's `approval` records the
verified approval: its `mode`; its `issuer`, the identifier (for example a
DID) the evidence authenticates, which matches the URI pattern of
section 8.6; `profile`, the `type` of the presented
`approvalEvidence`; its
`intentDigest`, the intent digest the evidence carries, which the producer
records equal to the authorization's `intentDigest`; its `evidenceDigest`;
`expiresAt`, the expiry derived from the evidence (section 7.1); and, when the approval names the person or party who
approved, a typed `subject`, either `{kind:"did", id}` or
`{kind:"oidc-subject", issuer, subject, bindingEvidenceDigest}`, where an
OIDC subject [OIDC-CORE] is identified by `(issuer, subject)` and never by
`sub` alone.

**Who may approve.** A delegator requires approval with the `requireApproval`
member of the payment caveat (section 8.4). Each credential that carries a
requirement has an **effective approver set**: its `approvers`, or, when
`approvers` is absent, the payer alone (the accountable root). Along the chain
an effective approver set only narrows (section 8.4.2, rule 6). An approval
satisfies the chain only when its mode is accepted by the leaf requirement and
its issuer is in the effective approver set of every credential that carries a
requirement; because sets only narrow, the leaf's set is the one checked.

No delegate approves its own payment: an approval whose issuer, or whose `did`
subject, is a delegate of the chain (the actor or the delegate of any
credential in it, section 4.1) or, when `principal` differs from
`responsibleParty`, the principal, MUST NOT satisfy a requirement, whatever
`approvers` lists. The Authority Verifier MUST refuse such evidence as invalid
(`payment_approval_invalid`) by the no-self-approval rule of section 8.4.6,
step 9, before it evaluates the intent rules, so a delegate's approval never
reaches the approver set of rule `intent.approval` (section 8.4.4). DIDs
compare as exact strings, so the comparison holds only while no DID resolves
to another DID's keys, on either side of it: every key resolution the Executor
relies on for the request proof it authenticates, and every one an Authority
Verifier relies on for the delegation credentials and approval evidence, MUST
return keys only from a DID document whose `id` is exactly the DID it
resolves. Otherwise a delegate could act under an alias of its DID (for
`did:web`, one that spells out the default port, writes the host in another
case, or percent-encodes a character that needs none) and approve under the
DID itself. A Payment Authorization that records an approval MUST have been
decided with the chain's complete delegate list and MUST record it
(`delegation.delegates`). A login, an OAuth scope, or an ID Token alone is
never economic approval.

An approval is recorded only when the effective constraints require approval
for the intent and the approval meets that requirement. Evidence presented when
no requirement applies is still verified, and refused if it does not verify,
but it is not recorded: an approval nobody required is not evidence the payer
relied on.

When approval is required and no approval meets the requirement, the refusal
is `payment_approval_required` (rule `intent.approval`, section 8.4.4), a
challenge: the client can obtain approval evidence for the intent's digest and
present it as `approvalEvidence`. (Informative: the execution profile's
refusal of this reason carries the intent digest and the chain's effective
`requireApproval`.)

Without AP2 or Verifiable Intent, sufficient authority is either (a) a current
payment-constraints caveat chain that contains the intent and does not require
approval for it (delegated authority alone), or (b) such a chain plus a
verified approval of a mode and issuer the chain accepts. (Informative:
sufficient authority is not funding. The execution profile separately checks
that the funding source a rail credential debits is bound to the responsible
party.)

The authorization expiry MUST be the earliest of:

- Payment Intent expiry;
- the request proof's `expires`, never extended by clock skew, which the
  Executor reads from the proof it verified when it authenticated the request,
  never from a fact an Authority Verifier states, so that this bound holds
  whatever Authority Verifier it uses;
- every delegation bound in the chain (`validUntil` and `ValidUntil` caveats);
- the payment caveat's `expiresAt`;
- verified status/freshness evidence;
- the `expiresAt` of the recorded approval.

The request proof's `expires` and status/freshness evidence are **renewable**
bounds: they belong to one request and the status it reads, not to the covered
bytes. Every other bound above is **fixed** by the covered bytes: the intent,
the chain the proof-covered `delegationDigest` names, and the covered approval
evidence. How an Executor records these bounds with each attempt, and acts
when each kind expires, is defined by the execution profile.

(Informative: the rail terms bound each attempt further, under the execution
profile. Its rail adapter verifies the quote the intent binds by
`quoteDigest`, and the other rail terms, each with its own expiry; it takes
from that quote the verified quote of section 8.4.4, which has no expiry
member; and it bounds the attempt by the earliest of the authorization expiry
and those two expiries, refusing with `payment_quote_expired` a quote or terms
already expired when they are verified.)

A Payment Authorization MUST be created only after deterministic verification
of the underlying signatures, delegation chain, holder binding, audience,
action, caveats, constraints, expiry, and current revocation state; merely
receiving the JSON shape is not verification. Every fact it records — the
intent digest, the evaluated constraints, the approval, and the complete
idempotency binding — MUST be one the Executor's authentication or the
Authority Verifier derived for that request: its producer never pairs
genuine authority facts with another intent, request, key, phase, scope,
approval, or constraint result. (Informative: an implementation can enforce
this by accepting the facts only as an opaque in-process capability that the
successful verification minted.)

Example: the Payment Authorization that records the decision on the
section 8.1 intent under the chain of the example in section 8.4, at the
decision time `1789952410000`, with verified approval facts of mode
`human-present` from `did:web:consent.example` and the quote and fee rules
deferred (section 8.4.4). Its `intentDigest` (the digest of that intent),
`delegation`, `effectiveConstraintsDigest`, `decisionTrace`, and
`idempotency.scope` are the values this document derives for that decision;
the holder-proof digest, the approval's `evidenceDigest`, and the request
digest are illustrative. Its `expiresAt` is the earliest bound of the
authorization expiry, the request proof's `expires` (`1789952440` seconds):

```json
{
  "schema": "https://schema.kya-os.org/experimental/payment-authority/2026-09-22/authorization",
  "profile": "org.kya-os/payments.v1",
  "authorizationId": "urn:uuid:22222222-2222-4222-8222-222222222222",
  "intentDigest": "sha256:dad2fe842ee1ce1cb972234653203b884ec829532536e28979563ef1d9582e44",
  "decision": "authorized",
  "verifier": "did:web:merchant.example#payments",
  "actor": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "principal": "did:web:company.example",
  "responsibleParty": "did:web:company.example",
  "audience": "did:web:merchant.example",
  "action": "payments.transfer",
  "delegation": {
    "credentialRef": "urn:cap:company-agent-checkout",
    "credentialDigest": "sha256:b71e81029fedc60078302e692e1a06f37aabdc0d0ebe89bbbf37536bfa407fc4",
    "chainDigests": [
      "sha256:b71e81029fedc60078302e692e1a06f37aabdc0d0ebe89bbbf37536bfa407fc4"
    ],
    "delegates": ["did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"]
  },
  "holderProof": {
    "profile": "org.kya-os/proof.v1",
    "digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
  },
  "effectiveConstraintsDigest": "sha256:0f1f471564db993f54908ccf127f4638efff26627de432c5571633f294b92963",
  "decisionTrace": [
    { "rule": "constraints.structure", "result": "pass" },
    { "rule": "intent.businessAmount", "result": "pass" },
    { "rule": "intent.payee", "result": "pass" },
    { "rule": "intent.resources", "result": "pass" },
    { "rule": "intent.rail", "result": "pass" },
    { "rule": "intent.settlementAmount", "result": "pass" },
    { "rule": "intent.quote", "result": "deferred" },
    { "rule": "intent.fees", "result": "deferred" },
    { "rule": "intent.approval", "result": "pass" },
    { "rule": "intent.expiry", "result": "pass" }
  ],
  "approval": {
    "mode": "human-present",
    "issuer": "did:web:consent.example",
    "profile": "https://consent.example/approval/v1",
    "intentDigest": "sha256:dad2fe842ee1ce1cb972234653203b884ec829532536e28979563ef1d9582e44",
    "evidenceDigest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    "expiresAt": 1789952450000,
    "subject": { "kind": "did", "id": "did:web:alice.company.example" }
  },
  "idempotency": {
    "key": "checkout-1:execute:1",
    "phase": "execute",
    "scope": "org.kya-os/payments.v1:{\"caller\":\"did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK\",\"operation\":\"tools/call#checkout.complete\",\"tenant\":\"did:web:merchant.example\"}",
    "requestDigest": "sha256:9999999999999999999999999999999999999999999999999999999999999999"
  },
  "evidence": [],
  "createdAt": 1789952410000,
  "expiresAt": 1789952440000
}
```

### 8.3 Payment Outcome

`PaymentOutcomeV1` records the durable lifecycle state and public evidence. Its
schema is:

`https://schema.kya-os.org/experimental/payment-authority/2026-09-22/outcome`

This section defines the outcome's members and the structure a consumer
verifies, which is Core Authority (section 4.3). Producing outcomes belongs
to the Execution tier, whose rules the execution profile defines; the
production rules stated here serve to define what each member means.

Its members are:

- `outcomeId`, an identifier the producer assigns to this observation, unique
  among the observations it produces;
- `attemptId`, the identifier of the attempt, shared by every observation of
  it (below); `sequence`, the observation's zero-based position in the
  attempt's stream; and `previousOutcomeDigest`, the outcome digest
  (section 10) of the observation before it, present exactly when `sequence`
  is not zero;
- `producer`, the identity of the component that records and attests the
  outcome;
- `intentDigest` and `authorizationDigest`, the digests of the intent and of
  the Payment Authorization that created the attempt;
- `state`, the published state (below), and `updatedAt`, the time the producer
  recorded the observation (section 7.1), never earlier than its
  predecessor's;
- `idempotency`, the idempotency binding of that authorization (section 8.2);
- `rail`: the attempt's rail protocol `id`, exact `version`, and `specDigest`
  (section 6), and the rail's own references, `transactionRef` to the
  transaction that moved value and `reconciliationRef` to a pending
  settlement (below);
- `effectAmount`, the amount the rail reported as moved (below);
- `reason`, which the producer records exactly when the state is `failed`
  (below): `code`, `newIntentMaySucceed`, the optional `basis`, and the
  optional `detailDigest`, the digest of the exact bytes of
  the diagnostic detail the producer keeps for the failure (for example the
  rail-native code), which the outcome itself never carries;
- `evidence`, references to the evidence the observation rests on
  (section 9);
- `correction` and `finality`, optional (below); and
- `extensions`, optional (section 8).

An attempt exists only once authority is decided: approval, when required, is
obtained before any attempt (section 8.2), and a refused request records none.
No outcome state therefore precedes `authorized`, which records an attempt
with nothing yet sent to the rail; `submitted` records the attempt's
**submission**, its rail credential sent to the rail, with no rail result yet
recorded. An Executor retires an `authorized` attempt it will not submit by
failing it. Allowed transitions are exact:

| From | To |
| --- | --- |
| `authorized` | `submitted`, `failed` |
| `submitted` | `settlement_pending`, `settled`, `failed` |
| `settlement_pending` | `settled`, `failed` |
| `settled` | none |
| `failed` | none, except a correction to `settled` or `settlement_pending` |

Exact retransmission of the same sequence and digest is idempotent. Advancing
the sequence without one of the state transitions shown above, or changing an
observation already accepted at a sequence, MUST fail
(`payment_state_transition_invalid`). When an Executor records each state, and
how a submission that never reached the rail returns to `authorized` without a
published transition, are defined by the execution profile.

- `settlement_pending` is nonterminal: the rail holds the submission and has
  not settled it. It MUST carry `reconciliationRef`, the rail's reference by
  which the pending settlement is read again. (Informative: a timeout, lost
  response, or unknown transport outcome is no rail result; the execution
  profile's rules for a lost submission decide what is recorded, never
  `failed` while settlement may have occurred, and it reads an unresolved
  outcome again by its existing reference before it creates any other attempt
  for the same intent digest, if it may create one at all.)
- `settled` MUST carry `transactionRef` and `effectAmount`, the exact amount
  the rail reported as moved: evidence, never copied from the intent, which no
  other state carries. When it differs from the effective settlement amount,
  the rail fact is kept and the discrepancy is surfaced for reconciliation and
  dispute handling, never silently normalized.
- `finality`, present only on a `settled` outcome, is the level at which the
  settlement was read before the rail's own final state, a level its payee
  declared final. The producer adds the same level to the outcome's **rail
  evidence**: each evidence reference whose `class` is `rail_receipt`, and
  each that names no class (section 9). A consumer MUST NOT treat such a
  settlement as immutable at the rail. Since `settled` has no successor, a
  reorganization that drops the transaction leaves the record standing: the
  payee's declared risk.
- `failed` MUST carry a `reason`, and a producer MUST NOT record a `reason` on
  an outcome of any other state. The schema enforces the first rule and part
  of the second: it refuses a `reason` that names a `basis` on any state but
  `failed` (Appendix A.6), and otherwise admits a `reason` on any state, so
  the rest of the second rule is the producer's obligation, which a consumer
  does not check (section 8.7). The reason's `code` is an **outcome reason**,
  one of the section 13 wire reasons that can end an attempt:
  `payment_failed`, for a rail failure such as an issuer decline, whose
  rail-native code stays in diagnostics; `payment_quote_expired`;
  `payment_authority_expired`; `payment_delegation_revoked`;
  `payment_authority_recheck_failed`; or `payment_denied`, which records any
  other code that a refusal ending an attempt carries (section 13). An attempt
  ended because a fixed bound of its authorization (section 8.2) expired
  records `payment_authority_expired`, unless the execution profile records
  `payment_quote_expired`. (Informative: it does when the quote the intent
  binds expired no later than that bound, and when the other rail terms it
  verified expired; section 8.2.) `newIntentMaySucceed` records whether a new
  intent for the purchase may succeed: `true` after an expiry, which a new
  intent can replace; `false` after a revocation, a failed authority recheck
  (`payment_authority_recheck_failed`), or a denial; and, for a rail failure,
  what the rail result states, except that a failure whose basis is `close`
  gives `true`. `basis` names, for a rail failure that rests on more than the
  submission's own answer, the rail evidence that ends it: `close`, the rail
  confirmed that the payment identity of a lost submission was closed while it
  held no submission of it; `slot`, a final rail state at or after the end of
  the redemption slot of a credential others can redeem showed that slot
  unused; or `tracked`, the rail failed a submission it found or tracks. No
  other failure names a basis. When an Executor records each basis, and the
  lost-submission and redemption-slot rules they rest on, are defined by the
  execution profile. A failed attempt is final, but for a correction.

**Correction.** A final state changes only by a correction: the rail's own
answer to the attempt's submission, never a later read of the rail's state,
that contradicts a rail failure naming a basis by being `settled`, or
`settlement_pending` when that basis is `close`. The producer records it with
`correction: true` directly after the `failed` observation it corrects, which
its `previousOutcomeDigest` names, keeping the correcting answer's evidence;
an attempt has at most one correction, and the state recorded after it
carries none. A conforming rail never produces a correction: one arises only
from a rail, or the execution profile's rail adapter, that contradicts its own
report, and it surfaces a purchase that may have been paid twice.

When Portable Evidence conformance is claimed, outcomes form an append-only
observation stream for one `attemptId`. Its producer MUST start it at
`sequence` zero in state `authorized` or `submitted`, never at a rail result;
MUST give every later observation the **binding** of the observation before
it: the same `attemptId`, `producer`, `intentDigest`, `authorizationDigest`,
all four members of `idempotency`, and rail protocol (`rail.id`,
`rail.version`, and `rail.specDigest`, present or absent alike); MUST append an
observation only for a transition of the table above or a correction, which
directly follows the `failed` observation it corrects, whose reason is
`payment_failed` and names a basis, and is `settled`, or `settlement_pending`
only after a failure whose basis is `close`, at most once per stream; and MUST
use compare-and-swap or an equivalent transactional write so that at most one
successor is accepted for a given predecessor. A record the producer keeps
without changing the published state appends no observation.

A consumer of a stream treats an exact retransmission (the same sequence and
digest) as the observation it repeats, and reads the remaining observations
in `sequence` order, whatever order they arrived in: an observation's
predecessor is the one whose `sequence` is one less, and the stream's first
observation is the one of lowest `sequence`. It MUST refuse the stream
(`payment_outcome_stream_invalid`) when:

1. its first observation has a `sequence` other than zero or a state other
   than `authorized` or `submitted` (a bad start);
2. a sequence is missing (a gap), or one sequence carries two digests;
3. an observation's `previousOutcomeDigest` is not the outcome digest of the
   observation before it (a broken link), or two observations name one
   predecessor (a fork);
4. an observation's binding differs from its predecessor's (an unstable
   binding);
5. an observation that is not a correction has a state the table above does
   not allow after its predecessor's;
6. a correction does not directly follow a `failed` observation whose reason
   is `payment_failed` and names a basis, is `settlement_pending` after a
   failure whose basis is not `close`, or is the stream's second; or
7. an observation's `updatedAt` is earlier than its predecessor's (a time
   regression).

A current-state projection is a cache and MUST NOT replace the stream when
Portable Evidence conformance is claimed. Finer internal states that an
Executor keeps (the execution profile) are each published as one of the states
above. The Executor
assigns `attemptId`, never a client: when an attempt already exists for the
idempotency binding, the Executor continues it under its existing
`attemptId`, whatever identifier a caller proposes.

Refunds and reversals move value from the payee back to the payer, the
opposite direction to the payer-rooted authority this profile defines, and are
outside version 1 (section 3). A settled outcome remains immutable history in
the Executor's record; a later profile defines refunds and may link them to
the original intent by its digest.

Example: the third observation (after `authorized` and `submitted`) of the
attempt that the example Payment Authorization of section 8.2 created; its
`authorizationDigest` is that authorization's digest (section 10), and its
`effectAmount` is the intent's `settlementAmount`, which the rail moved. The
previous outcome digest, the transaction reference, and the evidence digest
are illustrative:

```json
{
  "schema": "https://schema.kya-os.org/experimental/payment-authority/2026-09-22/outcome",
  "profile": "org.kya-os/payments.v1",
  "outcomeId": "urn:uuid:33333333-3333-4333-8333-333333333333",
  "attemptId": "urn:uuid:55555555-5555-4555-8555-555555555555",
  "sequence": 2,
  "previousOutcomeDigest": "sha256:7777777777777777777777777777777777777777777777777777777777777777",
  "producer": "did:web:merchant.example#payments",
  "intentDigest": "sha256:dad2fe842ee1ce1cb972234653203b884ec829532536e28979563ef1d9582e44",
  "authorizationDigest": "sha256:1ea4c7abea8f269ae39be80aec191dec9a38fe371bb891dedaaf54a1289d7c63",
  "state": "settled",
  "updatedAt": 1789952425000,
  "idempotency": {
    "key": "checkout-1:execute:1",
    "phase": "execute",
    "scope": "org.kya-os/payments.v1:{\"caller\":\"did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK\",\"operation\":\"tools/call#checkout.complete\",\"tenant\":\"did:web:merchant.example\"}",
    "requestDigest": "sha256:9999999999999999999999999999999999999999999999999999999999999999"
  },
  "rail": {
    "id": "https://raw.githubusercontent.com/x402-foundation/x402/71eb9a55e081e7b81ba3046d0bd17c3eb9c7bf81/specs/x402-specification-v2.md",
    "version": "2",
    "specDigest": "sha256:6666666666666666666666666666666666666666666666666666666666666666",
    "transactionRef": "urn:example:tx:0xabababababababababababababababababababababababababababababababab"
  },
  "effectAmount": {
    "asset": {
      "namespace": "caip19",
      "id": "eip155:84532/erc20:0x036CbD53842c5426634e7929541eC2318f3dCF7e"
    },
    "coefficient": "44500000",
    "scale": 6
  },
  "evidence": [
    {
      "type": "urn:example:x402-settlement-response",
      "format": "application/json",
      "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      "canonicalization": "raw",
      "class": "rail_receipt"
    }
  ]
}
```

### 8.4 Payment constraint caveat and attenuation

A **payment action** is the `action` a Payment Intent names, and a **payment
chain** is the delegation chain a payment request presents for it; step 8 of
section 8.4.6 refuses a payment chain whose leaf does not grant that action.
Because each hop's `allowedAction` is a subset of its parent's, every
credential of a payment chain whose leaf grants the payment action grants it
too: each is **payment-granting**. Every credential of a payment chain MUST contain exactly
one recognized
`org.kya-os/payment-constraints` caveat version `1.0.0` in
`credentialSubject.caveats` and MUST carry a status entry whose
`statusPurpose` is `revocation`; both are checked of every credential the
chain presents, before its action is (section 8.4.6, steps 4 and 6). The base
card delegation schema leaves `statusPurpose` optional; a payment chain
requires it, as W3C Bitstring Status List v1.0 does. A missing status entry, or
one of another purpose (a suspension can be lifted, a revocation cannot),
invalidates the chain (`payment_delegation_invalid`). A missing or duplicated
payment caveat, one of an unknown version, or one that does not parse strictly,
such as one with an empty list (every list holds at least one entry, below),
invalidates it too (`payment_constraint_invalid`). Every payment-granting
credential hands authority to another party: the Authority Verifier MUST
refuse a credential whose delegate (section 4.1) is its own issuer
(`payment_delegation_invalid`, section 8.4.6, step 1), so no delegate can
lengthen a chain by re-delegating to itself. A payment chain has at most ten
credentials. The limit is this profile's own: SPEC.md §6.10 sets no limit on
chain length and leaves a cap to verifier policy. A longer chain is invalid
rather than partially evaluated. A presented credential's RFC 8785
serialization is at
most 65,536 bytes, and a credential carries at most 32 caveats; a chain or a
credential over these ceilings is `payment_delegation_invalid`. A payment
caveat's RFC 8785 serialization is at most 16,384 bytes; a larger one is
`payment_constraint_invalid`. The Authority Verifier checks the chain length,
each credential's size and caveat count, the `delegationDigest` of the payment
argument (sections 8.2 and 10), and that the leaf delegate is the proof key's
DID before any signature, status, or attenuation work (section 8.4.6, step 1),
so that work is bounded by these ceilings. Parsing the presented text and
scanning it for repeated member names (section 10) come before the ceilings,
which are measured on the parsed value, and are linear in the presented
bytes, which the transport that carries the request bounds (the execution
profile defines the handling of hostile input before authentication,
section 15).

The caveat schema is
`https://schema.kya-os.org/experimental/payment-authority/2026-09-22/constraints`
(`payment-constraints.schema.json` in this folder). These are per-intent
ceilings. The caveat's members are `type` and `version`, the constants above;
`businessLimits`, the per-asset ceilings on the business amount; the
allowlists `payees` (parties, as the intent's `payee`), `resources` (each an
`id` with an optional terms `digest`), and `rails` (each a `protocol`, with
any of the selection members of section 8.1 that name the rail mechanism
and account: `methodId`, `handlerId`, `scheme`, `network`, `transferMethod`,
`paymentFlow`, and `fundingAccount`); the grants
`settlementLimits`, per-asset ceilings on a settlement amount that differs
from the business amount, `quoteAuthorities`, the issuers whose verified
quotes may bind a conversion, and `fees`, the payer-borne fee policy:
`{"mode":"prohibited"}`, or `{"mode":"capped","limits":[...]}` with a ceiling
per listed asset; the requirement `requireApproval` (section 8.4.1); and
`expiresAt`, the exclusive end of the authority it grants. Every list holds 1
to 256 entries (`requireApproval.modes` 1 to 3), no two of one semantic key
(section 8.4.2, rule 8), and the schema bounds the whole caveat
(`kyaCanonicalJson`, section 8.6) to 16,384 canonical bytes, a nesting depth
of 8, and 16,384 values.

Example: a one-credential payment chain, in which the payer
`did:web:company.example` delegates to the agent that presents the
section 8.1 intent, with a payment caveat that admits that intent once the
approver it names approves it (the proof value is illustrative):

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/security/zcap/v1",
    "https://kya-os.org/ns/delegation/v1"
  ],
  "id": "urn:uuid:44444444-4444-4444-8444-444444444444",
  "type": ["VerifiableCredential", "DelegationCredential"],
  "issuer": "did:web:company.example",
  "validFrom": "2026-09-01T00:00:00Z",
  "validUntil": "2027-01-01T00:00:00Z",
  "credentialSubject": {
    "id": "urn:cap:company-agent-checkout",
    "invoker": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "parentCapability": "did:web:merchant.example:checkout",
    "invocationTarget": "did:web:merchant.example:checkout",
    "allowedAction": ["payments.transfer"],
    "caveats": [
      {
        "type": "org.kya-os/payment-constraints",
        "version": "1.0.0",
        "businessLimits": [
          {
            "asset": { "namespace": "iso4217", "id": "CHF" },
            "coefficient": "10000",
            "scale": 2
          }
        ],
        "payees": [{ "id": "did:web:merchant.example" }],
        "rails": [
          {
            "protocol": {
              "id": "https://raw.githubusercontent.com/x402-foundation/x402/71eb9a55e081e7b81ba3046d0bd17c3eb9c7bf81/specs/x402-specification-v2.md",
              "version": "2",
              "specDigest": "sha256:6666666666666666666666666666666666666666666666666666666666666666"
            },
            "scheme": "exact",
            "network": "eip155:84532"
          }
        ],
        "settlementLimits": [
          {
            "asset": {
              "namespace": "caip19",
              "id": "eip155:84532/erc20:0x036CbD53842c5426634e7929541eC2318f3dCF7e"
            },
            "coefficient": "100000000",
            "scale": 6
          }
        ],
        "quoteAuthorities": ["did:web:quotes.example"],
        "fees": { "mode": "prohibited" },
        "requireApproval": {
          "modes": ["human-present"],
          "approvers": ["did:web:consent.example"],
          "above": [
            {
              "asset": { "namespace": "iso4217", "id": "CHF" },
              "coefficient": "2500",
              "scale": 2
            }
          ]
        }
      }
    ]
  },
  "credentialStatus": {
    "type": "BitstringStatusListEntry",
    "statusPurpose": "revocation",
    "statusListIndex": "94567",
    "statusListCredential": "https://company.example/status/1",
    "statusSize": 1
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "verificationMethod": "did:web:company.example#key-1",
    "proofPurpose": "assertionMethod",
    "created": "2026-09-01T00:00:00Z",
    "proofValue": "z3FXQjecWufY46yg5abdVZsXqLhxhueuSoZgNSARiKBk9czhSePTFehP8c3PGfb6a22gkfUKods5D2UAUL5n2Brbx"
  }
}
```

The caveat admits a business amount of at most CHF 100.00, paid to the one
payee by x402 `exact` on `eip155:84532`, with a settlement of at most 100 USDC
whose conversion a quote from `did:web:quotes.example` binds, and no
payer-borne fee. Because its `above` lists a threshold of CHF 25.00 and none
for USDC, every intent above CHF 25.00, and every intent that settles in USDC,
requires a `human-present` approval from `did:web:consent.example` (section
8.4.1). The digest of the credential (section 10) is
`sha256:b71e81029fedc60078302e692e1a06f37aabdc0d0ebe89bbbf37536bfa407fc4`, and
the effective-constraints digest of the caveat (section 8.4.2) is
`sha256:0f1f471564db993f54908ccf127f4638efff26627de432c5571633f294b92963`.

#### 8.4.1 Member classes

Each member belongs to exactly one attenuation class. The class fixes what its
absence means, which is what makes attenuation monotone:

| Class | Members | Absence means | A child may |
| --- | --- | --- | --- |
| Ceiling | `businessLimits` (required), `expiresAt` | (`businessLimits` cannot be absent) unbounded expiry | lower a ceiling; drop an asset from `businessLimits`; never omit an inherited `expiresAt` |
| Allowlist | `payees`, `resources`, `rails` | unrestricted | introduce a non-empty allowlist; shrink an inherited one; never omit an inherited one |
| Grant | `settlementLimits`, `quoteAuthorities`, capped `fees` | **not granted** | drop the grant or narrow it; **never introduce one its parent lacks** |
| Requirement | `requireApproval` | not required | introduce a requirement; make an inherited one stricter; never omit or relax an inherited one |

Omitted `fees` is exactly equivalent to `{"mode":"prohibited"}`: no payer-borne
fee may be charged. Fees are never unbounded by default.

`requireApproval` is `{ "modes": [...], "approvers"?: [...], "above"?: [amount, ...] }`.
`modes` lists the approval modes (section 8.2) the delegator accepts, and
`approvers`, when present, the exact approval issuers it accepts, each a
`reference` string (Appendix A.4) that matches a verified approval's `issuer`
(section 8.2) only when the two strings are equal.
The credential's effective approver set is `approvers`, or the payer alone when
`approvers` is absent (section 8.2).

Without `above`, every payment requires approval. `above` is a set of exemption
thresholds, at most one per exact asset. A payment is exempt only when its
business amount, and everything that can leave the funding source, are each at
or below the threshold for their own asset. What can leave the funding source is
summed per asset: the effective settlement amount (section 7) plus, under a
capped fee policy, the fee ceiling of each capped asset. An amount in an asset
with no threshold always requires approval. The business amount is declared by
the client; the settlement amount and fees are what actually leave, so neither a
nominal business amount paired with a large converted settlement nor large
payer-borne fees can evade the requirement. Using the fee ceiling, not the
eventual fees, keeps the decision exact when authority is decided: verified
fees can only be lower.

#### 8.4.2 Edge rules

For each root-to-leaf edge:

1. A child ceiling MUST use the same exact asset and be less than or equal to
   its parent ceiling (exact cross-scale comparison below). It MAY remove an
   allowed asset.
2. A child allowlist MUST be a non-empty subset: each child entry is admitted
   by some parent entry, one with the same `id` (for a rail, the same
   protocol `id` and `version`) whose every commitment, digest, and qualifier
   the child entry carries unchanged. A child MAY introduce an allowlist when
   the parent omitted it; after introduction it MUST NOT be omitted.
3. A child MAY add an account commitment to an allowed payee or a digest to an
   allowed resource. It MUST NOT remove or change an inherited commitment.
4. Rail protocol id and version match exactly. A child MAY add a
   `specDigest` to a rail whose protocol `id` is not an HTTP(S) locator (the
   schema already requires one for an HTTP(S) locator, section 6), and a
   method, handler, scheme, network, transfer-method, payment-flow, or
   funding-account qualifier; it MUST NOT remove or change one it inherited.
5. A child grant MUST be absent or a subset of the parent's grant:
   `settlementLimits` per exact asset less than or equal to the parent's,
   `quoteAuthorities` a subset, and `fees` either prohibited (or omitted) or
   capped within the parent's capped limits. A grant absent from the parent
   MUST be absent from the child.
6. A child requirement MUST be present whenever the parent's is, with `modes` a
   subset of the parent's. The `approvers` member is compared as written, not
   as the effective approver set it stands for: below a requirement without
   `approvers`, the child requirement MUST NOT carry `approvers`, even one that
   lists only the payer (naming approvers would replace the payer); below a
   requirement with `approvers`, the child requirement MUST carry `approvers`,
   every entry of which the parent lists, even where the parent lists the
   payer, whom omitting the member would leave as the sole approver. A child
   MAY remove listed approvers. The effective approver set therefore only
   narrows. A child that introduces a requirement where its parent has none
   MAY name any approvers and any `above` thresholds, because it only adds a
   restriction. Within an inherited
   requirement, `above` exemptions behave as a grant: a child MAY drop `above`
   or any threshold in it, or lower a threshold within the same asset, but MUST
   NOT add `above` to an inherited requirement that lacks it, add a threshold
   for an asset the parent's `above` lacks, or raise one.
7. A child expiry MUST NOT exceed its parent's, and a child MUST NOT omit an
   inherited expiry: omitting it is widening.
8. A member set with two entries of the same **semantic key** is invalid. The
   semantic key of an amount is its exact asset; of a quote authority, an
   approver, or an approval mode, the string; of a payee, resource, or rail,
   the complete member.

Amounts are compared without floating point. For matching assets:

```text
k = max(child.scale, parent.scale)
child.coefficient * 10^(k - child.scale)
    <= parent.coefficient * 10^(k - parent.scale)
```

Because every edge is a subset, the leaf caveat is the effective constraint
set. The verifier normalizes it — every set member ordered by the unsigned
octets of its RFC 8785 serialization (a memcmp over the canonical UTF-8 bytes),
amounts at minimal scale (section 7), approval modes ordered the same way, and a
prohibited fee policy omitted because omission is equivalent — and computes
`SHA-256("org.kya-os.payments.constraints.v1" || 0x00 || JCS(value))`.
`effectiveConstraintsDigest` records that result but never substitutes for
verifying every chain edge.

#### 8.4.3 Composition with the base chain verifier

The base chain rules (SPEC.md §6.10) require an unknown caveat type to be
replicated verbatim. This profile depends on the amendment to that rule that
it proposes in `BASE-AMENDMENTS.md` (item 1; open decision 10), which is not
part of SPEC.md until the Working Group adopts it: a verifier that implements a
profile defining a narrowing relation for a caveat type applies that relation
instead of verbatim replication, and a profile can never redefine a built-in
type (`MaxAmount`, `ValidUntil`). A verifier that implements no such profile is
unaffected. An Authority Verifier that implements this profile MUST apply the
edge rules above as the narrowing relation of the
`org.kya-os/payment-constraints` caveat in its base chain verification, and
MUST reject an edge whose relation fails or throws. A base verifier without the
registration accepts only verbatim re-delegation of the payment caveat and
therefore rejects any narrowed chain; it MUST NOT be used as this profile's
Authority Verifier. Until the Working Group adopts the amendment, a narrowed
payment chain is verifiable only by profile-aware verifiers (section 2).

#### 8.4.4 Intent evaluation

The payer check (section 8.1) precedes constraint evaluation (section 8.4.6,
steps 9 and 10).

The verifier then evaluates the chain's payment caveats, root to leaf, and the
immutable intent, given the decision time, the mode and issuer of the verified
approval when one was presented, and, unless the quote and fee rules are
deferred (below), the payer-borne fees and the verified quote (check 2).
It applies the checks below in order. The first check that fails decides: no
later check runs, the decision is a refusal with that check's reason, and the
decision trace records that check's rule identifier (section 8.4.5 lists
every identifier).

1. **Input bounds** (`constraints.input`). Before any rule, the verifier
   refuses with `payment_constraint_invalid` a chain of fewer than 1 or more
   than 10 payment caveats, more than 256 payer-borne fee amounts, or a
   decision time that is not an integer from 0 through 2^53 − 1 (section 7.1).
2. **Structure** (`constraints.structure`). The intent is parsed strictly by
   its schema (section 8.1), and every caveat (section 8.4 and rule 8 of
   section 8.4.2) and every fee amount (section 7) by theirs, so a member a
   schema does not define, or a missing member it requires, fails this check;
   the verified quote, when given, has exactly the members below; and
   the approval facts, when given, have at least the two members below. A
   quote, or a `fees` member that is present, an empty list included, given
   while those rules are deferred is refused too. The
   **verified quote** is an object of exactly the members
   `issuer`, the quote authority that authenticated it (1 to 2,048 code
   points); `digest`, the `sha256:` digest of the quote (section 10), as the
   execution profile's adapter rule derives it;
   `source`, the amount it converts; and `target`, the amount it converts it
   into (both amounts of section 7). The constraint evaluator receives the
   verified quote in exactly this shape, and the quote's expiry is not part of
   it: a quote given with an `expiresAt`, or with any other member beyond
   these four, fails this check. The **approval facts** are an object whose
   `mode` is an approval mode (section 8.2) and whose `issuer` is a non-empty
   string: the mode and issuer of the verified approval; any other member of
   it is ignored. A failure is `payment_constraint_invalid`.
3. **Attenuation.** Every edge, root first, is checked against section 8.4.2,
   member class by member class in the order of the rule identifiers
   `attenuation.businessLimits`, `attenuation.payees`,
   `attenuation.resources`, `attenuation.rails`,
   `attenuation.settlementLimits`, `attenuation.quoteAuthorities`,
   `attenuation.fees`, `attenuation.requireApproval`, and
   `attenuation.expiry`. The first widening is `payment_constraint_widening`.
4. **Intent rules.** The intent is evaluated against the leaf caveat, the
   effective constraints, by the rules of the table below, in order.

Checks 1 and 2 can fail only when the constraint evaluator is used on its
own, as the `constraints` vectors use it (section 15.1) and as the
re-evaluation that precedes a payment effect uses it (below). In the
verification order of section 8.4.6 their inputs are refused earlier, each
with its own reason: the chain's length at step 1
(`payment_delegation_invalid`), each payment caveat at step 6
(`payment_constraint_invalid`), the intent when the request is authenticated
(`payment_artifact_invalid`), a decision time outside section 7.1 there too
(`payment_configuration_invalid`), and the approval facts with their evidence
at step 9 (`payment_approval_invalid`); the quote and fees are no inputs at
authority time. Check 3 repeats step 6, so at step 10 only an intent rule can
fail.

An effective settlement amount (section 7) that differs from the business
amount, in asset or value, is a **conversion**.

| # | Rule | The intent passes when |
| --- | --- | --- |
| 1 | `intent.nonZeroAmount` | The business `amount` is non-zero. |
| 2 | `intent.businessAmount` | `businessLimits` holds a limit for the amount's exact asset, and the amount does not exceed it. |
| 3 | `intent.payee` | `payees` is absent, or the intent's payee matches an allowed payee: the same `id` and, when the allowed payee carries an account commitment, the same `accountDigest` and `accountDigestMethod`. The match is one-sided: an account commitment that the intent's payee carries and the allowed payee lacks is not compared. |
| 4 | `intent.resources` | `resources` is absent, or every intent resource matches an allowed resource: the same `id` and, when the allowed resource names a `digest`, the same `digest`. |
| 5 | `intent.rail` | `rails` is absent, or the payment selection is within an allowed rail: the same protocol `id` and `version`, and the same value for every qualifier the allowed rail names: `specDigest`, `methodId`, `handlerId`, `scheme`, `network`, `transferMethod`, `paymentFlow`, and `fundingAccount`. |
| 6 | `intent.nonZeroSettlement` | A stated `settlementAmount` is non-zero. |
| 7 | `intent.settlementAmount` | The intent is not a conversion, or a `settlementLimits` grant covers the settlement amount: it holds a limit for the amount's exact asset, and the amount does not exceed it. |
| 8 | `intent.quote` | The intent is not a conversion; or the intent carries a `quoteDigest`, the effective constraints carry a `quoteAuthorities` grant, and, unless the rule is deferred, the verified quote binds the conversion: its `digest` is exactly the string `quoteDigest`, its `source` equals the business `amount` and its `target` the `settlementAmount` (the same asset and value, section 7), and its `issuer` is listed in `quoteAuthorities`. |
| 9 | `intent.fees` | The rule is deferred; or, once payer-borne fees whose coefficient is `"0"` are disregarded, no fee remains under a prohibited or omitted fee policy, and, under a capped policy, every remaining fee is in an asset the cap list names and each asset's exact sum of the remaining fees does not exceed its limit. |
| 10 | `intent.approval` | `requireApproval` is absent or does not apply to the intent (it applies unless `above` exempts the intent, section 8.4.1); or a verified approval is present whose mode is in `modes` and whose issuer is in the effective approver set: listed in `approvers`, or the payer when the requirement lists no approvers. |
| 11 | `intent.expiry` | The effective constraints state no `expiresAt`, or the decision time is before it and the intent's `expiresAt` does not exceed it. |

A failing `intent.approval` is `payment_approval_required`, the challenge of
section 8.2; every other failing intent rule is `payment_constraint_denied`.
Business ceilings are never reused as exchange-rate limits, and the quote is
what ties the client-declared business amount to the amount that moves.

When authority is decided, the quote and the payer-borne fees are rail facts
not yet verified. The quote rule of a converted intent and the fee rule are
then recorded as `deferred` (section 8.2). The party that makes a payment
effect (section 4.3) MUST NOT make one under a decision that deferred a rule
until it has evaluated the intent again and that **re-evaluation** has
passed. The re-evaluation is the constraint evaluation of this section, with
no rule deferred, over these inputs:

- the chain: one caveat, the effective constraints of the authority decision,
  which are its chain's leaf caveat (section 8.4.2);
- the same intent;
- the payer-borne fees verified for the payment (none when none were
  verified) and, for a conversion, the verified quote;
- the approval facts: the `mode` and `issuer` of the approval that the
  authority decision recorded (section 8.2), and none when it recorded none;
  and
- the decision time: a reading of the clock taken for the payment effect,
  after the authority decision (section 7.1), never the decision time of that
  decision.

Every check of this section runs again, every intent rule among them, not
only the deferred ones; check 3 has no edge to check. The re-evaluation runs
the payment constraints only: every other caveat, one that a registered
evaluator decides included, is evaluated only when authority is decided
(section 8.4.6, step 7), at the decision time. (Informative: the execution
profile's final authority recheck before submission is the step that reads
the chain again at that later time, re-reading the live status of every
delegation in it; a registered evaluator whose answer depends on time is
therefore evaluated at the decision time unless that recheck runs it again.)
A check that fails
refuses the payment effect with its reason, so a caveat `expiresAt` reached by
the time of the re-evaluation fails `intent.expiry`
(`payment_constraint_denied`). A re-evaluation that cannot read the effective
constraints or the approval facts that the authority decision established,
or that cannot complete, fails closed (`payment_constraint_invalid`).
Approval evidence is verified only when authority is decided (section 8.4.6,
step 9); the re-evaluation verifies no evidence and re-reads the facts of the
approval recorded then. It changes nothing in the Payment Authorization,
whose trace remains that of the authority decision. (Informative: the
execution profile obtains the fees and the quote from the rail terms its
adapter verifies, and checks the quote's own expiry apart from the verified
quote, section 8.2.)

**Decision trace.** The trace is an ordered list of entries, each a `rule`
identifier, a `result`, and, for an attenuation entry, the `hop`: the 0-based
index from the root of the edge's child credential, 1 for the first edge. It
holds the entries of this constraint evaluation only. A refusal at another
step of section 8.4.6, a caveat refusal of section 8.4.5 among them, names its
rule and `hop` in the refusal and never in a trace. The trace of an authorized
decision is exactly:

1. `constraints.structure`, `pass`;
2. for each edge, root first, one entry per attenuation rule identifier, in
   the order of check 3 above, each `pass` with the edge's `hop`; then
3. one entry for each of intent rules 2 to 5 and 7 to 11, in table order:
   `deferred` for `intent.fees`, and for `intent.quote` of a conversion, when
   those rules are deferred, and `pass` otherwise. Rules 1 and 6 have no entry
   of their own; they only refuse.

For example, a one-credential chain has no edge, so no entry of its trace
carries a `hop`. Authorized with the quote and fee rules deferred, for an
intent that is not a conversion (the `constraints` vector
`valid-execution-terms-deferred-without-conversion`, section 15.1), its
decision records exactly this `decisionTrace`:

```json
[
  { "rule": "constraints.structure", "result": "pass" },
  { "rule": "intent.businessAmount", "result": "pass" },
  { "rule": "intent.payee", "result": "pass" },
  { "rule": "intent.resources", "result": "pass" },
  { "rule": "intent.rail", "result": "pass" },
  { "rule": "intent.settlementAmount", "result": "pass" },
  { "rule": "intent.quote", "result": "pass" },
  { "rule": "intent.fees", "result": "deferred" },
  { "rule": "intent.approval", "result": "pass" },
  { "rule": "intent.expiry", "result": "pass" }
]
```

For a conversion, the `intent.quote` entry is `deferred` instead.

A refusal's trace holds exactly one entry whose result is `deny`, its last.
It is `constraints.input` or `constraints.structure` alone; or, for a widening
at hop h, the entry of item 1, then the nine `pass` entries of item 2 for each
edge before hop h, then one `deny` entry for the widening rule with `hop` h,
and no entry for a rule of edge h that passed before it; or, for an intent
rule, the entries of items 1 and 2, then one `deny` entry for the failing
intent rule, and no entry for an intent rule that passed before it. The
corpus does not compare traces (section 15.1.1). A
Payment Authorization records only the trace of an authorized decision, so its
entries (the authorization schema's `decisionTraceEntry`) carry `pass` or
`deferred`, never `deny`.

**Result.** Besides its trace, the evaluation yields its decision. An
authorized decision carries the effective-constraints digest (section 8.4.2)
and the identifiers of the rules recorded as `deferred`, in table order. A
refusal carries its reason, its rule identifier, the `hop` of an attenuation
rule, and, unless it is `constraints.input` or `constraints.structure`, an
effective-constraints digest: for a widening at `hop` h, the digest of the
effective constraints of the chain up to the hop before the widening, that
is, of the normalized caveat at hop h − 1, every edge before it having
passed; for
an intent rule, the digest of the full effective constraints, the leaf
caveat. The `constraints` vectors record this result (section 15.1.1).

#### 8.4.5 Every caveat restricts the payment

Base re-delegation treats every caveat as a restriction a child cannot drop.
The Authority Verifier MUST therefore evaluate every caveat of every credential
in the chain against the intent before authorizing it:

- `org.kya-os/payment-constraints`: the algebra above;
- `ValidUntil` (members `type`, `date`): its date is parsed per section 7.1
  and bounds the authorization expiry, and the caveat is refused once its
  date is reached (`payment_delegation_invalid`);
- `MaxAmount` (members `type`, `limit`, optional `currency`): `limit` matches the
  grammar below, and a `currency` member that is present, with a `null` value
  included, is three uppercase ASCII letters. A decimal limit is an amount of
  one named currency, so a `MaxAmount` without `currency` denies every
  payment; with it, the Authority Verifier refuses a business amount that is
  not in exactly that ISO 4217 currency, or that exceeds `limit` (exact
  comparison). Currency codes compare
  exactly; the profile does not consult the ISO 4217 register. `MaxAmount`
  bounds only the business amount; converted settlement is governed by the
  payment caveat's grants and the verified quote;
- the Authority Verifier refuses a built-in caveat carrying any other member
  (`payment_caveat_unsupported`): the member may express a restriction, such as
  a spend window, that the built-in evaluation would silently ignore;
- a caveat type for which the deployment registered an evaluator is decided by
  it. Registration is exact-type and cannot override the payment caveat or a
  built-in. A registered evaluator MUST answer within the call, never with an
  answer deferred until after it returns, and MUST decide from the
  caveat, the intent, and the decision time alone, so it depends on no service
  (the re-evaluation of section 8.4.4 does not run it again).
  It admits the intent only by answering `true` within the call; any other
  answer, a deferred one (such as a promise) included, denies
  (`payment_constraint_denied`), and one that throws denies with
  `payment_caveat_unsupported`, since a throw is its answer about the caveat
  (rule `caveat.evaluator` in both cases). An Authority Verifier
  that registers an evaluator for a type SHOULD also register a re-delegation
  relation for it; without one the caveat is copied verbatim; and
- any other caveat type denies (`payment_caveat_unsupported`), because the
  verifier cannot evaluate a restriction it does not define.

A `MaxAmount` limit is a non-negative decimal with no sign, exponent, or
leading zero (trailing fraction zeros are allowed, so `500` and `500.00` are
equal limits), matched in full (a trailing line terminator never matches):

```abnf
limit    = integer [ "." fraction ]
integer  = "0" / ( %x31-39 0*59DIGIT )   ; no leading zero; at most 60 digits
fraction = 1*18DIGIT
```

Caveats are evaluated credential by credential from the root, and each
credential's caveats in their order, the payment caveat skipped (steps 6 and
10 of section 8.4.6 decide it); the first caveat that fails decides, with the
reason the table below gives its rule, and the refusal names that rule and the
`hop` of the caveat, the 0-based index from the root of the credential that
carries it (section 8.4.6, step 7). Within one caveat, `caveat.malformed` is
checked first, then `caveat.members`, then the rules of its type in the order
of the table below. This evaluation takes a caveat as well-formed when it is
a JSON object whose `type` is a string, and refuses any other caveat as
`caveat.malformed`. An empty `type` is a string: the
evaluation treats it as any other type nothing evaluates
(`caveat.unsupported`). The credential parse of step 1 is stricter: each
caveat is an object whose `type` is a non-empty string and whose `date`,
`limit`, and `currency`, when present, are strings. Within the verification
order some caveats therefore fail an earlier step first and carry that step's
reason, `payment_delegation_invalid`: step 1 refuses every caveat that
`caveat.malformed` would refuse, one with an empty `type`, and one with a
non-string `date`, `limit`, or `currency`, and step 5 refuses a `ValidUntil`
whose `date` string is not exact or is reached. At step 7 only
`caveat.validUntil.malformed` (a `ValidUntil` without `date`) and
`caveat.maxAmount.malformed` still give that reason.

**Rule identifiers.** The decision trace of section 8.4.4 names its entries by
the `constraints.*`, `attenuation.*`, and `intent.*` identifiers below; a
caveat refusal names its `caveat.*` identifier, with its `hop`, in the refusal
only; and the vector corpus (section 15.1) names each refusal by its
identifier.

| Identifier | Fails when | Reason |
| --- | --- | --- |
| `constraints.input` | An input bound of section 8.4.4, check 1, is not met. | `payment_constraint_invalid` |
| `constraints.structure` | The intent, a payment caveat, a fee amount, the verified quote, or the approval facts are malformed, or a quote or a `fees` member, an empty list included, was given for deferred rules (section 8.4.4, check 2). | `payment_constraint_invalid` |
| `attenuation.<member>` | The edge at `hop` widens that member class (section 8.4.2): `businessLimits`, `payees`, `resources`, `rails`, `settlementLimits`, `quoteAuthorities`, `fees`, `requireApproval`, or `expiry` (the `expiresAt` ceiling). | `payment_constraint_widening` |
| `intent.<rule>` | The intent rule of that name (section 8.4.4) fails. | `payment_approval_required` for `intent.approval`; otherwise `payment_constraint_denied` |
| `caveat.malformed` | A caveat is not a JSON object whose `type` is a string (an empty `type` is a string: `caveat.unsupported`). | `payment_delegation_invalid` |
| `caveat.members` | A `ValidUntil` or `MaxAmount` caveat carries a member outside its member set. | `payment_caveat_unsupported` |
| `caveat.unsupported` | A caveat is of a type that is not the payment caveat, a built-in, or a registered type. | `payment_caveat_unsupported` |
| `caveat.validUntil.malformed` | A `ValidUntil` has no `date` string in the section 7.1 grammar. | `payment_delegation_invalid` |
| `caveat.validUntil.expired` | The decision time is at or after a `ValidUntil` date. | `payment_delegation_invalid` |
| `caveat.maxAmount.malformed` | A `MaxAmount` has no `limit` string in the grammar above, or a `currency` member, `null` included, that is not three uppercase ASCII letters. | `payment_delegation_invalid` |
| `caveat.maxAmount.currency` | A `MaxAmount` names no `currency`, or the business amount is not in exactly that ISO 4217 currency. | `payment_constraint_denied` |
| `caveat.maxAmount` | The business amount exceeds a `MaxAmount` `limit`. | `payment_constraint_denied` |
| `caveat.evaluator` | A registered evaluator answers anything but `true` within the call (a denial, or a deferred answer), or throws. | `payment_constraint_denied`; `payment_caveat_unsupported` when it throws |

#### 8.4.6 Verification order

The Authority Verifier MUST decide an authenticated payment request by the
steps below, in exactly this order, and MUST refuse it at the first step that
fails: no later step runs, and the refusal carries the one section 13 reason
that step names for the failure. Before step 1 the Executor has authenticated
the request and made the checks that the request and the intent alone decide
(section 4.2), and the request has passed them: the intent's audience, payee,
presenter, `createdAt`, and expiry (sections 4.1, 7.1, and 8.1), its
extensions (check V5 of section 8.7, and section 14, item 6), and the request
proof's `expires` (sections 7.1 and 8.2). The order of those checks, and so
the reason a request carries when several of them fail, is defined by the
execution profile; the first-failure rule of this section, and of section 13,
applies from step 1, to a request that has passed them all.

1. **Bounded parse.** A chain of 1 to 10 credentials is presented, and no
   object in them repeats a member name (section 10); each credential's
   RFC 8785 serialization is at most 65,536 bytes, and it carries at most 32
   caveats; and the chain is the one the proof-covered `delegationDigest`
   names (section 10). Only then is each credential parsed: no member is named
   `__proto__`, it is a well-formed delegation credential (SPEC.md §6.10)
   whose caveats are each well-formed as section 8.4.5 requires of this step,
   its delegate is not its own issuer (section 8.4), and none of its issuer,
   its delegate (section 4.1), and its `credentialSubject.id` is longer than
   2,048 code points, the bound of the `did` and `reference` members of a
   Payment Authorization that record such identifiers (`principal`,
   `responsibleParty`, `delegation.delegates`, and `delegation.credentialRef`;
   Appendix A.2); every `credentialSubject.id` is non-empty, and no two
   credentials of the chain have the same one, so no credential appears twice
   and the credential digests that `delegation.chainDigests` records are
   distinct, as the authorization schema requires; and the leaf's delegate is
   the actor. Failure: `payment_delegation_invalid`.
2. **Accepted payer.** When the Executor restricts the payers it serves, the
   root issuer is one of them, checked before any DID resolution or status
   fetch (section 14, item 22). Failure: `payment_delegation_invalid`.
3. **Credential proofs.** Every credential carries one proof, never a proof
   set or a proof chain: its `proof` is a single object, without
   `previousProof`. That proof is a `DataIntegrityProof` whose `proofPurpose`
   is `assertionMethod` and whose `verificationMethod` is a DID URL whose DID
   is exactly the credential's issuer (its `issuer`, or `issuer.id`), so an
   issuer that is not a DID never verifies; the issuer's DID document,
   resolved under the document-`id` rule of section 8.2, lists that
   verification method in its `assertionMethod` relationship. The proof's
   `created`, when present, is at most the 60-second skew of section 7.1
   after the decision time, and its `expires`, when present, is after the
   decision time, each a bound in the section 7.1 grammar. The proof verifies
   over every member of the credential as presented other than its proof
   value, as its Data Integrity cryptosuite defines [VC-DATA-INTEGRITY] (for
   `eddsa-jcs-2022`, [VC-DI-EDDSA] §3.3; section 14, item 18). Failure:
   `payment_delegation_invalid`.
4. **Revocability.** Every credential carries a status entry whose
   `statusPurpose` is `revocation` (section 8.4). Failure:
   `payment_delegation_invalid`.
5. **Validity window.** Every start bound (`validFrom`) is exact (section 7.1)
   and reached, and every expiry — each credential's `validUntil` and each
   `ValidUntil` caveat's `date` — is exact and not reached; an expiry is
   exclusive. Failure: `payment_delegation_invalid`.
6. **Payment caveats.** Every credential carries exactly one payment caveat,
   and each is at most 16,384 bytes and parses strictly (section 8.4 and
   rule 8 of section 8.4.2). Failure: `payment_constraint_invalid`. Then every
   edge, root to leaf, is checked against section 8.4.2 in the rule order of
   section 8.4.4, check 3. Failure: `payment_constraint_widening`, and the
   refusal names the widening rule and its `hop`.
7. **Every other caveat.** Every other caveat restricts the payment
   (section 8.4.5), root first, the first failure deciding, with the reason
   the rule table of section 8.4.5 gives: `payment_caveat_unsupported` for a
   caveat of a type nothing evaluates, a built-in with a member outside its
   member set, or a registered evaluator that throws;
   `payment_constraint_denied` for a `MaxAmount` whose currency or limit does
   not admit the business amount, or a registered evaluator that does not
   admit the intent within the call; and
   `payment_delegation_invalid` for a malformed `ValidUntil` or `MaxAmount`
   (steps 1 and 5 have already refused every other caveat that the rule
   table gives this reason, section 8.4.5). The refusal names the rule and
   its `hop`.
8. **Base chain and live status.** The base chain rules (SPEC.md §6.10) hold,
   with the narrowing relation of section 8.4.3 registered, the per-hop
   `audience` rule (SPEC.md §11.6) read as `BASE-AMENDMENTS.md` item 3
   proposes, so that the chain's constant `invocationTarget` is its audience
   binding, and the root bound to the Executor's protected resource, which
   the Authority Verifier asserts, never asserting a resource owner, since a
   payment chain is rooted at the payer (step 9). Failure:
   `payment_delegation_invalid`. Then every credential's status is read
   (section 14, item 19), root to leaf, as the base walk reads it (SPEC.md
   §6.10, Revocation). The read stops at the first credential that a list
   reports revoked, or whose status is unavailable or unauthenticated, and
   that credential decides the reason: `payment_delegation_revoked` when a
   live list reports it revoked, and otherwise `payment_authority_stale`. A
   credential that a list which is not live reports unrevoked does not stop
   the read; once every credential has been read, any such credential is
   `payment_authority_stale`. So a revoked credential below one whose list
   is not live but reports it unrevoked is `payment_delegation_revoked`, and
   one below a credential whose status is unavailable is
   `payment_authority_stale`, since its status is never read. Then the leaf's
   `allowedAction` contains the intent's action. Failure:
   `payment_action_not_granted`.
9. **Approval evidence, intent, and payer.** Approval evidence, when
   presented, yields a verified approval under a format the Authority
   Verifier implements (section 8.2); that approval names exactly the intent
   digest computed for the intent and the evidence digest computed over the
   presented `value` (section 8.2), has
   not expired at the decision time, and is admitted by the authorization
   schema's `approval` member; and, by the **no-self-approval rule**, neither
   its issuer nor its `did` subject is a delegate of the chain (section 4.1)
   nor, when `principal` differs from `responsibleParty`, the principal,
   whatever `approvers` lists.
   Failure: `payment_approval_invalid`.
   Then the intent digest that the verified request binds is the digest of
   the intent being decided (failure: `payment_intent_mismatch`), and the
   intent's `payer` is the verified responsible party (section 8.1; failure:
   `payment_payer_mismatch`).
10. **Intent evaluation.** The constraint evaluation of section 8.4.4, whose
    trace the Payment Authorization records. Only an intent rule can fail
    here: `intent.approval` is `payment_approval_required`, and every other
    intent rule `payment_constraint_denied`.

A request that fails several steps is refused with the reason of the first:
a `MaxAmount` exceeded at hop 0 of a chain whose payment caveat widens at
hop 1 is refused at step 6 (`payment_constraint_widening`, naming the widening
rule and hop 1), never at step 7.

### 8.5 Artifact authenticity and envelopes

The core artifact schemas define canonical **content objects**; they are not
self-authenticating merely because they contain identities and digests.

- A Payment Intent MUST be covered by the KYA request/holder proof, as the
  `intent` of the payment argument (section 8.2).
- A Payment Authorization is evidence to the party that recomputed it from its
  own verification (section 8.2), which keeps it with integrity protection. A
  party relies on an authorization it did not recompute only under the
  Portable Evidence tier, in an envelope that identifies the same `verifier`
  and covers the complete canonical authorization bytes.
- A Payment Outcome is the statement of its identified `producer`. A party
  other than its producer relies on it only under the Portable Evidence tier,
  in an envelope that covers the complete canonical outcome bytes.

Envelopes belong to the optional Portable Evidence tier (section 4.3), whose
envelope formats — for example a KYA response proof, an HTTP Message
Signature, or a rail-native receipt — the execution profile defines. Core
Authority requires no envelope.

A receiver MUST NOT trust `verifier`, `producer`, `decision`, `state`, or any
digest solely because the JSON shape validates. Under the Portable Evidence
tier, envelope verification and authorization to speak for that
verifier/producer are separate checks, both of which that tier requires.
Locally recomputed records need no redundant wire signature, but the integrity
of their storage and their audit provenance remain part of the trusted
computing base.

### 8.6 Schema and semantic-validation contract

Experimental payment schemas declare
`https://schema.kya-os.org/experimental/payment-authority/2026-09-22/meta`,
whose semantic-validation vocabulary,
`https://schema.kya-os.org/experimental/payment-authority/2026-09-22/vocabulary/semantic-validation`,
is required. It defines the
`kyaOrderedNumberRange`, `kyaNotAfter`, `kyaUniqueProperty`, `kyaUniqueBy`,
`kyaCanonicalJson`, and `kyaCanonicalJsonCollection` assertions used by these
schemas, whose values follow `payment-profile-vocabulary.schema.json`. A
processor that does not implement the vocabulary MUST refuse the schema;
treating its keywords as annotations is nonconformant. (Informative: Ajv does
not read `$vocabulary`. In strict mode it refuses a schema that uses one of
these keywords when none is registered, but compiles a schema that declares
the meta-schema without using them, such as the extension settings schema; a
conforming use of Ajv registers the vocabulary's keywords.)

A schema's `description` strings name a member and the section of this
document that defines it. They state no rule: the text and the assertions of
the schema govern.

Each keyword asserts over the instance it is applied to, in the JSON data
model, where an array is not an object and has no named members. Every keyword
but `kyaCanonicalJson` applies only to an object instance, and any other
instance passes it. In the keyword values, `first`, `last`, `value`,
`limitObject`, `limit`, `array`, and `property` each hold a member name, and
`path` and each entry of `properties` hold a **path**: member names joined by
`.`, which resolves from a value one member at a time, and resolves to nothing
when a step reaches a value that is not an object or has no member of that
name.

- `kyaOrderedNumberRange` `{first, last, exclusive}`: when the instance's
  members named by `first` and `last` are both numbers, the second MUST be
  greater than the first if `exclusive` is `true`, and not less than it
  otherwise (`exclusive` defaults to `false`). When either member is absent or
  not a number, the keyword passes.
- `kyaNotAfter` `{value, limitObject, limit}`: when the instance's member
  named by `value` is a number, its member named by `limitObject` is an
  object, and that object's member named by `limit` is a number, the first
  number MUST NOT exceed the second. In every other case the keyword passes.
- `kyaUniqueProperty` `{array, property}`: when the instance's member named by
  `array` is an array, no two of its items have the same key. An item's key is
  its member named by `property` when the item is an object that has one, and
  otherwise *none*. Two keys are the same when both are *none*, or both are
  the same string, the same number by value, both `true`, both `false`, or
  both `null`; a key that is an object or an array is the same as no other.
  When that member is absent or not an array, the keyword passes.
- `kyaUniqueBy`, a list of `{path, properties}`: the instance passes when
  every entry does. An entry's `path` resolves from the instance; when it
  resolves to nothing, the entry passes, and when it resolves to a value that
  is not an array (`null` included), the entry fails. Otherwise each item of
  the array has a projection: the item itself, or, with `properties`, the
  array of the values that each listed path resolves to from the item, in the
  listed order. The entry fails when a projection is not a canonical value
  (section 10), which includes a listed path that resolves to nothing, and
  when two projections have the same RFC 8785 serialization.
- `kyaCanonicalJson` `{maxBytes, maxDepth, maxNodes}`, which applies to an
  instance of any type: the instance MUST be a canonical value (section 10),
  its RFC 8785 serialization MUST be at most `maxBytes` UTF-8 bytes, its
  depth at most `maxDepth`, and its number of values at most `maxNodes`.
  Depth counts values, not containers: the top-level value has depth 1, and
  each member value or array element is one deeper than the value that
  contains it, so `{"a":[1]}` has depth 3. The count counts every value, the
  top-level one included, so `{"a":[1]}` holds 3 values.
- `kyaCanonicalJsonCollection` `{property, maxBytes}`: every member value of
  the instance MUST be an object whose member named by `property` is a
  canonical value, and the UTF-8 lengths of those values' RFC 8785
  serializations MUST sum to at most `maxBytes`.

The schemas apply `kyaOrderedNumberRange` (exclusive) to the `createdAt` and
`expiresAt` of the intent and the authorization; `kyaNotAfter` to the
authorization's `expiresAt` against `approval.expiresAt`; `kyaUniqueProperty`
to the intent's `resources` by `id` and to the authorization's and the
outcome's `evidence` by `digest`; `kyaUniqueBy` to the payment caveat's lists
of amounts (by asset), payees, resources, and rails (section 8.4);
`kyaCanonicalJson` to each extension's `data` and to the payment caveat as a
whole; and `kyaCanonicalJsonCollection` to each `extensions` map, over
`data`.

**String lengths.** Every length bound of this profile, in the schemas and in
the text, counts Unicode code points, as JSON Schema's `minLength` and
`maxLength` do (a UTF-16 surrogate pair is one code point), and an
implementation MUST count this way. Every bounded string is also well-formed
Unicode: an implementation MUST refuse a lone surrogate, which JSON Schema
cannot express and RFC 8785 cannot serialize (section 10), where it enters.
(The execution profile applies the same rule to the references a rail adapter
reports.) Bounds stated in UTF-8 bytes (the
approval evidence `value` of section 8.2 and the limits of `kyaCanonicalJson`
and `kyaCanonicalJsonCollection`) count bytes.

**DIDs.** The schemas' `did` pattern (`did:` followed by one or more
characters, none of them CR or LF; any other character, U+2028 and U+2029
included, is admitted) is a coarse filter, not the DID syntax of W3C DID 1.0
§3.1. A DID that names a
party in an artifact is checked by exact comparison with a DID the verifier
derived (the payer with the chain's root issuer, the presenter and the actor
with the request proof's DID; section 4.1). This document checks no DID
against the DID syntax itself; an approval evidence format can (section 8.2).

**URIs.** The schemas' URI pattern, `^[A-Za-z][A-Za-z0-9+.-]*:[^\r\n]+$`
(`absoluteUri` in the authorization schema), which an approval's `issuer`, an
`oidc-subject` approval subject's `issuer`, the `id` of a `uri` asset, an
extension's `schema`, and the URI form of an extension identifier all use, is
a coarse filter too: a scheme (an ASCII letter followed by ASCII letters,
digits, `+`, `.`, or `-`), `:`, and one or more characters, none of them CR or
LF (any other character, a space and U+2028 included, is admitted). It is not
the `absolute-URI` syntax of RFC 3986 §4.3: `urn:not a uri` matches it. A
party that produces such a value SHOULD write it as an RFC 3986 absolute URI;
a consumer checks only the pattern, and this document compares these values
only as exact strings (an approval's issuer with `approvers` or the payer,
section 8.4.1, and with the delegates of the chain, section 8.2; an asset with
another, section 7), never by URI syntax or normalization.

Structural JSON Schema success still does not establish signature, authority,
freshness, attenuation, funding authority, or rail validity. Artifact
validation (section 8.7) and the `semantic` vectors of the corpus
(section 15.1) are part of Core Authority conformance.

### 8.7 Artifact validation

A party that accepts a Payment Intent, a Payment Authorization, a Payment
Outcome, or a payment caveat as JSON text, whatever its role, is a
**consumer** of it, and MUST validate it in three steps, refusing it at the
first that fails: parse it as section 10 requires (no object with two members
of one name, no string that is not well-formed Unicode); validate it against
its schema with the required vocabulary (section 8.6); and apply these checks,
which the schemas do not state:

- **V1** (every artifact). No object in it, at any depth, extension data
  included, has a member named `__proto__` (section 14, item 26).
- **V2** (Payment Authorization). When `delegation.delegates` is present, it
  contains `actor`.
- **V3** (Payment Authorization). When `approval` is present,
  `approval.issuer` is not an entry of `delegation.delegates`, nor, when
  `principal` differs from `responsibleParty`, `principal`.
- **V4** (Payment Authorization). When `approval.subject` is present with
  `kind` `did`, its `id` is not an entry of `delegation.delegates`, nor, when
  `principal` differs from `responsibleParty`, `principal`.
- **V5** (every artifact that carries `extensions`). Every extension for whose
  exact `version` the consumer has a handler passes that handler (section 14,
  item 6), and every critical extension has one: an artifact that carries a
  critical extension whose identifier, or whose exact version, the consumer
  has no handler for is refused. V5 refuses a noncritical extension only when
  the consumer has a handler for its exact version and that handler refuses
  it; one without such a handler passes, so the validity of an artifact that
  carries a noncritical extension also depends on the handlers its consumer
  has.

V3 and V4 apply the no-self-approval rule (section 8.4.6, step 9) to the
record: a principal that differs from `responsibleParty` is the delegate of a
credential nearer the root, whether or not `delegates` names it. A failure is
`payment_artifact_invalid`, except that a V5 failure is
`payment_extension_unsupported` for a critical extension without a handler
and `payment_extension_invalid` for an extension its handler refuses, and
that a payment caveat in a presented chain
is refused at the step of section 8.4.6 that reaches it first, with that
step's reason. V5 applies after V1 to V4, so an artifact that fails both
carries the reason of the earlier. These steps, V5 included, are all the
validation of a single artifact. V5 depends on the handlers the consumer has,
so a vector decides it only for the handlers it fixes: the `admission`
vectors (section 15.1) decide it for an Executor with no extension handler.
The other steps decide the corpus's `semantic` vectors, which carry no
critical extension and are decided as by a consumer with no extension
handler. The verification
steps that compare an artifact with other inputs (section 8.4.6) and the
checks of an outcome stream (section 8.3) are not artifact validation.

Every other rule this document states about an artifact's members is an
obligation of the party that produces the artifact, for example that
`delegation.credentialDigest` is the last entry of `delegation.chainDigests`
and `approval.intentDigest` equals `intentDigest` (section 8.2), that an
outcome carries a `reason` without a `basis` only when its state is `failed`
(the schema refuses a `basis` on any other state; section 8.3), or that an
authorization's evidence carries no `finality` (section 9). A consumer does
not check these from the artifact alone; a party that relies on them
recomputes the record (section 8.5).

## 9. Evidence references

Foreign signed artifacts are represented by evidence references. Example
(digests are illustrative):

```json
{
  "type": "https://ap2-protocol.org/profiles/mandate.payment.1",
  "format": "application/sd-jwt",
  "digest": "sha256:7777777777777777777777777777777777777777777777777777777777777777",
  "ref": "urn:example:evidence:payment-mandate-123",
  "canonicalization": "raw",
  "class": "approval",
  "custodian": "did:web:merchant.example",
  "retentionPolicy": {
    "id": "urn:example:policy:card-dispute",
    "digest": "sha256:8888888888888888888888888888888888888888888888888888888888888888"
  }
}
```

`type` identifies the kind of evidence (for example an AP2 mandate profile),
`format` names the format of its bytes (for example a media type), and
`digest` is the `sha256:` digest (section 10) of those bytes.
`canonicalization` names how the evidence bytes were canonicalized before
`digest` was taken. This document
defines one value, `raw`: `digest` is taken over the octets of the evidence
in its `format`, never over an encoding a transport applied to carry them,
with no canonicalization and no domain separation. Any other value is defined
by the evidence format that uses it. (Informative: rail evidence is reported
by the execution profile's rail adapters; for x402, the evidence of a
settlement is a reference to a receipt of the transfer's public facts, with
`canonicalization` `RFC8785` and a `digest` taken over the RFC 8785
serialization of those facts.) An artifact's `evidence` holds at most 64
references, no two with the same `digest`.

`class` (one of `authority`, `approval`, `commerce_terms`, `funding_authority`,
`rail_authorization`, `rail_receipt`, `fulfillment`, `refund_or_reversal`,
`communication`), `custodian`, the party that holds the evidence, and
`retentionPolicy`, the `id` of the policy that governs it with the `digest` of
that policy, are optional. They let a deployment apply
retention and retrieval policy per evidence item without prescribing one
universal duration; a retrieval profile that relies on them can make them
mandatory. Payment authority never implies evidence access. `finality` is the
level at which a `settled` outcome's settlement was read before the rail's own
final state (section 8.3); the producer of that outcome adds it to the
outcome's rail evidence, each reference whose `class` is `rail_receipt` and
each that names no class. The authorization and outcome schemas share this
one evidence-reference shape, so both admit `finality`; a producer MUST NOT
include it in an authorization's evidence, which is recorded before any rail
result, and a consumer MUST ignore it there.

`ref`, optional, names where the evidence can be retrieved. It is an
identifier, not a credential, and its producer MUST NOT put in it user-info,
capability secrets, signed query parameters, authorization codes, or another
value whose possession alone grants access. Syntactically, `ref` MUST match the
schemas' `ref` pattern, which refuses user-info, a query, and a fragment; that
the rest of a reference carries no secret is the producer's obligation, which
no consumer can check from the artifact. The pattern admits exactly two forms:

- a scheme the WHATWG URL standard treats as special, written in lowercase
  (`http`, `https`, `ws`, `wss`, `ftp`, `file`), followed by `://`, a
  non-empty authority that contains no `/`, and optionally a path that starts
  with `/`; or
- any other scheme, which is a lowercase ASCII letter followed by lowercase
  ASCII letters, digits, `+`, `.`, or `-` and is never `javascript`,
  `vbscript`, or `data`, followed by `:` and a non-empty remainder.

In both forms no character after the scheme is `?`, `#`, `@`, `\`, or
whitespace (as ECMA-262 `\s` matches it), and a scheme with an uppercase
letter, such as `HTTPS://host/path`, matches neither form. A `ref` therefore
never carries user-info, a query, or a fragment; a special-scheme reference always names an
authority after `//`, because the WHATWG parser reads `https:user:pass@host`
as user-info, so `file:///var/evidence/1`, whose authority is empty, matches
neither form;
and an evidence viewer never renders an executable reference. A reference that
violates the pattern never appears in a valid artifact; the execution profile
defines how an Executor omits one that its rail adapter reports. If a
reference is dereferenceable, the evidence service applies independent
authenticated authorization, minimization, retention, and erasure policy;
unauthenticated possession of the outcome is insufficient.

A party that retains or verifies foreign signed evidence MUST keep the
original bytes its signature format needs, and MUST NOT verify AP2, UCP, x402,
HTTP signatures, or another format against a parsed-and-reserialized
approximation.

## 10. Digests and canonicalization

Core artifacts use RFC 8785 JSON Canonicalization Scheme and SHA-256 with domain
separation:

```text
SHA-256(UTF8(domain) || 0x00 || JCS(artifact))
```

Domains are:

| Artifact | Domain |
| --- | --- |
| Intent | `org.kya-os.payments.intent.v1` |
| Effective payment constraints (normalized, section 8.4.2) | `org.kya-os.payments.constraints.v1` |
| Authorization | `org.kya-os.payments.authorization.v1` |
| Outcome | `org.kya-os.payments.outcome.v1` |
| Delegation credential (each chain entry, every member as presented) | `org.kya-os.payments.credential.v1` |
| Delegation chain (the ordered credential digests) | `org.kya-os.payments.delegation-chain.v1` |
| Holder proof (the verified request-proof object, every member as presented) | `org.kya-os.payments.holder-proof.v1` |
| Answer (an MCP result without its top-level `_meta`; defined by the execution profile) | `org.kya-os.payments.answer.v1` |
| Vector corpus (informative: the `vectors` member of the corpus file, section 15.1) | `org.kya-os.payments.vector-corpus.v1` |

A credential digest covers every member of the credential as presented,
canonicalized by RFC 8785; no member is removed or added (for example a status
entry's `statusSize` stays, whether or not this profile reads it). A
holder-proof digest likewise covers every member of the verified request-proof
object as presented, its signatures `jws` and, when present, `httpSig`
included, canonicalized by RFC 8785; no member is removed or added. The
`delegationDigest` of the payment argument (section 8.2),
which the request proof covers, is the delegation-chain digest of the JSON
array of root-to-leaf credential digests, so anyone holding a Payment
Authorization can recompute it from `delegation.chainDigests`.

**Duplicate member names.** RFC 8785 requires its input to be I-JSON
[RFC7493], and I-JSON forbids an object with two members of the same name,
which RFC 8259 leaves each parser to resolve in its own way. A party that
parses a payment artifact or a delegation credential
from JSON text MUST refuse the text when any object within it has two members
whose names are equal once escapes are decoded, before any digest or signature
check: with `payment_artifact_invalid` for a payment artifact, and with
`payment_delegation_invalid` for a delegation credential, as
for any structurally invalid chain (section 13). Otherwise two parsers could
read one text two ways, and a digest or signature would not cover what each
reads. (Informative: the execution profile applies the same rule to the
payment argument.)

`requestDigest` is not another domain-separated payment digest. It carries
exactly the 32 SHA-256 bytes that the verified Entity Card request proof's
`requestHash` covers:

```text
SHA-256(JCS({ method, params minus its top-level _meta }))
SHA-256(JCS({ method }))    when the request has no params
```

The `_meta` removal, and the omission of an absent `params`, are the base
pre-signing transformation (SPEC-ENTITY-CARD §8.3, steps 2 and 3): `_meta`
carries the proof and capability declarations and is never authoritative. The
card profile encodes those bytes as a `Content-Digest` string,
`sha-256=:<base64>:` (the Digest Fields of [RFC9530], which SPEC-ENTITY-CARD
attributes to RFC 9421); the payment profile encodes the same bytes as
`sha256:<lowercase hex>`. The conversion is lossless, accepts only a
canonically padded base64 [RFC4648] encoding of exactly 32 bytes, and is
performed only after the request proof covering that hash succeeds. Only a
client holder proof supplies this value, so the legacy session profile's
server-generated `sha256:<hex>` request hash is not an input. An
implementation MUST NOT hash a different preimage, apply a payment domain to
it, or accept a caller-supplied digest. If a future profile needs a
payment-specific composite binding, it receives a different field and domain;
it does not redefine `requestDigest`.

All digest strings use lowercase `sha256:<64 hex characters>`.

**Digests of other bytes.** `quoteDigest`, `specDigest`,
`approval.evidenceDigest`, and an evidence digest whose `canonicalization` is
`raw` are each `sha256:` followed by the lowercase hex of SHA-256 over octets,
with no canonicalization and no domain separation. The octets each covers are
stated where it is produced: `specDigest` in section 6,
`approval.evidenceDigest` in section 8.2, a `raw` evidence digest in
section 9, and a quote's digest by the execution profile's adapter rule
(informative: section 12.5 describes the one x402 case in which the rail's
own bytes are the quote). Every decision of this
document that involves one of them, or any other evidence digest, is an exact
comparison of `sha256:` strings, and the only one it recomputes is
`approval.evidenceDigest` (section 8.2).

**Canonical values.** Every value this profile canonicalizes with RFC 8785,
for a digest, a byte bound (section 8.6), or a set order (section 8.4.2),
MUST be a **canonical value**, and a value that is not one MUST be rejected
before canonicalization (in a payment artifact or a delegation credential,
with the reason a duplicate member name carries there, above). A canonical
value is a JSON value [RFC8259] in which:

- no object has two members whose names are equal once escapes are decoded
  (above);
- every string, member names included, is well-formed Unicode: it holds no
  lone surrogate, which RFC 8785 cannot serialize; and
- every number is finite, and a number whose value is integral is a safe
  integer, of magnitude at most 2^53 − 1. A number is the IEEE 754
  double-precision value nearest the number its JSON text writes, the data
  model RFC 8785 §3.2.2.3 serializes, so `2`, `2.0`, and `2e0` are one
  integral value, and `1e16` is an integral value beyond the bound and is
  rejected.

Any other finite number, such as `1.5` or `-0.001`, is admitted and is
serialized as RFC 8785 §3.2.2.3 prescribes, in the ECMAScript Number
serialization; an integral value is serialized as the integer it equals, and
negative zero as `0`. These are the profile's **safe-canonical-value rules**.
The profile's own integer members stay integers because their schemas type
them so; a fraction reaches a digest only where the profile leaves the type
open, as in extension data (`intent-fractional-extension`, section 15.1) or a
delegation credential. An implementation that canonicalizes host values
rather than parsed JSON text MUST also reject what is no JSON value: a sparse
array, an accessor, a cycle, `undefined`, a `bigint`, and a non-plain
object.

(Informative: the execution profile refuses ill-formed Unicode anywhere in
the payment argument before any digest is taken, so the UTF-8 bytes that the
evidence digest of section 8.2 covers are exactly the text presented.)

RFC 8785 is applied to the JSON data model: an object member that happens to be
named `toJSON` is an ordinary member and is sorted like any other. (Informative:
an implementation built on a host serializer that treats such a member
specially, as JavaScript's does, therefore does not hand the object to it.)

## 11. MCP extension negotiation

Under MCP `2026-07-28`, the server advertises the optional extension in the
`capabilities.extensions` member returned by `server/discover`:

```json
{
  "capabilities": {
    "extensions": {
      "org.kya-os/decentralized-authority": {},
      "org.kya-os/payment-authority": {
        "version": "1.0.0",
        "profiles": ["org.kya-os/payments.v1"],
        "required": false
      }
    }
  }
}
```

The client declares its selection on every request in the stateless capability
carrier (shown without unrelated `_meta` members):

```json
{
  "params": {
    "_meta": {
      "io.modelcontextprotocol/clientCapabilities": {
        "extensions": {
          "org.kya-os/decentralized-authority": {},
          "org.kya-os/payment-authority": {
            "version": "1.0.0",
            "profiles": ["org.kya-os/payments.v1"]
          }
        }
      }
    }
  }
}
```

For MCP `2025-11-25`, the same client settings are carried in the
initialize-era `capabilities.extensions` field, and an implementation that
supports both protocol versions MUST normalize the two carriage forms into
one declaration (SPEC-MCP-EXTENSION §3.1). A present per-request entry has
precedence and a malformed one MUST NOT silently fall back to initialize state.

The settings follow `payment-extension-settings.schema.json`, whose `$id` is
`https://schema.kya-os.org/experimental/payment-authority/2026-09-22/mcp-extension-settings`
(Appendix A.5). They have three optional members: `version`, the settings
version (default `1.0.0`); `profiles`, the payment profiles the peer supports,
in its order of preference (default `["org.kya-os/payments.v1"]`); and
`required` (below). An empty payments declaration means the defaults. A peer
MUST ignore unknown settings, for forward compatibility. `required` is server
policy only. A server that declares `true` MUST apply required mode (below) to
every operation it gates on this extension, and so refuses an operation with
no payment effect too unless the profile is active; with `false`, the default,
such an operation is in optional mode and proceeds whether or not the profile
is active. An operation that can create a payment effect is in required mode
whatever the value (below). A server MUST ignore the `required` member of a
well-formed client declaration, which cannot make an operation authoritative.

A declaration that the settings schema refuses is a **malformed
declaration**: one that is not a JSON object, or whose `version`, `profiles`,
or `required` the schema refuses (a `version` that does not match its pattern
or is longer than 128 code points; a `profiles` that is empty, longer than 32
entries, repeats an entry, or holds an entry that is not a string of 1 to 256
code points; a `required` that is not a boolean). Required mode refuses a
client's malformed declaration with `-32602` and `malformed_declaration`
(below).

The payments extension MUST NOT activate unless both peers also negotiated
`org.kya-os/decentralized-authority`. The settings `version` is a version in
the grammar of Semantic Versioning 2.0.0 [SEMVER]: `MAJOR.MINOR.PATCH`, each a
non-negative integer without a leading zero, optionally followed by `-` and a
pre-release, and without build metadata. A peer MUST declare its version in
that grammar. The schema's pattern is coarser: it also admits a leading zero,
as in `01.0.0`, and does not check the pre-release's identifiers; like the
grammar, it refuses build metadata. A `version` that the schema refuses makes
the declaration malformed (above).
Settings versions follow the base extension rule (SEP-2133,
SPEC-MCP-EXTENSION §1.2): a breaking change requires a new extension
identifier, so the versions of one identifier change only additively. Peers
whose versions share a major version interoperate, and a different major
version, for which that rule leaves no use, is a mismatch. Peers compare
major versions, the digits before the first `.`, as strings of digits,
exactly: two versions in
the grammar have no leading zero, so their major versions are equal strings
exactly when they are equal integers, and a version that the schema admits
but the grammar refuses, such as `01.0.0`, matches only a major version
spelled the same way (`01`, never `1`). The exact profile id is the
security boundary: profile selection is the first client-preferred value
in the server's supported set, compared exactly. Absence, malformation,
dependency failure, a major-version mismatch, or an empty profile intersection
means the payments profile is inactive.

**Every operation that can create a payment effect MUST require the profile**
(operation-required mode), because the `_meta` declaration is
intermediary-mutable (SPEC-MCP-EXTENSION §4.3) and an optional-mode operation
could otherwise be downgraded by stripping it. Optional mode applies only to
operations with no payment effect. So that clients can discover which tools
require it, a server MUST mark each payment-effect tool's `tools/list` entry with
`_meta["org.kya-os/payment-authority"] = {"required": true}`; the mark is a
discovery hint, and the server's own gate remains authoritative.

In required mode the server MUST reject, before any side effect, an absent client
declaration, or one without the base authority extension, with JSON-RPC error
`-32021` and `error.data.reason` `extension_not_declared`; a malformed
declaration with `-32602` and `malformed_declaration` (SPEC-MCP-EXTENSION §5.2);
and a major-version or profile mismatch with `payment_profile_unsupported`
under the implementation's domain error code, which SPEC-MCP-EXTENSION §5.1
allocates outside the JSON-RPC reserved range and on which no client
dispatches (SPEC-MCP-EXTENSION §5.2). For `-32021`, `error.data` follows
SPEC-MCP-EXTENSION §4.2: `requiredCapabilities.extensions` lists every missing
extension (the base authority extension and, with its settings, this one),
`reason` is `extension_not_declared`, and `extension` names the first missing
one, the base authority extension when both are missing. A server that
advertises this extension without the base authority extension is misconfigured
(`payment_configuration_invalid`).

### 11.1 Identifiers and `_meta` members defined by this profile

| Member | Where | Meaning |
| --- | --- | --- |
| `org.kya-os/payment-authority` | `capabilities.extensions` and the per-request client capabilities | Extension settings (above) |
| `org.kya-os/payment-authority` | a `tools/list` entry's `_meta` | `{"required": true}`: the tool creates a payment effect and requires the profile |
| `org.kya-os/delegation-credentials` | a payment request's `params._meta` | The presented delegation credentials, root first (carrier rules defined by the execution profile) |
| `org.kya-os/payment-answer` | a payment result's `_meta` | The Executor's answer proof for the request it answers (defined by the execution profile) |

All are reverse-DNS names under `org.kya-os/`. The registration of the three
`_meta` keys in the `_meta` key registry (SPEC-ENTITY-CARD §14.1) is proposed
in `BASE-AMENDMENTS.md` (item 4; open decision 10); until then they are
defined by this profile only. None is ever trusted as authority by itself. No
`_meta` member is part of the request hash or of any proof's signing input
(SPEC-ENTITY-CARD §8.3; SPEC.md §7.6 states the same rule for response
proofs). `org.kya-os/delegation-credentials` plays, for MCP, the
role SPEC.md §8.1 gives the authoritative HTTP header
`KYA-OS-Delegation-Credential`: it transports self-authenticating credentials
outside the signed bytes, and the verifier derives authority only from their own
proofs. It is distinct from the advisory `KYA-OS-Delegation-Chain` header, which
is never used for decisions. This profile adds one binding the base does not
require: the proof-covered `delegationDigest` selects the credentials, so a
stripped or substituted carrier fails closed.

## 12. Standards mappings

This section is informative. It describes how adjacent specifications relate
to the profile's artifacts, at the level of the data model. The requirements
of a rail or commerce mapping, such as the x402 rules of section 12.5, are the
execution profile's adapter rules, which also define how an adapter verifies,
settles, and reconciles.

### 12.1 UCP

UCP is a commerce adapter. Its current dated release is `2026-08-25`; discovery,
services, capabilities, payment handlers, and extension versions remain exact
UCP concepts. See the [UCP overview](https://ucp.dev/2026-08-25/specification/overview/).

- A merchant-signed checkout or stable checkout snapshot maps to `commerce` and
  a resource digest.
- UCP `Idempotency-Key` maps to the idempotency key of the payment argument
  (`idempotency.key`, section 8.2) and remains covered by the request
  signature/digest.
- UCP payment handler id maps only to `handlerId`.
- UCP integer minor-unit totals map to an amount (section 7) without floating
  point.
- UCP checkout state remains authoritative for commerce lifecycle.

The current UCP release includes an official
[AP2 Mandates extension](https://ucp.dev/2026-08-25/specification/payment/extensions/ap2-mandates/).
A KYA implementation that accepts AP2 evidence composes with that extension
rather than inventing a second checkout-mandate format; until an approval
evidence format for AP2 exists (open decision 12), doing so is outside Core
Authority conformance (section 8.2). KYA adds multi-hop delegated authority, revocation,
holder proof, and audit binding around the AP2 evidence.

UCP capability negotiation and the MCP extension negotiation of section 11 are
separate and neither implies the other: UCP selects the commerce capabilities of
a checkout, while section 11 selects this profile for the payment tool call
that pays for it.

For a reverse-DNS `org.kya-os.*` UCP entity, the machine-readable schema origin
stays under the namespace authority, without redirects, and namespace control
and change governance are documented before a stable UCP registration is
requested (open decision 4).

### 12.2 ACP

ACP's Delegate Payment API creates a scoped payment token with amount, merchant,
checkout, and expiry restrictions. That artifact may be retained as foreign
funding/rail evidence; it does not by itself establish a KYA delegation chain.
This profile is not ACP-compatible and claims no ACP compatibility; an ACP
adapter preserves ACP field and signature semantics. See the
[ACP specification](https://github.com/agentic-commerce-protocol/agentic-commerce-protocol).

### 12.3 AP2

AP2 is authorization/intent evidence, not a rail. AP2 v0.2 defines signed
checkout/payment mandates and receipts, and requires deterministic verification.
See the [AP2 specification](https://github.com/google-agentic-commerce/AP2/blob/v0.2.0/docs/ap2/specification.md).

- Preserve AP2 raw artifacts and their native canonicalization/signature rules.
- Map their digests into evidence references (section 9).
- An AP2 mandate can serve as approval evidence (section 8.2) only when it
  carries the Payment Intent digest itself; a mandate that binds only
  checkout or payment hashes binds no intent.
- Do not infer KYA multi-hop delegation from AP2.
- Share only the disclosures needed by the verifier.

### 12.4 Verifiable Intent

Verifiable Intent already defines a credential-provider–user–agent delegation
chain, machine-enforced payment constraints, payment/checkout binding,
recurrence, and selective disclosure; those concepts are not unique to this
profile. A VI credential or presentation can be retained as foreign
approval/funding evidence after native verification, and can serve as
approval evidence (section 8.2) only when it carries the Payment Intent
digest itself.
KYA's proposed additional scope is multi-hop organizational delegation, live
status/revocation, explicit responsible party, and normalized cross-rail
outcomes. See the
[Verifiable Intent repository](https://github.com/agent-intent/verifiable-intent).

### 12.5 x402

x402 is a rail adapter. The core v2 specification [X402], cited at commit
`71eb9a55e081e7b81ba3046d0bd17c3eb9c7bf81`, separates transport, scheme, and
network concerns and uses string atomic amounts. See the
[x402 v2 specification](https://raw.githubusercontent.com/x402-foundation/x402/71eb9a55e081e7b81ba3046d0bd17c3eb9c7bf81/specs/x402-specification-v2.md).

- `x402Version`, a JSON integer, maps to the payment protocol version, which
  is its decimal spelling with no sign or leading zero (`2` is `"2"`). A
  protocol reference
  uses an immutable specification locator with its `specDigest` (section 6);
  a mutable `blob/main` URL is not a durable identifier.
- `scheme`, CAIP-2 `network`, `asset`, and `payTo` remain distinct native
  fields; the adapter normalizes `payTo` to the party it compares with the
  intent's `payee`.
- The original `PaymentRequired` JSON text is retained. Its digest is
  `sha256:` followed by the lowercase hex of SHA-256 over the UTF-8 bytes of
  that text as the payer received it, after removing only an encoding the
  x402 transport defines (for example the base64 of a header value), with no
  canonicalization and no domain separation, so the payer's client and the
  payee's adapter compute it from the same bytes.
- For a converted intent, `quoteDigest` is the digest of the **conversion
  quote**: bytes, authenticated by a quote authority, that state both the
  business amount and the settlement amount (section 8.4.4). A
  `PaymentRequired` states only the settlement requirement, so it is the
  conversion quote, with the digest above, only when it carries such an
  issuer-authenticated statement (for example in its `extra` member);
  otherwise the conversion quote is a separate artifact from the quote
  authority, whose digest the execution profile's adapter rule derives. This
  document compares the verified quote's `digest` with `quoteDigest` only as
  an exact string (rule `intent.quote`, section 8.4.4).
- The selection's `transferMethod` and `paymentFlow` carry the x402 mechanism
  as x402 v2 §6.1 resolves it: the `assetTransferMethod` the payment
  requirements name in `extra`, or the scheme's default for its network
  (`eip3009` for `exact` on EVM), and their `paymentFlow`, or
  `authorization`. The execution profile resolves the same values from the
  Executor's own payment requirements and matches them exactly against the
  selection.
- The selection's `fundingAccount` is the CAIP-10 account
  `eip155:<chain id>:<address>` on its `network` whose address signs every
  payload, as the EIP-3009 `from` or the Permit2 [PERMIT2] owner.
- The mapping gives a credential policy only to an x402 version 2 selection
  whose `scheme` is `exact` and whose `network` is in the CAIP-2 `eip155`
  namespace, under the `authorization` flow, for two transfer methods:
  `eip3009`, an EIP-3009 [EIP-3009] `transferWithAuthorization`, and
  `permit2`, a Permit2 `permitWitnessTransferFrom` whose spender is x402's
  Permit2 proxy. Anyone holding such a payload can submit it, so every
  credential is one others can redeem: the intent signs `redeemableByOthers`
  and its `fundingAccount` and names its presenter (section 8.1). The
  presenter's wallet signs each payload as the `fundingAccount` and sets its
  `nonce` to the 32 bytes of the intent's digest, so every payload for the
  intent consumes one redemption slot,
  keyed by network, owner account, and nonce (for EIP-3009, within the
  contract of the intent's token), and the rail redeems at most
  one of them; the payload's end of validity is at most the intent's
  `expiresAt`. The field encodings, address spellings, and validity bounds
  are the execution profile's adapter rules. Other transfer methods
  (`erc7710`, whose delegations may be multi-use and carry no per-payment
  nonce), other flows (`upfront`, `escrow`), and other schemes and networks
  have no credential policy under this mapping (open decision 14).
- An x402 payment payload, which the x402 MCP transport carries in
  `_meta["x402/payment"]`, stays private to the adapter.
- Verification, authorization, execution, pending settlement, and final
  settlement remain separate states, and x402 implementation-specific
  features do not replace KYA delegation or this profile's idempotency
  contract.

### 12.6 W3C browser payments

W3C Payment Request is a human-present browser adapter, not the base autonomous
agent transport. `supportedMethods` maps to `methodId`; opaque method-specific
data stays with the adapter. See the current
[Payment Request specification](https://www.w3.org/TR/payment-request/) and
[Payment Method Identifiers](https://www.w3.org/TR/payment-method-id/).

A FIDO authenticator's WebAuthn assertion [WEBAUTHN] and a W3C Secure Payment
Confirmation assertion [SPC], which the browser obtains after showing the
person the payee and the amount, are candidate `human-present` approval
evidence formats (section 8.2) for the execution profile to define, each with
the intent digest carried in the challenge the assertion signs.

### 12.7 Visa Trusted Agent Protocol

Visa TAP's Agent Recognition Signature uses HTTP Message Signatures to identify
registered agents and bind selected request components. It may authenticate a
recognized HTTP agent lane, but it does not represent KYA delegation, economic
constraints, or responsible-party authority. A TAP adapter preserves the native
signature input and records only a digest/reference in KYA evidence. See the
[Visa TAP specifications](https://developer.visa.com/capabilities/trusted-agent-protocol/trusted-agent-protocol-specifications).

### 12.8 Mastercard Agent Pay

Mastercard Agent Pay and its Verifiable Intent work address registered agents,
agentic tokens, intent evidence, permissioning, and traceability. A Mastercard
credential or token remains rail/network evidence and can satisfy funding
authority when its native verification binds the responsible party to the
funding source. This profile does not replace those controls. See the
[Mastercard Agent Pay overview](https://www.mastercard.com/us/en/business/artificial-intelligence/mastercard-agent-pay.html).

### 12.9 EMVCo Agentic Payments

EMVCo's September 2026 draft framework, under public review, proposes shared
Intent Services, lifecycle state, and recurring-purchase controls. It is
overlapping work, not a dependency of this profile, and no EMVCo conformance
can be claimed until a final EMVCo specification and mapping exist. See the
[EMVCo public-review announcement](https://www.emvco.com/news/emvco-requests-feedback-on-framework-for-secure-interoperable-and-scalable-card-based-agentic-payments/).

### 12.10 A2A and HTTP

Version 1 normatively binds the profile to MCP (section 11 and the execution
profile), because `requestDigest` is defined by the Entity Card request proof
over a JSON-RPC request. The artifacts are transport independent, but an HTTP or
A2A binding needs its own request-proof and request-digest definition (for
example an HTTP Message Signature with `Content-Digest` covering the payment
body, or an A2A extension URI with a message-level proof) before it can claim
conformance. Those bindings are open Working Group work. MCP and A2A message ids
remain correlation only.

## 13. Error taxonomy

Wire reasons are lowercase snake case. How a refusal of an authenticated
request carries its reason, and whether any refusal is retryable, are defined
by the execution profile: no rule or test of this document depends on either.
The table below is normative: the meaning column determines which reason a
failure carries, in any implementation, and a request that fails more than one
step of section 8.4.6 carries the reason of the first that fails (the checks
before step 1 come first, in the execution profile's order). The vector corpus
(section 15.1) reports a refusal's `code` as
the upper-snake form of its wire reason (`PAYMENT_CONSTRAINT_DENIED` for
`payment_constraint_denied`), which is not a wire value; an outcome's
`reason.code` is the wire reason itself (section 8.3).

Base KYA-OS reasons are reused verbatim only where the base specifications
define them for this path, and in one profile extension of a base reason:
`proof_missing`, `proof_invalid`, and `proof_level_insufficient`
(SPEC-ENTITY-CARD Appendix D.2) for request-proof failures, and
`extension_not_declared` (with JSON-RPC `-32021`) and `malformed_declaration`
(with `-32602`) for negotiation failures (SPEC-MCP-EXTENSION §5.2). The
extension is `proof_invalid` for a request proof that the base counts as
unexpired but that this profile reads as expired, at or after its `expires`
(section 7.1). The legacy session-profile reasons of
SPEC-ENTITY-CARD Appendix D.4 are not reused, and `step_up_required` and
`needs_authorization` remain proof outcomes and challenges, not error reasons.
A refusal issued before the request is authenticated is a JSON-RPC error that
carries its reason in `error.data.reason`: its `code` is `-32021` for
`extension_not_declared`, `-32602` for `malformed_declaration` (section 11),
and the implementation's domain error code for any other reason. This document
defines the reasons for the failures of its own rules:

| Wire reason | Meaning |
| --- | --- |
| `payment_profile_unsupported` | The payment extension's major version or profile did not intersect. |
| `payment_delegation_invalid` | The delegation chain fails a step of section 8.4.6 that names this reason: it is missing; it has more than ten credentials, a credential over 65,536 bytes or with more than 32 caveats, or an object that repeats a member name; it is not the proof-covered `delegationDigest`, or a credential in it is not a well-formed delegation credential or names an issuer, delegate, or `credentialSubject.id` longer than 2,048 code points, an empty `credentialSubject.id`, or the `credentialSubject.id` of another credential in the chain; it is rooted at a payer the Executor does not accept, contains a credential whose delegate is its own issuer, or is unsigned, signed other than by a key its issuer's DID document lists under `assertionMethod` (section 8.4.6, step 3), not revocable, not yet valid, or expired; a caveat other than the payment caveat is malformed, or a `ValidUntil` in it is reached (section 8.4.5); it is not bound to the resource or not joined to the proof key; or it fails another base chain rule (SPEC.md §6.10). |
| `payment_delegation_revoked` | A live status list reports a delegation in the chain as revoked, at the credential where the status read of section 8.4.6, step 8, stops. |
| `payment_action_not_granted` | The chain does not grant the intent's action. |
| `payment_caveat_unsupported` | A delegation carries a restrictive caveat this profile cannot evaluate: a caveat type nothing evaluates, a built-in with a member outside its member set, or a registered evaluator that throws (section 8.4.5). |
| `payment_approval_required` | The effective constraints require approval for the intent and no approval meets the requirement (rule `intent.approval`, section 8.4.4): none is present, or the verified approval's mode is not accepted, or its issuer is outside the effective approver set. The refusal is a challenge (section 8.2). |
| `payment_request_invalid` | The MCP request or operation is malformed, the caller identifier or the idempotency scope exceeds its limit, or an intent's `createdAt` is more than the profile's 60-second skew after the decision time (section 7.1). |
| `payment_artifact_invalid` | A payment artifact fails validation: strict parsing, canonical JSON, or well-formed Unicode (section 10), the schema with its vocabulary (section 8.6), or a check V1 to V4 (section 8.7). The execution profile assigns this reason too to a payment argument that fails its validation. |
| `payment_extension_unsupported` | An artifact carries a critical extension, or a critical extension version, that the consumer has no handler for (check V5, section 8.7). |
| `payment_extension_invalid` | An extension the consumer has a handler for failed that handler's bounded semantic validation (check V5, section 8.7; section 14, item 6). |
| `payment_intent_mismatch` | The received intent is not the one that binds it: not the intent the verified request carries (section 8.4.6, step 9) or a Payment Authorization records; its `audience` is not the Executor, or its `audience` or `action` is not the one the authority facts record (section 8.2); its payee's `id` is not a payee the Executor serves (section 4.1); or it names another agent than the requester as its presenter (section 8.1). |
| `payment_payer_mismatch` | The intent `payer` is not the verified responsible party. |
| `payment_request_mismatch` | The request digest of the verified request proof differs from the `idempotency.requestDigest` of the Payment Authorization used with it (sections 4.2 and 8.2). |
| `payment_authority_mismatch` | A Payment Authorization is inconsistent with the intent it binds, for example by outliving it, or differs from the authority facts derived for the request it is used with (sections 4.2 and 8.2). |
| `payment_authority_expired` | The intent or a Payment Authorization has expired, or another bound of the authorization expiry (section 8.2) has lapsed since the decision, an approval that expired after it was verified among them, unless a check that reads that bound finds it first. Those checks refuse a reached bound with their own reasons: at the decision time, the request proof's `expires`, a check before step 1 of section 8.4.6, `proof_invalid` (section 7.1); a delegation bound, `payment_delegation_invalid` (step 5); an approval's, `payment_approval_invalid` (step 9); a status-freshness bound, `payment_authority_stale` (step 8); and the payment caveat's `expiresAt`, at step 10 or in the re-evaluation that precedes a payment effect, `payment_constraint_denied` (rule `intent.expiry`, section 8.4.4). The execution profile orders its checks of the authorization expiry and that re-evaluation, and so decides which of them finds a lapsed caveat `expiresAt` first. |
| `payment_authority_stale` | Live status required for payment was unavailable, unauthenticated, or not live at the decision clock (section 14, item 19). A status-freshness bound (section 8.2) that lapses after the decision is an expiry (`payment_authority_expired`), since no check of this document reads it again. The execution profile assigns this reason too when its final recheck of authority cannot complete. |
| `payment_approval_invalid` | Presented `approvalEvidence` (section 8.2) yields no verified approval, or the verified approval it yields names another intent digest or an evidence digest other than the one the Authority Verifier computed (section 8.2), has expired at the decision time, or is not admitted by the authorization schema's `approval` member; or its issuer, or its `did` subject, is a delegate of the chain or, when `principal` differs from `responsibleParty`, the principal, refused by the no-self-approval rule before the approver set is consulted and whatever it lists (section 8.4.6, step 9). |
| `payment_constraint_invalid` | A credential of the payment chain carries no payment-constraints caveat or more than one, or one over 16,384 bytes or failing its strict parse (section 8.4.6, step 6); or, for the constraint evaluator used on its own, an input is out of bounds or malformed (`constraints.input`, `constraints.structure`, section 8.4.4); or the re-evaluation that precedes a payment effect cannot read the effective constraints or the approval facts the authority decision established, or cannot complete (section 8.4.4). |
| `payment_constraint_widening` | A delegation hop widens a payment caveat (sections 8.4.2 and 8.4.6, step 6). |
| `payment_constraint_denied` | The effective constraints (an intent rule other than `intent.approval`, section 8.4.4), a `MaxAmount` caveat, or a registered caveat evaluator that does not admit the intent within the call do not permit the payee, resource, amount, fee, rail, conversion, or expiry (including a verified quote that does not bind the conversion). |
| `payment_state_transition_invalid` | A lifecycle transition a producer requests is not allowed (section 8.3). |
| `payment_outcome_stream_invalid` | An outcome stream a consumer verifies has a bad start, gap, fork, broken link, unstable binding, disallowed transition, misplaced correction, or time regression (section 8.3). |
| `payment_configuration_invalid` | The Authority Verifier or the extension is misconfigured (for example, section 11), or a decision time is outside section 7.1 (section 8.4.4). The execution profile assigns this reason too to the Executor's own configuration failures. |
| `payment_denied` | A deployment-specific check denied the payment; detail belongs in diagnostics. Any deployment-specific code maps to it. |

**Reasons the execution profile assigns.** The causes of the reasons below
arise only in processing that the execution profile defines, and so do their
meanings. They are listed here so that this section names every wire reason
this profile reserves, and because the outcome schema's `reason.code` admits
three of them (section 8.3); the glosses are informative:

- `payment_artifact_unauthenticated`: an envelope that the Portable Evidence
  tier requires (section 8.5) did not verify;
- `payment_authority_recheck_failed`: the Executor's final recheck of
  authority before a submission did not confirm it (an outcome reason);
- `payment_quote_expired`: the quote the intent binds, or other rail terms the
  Executor verified, had expired (section 8.2; an outcome reason);
- `payment_failed`: the rail reported a terminal failure, such as an issuer
  decline, whose rail-native code stays in diagnostics (an outcome reason); and
- `payment_evidence_invalid`: evidence that a rail adapter reported is
  malformed or conflicting.

The execution profile also defines the further reasons of request processing,
idempotency, recovery, and rail adapters. Errors MUST NOT echo credentials,
policy secrets, or rail payloads.

## 14. Security and privacy requirements

These requirements bear on the artifacts, digests, schemas, identifiers, money,
evidence references, and negotiation of this document; those of request
processing, execution, and recovery are in the execution profile. Items 6,
19, 20, and 22 state requirements of their own, in the key words of
section 5. Every other item restates, for review, requirements that the
sections it cites or the artifact sections (section 8) state, or, as
items 1 to 5 and 7 do, the security property that those requirements serve.

1. **Independent proofs.** A valid rail signature proves payment authority under
   that rail; it does not prove permission for a KYA action or resource.
2. **Independent value.** A KYA delegation proves authority, not funds or
   successful settlement.
3. **Trusted approval.** Approval policy and signature verification run in
   deterministic code or a trusted surface.
4. **Evidence minimization.** Audit carries digests and references; raw payment
   evidence has a separate access and retention policy.
5. **Artifact authenticity.** Schema validation never substitutes for a
   verified envelope or locally established provenance.
6. **Criticality.** A critical extension requires an exact-version semantic
   handler, not merely a recognized id (check V5, section 8.7). A handler
   MUST answer within the call, and a consumer MUST refuse
   (`payment_extension_invalid`) an answer deferred until after the handler
   returns. A consumer MAY ignore an unknown noncritical extension, which
   remains digest-covered. The schemas refuse unknown members outside the
   extension map, and limit the data of every extension, critical or not, to
   16 KiB of canonical UTF-8 per extension, 64 KiB combined, nesting depth 16
   per extension, and 1,024 JSON values per extension, depth and values
   counted as section 8.6 counts them, and an artifact to 64 extensions; an
   artifact over a limit fails its validation (`payment_artifact_invalid`,
   section 8.7). These limits are exact: a consumer applies no other limit
   to extension data. Handlers MUST be deterministic and free of side
   effects. A consumer bounds the work of each handler, and MUST refuse
   (`payment_extension_invalid`) an extension whose handler exceeds that
   bound, as it refuses one whose answer is deferred.
7. **No algorithm overclaim.** Compliance depends on the deployed validated
   modules and boundary, not merely choosing an algorithm named by a standard.
8. **Grants never originate below the root.** Converted settlement, quote
   authority, and payer-borne fees exist only if the accountable root granted
   them; a delegate can narrow or drop a grant but never create one.
9. **Fees fail closed.** An omitted fee policy prohibits payer-borne fees.
10. **Every caveat binds.** Every caveat in the chain is evaluated against the
    intent; one the verifier cannot evaluate denies.
11. **Payer binding.** An intent names its payer, and only that payer's
    verified authority can authorize it.
12. **Bounded work.** Chain length, credential size, caveat count, and the
    length of each issuer, delegate, and `credentialSubject.id` in the chain
    are bounded before any signature, status, or semantic processing (section
    8.4.6, step 1), extensions when the intent is parsed, and a payment
    caveat's size before its strict parse (step 6), so signature, status,
    and semantic work is bounded by these ceilings. Parsing and the scan for
    repeated member names (section 10), which come before the ceilings, are
    linear in the presented bytes, which the transport that carries the
    request bounds.
13. **Signed chain selection.** The presented delegation chain is bound by the
    proof-covered `delegationDigest`; an intermediary cannot substitute another
    chain the actor holds.
14. **Exemptions bind what moves.** An approval exemption applies only when both
    the declared business amount and the amount that leaves the funding source
    are within thresholds, and a conversion is bound by a verified quote.
15. **One decision clock.** Every check in one verification uses the same
    decision time (section 7.1).
16. **Canonical bytes.** RFC 8785 is applied to the JSON data model, and only
    to the canonical values of section 10; anything else is rejected before
    canonicalization. Equal JSON values always produce equal digests,
    whatever their member order.
17. **No self-approval.** Neither a delegate in the chain — the actor or any
    credential's delegate (section 4.1) — nor, when `principal` differs from
    `responsibleParty`, the principal approves its own payment (the
    no-self-approval rule, section 8.4.6, step 9); each
    credential's effective approver set only narrows along the chain, so
    without named approvers only the payer approves; and no payment credential
    is issued to its own issuer.
18. **Signatures and digests over what was presented.** A credential digest
    covers every member of the credential as presented, canonicalized by
    RFC 8785 (section 10): no member is removed or added, so no parsed
    projection stands in for the credential. A credential's proof covers every
    member of the credential as presented other than its proof value, as its
    Data Integrity cryptosuite defines [VC-DATA-INTEGRITY]: for
    `eddsa-jcs-2022` ([VC-DI-EDDSA] §3.3; SPEC.md §6.10), the credential
    without its `proof` member, and that proof without its `proofValue`. A
    credential's proof is made by a key its issuer's DID document lists under
    `assertionMethod` (section 8.4.6, step 3), so no party can sign a
    credential in the name of another. The
    approval evidence digest covers the UTF-8 bytes of the presented
    `approvalEvidence.value` string (section 8.2). Presented JSON whose
    objects repeat a member name is refused before any digest or signature
    check (section 10), so every party reads the bytes a digest or signature
    covers the same way.
19. **Authenticated, time-bounded status.** The revocation checker used for
    payment MUST verify each status-list credential's proof as step 3 of
    section 8.4.6 verifies a delegation credential's, with the list's issuer
    in place of the credential's issuer: one `assertionMethod` proof, made by
    a key that the DID document of the list's issuer lists under
    `assertionMethod`; MUST accept only
    the list the status entry names (its `id` equals the entry's
    `statusListCredential` by exact string comparison, never after URL
    normalization), so whoever serves that URL cannot substitute
    another list its issuer signed; MUST accept the
    list only when its issuer may speak for the listed credential, meaning the
    list's issuer is a party SPEC.md §6.5.1 lets revoke it — that credential's
    issuer or the issuer of any credential nearer the root of the same chain —
    or a list issuer that the deployment's configuration designates for the
    credentials of that credential's issuer, a designation that is outside
    the base text, since SPEC.md §6.5.1 defers delegated revocation
    authority, and that `BASE-AMENDMENTS.md` item 5 proposes; and MUST treat
    the list as live only while it declares an end (`validUntil`,
    `expirationDate`, or a `ttl`), every timestamp bound it declares is in the
    section 7.1 grammar, a `ttl` it declares is valid and counted as
    section 7.1 defines, every end it declares is after the decision time,
    and every start it declares (`validFrom`, `issuanceDate`) is at or before
    it. A list that declares two ends is stale once either passes; and
    MUST read only a status entry whose `statusPurpose` is `revocation`
    (section 8.4), because a revocation is final and a suspension is not. A list
    without a readable bound could be replayed after a revocation, so it is
    stale. Anything else is unavailable status (`payment_authority_stale`).
    (Informative: a list can be replayed until its bound, so the lifetime its
    publisher gives a list bounds how long a revocation can stay unseen.) The
    base default revocation checker cannot meet this item until
    `BASE-AMENDMENTS.md` item 5 is adopted: its seam receives only the status
    entry, it treats a validity window's end as inclusive, and it reports a
    read it rejects as revoked.
20. **Public commitments to the intent.** A rail credential others can redeem
    commits to the intent it pays (as the execution profile requires), and a
    commitment on a public rail is public: an x402 `nonce` shows the intent
    digest on chain (section 12.5), so anyone who holds that digest — a
    holder of a Payment Authorization, an approval, a refusal, or an outcome —
    can find the transfer and the payer's address. So that a party who knows
    the rest of an intent cannot confirm a guessed one against a public
    commitment, an `intentId` SHOULD carry at least 122 bits of entropy (a
    random version-4 UUID [RFC9562] does). A hiding commitment, such as a
    salted digest of the intent, would avoid the link (open decision 13). An
    intent that signs its `fundingAccount` (section 8.1) names the payer's
    account to every holder of the intent, who can find that account's other
    transfers on a public rail; a payer that needs to keep its purchases
    apart pays each from an account it uses for nothing else, bound to its
    DID by an attestation that is not
    public (a CAIP-10 account listed in its DID document publishes the link).
21. **Approval authority.** Approval evidence verifies only under a format
    the execution profile defines or an extension format outside Core
    Authority conformance (section 8.2). (Informative: an approver
    whose approval key an agent holds has handed that agent its approval
    authority, whatever the format.)
22. **Refusal before attacker-directed work.** An Executor MAY restrict the
    payers it serves, and serves only the payees section 4.1 states. The
    Authority Verifier MUST refuse a chain rooted at a payer the Executor does
    not serve at step 2 of section 8.4.6, and the Executor MUST refuse an
    intent for a payee it does not serve before step 1
    (`payment_intent_mismatch`), each before any DID resolution or status
    fetch the chain would direct.
23. **Well-formed text.** Ill-formed Unicode in the intent or in approval
    evidence is refused before any digest is taken (sections 8.6 and 10).
24. **Inert evidence references.** An evidence `ref` is never a script-capable
    URI, user-info, a query, or a fragment (section 9).
25. **Unrequired approvals are not evidence.** An approval is recorded only when
    the chain required approval for the intent and the approval met the
    requirement (section 8.2).
26. **Lossless parsing.** A member named `__proto__` anywhere in a presented
    credential, a payment caveat, or a payment artifact
    is refused, and so is any object there with two members of the same name
    (section 10), so a parsed projection never drops or replaces a member a
    signature or digest covers. (Informative: the execution profile applies
    the same rules to the payment argument.)
27. **The intent signs its credential policy.** Whether a credential for an
    intent may be one others can redeem, and so whether every credential
    commits to it, is what the intent signs (`redeemableByOthers`, section
    8.1), never an adapter's answer.
28. **One presenter.** An intent that names its presenter is presented by that
    agent alone: the Executor refuses any other requester before any chain
    resolution or status read (section 8.1). An intent that names none is
    shared, and is never paid with a credential others can redeem.
29. **Resource binding.** A chain authorizes payments only at the resource its
    root names; the Authority Verifier always asserts its protected resource
    and never a resource owner, because a payment chain is rooted at the payer
    (section 8.1), not at the Executor (`BASE-AMENDMENTS.md`, item 2).

(Informative: the Executor, acting for the payee, reads the payment caveat of
every hop (section 8.4.5), so the payee learns the limits each delegator in
the chain set, and the other payees, resources, and rails it allows. The
terms of the current payment cannot change once the payee reads them, since
authority is presented only with the immutable intent; the payee can still use
what it learned for later purchases. Every spend bound is per intent, so
loosening a ceiling to disclose less widens what one payment may spend.)

## 15. Conformance requirements

A conformance claim names the tiers it covers (section 4.3); each tier's tests
are required only of implementations claiming it. An implementation that
delegates Data Integrity verification of delegation credentials and status
lists, or DID resolution, to host seams names in its claim the verifier and the
resolvers its deployment uses; those resolvers MUST meet the document-`id` rule
of section 8.2. The tests of the Execution tier, among them request
authentication, response binding, the payment argument, hostile input before
authentication, and rail terms, are defined by the execution profile. So are
the Authority Verifier tests that need an approval evidence format, an
in-process authority capability (the informative note on authority facts
in section 8.2), or request binding: evidence that
does not verify, or whose verified approval names another intent or evidence
digest; evidence whose issuer or `did` subject is the actor or an
intermediate delegate, even one the delegator names as an approver; an
approval claimed without presented evidence; an unrequired approval verified
but not recorded; an authorization outliving its approval evidence; such a
capability that cannot be constructed or deserialized, and genuine
authority facts reused with a substituted intent or request; and an intent
audience or a request digest that the Executor's authentication does not
accept. So are the tests of each approval evidence format and of the party
that issues approval evidence (section 4.2). The Core
Authority tests below are grouped by the role that performs them
(section 4.2), and an implementation claims the groups of the roles it plays.

**Core Authority.** An implementation that claims Core Authority MUST test at
least the *Every role* group below and the group of each role it claims.

*Every role:*

- intent canonicalization and fixed digest vectors, and the request-digest
  conversion from the card `requestHash` encoding, with non-canonical and
  legacy encodings rejected;
- decimal/float/leading-zero rejection, canonical zero handling, exact
  cross-scale comparison, minimal-scale normalization, and business/settlement
  amount separation;
- time normalization (section 7.1), including a bound with a trailing line
  terminator refused;
- RFC 8785 member ordering by UTF-16 code units, independent of a member named
  `toJSON`, and the canonical values of section 10: a fraction serialized in
  the ECMAScript form, negative zero as `0`, and a non-finite number or an
  integral value beyond 2^53 − 1 refused;
- artifact validation (section 8.7) of each artifact the role accepts: strict
  JSON Schema compilation with the required payment vocabulary, refusal when
  the vocabulary is unavailable, each keyword of section 8.6 at the edges its
  definition states, checks V1 and V5, and the `semantic` vectors that
  section 15.1 assigns the role (for an intent, among them one that signs
  `redeemableByOthers` without a presenter or a `fundingAccount`, refused);
- extension byte, depth, and value-count limits on every extension, critical
  or not; string lengths counted in code points at a bound reached with astral
  characters; and a lone surrogate refused where a bounded string enters; and
- evidence references carrying user-info, a query, a fragment, or a
  script-capable scheme never accepted.

*Agent/Client* (constructs the intent):

- an intent constructed for one agent names that agent as its presenter, and
  one whose selection signs `redeemableByOthers` names its presenter and its
  `fundingAccount` (section 8.1); and
- its side of the negotiation: its selection declared on every request in the
  per-request capability carrier (section 11).

*Payee/Executor, as the server of the negotiation* (section 11):

- extension absent, optional, required, malformed, dependency missing,
  major-version mismatch, empty profile intersection, downgrade attempts, and a
  payment-effect operation requiring the profile;
- the section 11 negotiation errors; and
- non-payment operations unaffected by the extension in optional mode, and,
  under a server's `required: true`, refused without the profile when the
  server gates them (section 11).

*Payee/Executor, as the party that authenticates the request* (section 4.2):

- the checks before step 1 of section 8.4.6, each refused with its reason
  before any chain resolution or status read: an intent that names another
  agent than the requester as its presenter, whose `audience` is another
  Executor, or whose payee the Executor does not serve
  (`payment_intent_mismatch`), the default set of served payees
  (section 4.1) among them; an intent whose `createdAt` is more than
  60 seconds after the decision time (`payment_request_invalid`), and one
  exactly 60 seconds after it, accepted; an intent at its `expiresAt`
  (`payment_authority_expired`); a critical extension the Executor has no
  handler for (`payment_extension_unsupported`), and a noncritical one,
  accepted; and a request proof at its `expires` (`proof_invalid`), and one
  a millisecond before it, accepted; and
- the `admission` vectors (section 15.1).

*Authority Verifier:*

- the verification order of section 8.4.6: a request that fails two steps
  refused with the reason of the earlier one, including a `MaxAmount` exceeded
  at one hop of a chain whose payment caveat widens at a later hop (refused as
  the widening), and an over-long chain or an over-caveated credential refused
  (`payment_delegation_invalid`) before any signature work;
- every payment-constraint attenuation edge: ceiling decrease, allowlist subset,
  added qualifiers, silent constraint drop, widening, duplicate semantic key,
  unknown caveat version, introduction of any grant below a parent that lacks
  it, and every requirement rule;
- omitted-fee-policy denial of any non-zero payer-borne fee, and identical
  digests for omitted and prohibited fee policies;
- composition with the base chain verifier: verbatim-only behaviour without the
  registered narrower, narrowing accepted and widening rejected with it, and
  built-in caveats not overridable;
- evaluation of every caveat: `MaxAmount` ceiling, currency, and limit grammar
  (including a trailing line terminator), `ValidUntil`, a built-in caveat with
  an extra member, a registered evaluator admitting, denying, answering with a
  deferred answer (denied), and throwing, and denial of an unsupported caveat
  type;
- approval thresholds on both the business and the effective settlement amount,
  including a nominal business amount paired with a large converted settlement
  and a fee ceiling counted toward an exemption, and the approver allowlist;
- payee, action, resource, amount, quote, expiry, payer, and approval
  requirement mismatch;
- settlement amount without quote binding, a verified quote whose digest,
  source, target, or issuer does not bind the conversion, a quote given with
  an `expiresAt` member (refused, `constraints.structure`), and deferred
  quote and fee rules recorded as `deferred`;
- approval facts (section 8.4.4) whose issuer is not the payer, under a
  requirement without named approvers, refused by rule `intent.approval`; approvers
  introduced below a payer-only requirement (even ones that name only the
  payer), an inherited approver list omitted (even one that names the payer),
  and a credential whose delegate is its own issuer, including one whose
  `issuer` is an object (section 4.1); checks V2 to V4 of section 8.7 and the
  authorization `semantic` vectors (section 15.1), among them the
  no-self-approval rule as a check of the recorded facts: a Payment
  Authorization whose approval's issuer or `did` subject is a delegate of the
  chain or, when `principal` differs from `responsibleParty`, the principal,
  refused (checks V3 and V4);
  approval evidence whose
  `type` and `format` name no format the verifier implements, refused
  (`payment_approval_invalid`); and the approval challenge
  (`payment_approval_required`, section 8.2);
- a delegation credential whose Data Integrity proof does not verify, or
  verifies under a key that the issuer's DID document does not list under
  `assertionMethod` (the actor's own key, for example), or names another
  `proofPurpose`, or was created more than 60 seconds after the decision time,
  each refused (`payment_delegation_invalid`); a chain in which a
  `credentialSubject.id` is empty or two credentials share one, refused before
  any signature work; and a member named `__proto__`, or an object with two
  members of the same name, in a credential or a payment caveat;
- each intent rule of section 8.4.4 failing, and the first of several failing
  rules deciding, including a zero `settlementAmount`, a zero fee in an asset
  the cap list omits (disregarded), more than 256 fees, a chain of more than
  10 caveats, a negative or fractional decision time (these three refused by
  the constraint evaluator's input bounds before any rule), an intent with a
  member its schema does not define (refused by its structure check), and the
  decision trace of an authorized decision;
- revoked/stale/unavailable status (distinguished), and the precedence of
  section 8.4.6, step 8, across hops: a revoked leaf below a root whose list
  is not live but reports it unrevoked (`payment_delegation_revoked`), and
  below a root whose status is unavailable (`payment_authority_stale`); an
  unrevocable hop (no status entry, or one whose purpose is not
  `revocation`), strict delegation time bounds, resource binding,
  schema-invalid credentials, a chain that does not match `delegationDigest`,
  oversized inputs, and unknown critical extensions;
- status read for each credential's issuer at the decision clock: a list from
  another issuer, a list other than the one the entry names, an unverified
  list, a list signed by a key that is not its issuer's, an unbounded list, a
  list at its exact expiry, and a list that declares two ends of which one has
  passed are all unavailable status;
- a chain rooted at an unaccepted payer refused before any credential-proof or
  status work, a status list issued by an ancestor issuer accepted and one by a
  descendant that the deployment has not designated refused, and a status
  timestamp bound outside the section 7.1 grammar treated as stale; and
- chains without a payment caveat remaining unaffected by the extension.

*Evidence Consumer:*

- artifact validation (section 8.7) of Payment Authorizations and Payment
  Outcomes: checks V2 to V4, and the authorization and outcome `semantic`
  vectors (section 15.1), including the four authorization vectors that pass
  the schema and fail check V2, V3, or V4, each refused;
- a Payment Authorization or a Payment Outcome that carries a critical
  extension, or a critical extension version, the consumer has no handler
  for, refused (`payment_extension_unsupported`, check V5); and
- an outcome stream that fails each stream check of section 8.3 in turn,
  refused (`payment_outcome_stream_invalid`): a bad start, a gap, a
  duplicate sequence with another digest, a broken link (stream check 3: an
  observation whose `previousOutcomeDigest` is not the outcome digest,
  section 10, of the observation before it), a fork, an unstable binding, a
  disallowed transition, a misplaced correction, a second correction, and a
  time regression, and the valid streams of the `outcomeStreams` vectors
  (section 15.1), each accepted.

**Portable Evidence.** Its tests, missing or invalid envelopes and
verifier/producer mismatch among them, are defined by the execution profile,
which defines its envelopes (section 8.5).

**Interop.** The tests of each mapping (section 4.3), native-byte
preservation, `quoteDigest`, and payee normalization among them, are
defined by the execution profile with its adapter rules (section 12).

### 15.1 Vector corpus

`vectors/payment-authority-vectors.json` is the fixed vector corpus. Core
Authority conformance covers these of its vector sets, each assigned to the
roles (section 4.2) that reproduce it: `artifactDigests`, `requestDigests`,
`amountComparisons`, `normalization`, and `time` to every role; `constraints`,
`narrowing`, and `caveats` to the Authority Verifier; `admission` to the
Payee/Executor; `outcomeStreams` to the Evidence Consumer; and `semantic` by
the kind of artifact each vector names (its
`artifact`, section 15.1.1). The `semantic` vectors of an intent go to the
roles that handle Payment Intents (section 4.2), the Agent/Client, the
Authority Verifier, and the Payee/Executor; those of a payment caveat to the
Authority Verifier; those of an authorization to the Authority Verifier and
the Evidence Consumer; and those of an outcome to the Evidence Consumer. The
sets are:

- `artifactDigests`: the intent, effective-constraints, authorization,
  outcome, credential, delegation-chain, and holder-proof digests with their
  exact canonical bytes, including an intent whose extension data holds
  fractional numbers (`intent-fractional-extension`, section 10);
- `requestDigests`: request-digest conversions (section 10), with non-canonical
  and legacy encodings refused;
- `amountComparisons` and `normalization`: exact comparison and minimal-scale
  normalization (section 7);
- `time`: time normalization (section 7.1), including a bound with a
  trailing line terminator, refused;
- `constraints`: the constraint evaluator of section 8.4.4 used on its own
  (the attenuation of step 6 and the intent evaluation of step 10 of
  section 8.4.6, with the evaluator's own input and structure checks):
  positive and negative cases, each refusal with its code and rule
  identifier: a negative and a fractional decision time
  (`invalid-decision-time-negative` and `invalid-decision-time-fractional`,
  `constraints.input`; a decision time beyond 2^53 − 1 cannot appear in the
  corpus, since canonical values, section 10, refuse an integral value beyond
  that bound), an intent with a member its schema does not define
  (`invalid-intent-unknown-member`, `constraints.structure`), every widening
  class of section 8.4.2, the requirement class
  with per-asset thresholds and approver sets, the conversion rules with
  verified quotes, deferred execution terms with the exact deferred rule
  list, a `fees` member given while they are deferred, refused even when it
  is an empty list (`invalid-deferred-with-empty-fees`,
  `constraints.structure`), one-caveat chains evaluated with verified fees
  and quotes, the form
  the re-evaluation of section 8.4.4 takes (for example
  `valid-conversion-with-grants`), the equality edge of every ceiling,
  threshold, cap, and expiry, and
  reference lengths counted in code points (section 8.6):
  `valid-reference-astral-2048`, a reference of astral characters exactly at
  the bound, is accepted, which a count of UTF-16 code units would reject, and
  `invalid-reference-astral-2049`, one past it, is refused;
- `narrowing`: the narrowing relation of the payment caveat (sections 8.4.2
  and 8.4.3);
- `caveats`: the caveat evaluation of section 8.4.5 used on its own, step 7
  of section 8.4.6, with the payment caveat skipped: each refusal with its
  code, rule identifier, and `hop`, including a `MaxAmount` whose `currency`
  is `null` (`invalid-maxamount-currency-null`, `caveat.maxAmount.malformed`);
- `admission`: the Executor's checks before step 1 of section 8.4.6
  (section 4.2), each at its edge: a presenter, an `audience`, and a payee
  that do not match the requester, the Executor, and the payees it serves; a
  `createdAt` 60 seconds after the decision time (accepted) and a millisecond
  beyond that; an intent a millisecond before its expiry and at it; a request
  proof a millisecond before its `expires` and at it; and an unhandled
  noncritical extension (accepted) and an unhandled critical one. Each
  refusal fails one of these checks only, since the execution profile orders
  them (section 8.4.6);
- `outcomeStreams`: the stream checks of section 8.3 used on their own:
  streams accepted (a start at `authorized` and at `submitted`, an exact
  retransmission, observations that arrive out of `sequence` order, a pending
  settlement, two equal `updatedAt` values, and a
  correction to `settled` after a failure whose basis is `slot` and to
  `settlement_pending` after one whose basis is `close`), and at least one
  stream refused by each of the seven checks; and
- `semantic`: negative cases for the section 8.6 keywords, for a presenter
  that does not match the `did` pattern, and for a presenter or funding
  account missing where the selection signs `redeemableByOthers`; structural
  cases for the payment caveat (amount coefficients, approval thresholds and
  approvers, reference lengths, rail members and specification digests,
  account commitments, rail mechanism and funding-account qualifiers), for an
  outcome's required and state-dependent members, and for a recorded approval
  without `delegation.delegates`; and five cases that pass their schema and
  fail a check of section 8.7:
  `intent-proto-member-in-extension-data` (V1: extension data holds a member
  named `__proto__`), `authorization-delegates-without-actor` (V2:
  `delegation.delegates` does not name the actor),
  `authorization-approval-by-delegate` (V3: the approval's issuer is in
  `delegation.delegates`), `authorization-approval-by-unlisted-principal` (V3:
  the approval's issuer is the principal, which differs from
  `responsibleParty`), and
  `authorization-approval-subject-is-delegate` (V4: the approval's `did`
  subject is the actor, an entry of `delegation.delegates`).

The Payment Authorization and Payment Outcome records in `artifactDigests` and
`semantic`, and the observations of `outcomeStreams`, are fixtures for
digests and validation, not records a verifier or an Executor produced. Their
`decisionTrace` is abbreviated (section 8.4.4 gives an exact one), and every
digest in them is a placeholder of one repeated hex digit (such as
`sha256:aaaa…`), except an authorization's `intentDigest` and
`approval.intentDigest`, which are the `intent` vector's digest, and an
observation's `previousOutcomeDigest`, which is the outcome digest
(section 10) of the observation before it unless its vector breaks the link
on purpose. Their idempotency values are placeholders
too (an outcome's `scope` is the string `scope`). None of these placeholders
is a value an Executor derives (section 8.2). The delegation credentials
(`credential-0`, `credential-1`, and the `credentials` of the
`delegation-chain` vector) and the request proof (`holder-proof`) in
`artifactDigests` are likewise fixtures for digests, which cover them as
presented (section 10), not a chain or a proof a verifier accepts:
`credential-1` carries no `proof`, which step 3 of section 8.4.6 refuses, and
the request proof's `jws` signature is a placeholder.

The corpus also carries, for the execution profile, which defines the answer
and its proof, two answer digests in `artifactDigests` (domain
`org.kya-os.payments.answer.v1`) and the `answerProofs` set (EdDSA and ES256).
This document does not define them, and they are not part of a Core Authority
conformance claim, although the corpus digest covers them.

Each check of section 8.7 but V5 has a `semantic` vector; V5 depends on the
handlers a consumer has, so the `admission` vectors decide it only for an
Executor with no extension handler. The corpus does not
yet carry vectors for a request that fails more than one step of
section 8.4.6; adding them is open work.

An implementation that claims Core Authority MUST reproduce, as section 15.1.1
states, every vector assigned to the roles it claims, the two answer digests
excepted; it need not reproduce a vector assigned only to roles it does not
claim. The corpus is identified by its digest, and
`vectors/verify_vectors.py`, a standard-library-only Python verifier in this
folder, reproduces every vector, applying to the `semantic` vectors checks V1
to V4 of section 8.7 and its own restatement of the schema rules those vectors
exercise. It counts the checks of the execution-profile vectors (the answer
digests and `answerProofs`) apart from the Core Authority checks, reporting
`OK: <n> Core Authority checks and <m> execution-profile checks reproduced by
the Python verifier (corpus <digest>)`. `vectors/schemas.test.ts` checks the
corpus against the schemas, with the keywords of section 8.6 implemented. It
checks three things: the corpus's artifacts, each `artifactDigests` input that
is an intent, a payment caveat (the vector named `constraints`), an
authorization, or an outcome, all of which it asserts the schemas admit; its
`semantic` vectors, each decided as the corpus decides it except the five
named above, which only checks V1 to V4 refuse and which it asserts pass their
schema; and the intents, caveats, and outcomes inside the `constraints`,
`narrowing`, `caveats`, and `admission` sets, and the outcomes of the
`outcomeStreams` set (the intent of each `constraints`, `caveats`, and
`admission` vector, the payment caveats of each `constraints` vector's `chain`
and each `narrowing` vector's `parent` and `child`, and every observation of
each `outcomeStreams` vector), all admitted except five inputs that their
vectors make malformed on purpose, which the test names and asserts are
refused: the intent of `invalid-intent-unknown-member`, caveat 0 of
`invalid-reference-astral-2049`, and the `child` of `malformed-child`,
`unknown-version`, and `oversized-child`. Reproducing the corpus shows that
the corpus is reproducible, not that the text is complete; implementations by
other parties remain a Working Group goal. A Core Authority conformance claim
names the corpus digest recorded in the corpus file (`corpusDigest`: the
vector-corpus digest of section 10 over the file's `vectors` member).

#### 15.1.1 Vector format

The corpus file is one JSON object: `corpus` names it, `specification` names
the document it serves, `corpusDomain` is the vector-corpus domain of
section 10, `corpusDigest` is that domain's digest of `vectors`, and `vectors`
holds one array per vector set. Amounts are those of section 7, digests the
`sha256:` strings of section 10, and every `code` is the upper-snake form of
a section 13 wire reason. An implementation reproduces a vector when it
computes, from the vector's input members, exactly the vector's expected
members, compared as JSON values. The members of each set's vectors are:

- `artifactDigests`: `name`; `domain`, a digest domain of section 10; `input`;
  and the expected `canonical`, a string holding the RFC 8785 serialization
  of the hashed value, and `digest`, the digest of section 10 of that
  serialization under `domain`. The hashed value is `input`, except in the
  vector named `constraints`, where it is the normalization of `input`
  (section 8.4.2), which the vector's `normalized` member holds and which is
  compared too. The `delegation-chain` vector also carries `credentials`, the
  root-to-leaf credentials, and its `input` is their credential digests, each
  computed over every member of the credential as presented (section 10). The
  two answer vectors carry
  `result`, an MCP result, and their `input` is that result without its
  top-level `_meta`; they belong to the execution profile.
- `requestDigests`: `name`; `baseRequestHash`, a card `requestHash` string;
  and the expected `requestDigest`, the `sha256:` string the conversion of
  section 10 yields, or `null` where that conversion refuses the input.
- `amountComparisons`: `left` and `right`, two amounts in one asset, and the
  expected `compare`: −1, 0, or 1 as `left` is less than, equal to, or greater
  than `right` by exact value (section 7).
- `normalization`: `input`, an amount, and the expected `output`, its
  minimal-scale form (section 7).
- `time`: `input`, a string, and the expected `millis`, the epoch
  milliseconds section 7.1 gives it, or `null` where section 7.1 refuses it.
- `constraints`: `name`; the inputs of the constraint evaluator of section
  8.4.4: `chain`, the payment caveats root to leaf; `intent`; `now`, the
  decision time; `fees`, the payer-borne fee amounts (absent: none; a `fees`
  member that is present, an empty list included, is refused while the quote
  and fee rules are deferred, `constraints.structure`); `quote`,
  the verified quote (absent: none); `approval`, the approval facts (absent:
  no verified approval); and `deferExecutionTerms`, `true` when the quote and
  fee rules are deferred (absent: not deferred); and the expected `expect`,
  the evaluation's result (section 8.4.4, **Result**). `expect.valid` is
  `true` for an authorized decision, which carries `effectiveConstraintsDigest`
  and, only when a rule is deferred, `deferred`, the deferred rule identifiers
  in table order. A refusal has `valid` `false`, `code`, `rule`, `hop` for an
  attenuation rule only, and `effectiveConstraintsDigest` except for
  `constraints.input` and `constraints.structure`, as section 8.4.4 states.
  `expect` has no other member; the decision trace is not compared.
- `narrowing`: `name`; `parent` and `child`, two payment caveats; and the
  expected `narrows`, `true` exactly when both parse strictly (section 8.4 and
  rule 8 of section 8.4.2) and the edge from `parent` to `child` passes every
  rule of section 8.4.2.
- `caveats`: `name`; `caveats`, one array per credential, root first, of that
  credential's caveats; `intent`; `now`, the decision time; and the expected
  `expect`, the result of the caveat evaluation of section 8.4.5 with no
  registered evaluator: `{"valid": true}`, or `valid` `false` with `code`,
  `rule`, and `hop`.
- `outcomeStreams`: `name`; `observations`, Payment Outcomes in the order a
  consumer receives them; and the expected `expect`: `{"valid": true}`, or
  `{"valid": false, "code": "PAYMENT_OUTCOME_STREAM_INVALID"}`, the result of
  the stream checks of section 8.3, an exact retransmission (the same
  `sequence` and outcome digest) counting as the observation it repeats.
- `admission`: `name`; `intent`; `now`, the decision time; `requester`, the
  DID the verified request proof names; `requestProofExpires`, that proof's
  `expires` in epoch seconds, as the base carries it (section 7.1);
  `audience`, the Executor's DID; `payees`, the `id`s of the payees the
  Executor serves; and the expected `expect`: `{"valid": true}` when the
  request passes every check before step 1 of section 8.4.6, as decided by an
  Executor with no extension handler, or `valid` `false` with `code`.
- `semantic`: `name`; `artifact`, one of `intent`, `authorization`, `outcome`,
  and `constraints` (the payment caveat); `input`; and the expected `valid`,
  whether `input` passes the artifact validation of section 8.7 for that
  kind: its schema with the required vocabulary (section 8.6) and checks V1
  to V4, as decided by a consumer with no extension handler (no `semantic`
  vector carries a critical extension, so V5 passes each). Only the five
  cases named above pass their schema and fail a check of section 8.7.
- `answerProofs`: carried, with the two answer digests, for the execution
  profile, which defines the answer proof and the members of these vectors;
  they are not part of a Core Authority conformance claim.

## Open Working Group decisions

1. Should the MCP extension id `org.kya-os/payment-authority` move under a DIF or
   MCP registry namespace? (The profile name, Payment Authority, is resolved.)
2. Should `actor`, `principal`, `responsibleParty`, and `payer` remain DID-only in
   v1 or permit another typed party reference?
3. Which evidence retrieval/retention profile is appropriate for dispute use?
4. Which UCP capability should advertise KYA authorization support? The
   proposed vendor extension `org.kya-os.payments.delegated_authority` extending
   `dev.ucp.shopping.checkout` cannot be advertised until its schema is served
   from the namespace-authorizing origin without redirects.
5. Which receipt fields are safe and stable across card, bank, and on-chain
   adapters beyond the observed `effectAmount`?
6. Which zero-value verification operations, if any, should receive named
   adapter profiles?
7. Which account-commitment methods and funding-authority attestations should
   be registered for portable evidence conformance?
8. What are the normative HTTP and A2A bindings (request proof and request
   digest) for version 2?
9. Should a payer-controlled payment resource let one chain pay many
   Executors, with non-root hops naming the Executors they may pay (section 2)?
10. Should the base specifications adopt the five amendments this profile
    proposes in `BASE-AMENDMENTS.md` — profile-defined caveat narrowing
    (SPEC.md §6.10, which section 8.4.3 depends on), the description of a
    payment chain's root issuer, the per-hop audience reading for VC 2.0 + ZCAP
    chains, the `_meta` key registrations (section 11.1), and the status-read
    context with time-bounded lists (section 14, item 19)? Further amendments,
    on request binding, are proposed with the execution profile.
11. Should approval evidence bind a maximum total debit (settlement amount plus
    fee ceiling), so a `human-present` approver can show and sign the most the
    funding source can lose rather than the intent alone?
12. Which profiles should define AP2 mandates and Verifiable Intent
    presentations as approval evidence (type identifier, issuer and mode
    derivation, and where each carries the intent digest, section 8.2)?
13. Should the commitment of a rail credential to its intent (defined by the
    execution profile) be a hiding one, such as a salted digest of the intent,
    so that a public rail does not link its transfers to every holder of the
    intent digest (section 14, item 20)?
14. Which further x402 mechanisms should section 12.5 map — ERC-7710
    delegations, the `upfront` and `escrow` flows, other schemes, and other
    networks — stating for each which credentials others can redeem, their end
    of validity, their commitment to the intent, their redemption slot, and how
    it spells the funding account?

Until Working Group ratification and publication under new stable schema ids,
this document remains experimental and is not a ratified DIF standard.

## References

The text cites each reference by its tag or by the name of the document (for
example "RFC 8785" or "SPEC-ENTITY-CARD §8.3").

### Normative references

- **[RFC2119]** IETF. *Key words for use in RFCs to Indicate Requirement Levels* (BCP 14). https://datatracker.ietf.org/doc/html/rfc2119
- **[RFC8174]** IETF. *Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words* (BCP 14). https://datatracker.ietf.org/doc/html/rfc8174
- **[RFC8259]** IETF. *The JavaScript Object Notation (JSON) Data Interchange Format*. https://datatracker.ietf.org/doc/html/rfc8259
- **[RFC7493]** IETF. *The I-JSON Message Format*. https://datatracker.ietf.org/doc/html/rfc7493
- **[RFC8785]** IETF. *JSON Canonicalization Scheme (JCS)*. https://datatracker.ietf.org/doc/html/rfc8785
- **[RFC3339]** IETF. *Date and Time on the Internet: Timestamps*. https://datatracker.ietf.org/doc/html/rfc3339
- **[RFC3986]** IETF. *Uniform Resource Identifier (URI): Generic Syntax*. https://datatracker.ietf.org/doc/html/rfc3986
- **[RFC4648]** IETF. *The Base16, Base32, and Base64 Data Encodings* (base64). https://datatracker.ietf.org/doc/html/rfc4648
- **[RFC9530]** IETF. *Digest Fields* (the `Content-Digest` field). https://datatracker.ietf.org/doc/html/rfc9530
- **[JSON-SCHEMA]** JSON Schema. *JSON Schema Core* and *JSON Schema Validation*, draft 2020-12. https://json-schema.org/draft/2020-12
- **[IEEE754]** IEEE. *IEEE Standard for Floating-Point Arithmetic* (IEEE 754-2019; the double-precision format). https://standards.ieee.org/ieee/754/6210/
- **[ECMA-262]** Ecma International. *ECMAScript Language Specification* (the regular expressions of JSON Schema `pattern`). https://tc39.es/ecma262/
- **[ISO4217]** ISO. *ISO 4217, Codes for the representation of currencies*. https://www.iso.org/iso-4217-currency-codes.html
- **[CAIP-2]** Chain Agnostic Standards Alliance. *CAIP-2: Blockchain ID Specification*. https://chainagnostic.org/CAIPs/caip-2
- **[CAIP-19]** Chain Agnostic Standards Alliance. *CAIP-19: Asset Type and Asset ID Specification*. https://chainagnostic.org/CAIPs/caip-19
- **[DID-CORE]** W3C. *Decentralized Identifiers (DIDs) v1.0*. https://www.w3.org/TR/did-core/
- **[VC-DATA-MODEL-2]** W3C. *Verifiable Credentials Data Model v2.0*. https://www.w3.org/TR/vc-data-model-2.0/
- **[BITSTRING-STATUS-LIST]** W3C. *Bitstring Status List v1.0*. https://www.w3.org/TR/vc-bitstring-status-list/
- **[VC-DATA-INTEGRITY]** W3C. *Verifiable Credential Data Integrity 1.0*. https://www.w3.org/TR/vc-data-integrity/
- **[VC-DI-EDDSA]** W3C. *Data Integrity EdDSA Cryptosuites v1.0* (the `eddsa-jcs-2022` cryptosuite). https://www.w3.org/TR/vc-di-eddsa/
- **[OIDC-CORE]** OpenID Foundation. *OpenID Connect Core 1.0*. https://openid.net/specs/openid-connect-core-1_0.html
- **[KYA-OS-SPEC]** *KYA-OS Protocol Specification*, the base specification this document calls SPEC.md. [`SPEC.md`](../../SPEC.md)
- **[SPEC-ENTITY-CARD]** *KYA-OS Entity Card - Profile Specification*. [`SPEC-ENTITY-CARD.md`](../../SPEC-ENTITY-CARD.md)
- **[SPEC-MCP-EXTENSION]** *KYA-OS MCP Extension Binding*. [`SPEC-MCP-EXTENSION.md`](../../SPEC-MCP-EXTENSION.md)
- **[MCP]** *Model Context Protocol*, specification revisions `2026-07-28` and `2025-11-25`. https://modelcontextprotocol.io/specification/
- **[SEMVER]** *Semantic Versioning 2.0.0*. https://semver.org/spec/v2.0.0.html

### Informative references

- **[RFC9421]** IETF. *HTTP Message Signatures*. https://datatracker.ietf.org/doc/html/rfc9421
- **[WHATWG-URL]** WHATWG. *URL Living Standard*. https://url.spec.whatwg.org/
- **[RFC9562]** IETF. *Universally Unique IDentifiers (UUIDs)*. https://datatracker.ietf.org/doc/html/rfc9562
- **[ZCAP-LD]** W3C Credentials Community Group. *Authorization Capabilities for Linked Data*. https://w3c-ccg.github.io/zcap-spec/
- **[CAIP-10]** Chain Agnostic Standards Alliance. *CAIP-10: Account ID Specification*. https://chainagnostic.org/CAIPs/caip-10
- **[EIP-55]** Ethereum Improvement Proposals. *EIP-55: Mixed-case checksum address encoding*. https://eips.ethereum.org/EIPS/eip-55
- **[EIP-3009]** Ethereum Improvement Proposals. *EIP-3009: Transfer With Authorization*. https://eips.ethereum.org/EIPS/eip-3009
- **[ERC-7710]** Ethereum Improvement Proposals. *ERC-7710: Smart Contract Delegation*. https://eips.ethereum.org/EIPS/eip-7710
- **[PERMIT2]** Uniswap Labs. *Permit2* (`permitWitnessTransferFrom`). https://github.com/Uniswap/permit2
- **[X402]** x402 Foundation. *x402 Protocol Specification*, protocol version 2, `specs/x402-specification-v2.md` at commit `71eb9a55e081e7b81ba3046d0bd17c3eb9c7bf81`, with the `exact` scheme on EVM (`specs/schemes/exact/scheme_exact_evm.md`) and the MCP transport (`specs/transports-v2/mcp.md`) of the same commit. https://raw.githubusercontent.com/x402-foundation/x402/71eb9a55e081e7b81ba3046d0bd17c3eb9c7bf81/specs/x402-specification-v2.md
- **[UCP]** *Universal Commerce Protocol*, release `2026-08-25`, with its AP2 Mandates extension. https://ucp.dev/2026-08-25/specification/overview/
- **[ACP]** *Agentic Commerce Protocol*, including its Delegate Payment API. https://github.com/agentic-commerce-protocol/agentic-commerce-protocol
- **[AP2]** *Agent Payments Protocol (AP2)*, v0.2.0 (`docs/ap2/specification.md` at tag `v0.2.0`, commit `b4587ac1d055888a73b4b21750973cffba961793`). https://github.com/google-agentic-commerce/AP2/blob/v0.2.0/docs/ap2/specification.md
- **[VI]** *Verifiable Intent*. https://github.com/agent-intent/verifiable-intent
- **[PAYMENT-REQUEST]** W3C. *Payment Request API*. https://www.w3.org/TR/payment-request/
- **[PAYMENT-METHOD-ID]** W3C. *Payment Method Identifiers*. https://www.w3.org/TR/payment-method-id/
- **[WEBAUTHN]** W3C. *Web Authentication: An API for accessing Public Key Credentials*. https://www.w3.org/TR/webauthn/
- **[SPC]** W3C. *Secure Payment Confirmation*. https://www.w3.org/TR/secure-payment-confirmation/
- **[VISA-TAP]** Visa. *Trusted Agent Protocol specifications*. https://developer.visa.com/capabilities/trusted-agent-protocol/trusted-agent-protocol-specifications
- **[MASTERCARD-AGENT-PAY]** Mastercard. *Mastercard Agent Pay*. https://www.mastercard.com/us/en/business/artificial-intelligence/mastercard-agent-pay.html
- **[EMVCO-AGENTIC]** EMVCo. *Framework for card-based agentic payments*, public-review draft, September 2026. https://www.emvco.com/news/emvco-requests-feedback-on-framework-for-secure-interoperable-and-scalable-card-based-agentic-payments/
- **[A2A]** *Agent2Agent (A2A) Protocol*. https://a2a-protocol.org/
- **[SEP-2133]** *Extensions framework for MCP*, a proposal, cited as its pull request; the extension rules this document applies are those of [MCP] and SPEC-MCP-EXTENSION. https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2133

## Appendix A. Member index

This appendix restates the syntax of the schemas in this folder and adds no
requirement: where it and a schema differ, the schema governs. Section 8
defines what each member means, and section 11 the extension settings. In the
type column, a name in backquotes is a definition
of the same schema, listed below its table; `value` marks a member that the
schema constrains by an enumeration or a keyword rather than by a type; and
`asset`, `approvalSubject`, and `fees` are each one of several object shapes
(sections 7, 8.2, and 8.4). "pattern" marks a regular expression that the
schema states. Keywords of section 8.6 that apply to an artifact as a whole
rather than to one member are listed in section 8.6. The Required column
states only unconditional requirements: a member that a schema requires under
a condition, such as `presenter` when the selection signs
`redeemableByOthers`, is listed as not required, and A.6 lists every such
condition.

### A.1 Payment Intent (`payment-intent.schema.json`)

No member outside this table is admitted.

| Member | Required | Type | Schema constraints |
| --- | --- | --- | --- |
| `schema` | yes | constant | `"https://schema.kya-os.org/experimental/payment-authority/2026-09-22/intent"` |
| `profile` | yes | constant | `"org.kya-os/payments.v1"` |
| `intentId` | yes | `reference` |  |
| `createdAt` | yes | `timestamp` |  |
| `expiresAt` | yes | `timestamp` |  |
| `audience` | yes | `did` |  |
| `action` | yes | string | min length 1; max length 256 |
| `payee` | yes | `party` |  |
| `payer` | yes | `did` |  |
| `presenter` | no | `did` |  |
| `amount` | yes | `amount` |  |
| `resources` | yes | array of `resource` | min items 1; max items 256 |
| `commerce` | no | object |  |
| `commerce.id` | yes | `reference` |  |
| `commerce.version` | yes | string | min length 1; max length 128 |
| `commerce.specDigest` | no | `digest` |  |
| `commerce.sessionId` | no | `reference` |  |
| `commerce.artifactDigest` | no | `digest` |  |
| `payment` | yes | `paymentSelection` |  |
| `purpose` | no | string | min length 1; max length 4096 |
| `extensions` | no | `extensions` |  |

Definitions it uses:

| Definition | Type | Schema constraints |
| --- | --- | --- |
| `amount` | object |  |
| `amount.asset` (required) | `asset` |  |
| `amount.coefficient` (required) | `canonicalInteger` |  |
| `amount.scale` (required) | integer | min 0; max 255 |
| `asset` | object or object or object |  |
| `asset.namespace` (required) (form `namespace` `iso4217`) | constant | `"iso4217"` |
| `asset.id` (required) (form `namespace` `iso4217`) | string | pattern |
| `asset.namespace` (required) (form `namespace` `caip19`) | constant | `"caip19"` |
| `asset.id` (required) (form `namespace` `caip19`) | string | max length 258; pattern |
| `asset.namespace` (required) (form `namespace` `uri`) | constant | `"uri"` |
| `asset.id` (required) (form `namespace` `uri`) | string | min length 2; max length 2048; pattern |
| `canonicalInteger` | string | max length 78; pattern |
| `did` | string | min length 5; max length 2048; pattern |
| `digest` | string | pattern |
| `extension` | object |  |
| `extension.version` (required) | string | min length 1; max length 128 |
| `extension.schema` | string | min length 2; max length 2048; pattern |
| `extension.critical` (required) | boolean |  |
| `extension.data` (required) | value | `kyaCanonicalJson` |
| `extensions` | object | max members 64; `kyaCanonicalJsonCollection`; member names: min length 1, max length 256, pattern |
| `party` | object |  |
| `party.id` (required) | `reference` |  |
| `party.accountDigest` | `digest` |  |
| `party.accountDigestMethod` | value | one of `opaque-token-sha256`, `hmac-sha256`, `issuer-attestation-sha256` |
| `paymentSelection` | object |  |
| `paymentSelection.protocol` (required) | `protocolRef` |  |
| `paymentSelection.methodId` | `reference` |  |
| `paymentSelection.handlerId` | `reference` |  |
| `paymentSelection.scheme` | string | min length 1; max length 128 |
| `paymentSelection.network` | string | min length 1; max length 128 |
| `paymentSelection.transferMethod` | string | min length 1; max length 128 |
| `paymentSelection.paymentFlow` | string | min length 1; max length 128 |
| `paymentSelection.redeemableByOthers` | constant | `true` |
| `paymentSelection.fundingAccount` | string | min length 1; max length 256 |
| `paymentSelection.settlementAmount` | `amount` |  |
| `paymentSelection.quoteDigest` | `digest` |  |
| `protocolRef` | object |  |
| `protocolRef.id` (required) | `reference` |  |
| `protocolRef.version` (required) | string | min length 1; max length 128 |
| `protocolRef.specDigest` | `digest` |  |
| `reference` | string | min length 1; max length 2048 |
| `resource` | object |  |
| `resource.id` (required) | `reference` |  |
| `resource.digest` (required) | `digest` |  |
| `timestamp` | integer | min 0; max 9007199254740991 |

### A.2 Payment Authorization (`payment-authorization.schema.json`)

No member outside this table is admitted.

| Member | Required | Type | Schema constraints |
| --- | --- | --- | --- |
| `schema` | yes | constant | `"https://schema.kya-os.org/experimental/payment-authority/2026-09-22/authorization"` |
| `profile` | yes | constant | `"org.kya-os/payments.v1"` |
| `authorizationId` | yes | `reference` |  |
| `intentDigest` | yes | `digest` |  |
| `decision` | yes | constant | `"authorized"` |
| `verifier` | yes | `reference` |  |
| `actor` | yes | `did` |  |
| `principal` | yes | `did` |  |
| `responsibleParty` | yes | `did` |  |
| `audience` | yes | `did` |  |
| `action` | yes | string | min length 1; max length 256 |
| `delegation` | yes | object |  |
| `delegation.credentialRef` | yes | `reference` |  |
| `delegation.credentialDigest` | yes | `digest` |  |
| `delegation.chainDigests` | yes | array of `digest` | min items 1; max items 10; unique items |
| `delegation.delegates` | no | array of `did` | min items 1; max items 10; unique items |
| `holderProof` | yes | object |  |
| `holderProof.profile` | yes | string | min length 1; max length 256 |
| `holderProof.digest` | yes | `digest` |  |
| `effectiveConstraintsDigest` | yes | `digest` |  |
| `decisionTrace` | yes | array of `decisionTraceEntry` | min items 1; max items 512 |
| `approval` | no | object |  |
| `approval.mode` | yes | value | one of `human-present`, `human-not-present`, `standing-policy` |
| `approval.issuer` | yes | `absoluteUri` |  |
| `approval.profile` | yes | string | min length 1; max length 256 |
| `approval.intentDigest` | yes | `digest` |  |
| `approval.evidenceDigest` | yes | `digest` |  |
| `approval.expiresAt` | yes | `timestamp` |  |
| `approval.subject` | no | `approvalSubject` |  |
| `idempotency` | yes | `idempotency` |  |
| `evidence` | yes | array of `evidence` | max items 64 |
| `createdAt` | yes | `timestamp` |  |
| `expiresAt` | yes | `timestamp` |  |
| `extensions` | no | `extensions` |  |

Definitions it uses:

| Definition | Type | Schema constraints |
| --- | --- | --- |
| `absoluteUri` | string | min length 2; max length 2048; pattern |
| `approvalSubject` | object or object |  |
| `approvalSubject.kind` (required) (form `kind` `did`) | constant | `"did"` |
| `approvalSubject.id` (required) (form `kind` `did`) | `did` |  |
| `approvalSubject.kind` (required) (form `kind` `oidc-subject`) | constant | `"oidc-subject"` |
| `approvalSubject.issuer` (required) (form `kind` `oidc-subject`) | `absoluteUri` |  |
| `approvalSubject.subject` (required) (form `kind` `oidc-subject`) | string | min length 1; max length 255 |
| `approvalSubject.bindingEvidenceDigest` (required) (form `kind` `oidc-subject`) | `digest` |  |
| `decisionTraceEntry` | object |  |
| `decisionTraceEntry.rule` (required) | string | min length 1; max length 128 |
| `decisionTraceEntry.result` (required) | value | one of `pass`, `deferred` |
| `decisionTraceEntry.hop` | integer | min 1; max 9 |
| `did` | string | min length 5; max length 2048; pattern |
| `digest` | string | pattern |
| `evidence` | object |  |
| `evidence.type` (required) | `reference` |  |
| `evidence.format` (required) | string | min length 1; max length 256 |
| `evidence.digest` (required) | `digest` |  |
| `evidence.ref` | `reference` | pattern |
| `evidence.canonicalization` (required) | string | min length 1; max length 128 |
| `evidence.class` | value | one of `authority`, `approval`, `commerce_terms`, `funding_authority`, `rail_authorization`, `rail_receipt`, `fulfillment`, `refund_or_reversal`, `communication` |
| `evidence.custodian` | `reference` |  |
| `evidence.retentionPolicy` | object |  |
| `evidence.retentionPolicy.id` (required) | `reference` |  |
| `evidence.retentionPolicy.digest` (required) | `digest` |  |
| `evidence.finality` | string | pattern |
| `extension` | object |  |
| `extension.version` (required) | string | min length 1; max length 128 |
| `extension.schema` | string | min length 2; max length 2048; pattern |
| `extension.critical` (required) | boolean |  |
| `extension.data` (required) | value | `kyaCanonicalJson` |
| `extensions` | object | max members 64; `kyaCanonicalJsonCollection`; member names: min length 1, max length 256, pattern |
| `idempotency` | object |  |
| `idempotency.key` (required) | string | min length 1; max length 256 |
| `idempotency.phase` (required) | value | one of `execute` |
| `idempotency.scope` (required) | string | min length 1; max length 2048 |
| `idempotency.requestDigest` (required) | `digest` |  |
| `reference` | string | min length 1; max length 2048 |
| `timestamp` | integer | min 0; max 9007199254740991 |

### A.3 Payment Outcome (`payment-outcome.schema.json`)

No member outside this table is admitted.

| Member | Required | Type | Schema constraints |
| --- | --- | --- | --- |
| `schema` | yes | constant | `"https://schema.kya-os.org/experimental/payment-authority/2026-09-22/outcome"` |
| `profile` | yes | constant | `"org.kya-os/payments.v1"` |
| `outcomeId` | yes | `reference` |  |
| `attemptId` | yes | `reference` |  |
| `sequence` | yes | integer | min 0; max 9007199254740991 |
| `previousOutcomeDigest` | no | `digest` |  |
| `producer` | yes | `reference` |  |
| `intentDigest` | yes | `digest` |  |
| `authorizationDigest` | yes | `digest` |  |
| `state` | yes | value | one of `authorized`, `submitted`, `settlement_pending`, `settled`, `failed` |
| `updatedAt` | yes | integer | min 0; max 9007199254740991 |
| `idempotency` | yes | `idempotency` |  |
| `rail` | yes | object |  |
| `rail.id` | yes | `reference` |  |
| `rail.version` | yes | string | min length 1; max length 128 |
| `rail.specDigest` | no | `digest` |  |
| `rail.transactionRef` | no | `reference` |  |
| `rail.reconciliationRef` | no | `reference` |  |
| `effectAmount` | no | `amount` |  |
| `reason` | no | object |  |
| `reason.code` | yes | value | one of `payment_failed`, `payment_quote_expired`, `payment_authority_expired`, `payment_delegation_revoked`, `payment_authority_recheck_failed`, `payment_denied` |
| `reason.newIntentMaySucceed` | yes | boolean |  |
| `reason.basis` | no | value | one of `close`, `slot`, `tracked` |
| `reason.detailDigest` | no | `digest` |  |
| `evidence` | yes | array of `evidence` | max items 64 |
| `extensions` | no | `extensions` |  |
| `correction` | no | constant | `true` |
| `finality` | no | string | pattern |

Definitions it uses:

| Definition | Type | Schema constraints |
| --- | --- | --- |
| `amount` | object |  |
| `amount.asset` (required) | `asset` |  |
| `amount.coefficient` (required) | `canonicalInteger` |  |
| `amount.scale` (required) | integer | min 0; max 255 |
| `asset` | object or object or object |  |
| `asset.namespace` (required) (form `namespace` `iso4217`) | constant | `"iso4217"` |
| `asset.id` (required) (form `namespace` `iso4217`) | string | pattern |
| `asset.namespace` (required) (form `namespace` `caip19`) | constant | `"caip19"` |
| `asset.id` (required) (form `namespace` `caip19`) | string | max length 258; pattern |
| `asset.namespace` (required) (form `namespace` `uri`) | constant | `"uri"` |
| `asset.id` (required) (form `namespace` `uri`) | string | min length 2; max length 2048; pattern |
| `canonicalInteger` | string | max length 78; pattern |
| `digest` | string | pattern |
| `evidence` | object |  |
| `evidence.type` (required) | `reference` |  |
| `evidence.format` (required) | string | min length 1; max length 256 |
| `evidence.digest` (required) | `digest` |  |
| `evidence.ref` | `reference` | pattern |
| `evidence.canonicalization` (required) | string | min length 1; max length 128 |
| `evidence.class` | value | one of `authority`, `approval`, `commerce_terms`, `funding_authority`, `rail_authorization`, `rail_receipt`, `fulfillment`, `refund_or_reversal`, `communication` |
| `evidence.custodian` | `reference` |  |
| `evidence.retentionPolicy` | object |  |
| `evidence.retentionPolicy.id` (required) | `reference` |  |
| `evidence.retentionPolicy.digest` (required) | `digest` |  |
| `evidence.finality` | string | pattern |
| `extension` | object |  |
| `extension.version` (required) | string | min length 1; max length 128 |
| `extension.schema` | string | min length 2; max length 2048; pattern |
| `extension.critical` (required) | boolean |  |
| `extension.data` (required) | value | `kyaCanonicalJson` |
| `extensions` | object | max members 64; `kyaCanonicalJsonCollection`; member names: min length 1, max length 256, pattern |
| `idempotency` | object |  |
| `idempotency.key` (required) | string | min length 1; max length 256 |
| `idempotency.phase` (required) | value | one of `execute` |
| `idempotency.scope` (required) | string | min length 1; max length 2048 |
| `idempotency.requestDigest` (required) | `digest` |  |
| `reference` | string | min length 1; max length 2048 |

### A.4 Payment constraints caveat (`payment-constraints.schema.json`)

No member outside this table is admitted.

| Member | Required | Type | Schema constraints |
| --- | --- | --- | --- |
| `type` | yes | constant | `"org.kya-os/payment-constraints"` |
| `version` | yes | constant | `"1.0.0"` |
| `businessLimits` | yes | array of `amount` | min items 1; max items 256 |
| `payees` | no | array of `party` | min items 1; max items 256 |
| `resources` | no | array of `resource` | min items 1; max items 256 |
| `rails` | no | array of `rail` | min items 1; max items 256 |
| `settlementLimits` | no | array of `amount` | min items 1; max items 256 |
| `quoteAuthorities` | no | array of `reference` | min items 1; max items 256; unique items |
| `fees` | no | `fees` |  |
| `requireApproval` | no | object | `kyaUniqueBy` |
| `requireApproval.modes` | yes | array of value | min items 1; max items 3; unique items; items: one of `human-present`, `human-not-present`, `standing-policy` |
| `requireApproval.approvers` | no | array of `reference` | min items 1; max items 256; unique items |
| `requireApproval.above` | no | array of `amount` | min items 1; max items 256 |
| `expiresAt` | no | `timestamp` |  |

Definitions it uses:

| Definition | Type | Schema constraints |
| --- | --- | --- |
| `amount` | object |  |
| `amount.asset` (required) | `asset` |  |
| `amount.coefficient` (required) | `canonicalInteger` |  |
| `amount.scale` (required) | integer | min 0; max 255 |
| `asset` | object or object or object |  |
| `asset.namespace` (required) (form `namespace` `iso4217`) | constant | `"iso4217"` |
| `asset.id` (required) (form `namespace` `iso4217`) | string | pattern |
| `asset.namespace` (required) (form `namespace` `caip19`) | constant | `"caip19"` |
| `asset.id` (required) (form `namespace` `caip19`) | string | max length 258; pattern |
| `asset.namespace` (required) (form `namespace` `uri`) | constant | `"uri"` |
| `asset.id` (required) (form `namespace` `uri`) | string | min length 2; max length 2048; pattern |
| `canonicalInteger` | string | max length 78; pattern |
| `digest` | string | pattern |
| `fees` | object or object |  |
| `fees.mode` (required) (form `mode` `prohibited`) | constant | `"prohibited"` |
| `fees` (form `mode` `capped`) | object | `kyaUniqueBy` |
| `fees.mode` (required) (form `mode` `capped`) | constant | `"capped"` |
| `fees.limits` (required) (form `mode` `capped`) | array of `amount` | min items 1; max items 256 |
| `party` | object |  |
| `party.id` (required) | `reference` |  |
| `party.accountDigest` | `digest` |  |
| `party.accountDigestMethod` | value | one of `opaque-token-sha256`, `hmac-sha256`, `issuer-attestation-sha256` |
| `protocol` | object |  |
| `protocol.id` (required) | `reference` |  |
| `protocol.version` (required) | string | min length 1; max length 128 |
| `protocol.specDigest` | `digest` |  |
| `rail` | object |  |
| `rail.protocol` (required) | `protocol` |  |
| `rail.methodId` | `reference` |  |
| `rail.handlerId` | `reference` |  |
| `rail.scheme` | string | min length 1; max length 128 |
| `rail.network` | string | min length 1; max length 128 |
| `rail.transferMethod` | string | min length 1; max length 128 |
| `rail.paymentFlow` | string | min length 1; max length 128 |
| `rail.fundingAccount` | string | min length 1; max length 256 |
| `reference` | string | min length 1; max length 2048 |
| `resource` | object |  |
| `resource.id` (required) | `reference` |  |
| `resource.digest` | `digest` |  |
| `timestamp` | integer | min 0; max 9007199254740991 |

### A.5 Extension settings (`payment-extension-settings.schema.json`)

Members outside this table follow the schema.

| Member | Required | Type | Schema constraints |
| --- | --- | --- | --- |
| `version` | no | string | max length 128; pattern |
| `profiles` | no | array of string | min items 1; max items 32; unique items; items: min length 1; items: max length 256 |
| `required` | no | boolean |  |

### A.6 Conditional requirements

Conditional requirements the schemas state, beyond the tables above:

- **Payment Intent.**
  - When `payment.redeemableByOthers` is `true`, `presenter` and `payment.fundingAccount` are required.
  - `payment.settlementAmount` requires `payment.quoteDigest`.
  - A `payment.protocol` or `commerce` whose `id` begins with `http:` or `https:` (in any letter case) requires `specDigest`.
  - A party's `accountDigest` and `accountDigestMethod` appear together or not at all.
  - An asset takes exactly one of three forms, by `namespace`: `iso4217`, `caip19`, or `uri`.
- **Payment Authorization.**
  - When `approval` is present, `delegation.delegates` is required.
  - An approval `subject` takes exactly one of two forms, by `kind`: `did` or `oidc-subject`.
- **Payment Outcome.**
  - `sequence` zero admits no `previousOutcomeDigest`; any other `sequence` requires one.
  - `state` `settled` requires `effectAmount` and `rail.transactionRef`; any other state admits no `effectAmount`.
  - `state` `settlement_pending` requires `rail.reconciliationRef`.
  - `state` `failed` requires `reason`.
  - A `reason` that names a `basis` requires `state` `failed` and `reason.code` `payment_failed`.
  - `correction` `true` requires `state` `settled` or `settlement_pending` and a `sequence` of at least one.
  - `finality` requires `state` `settled`.
  - A `rail` whose `id` begins with `http:` or `https:` (in any letter case) requires `specDigest`.
  - An asset takes exactly one of three forms, as in the intent.
- **Payment constraints caveat.**
  - `fees` takes exactly one of two forms, by `mode`: `prohibited`, or `capped` with `limits`.
  - A party's `accountDigest` and `accountDigestMethod` appear together or not at all.
  - A rail `protocol` whose `id` begins with `http:` or `https:` (in any letter case) requires `specDigest`.
  - An asset takes exactly one of three forms, as in the intent.
