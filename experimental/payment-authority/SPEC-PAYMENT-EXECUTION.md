# KYA-OS Payment Authority Profile: Execution

- **Status:** Experimental Working Group discussion draft; not ratified.
  Identifiers and schema URLs in this document are drafts and are not
  deployed.
- **Profile:** `org.kya-os/payments.v1`
- **MCP extension:** `org.kya-os/payment-authority`
- **Depends on:** the Core Authority document of this profile,
  [`SPEC-PAYMENT-AUTHORITY.md`](./SPEC-PAYMENT-AUTHORITY.md) (cited as
  "Core §n"), and through it `org.kya-os/decentralized-authority`
- **Date:** 2026-10-21
- **Scope:** the payment request and its binding to the request proof;
  idempotency; attempts and the journal that records them; the processing
  algorithm of an Executor; the rail-adapter contract, lost submissions, and
  when each Payment Outcome state is recorded; the answers an Executor gives
  and the answer proof that authenticates them; and the rules by which a
  client repeats a request or replaces an intent.
- **Out of scope:** concrete rail mappings (x402 and others) and the rules for
  rail credentials that parties other than the Executor can redeem; approval
  evidence formats; the envelopes and retrieval of the Portable Evidence tier;
  and the requirements of the Interop mappings. These are defined by a second
  part of the execution profile, in preparation, which this document calls
  **the adapter profile**.

This folder holds this document's machine-readable artifacts beside Core's:
two JSON Schema files, `payment-argument.schema.json` and
`payment-answer.schema.json`, and the execution vector corpus,
`vectors/payment-execution-vectors.json`, with its verifier,
`vectors/verify_execution_vectors.py` (section 13.3).

## 1. Introduction

*This section is informative.*

Core defines what a payer authorizes and how a verifier decides whether a
request carries that authority. This document defines how an Executor acts on
that decision: how a request carries an intent, how a repeated request is
recognized, how one attempt per intent is kept across failures, outages, and
restarts, and what the Executor answers.

The central property is that a payment intent pays at most once, and that a
client that follows section 10 never causes a second payment for one purchase
through its own requests. An intermediary that delays, replays, drops, or
forges messages, and an outage of any component, can delay a payment or
leave its result unknown until the rail resolves it; under the conditions of
section 10.5 none of them can cause a second payment.

Two mechanisms carry the property. On the Executor's side, an intent has at
most one attempt, recorded durably before anything reaches the rail; an
attempt is submitted at most once, and its rail call begins only on a clock
reading, taken after the submission is recorded, that is before its expiry
(sections 5 to 8). On the client's side, a client replaces an intent only
after an answer the Executor signed shows that the intent can no longer pay
(section 10.3). The answer proof (section 9.5) makes those answers
unforgeable.

Core calls the definitions this document and the adapter profile provide
"the execution profile". Section 3.2 maps each of Core's deferrals to the
part that defines it.

## 2. Conventions and terms

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174]
when, and only when, they appear in all capitals, as shown here.

Sections 1 and 3.2, examples, and text marked informative are informative;
the rest of this document is normative. An algorithm (the processing steps of
section 7, the expiry table of section 7.4, and the client rules of
section 10) carries the force of the requirement that introduces it, and an
implementation MAY realize it by any means that gives the same results.

This document uses Core's terms (Core §4.1, §4.2): the **Executor** is Core's
Payee/Executor, the **client** is Core's Agent/Client, and the **Authority
Verifier** is Core's. It also uses:

- **requester:** the DID of the request proof the Executor verified for a
  request (Core §4.1, the actor and the caller);
- **payment request:** an MCP `tools/call` request that carries a payment
  argument (section 4);
- **binding:** the pair of an idempotency `scope` and `key` (section 5.1);
- **attempt:** the Executor's record of its one effort to pay an intent
  (section 6), whose published states are those of Core §8.3;
- **submission:** sending an attempt's rail operation that can move value to
  the rail (Core §8.3);
- **decision time:** the decision clock of one request (Core §7.1);
- **the skew:** the profile clock skew of 60 seconds (Core §7.1). This
  document relies on Core's assumption that the clocks of the parties differ
  by less than the skew;
- **final:** an attempt state with no successor but a correction (`settled`,
  which has none, and `failed`, Core §8.3);
- **rail adapter:** the Executor's component that speaks one rail
  (section 8);
- **reconcile interval:** the longest time the Executor lets pass between two
  observations of an attempt that is `submitted` or `settlement_pending`
  (section 8.3), which it states in its conformance claim.

All times are epoch milliseconds (Core §7.1) unless stated otherwise. A
length counted in "code points" is counted in Unicode code points, as Core
§8.6 counts them.

## 3. Relationship to Core Authority

### 3.1 Roles and conformance

This document defines the Execution tier of Core §4.3 for two roles:

- the **Executor**, which authenticates requests, keeps the journal, runs the
  processing algorithm, drives the rail adapters, records outcomes, and
  answers; and
- the **client**, which builds payment requests, verifies answers, and
  repeats requests or replaces intents by the rules of section 10.

An Executor that claims the Execution tier MUST also meet Core Authority for
the Payee/Executor role and use an Authority Verifier that meets Core
Authority. A client that claims the Execution tier MUST also meet Core
Authority for the Agent/Client role. Section 13 lists each role's tests.

A Gateway/Intermediary (Core §4.2) that authenticates a request itself does
so as section 7.1 requires of an Executor.

### 3.2 Where Core's deferrals are defined

| Core defers to "the execution profile" | Defined in |
| --- | --- |
| The draft identifiers the execution profile defines (Core §6) | section 4.6 |
| The payment argument, its schema, its carriage, the key's character rule (Core §8.2), and its lossless parsing (Core §10, §14 item 26) | section 4.2 |
| Delegation carrier rules (Core §11.1) | section 4.3 |
| Further bounds of request-proof freshness (Core §7.1) | section 4.5 |
| The order of the checks before step 1 of Core §8.4.6 | sections 7.1 and 7.2 (step 10) |
| How an Executor uses the idempotency binding (Core §8.2) | section 5 |
| How an Executor records the bounds of an attempt and acts on each expiry (Core §8.2), and the order of its expiry checks and the re-evaluation (Core §13) | sections 6.2 and 7.4 |
| Clock readings after the decision (Core §7.1) | sections 7.2 (step 13), 7.3, and 7.4 |
| When each outcome state is recorded, a submission that returns to `authorized`, lost submissions, and the bases `close` and `tracked` (Core §8.3) | sections 6.1, 7.3, 8.3, and 8.4 |
| How a refusal of an authenticated request carries its reason, and whether it is retryable (Core §13) | sections 9.2 and 9.3 |
| Funding authority (Core §8.2), and the signed terms a rail credential is checked against (Core §8.1) | sections 8.1 and 8.2 |
| Rail expiries read without skew (Core §7.1) | section 7.4 |
| Exact conversion to rail units (Core §7), and the match of a `quoteDigest` that commits to rail bytes other than a quote (Core §8.1) | section 8.1 |
| Well-formed Unicode in references an adapter reports (Core §8.6), and the omission of a reference Core §9 does not admit | section 8.4 |
| The answer and the answer proof, and the `org.kya-os/payment-answer` member (Core §10, §11.1) | section 9 |
| Executor and client duties in request processing, idempotency, recovery, and answering (Core §4.2), their security requirements (Core §14), and the Execution tier's tests (Core §15) | sections 7 to 10, 12, and 13 |
| The Authority Verifier tests that need request binding or an in-process authority capability (Core §15; Core §8.2 on authority facts) | sections 7.2 (step 11) and 13.1 |
| The members of the answer vectors and the `answerProofs` set of Core's corpus (Core §15.1) | section 13.3 |
| Reasons of request processing, idempotency, recovery, and rail adapters (Core §13) | section 11 |
| Each rail's mapping: its carriers, units, quote digests, rail terms, evidence, account spellings, the key or issuer of an account commitment (Core §7), and the basis `slot` | the adapter profile |
| Rail credentials others can redeem and their redemption slot (Core §8.1) | the adapter profile |
| Approval evidence formats, the approval issuer role, and the Authority Verifier tests that need a format (Core §4.2, §8.2, §15) | the adapter profile |
| Envelopes and the Portable Evidence tier (Core §4.3, §8.5) | the adapter profile |
| Requirements and tests of the Interop mappings (Core §4.3, §12) | the adapter profile |

So a client presents no rail credential that others can redeem (section 4.4),
an Executor that implements only this document refuses an intent that signs
`redeemableByOthers` (section 7.2, step 12), and its Authority Verifier, which
implements no approval evidence format, refuses presented approval evidence
(Core §8.2).

## 4. The payment request

### 4.1 Operation

A payment request is an MCP `tools/call` request [MCP]. Its **operation
identifier** is exactly `tools/call#<name>`, where `<name>` is the request's
tool name, 1 to 256 code points, containing no `#`, CR, or LF. The tool's
`tools/list` entry carries the payment mark of Core §11, and the operation is
in required mode (Core §11).

### 4.2 The payment argument

The request's `params.arguments` object carries the payment argument as its
member `payment`. The payment argument has exactly these members:

| Member | Required | Value |
| --- | --- | --- |
| `profile` | yes | the literal `org.kya-os/payments.v1` |
| `idempotencyKey` | yes | the client's key (section 5.1): 1 to 256 code points, with no CR, LF, or U+0000 |
| `intent` | yes | the Payment Intent (Core §8.1) |
| `delegationDigest` | yes | the delegation-chain digest (Core §10) of the chain the client presents |
| `approvalEvidence` | no | `{type, format, value}`: approval evidence (Core §8.2), whose `type` has 1 to 2,048 code points and `format` 1 to 256, neither with CR or LF, and whose `value` is a string of 1 to 65,536 UTF-8 bytes |

Its schema is `payment-argument.schema.json`, whose `$id` is
`https://schema.kya-os.org/experimental/payment-authority/2026-09-22/argument`.
The schema cannot count UTF-8 bytes; the 65,536-byte bound of `value` is the
Executor's check.

The Executor MUST refuse (`payment_artifact_invalid`) a payment argument that:

- is absent, or is not a JSON object, or has a member not listed above;
- violates its schema, or carries an intent that fails the schema or checks
  V1 to V4 of Core's artifact validation (Core §8.7; check V5, on
  extensions, is section 7.2's step 10), or an `approvalEvidence.value` of
  more than 65,536 UTF-8 bytes;
- holds, anywhere within it, a member named `__proto__` (Core §14, item 26).

Before it parses the request, the Executor MUST refuse
(`payment_request_invalid`) a request message whose JSON text [RFC8259],
`_meta` and all, is more than 2,097,152 bytes of UTF-8 or nests arrays and
objects more than 64 deep (the message object itself is depth 1), so that
every later check, the request proof's and the delegation carrier's included,
works on bounded input. It MUST also refuse a request message whose JSON text,
`_meta` and all, is not a canonical value (Core §10): one that holds an object
with two members whose names are equal once escapes are decoded, a string, a
member name included, that is not well-formed Unicode, or a number that is not
finite or is integral and not a safe integer. The reason is
`payment_artifact_invalid` when any such defect lies within the payment
argument, a duplicated `payment` member included; `payment_delegation_invalid`
when none does and one lies within a delegation credential of the carrier
(section 4.3), as Core §10 requires; and `payment_request_invalid` otherwise
(Core §13). It checks them on the JSON text of the request, before it parses
it into any structure that could hide them. Two parsers that read one text two
ways would disagree on what the request proof signed, since the request digest
covers `method` and all of `params` but `_meta` (section 4.5), or on what
`_meta` carries: the delegation carrier, the request proof, and the client's
capabilities (sections 4.3, 4.5, and 7.1, step 2). The other members of
`params.arguments` are the tool's own, and the other members of `params._meta`
belong to other extensions; this document reads none of them and constrains
them only by this rule.

A client MUST NOT place the only copy of the intent, its digest, the
idempotency key, the payee, the amount, the quote digest, or approval evidence
in `_meta`, because no request proof covers `_meta` (Core §11.1).

### 4.3 Delegation carrier

The client presents its delegation chain, root first, as a JSON array of
delegation credentials in `params._meta["org.kya-os/delegation-credentials"]`
(Core §11.1). The proof-covered `delegationDigest` selects and binds it: the
Executor MUST compute the delegation-chain digest (Core §10) of the presented
credentials and refuse the request (`payment_delegation_invalid`, Core §8.4.6,
step 1) when it differs from `delegationDigest`. The carrier only transports
the chain, which its credentials' own proofs authenticate.

A client that holds authority from several payers selects one chain per
request; the selection is signed through `delegationDigest`.

A payment chain is bound to one Executor. Its `invocationTarget` is constant
along the chain, and the Authority Verifier asserts it as the Executor's
protected resource (Core §8.4.6, step 8); this document reads that binding as
the per-hop audience that SPEC.md §11.6 requires, as `BASE-AMENDMENTS.md`
item 3 proposes. Payment authority therefore names a protected resource, an
action, and the payment caveat's allowlists, not a tool: a deployment that
needs per-tool scope gives each payment tool its own protected resource. A
payer that pays several Executors issues a chain for each.

### 4.4 Rail credential carrier

A rail credential — what the rail needs to move value, such as a network token
or a signed transfer authorization — travels in `params._meta`, under the
member that its rail adapter's mapping names (the adapter profile), outside
the payment argument. No request proof covers it, and it is not authority for
the payment: the Executor binds it to the payment only by the adapter checks
of section 8 (the signed terms, funding authority, and the payment identity).
An Executor MUST NOT echo a rail credential in an answer, an error, or a log,
and a client MUST NOT log one. A client MUST NOT present a rail credential
that a party other than the Executor can redeem at the rail: the adapter
profile says when one may travel, for an intent that signs
`redeemableByOthers` (section 7.2, step 12). Section 8.1, item 2, refuses one
presented anyway, but only once it has travelled uncovered past every
intermediary, so the refusal does not protect it.

### 4.5 Request proof

A payment request carries an Entity Card request proof (SPEC-ENTITY-CARD §8)
in `params._meta["org.kya-os/request-proof"]`, or under the legacy carrier key
and profile identifier that SPEC-ENTITY-CARD §8.1 requires a verifier to
accept, with the precedence it states, verified at assurance `L3` or
`L3-minus` (Core §4.3). Its `requestHash` covers the request without
`params._meta` (SPEC-ENTITY-CARD §8.3), so it covers the payment argument and
the tool's other arguments; the request digest is derived from it as Core §10
states.

Beyond the base verification (SPEC-ENTITY-CARD §11.2), the Executor applies
these profile rules to the request proof, each refused with `proof_invalid`:

1. its `did` is in DID syntax and at most 2,048 code points, so that an
   answer proof can name it (section 9.5);
2. its `nonce` is 1 to 512 code points, so that an answer proof can name it
   (section 9.5), whatever its alphabet (`BASE-AMENDMENTS.md` item 8 proposes
   base64url for the base); and
3. the decision time is before its `expires`, an exclusive end that no skew
   extends (Core §7.1).

With the base's lifetime bound (`expires` at most 60 seconds after
`created`, SPEC-ENTITY-CARD §8.2), rule 3 bounds how long before the decision
time a proof can have been created: less than 60 seconds. How far after it
the base bounds by its request-proof skew (SPEC-ENTITY-CARD §11.2, step 7); an
Executor MUST NOT configure a request-proof skew greater than the skew.

The Executor MUST consume the proof's nonce exactly once across every instance
that verifies requests for it (SPEC-ENTITY-CARD §12.2), and MUST keep each
consumed nonce at least until the proof's `expires` plus the largest
request-proof skew of any verifier that shares its nonce store, plus one
second, so that no verifier sharing the store accepts a copy of the proof
after the nonce is forgotten: the base compares whole epoch seconds
(SPEC-ENTITY-CARD §11.2, step 7), so a verifier accepts a proof through the
last second of that window. `BASE-AMENDMENTS.md` item 7 proposes this
retention rule for the base.

### 4.6 Identifiers

This document defines these draft identifiers, none of them stable (Core §6):
the schema URLs
`https://schema.kya-os.org/experimental/payment-authority/2026-09-22/argument`
and `https://schema.kya-os.org/experimental/payment-authority/2026-09-22/answer`;
the answer proof profile `org.kya-os/payment-answer.v1` and its optional JWS
`typ`, `kya-payment-answer+jws` (section 9.5); and the reasons of section 11.
It uses Core's answer digest domain and Core's `_meta` member
`org.kya-os/payment-answer` (Core §10, §11.1). Ratification replaces the
schema URLs with immutable versioned identifiers, as Core §6 states for
Core's own.

## 5. Idempotency

### 5.1 Binding and scope

Each payment request has an idempotency binding (Core §8.2) whose members the
Executor derives from its authentication of the request, except the key:

- `key` is the payment argument's `idempotencyKey`;
- `phase` is `execute`;
- `scope` is exactly `org.kya-os/payments.v1:` followed by the RFC 8785
  [RFC8785] serialization of `{tenant, caller, operation}`, where `tenant` is
  the namespace that the Executor's deployment configures for the intent's
  payee, `caller` is the requester, and `operation` is the operation
  identifier (section 4.1); and
- `requestDigest` is the request digest (Core §10).

The deployment configures a tenant for each payee the Executor serves, and
the Executor serves exactly those payees (Core §4.1). A deployment that
configures one tenant and no payees serves only the payee whose `id` is that
tenant, which is Core's default; an Executor that configures no tenant serves
no payee. No tenant ever comes from the request.

`tenant` and `caller` are each 1 to 512 code points without CR or LF, and the
scope at most 2,048 code points (Core §8.2). A tenant comes from
configuration, so the Executor MUST check every configured tenant against its
bounds when it loads its configuration, and MUST NOT load one that fails them;
no request then meets such a tenant. A caller outside its bounds is refused
`payment_request_invalid` (Core §8.2). RFC 8785 escapes control characters, so
a scope can exceed 2,048 code points while each member is within its own
bound; the Executor MUST refuse such a request (`payment_request_invalid`).
The **binding** of a request is its pair (`scope`, `key`). Two requests with
one binding come from the same requester, for the same tool and tenant.

### 5.2 Rules

The Executor MUST keep these rules, for every request it authenticates, over
every instance that shares its journal:

1. **One request per binding.** An attempt records the binding and the request
   digest of the request that created it. A request whose binding names an
   attempt recorded for another request digest is refused
   (`payment_idempotency_conflict`). A binding that names no attempt is
   unbound, whatever requests a refusal answered before: a refusal records
   nothing.
2. **One attempt per intent.** The journal holds at most one attempt per
   intent digest, whatever its binding. A request that would create a second
   attempt for an intent is refused (`payment_idempotency_conflict`).
3. **Repeats answer from history.** A request whose binding names an attempt
   recorded for the same request digest is a **repeat**. A repeat never
   creates an attempt; it continues the attempt or answers its recorded state
   (section 7.2, step 9).
4. **One payment identity per intent.** The rail adapter reports, for each
   payment, the identity under which its rail deduplicates it (section 8.1).
   The journal binds each payment identity to at most one intent and each
   attempt to one payment identity. A request whose payment identity is bound
   to another intent, or that would continue an attempt under another payment
   identity than the one recorded, is refused (`payment_replay`).

A repeat under the same binding is how a client asks again: the same covered
bytes, under a fresh request proof (section 10.1).

## 6. Attempts

### 6.1 Attempt record

An attempt records: its `attemptId`, which the Executor assigns (Core §8.3);
the binding and request digest of the request that created it; the intent
digest; the requester, which is the attempt's **actor**; the digest of the
Payment Authorization that created it; the payment identity; its bounds
(section 6.2); its state; the rail references and effect amount that the rail
reported; and, when it is `failed`, its reason (Core §8.3).

Its published states are those of Core §8.3, and it moves only by the
transitions Core §8.3 allows. While `authorized`, an attempt is either
**released**, when no call holds it, or **claimed**, when one call holds a
**submission claim** on it until a lease end the journal records, which is no
later than the attempt's expiry for that call (section 6.2). A claim is
internal: claiming and releasing publish nothing, and a claimed attempt is
published as `authorized`. A claim whose lease ends before its call records
`submitted` returns the attempt to released. Core §8.3 leaves to this document
how a submission that never reached the rail returns to `authorized` without a
published transition: here that case is exactly such a claim, since a call
sends nothing before it records `submitted`, and once `submitted` is recorded
the attempt never returns to `authorized`, unless a restore loses that record
(section 6.4). A call that records `submitted` keeps its claim through the
rail call and ends it at step 18. A `submitted` attempt that no call holds is
a **lost submission** (section 8.3): its call ended without a usable rail
answer, or its claim's lease ended, as after a crash before or during the
call. While a call holds it, it is not lost.

### 6.2 Bounds and the attempt expiry

An attempt's **expiry** is the earliest of its bounds:

- the **fixed bounds**, which the covered bytes set (Core §8.2): the intent's
  `expiresAt`, every delegation bound of the chain, the payment caveat's
  `expiresAt`, the recorded approval's `expiresAt`, and the expiry of what the
  intent binds by `quoteDigest`, its **bound quote**: the quote of a
  conversion, or, without one, the rail terms the digest commits to (section
  8.1, item 1), when the adapter verified it; and
- the **renewable bounds**, which belong to one request: the request proof's
  `expires`, the status freshness that the request's latest status read
  established (Core §8.2) — at the decision, then at the final recheck — and
  the expiry of rail terms that came with the request's rail credential and
  that the intent does not bind.

The Executor records the fixed bounds when it creates the attempt. Each
request that holds a claim on the attempt brings its own renewable bounds; the
attempt's expiry for that call is the earliest of the recorded fixed bounds
and the call's renewable bounds. Every bound is an exclusive end (Core §7.1).

### 6.3 Journal requirements

An Executor — every instance that answers for one `audience` DID — keeps one
journal, and the rules of section 5.2 hold over all of it. The Executor MUST
run its journal so as to:

1. make each write durable before the Executor answers on its basis or
   begins a rail call that relies on it;
2. be linearizable: a read that begins after a write completed observes that
   write, from every instance;
3. enforce atomically with the write that creates an attempt the uniqueness
   of section 5.2 (one attempt per binding, one per intent digest, and one
   intent per payment identity), and refuse that write for an intent under
   the horizon (section 6.4) or at or before the retention cutoff (section
   6.5), as the journal holds them at that write;
4. make every state change and every claim a compare-and-swap on the
   attempt's current version, so that of two writers that read one version at
   most one succeeds; and
5. refuse every write by a process that predates the latest restore of the
   journal (section 6.4).

When its journal cannot read or write, the Executor answers no request on a
guess: the request is refused (`payment_journal_unavailable`), and the
attempt keeps the state the journal last recorded. This refusal takes the
place of any answer section 7 would give from a write that did not happen,
such as a failed or released attempt (section 7.4); it carries
`attemptRecorded` and `attempt` as the journal last recorded them, when the
journal could be read (section 9.4).

### 6.4 Loss of journal records

A journal can lose records: a restore from a backup, or a failover to a
replica that may lag, removes what was written after the copy. A lost attempt
breaks section 5.2, rule 2, and makes `attemptRecorded: false` (section 9.4)
untrue. An Executor whose journal may have lost records MUST therefore, before
it processes any request on the restored journal:

1. stop every process that wrote to the journal before the loss, and ensure
   that the journal refuses any write such a process attempts later (section
   6.3, item 5); and
2. once they have stopped, set a **horizon**: the reading of a clock that
   never runs backward and is within the skew of every clock the Executor's
   instances read, plus the skew. Every decision time of a request whose
   record the loss could have removed is then earlier than the horizon.

An intent is **under the horizon** when its `createdAt` is earlier than the
horizon plus the skew: a request could have presented it before the horizon,
since the Executor accepts a `createdAt` up to the skew after its decision
time (Core §7.1). The journal tags every write with the horizon in force
when it was made, or with none before the first; a recorded attempt that is
not final and whose latest write carries an earlier horizon, or none, is
**held back**: the restore may have removed its later states. No clock decides
which writes precede the horizon. The Executor MUST:

- refuse every request for an intent under the horizon for which the journal
  holds no attempt (`payment_journal_indeterminate`), and never create an
  attempt for it;
- neither claim, fail, nor report in any answer a held-back attempt, and
  refuse every request for its intent (`payment_journal_indeterminate`; an
  outage, section 9.2, cause 1). Only a write under the horizon in force ends
  a hold-back, and only an observation of the attempt's payment identity at
  the rail, made after the horizon was written, writes a held-back attempt
  (section 8.3); one that no observation resolves stays held back; and
- otherwise process requests as this document states: a final attempt, or one
  whose latest write carries the horizon in force, is answered as recorded.

A refusal that this section requires carries no `attemptRecorded` (section
9.4). The Executor MUST write the horizon to the journal before it processes
any request on the restored journal, and every instance MUST read it from
there.

An Executor whose journal is never restored and never fails over to a replica
that may lag MAY declare so in its conformance claim; it then sets no horizon.

### 6.5 Retention

An Executor MUST NOT delete an attempt unless it is final and a clock that
never runs backward and is within the skew of every clock its instances read
(section 6.4) reads at least its intent's `expiresAt` plus the skew plus the
longer of its reconcile interval and 300 seconds, so that the intent has
expired by every instance's clock. (Informative: the wait covers most of a
client's repeats, which end at its bound, section 10.2; a request that still
arrives after a deletion is refused as below, and its client resolves with the
payer.) Deleting is a planned loss of records, so the Executor keeps a
**retention cutoff**: the latest `expiresAt` among the intents whose attempts
it has deleted. It MUST refuse every request for an intent whose `expiresAt`
is at or before the cutoff and for which the journal holds no attempt
(`payment_journal_indeterminate`), without `attemptRecorded` (section 9.4),
and never create an attempt for it, the create of a request that passed step 9
before the cutoff moved included (section 6.3, item 3). A client's answers
about such an intent then never report that it has no attempt, and never show
an attempt created after the deletion, so neither case of section 10.3 can
follow a deletion. The Executor MUST write the new cutoff to the journal
before it deletes, and every instance MUST read it from there. An Executor
states in its conformance claim how long it keeps final attempts after their
intent's expiry.

## 7. Processing

### 7.1 Before authentication

A request is **authenticated** once it has passed steps 1 to 6 below: its
intent addressed to this Executor, its request proof verified, and its nonce
consumed (section 4.5). Before that, every refusal is a JSON-RPC error
[JSON-RPC] (section 9.3). The Executor MUST process a payment request in this
order, and refuse it at the first step that fails:

1. **Operation.** First, the request message is within the bounds of section
   4.2 (else `payment_request_invalid`); then its text, `_meta` included, is a
   canonical value as section 4.2 requires (else the reason section 4.2
   gives); then the request is a `tools/call` whose tool name meets section
   4.1 (else `payment_request_invalid`).
2. **Negotiation.** The extension negotiation of Core §11 succeeds for the
   operation, in required mode.
3. **Payment argument.** The payment argument is valid (section 4.2), and the
   intent's digest is computed (Core §10); else `payment_artifact_invalid`.
4. **Audience.** The intent's `audience` is a DID the Executor answers for;
   else `payment_intent_mismatch`.
5. **Answer signer.** The Executor can sign, as that DID, an answer that
   verifies as a client verifies it (section 9.5); else
   `payment_configuration_invalid`.
6. **Request proof.** A request proof is present (else `proof_missing`),
   verifies by SPEC-ENTITY-CARD §11.2 and section 4.5 at the decision time,
   which the Executor reads once, here, with the intent's `audience` as the
   proof's expected audience (else `proof_invalid`), and reaches `L3` or
   `L3-minus` (else `proof_level_insufficient`). Its nonce is consumed.

Steps 4 and 5 precede the request proof so that every authenticated request
can be answered: the answer signer is the intent's `audience` (section 9.5),
and the Executor cannot sign an answer to an intent addressed to another
party.

### 7.2 After authentication

Every refusal of an authenticated request is a signed refusal (section 9.2),
except the error of section 9.5 when no answer proof can be produced. The
Executor MUST continue in this order:

7. **Presenter.** When the intent names a `presenter`, it is the requester;
   else `payment_intent_mismatch`.
8. **Payee and scope.** The intent's payee is one the Executor serves, which
   section 5.1 fixes from configuration alone (Core §4.1, §14 item 22; else
   `payment_intent_mismatch`), and the idempotency
   scope is derived and within its bounds, the requester among them as its
   `caller` (else the reason section 5.1 gives).
9. **History.** The journal is read by the binding and by the intent digest.
   Sections 6.4 and 6.5 decide first, here, for an intent under the horizon or
   at or before the retention cutoff that has no attempt, and for a held-back
   attempt.
   - A binding that names an attempt for another request digest is refused
     (`payment_idempotency_conflict`).
   - A repeat whose attempt is `submitted`, `settlement_pending`, `settled`,
     or `failed` is answered with that attempt (section 9.1), and processing
     ends: no live authority is read and nothing is created. Before answering
     a repeat of an attempt that is not final, the Executor SHOULD observe it
     at the rail (section 8.3).
   - A repeat whose attempt is `authorized` and claimed by another call is
     answered with that attempt, and processing ends.
   - A repeat whose attempt is released continues with step 10, as a
     **resumption** of that attempt.
   - Otherwise the request continues with step 10 as a **first request**.

   Step 9 precedes every live read so that a repeat of a request whose effect
   was recorded learns that outcome even after a delegation is revoked or the
   intent expires.
10. **Intent bounds and extensions.** The intent's `createdAt` is at most the
    skew after the decision time (else `payment_request_invalid`); the
    decision time is before the intent's `expiresAt` (else
    `payment_authority_expired`); and the intent passes check V5 of Core
    §8.7 for the extension handlers the Executor has, with the reasons V5
    gives (`payment_extension_unsupported`, `payment_extension_invalid`). Steps 4,
    6 (the request proof's `expires`), 7, 8 (the payee), and 10 make, in that
    order, the checks that Core §8.4.6 requires before its step 1.
11. **Authority.** The Authority Verifier decides the request by Core §8.4.6,
    at the decision time. A refusal carries the reason Core §8.4.6 gives. A
    deployment-specific check the Executor adds runs here, after the Authority
    Verifier has decided, and refuses with `payment_denied` (Core §13). The
    Executor accepts the authority facts only for this request (Core §4.2,
    §8.2), and refuses, with the reasons Core §13 gives, facts that name
    another request digest (`payment_request_mismatch`) or another intent
    (`payment_intent_mismatch`), and facts that name another holder-proof
    digest or idempotency binding, that record an approval when the request
    presented no `approvalEvidence`, or that it cannot read
    (`payment_authority_mismatch`). Each of these refusals, whatever its
    reason, is a fault of the Executor's own components (section 9.2, cause
    5).
12. **Rail terms.** In this order: an Executor that does not implement the
    adapter profile refuses an intent that signs `redeemableByOthers`
    (`payment_rail_unsupported`); then the rail adapter for the
    intent's `payment.protocol` makes the checks of section 8.1, items 1 to
    3, in their order, and reports what item 4 lists, and the Executor
    refuses a bound quote that has expired, then rail terms that have expired
    (section 7.4). Each refusal carries the reason section 8.1 or 7.4
    gives it.
13. **Re-evaluation.** The Executor reads its clock and checks every bound at
    that reading (section 7.4). When the authority decision deferred a rule,
    it then runs, at the same reading, the re-evaluation of Core §8.4.4 with
    the fees and quote of step 12 (Core §7.1); a failure carries its Core
    reason, and a re-evaluation that cannot complete fails closed with
    `payment_constraint_invalid`, as Core §8.4.4 requires (section 7.4).
14. **Attempt.** For a first request, the Executor creates the attempt,
    `authorized` and claimed by this call, in one journal write that enforces
    section 5.2, rules 2 and 4, and section 6.3, item 3: a create that the
    horizon or the retention cutoff refuses there, though step 9 found none
    in force, refuses the request (`payment_journal_indeterminate`), as
    step 9 would have. A create that loses to another call's create
    for the same binding and request digest makes this request a repeat: the
    Executor reads the journal again and continues as step 9 states, except
    that a released attempt is claimed here under this request's step-11
    decision, with no second decision (Core §4.2); one that
    loses to a create for the same binding and another request digest is
    refused with `payment_idempotency_conflict` (section 5.2, rule 1).
    Otherwise, when the intent already has an attempt, the request is refused
    with `payment_idempotency_conflict`, and when the payment identity is
    bound to another intent, with `payment_replay`.
    For a resumption, the payment identity is the attempt's (else
    `payment_replay`), and the Executor claims the released attempt by
    compare-and-swap; if another call claimed or advanced it first, the
    request is answered with the attempt as that call recorded it. The
    Executor records the Payment Authorization of step 11 with the attempt; a
    resumption's authorization is recorded beside the one that created the
    attempt, whose digest stays the attempt's `authorizationDigest` (Core
    §8.3).

Steps 15 to 18 (section 7.3) then run in order, under the claim.

No step before step 17 makes a payment effect. A refusal at step 15 or 16,
under a claim, first fails or releases the attempt as section 7.4 states, or,
when the journal cannot be written, leaves the claim to end at its lease end;
a lost swap at step 16 leaves the attempt as the journal holds it.

### 7.3 Final recheck and submission

15. **Final recheck.** At the last reversible point — immediately before the
    submission — the Executor reads its clock and, at that reading, first
    reads again the status of every credential in the chain by the walk of
    Core §8.4.6, step 8, which renews the status freshness when every list it
    reads is live, while a walk that reads a list that is unavailable,
    unauthenticated, or not live leaves the freshness of the decision in
    force; then checks every bound of the attempt; then runs the re-evaluation
    of Core §8.4.4, whether or not a rule was deferred. A recheck that does
    nothing is not conformant. Section 7.4 decides the claim from the result.
16. **Submit.** The Executor reads its clock again and checks the attempt's
    bounds at that reading (section 7.4). It then records the attempt
    `submitted`, by a compare-and-swap conditioned on the attempt being still
    claimed by this call with a lease end after that reading; a lost swap
    refuses the request (`payment_attempt_conflict`) and leaves the
    attempt as the journal holds it.
17. **Rail call.** After the step-16 record has been written, durable (section
    6.3, item 1), and before it begins the rail call, the Executor reads its
    clock once more, and MUST NOT begin the call unless that reading is before
    the attempt's expiry and before its claim's lease end; a reading at or
    after the lease end, but before the expiry, leaves the attempt a lost
    submission that was never sent (section 8.3). The reading governs the
    decision to begin, not the moment the call begins: a pause after it, such
    as a scheduler or virtual-machine pause, can start the call later, so the
    adapter gives the rail the attempt's expiry as a deadline where the rail
    enforces one (section 8.1, item 5). When that reading is at or after the
    expiry, the Executor does not begin the call and records the attempt
    `failed`, with the reason the first row of section 7.4 gives for the
    expired fixed bounds, or, when only renewable bounds expired, with
    `payment_quote_expired` if the rail terms' expiry is no later than every
    other expired bound and `payment_authority_expired` otherwise; it can do
    so only because it knows that no part of the call was sent. Otherwise the
    adapter submits. A call that a crash interrupts between step 16 and its
    start becomes a lost submission when its claim's lease ends (section 6.1).
18. **Record.** The Executor records the rail's answer as section 8.4 states,
    ends the call's claim, and answers the request with the attempt (section
    9.1); a report that section 8.1 refuses is answered by that refusal
    (`payment_evidence_invalid`), and the attempt keeps its recorded state. A
    write here that loses its compare-and-swap (section 6.3, item 4) records
    nothing, and the request is answered with the attempt as the journal then
    holds it. When the call ended without a usable rail answer, the attempt
    stays `submitted`, a lost submission once the claim ends, and is answered
    so.

A failure of the journal at any step is answered as section 6.3 states.

### 7.4 Expiry at each check

A bound has expired at a check when the clock reading of that check is at or
after it; no skew extends a bound, a quote's and rail terms' expiries included
(Core §7.1). The checks are the decision time, read at step 6 and used through
step 12, the reading of step 13, the final recheck (step 15), and the reading
of step 16; step 17 is decided as it states. Before a claim the steps run in
order and the first that fails decides. Under a claim, the first row of the
table that applies decides. The table gives reasons; each refusal's class is
the one section 9.2 sets for its cause (a fixed bound rests on the covered
bytes, a renewable one is cause 2):

| At a check | Before a claim (steps 6 to 13) | Under a claim (steps 15 and 16) |
| --- | --- | --- |
| A fixed bound has expired | refuse with the reason of the check that finds it (below) | fail the attempt: `payment_quote_expired` when the bound quote's `expiresAt` is no later than every other expired fixed bound, else `payment_authority_expired` |
| A renewable bound has expired | refuse: the request proof's `expires` is `proof_invalid` (step 6, an error before authentication); status freshness, `payment_authority_stale` (step 11); rail terms, `payment_quote_expired` (step 12) | release the attempt; refuse: `payment_quote_expired` when the rail terms' expiry is no later than every other expired renewable bound, else `payment_authority_expired` |
| The status walk stops at a credential that a live list reports revoked | refuse: `payment_delegation_revoked` (step 11) | fail the attempt: `payment_delegation_revoked` |
| The status walk stops at a status that is unavailable or unauthenticated, ends with a list that is not live, or the status walk of the recheck cannot complete | refuse: `payment_authority_stale` (step 11) | release the attempt; refuse: `payment_authority_stale` |
| The re-evaluation fails a rule | refuse with the rule's Core reason (step 13) | fail the attempt: `payment_authority_recheck_failed` |
| The re-evaluation cannot complete | refuse: `payment_constraint_invalid` (step 13; Core §8.4.4) | release the attempt; refuse: `payment_constraint_invalid` |

Before a claim, through step 12, the check that reads a fixed bound finds it,
with the reason Core gives that check: the intent's `expiresAt`,
`payment_authority_expired` (step 10); a delegation bound,
`payment_delegation_invalid` (Core §8.4.6, step 5); the approval's,
`payment_approval_invalid` (Core §8.4.6, step 9); the payment caveat's
`expiresAt`, `payment_constraint_denied` (rule `intent.expiry`, Core §8.4.4);
and the bound quote's, `payment_quote_expired` (step 12). The reading of
step 13 checks every bound; a bound expired there refuses the request with
the reason the claim column of the first two rows chooses. Under a claim, the
first row precedes the re-evaluation, so a payment caveat whose `expiresAt` is
reached between the decision and the recheck fails the attempt with
`payment_authority_expired`: this is the order of Core §13's
`payment_authority_expired` row that Core leaves to this document. Under this
document the terms of a rail credential are renewable; the adapter profile
makes the terms of a credential others can redeem fixed.

A request whose claim fails the attempt is answered with the failed attempt
(section 9.1); one whose claim releases it is refused as the table states,
with the released attempt in `attempt` (section 9.4). A fail or release write
that loses its compare-and-swap (section 6.3, item 4) changes nothing, and the
request is answered with the attempt as the journal then holds it.

For a resumption, a fixed bound found expired before the claim (steps 10 to
13), or a credential that a live list reports revoked (step 11), fails the
released attempt with the reason of the claim column of the first or the
third row, and the request is answered with the failed attempt (section 9.1).
For an expired bound, the next paragraph requires this of any report of such
an attempt; for a revocation, it records `newIntentMaySucceed` `false`, as
Core §8.3 requires, where a later expiry would record `true`.

A claim whose lease ends releases its attempt. The Executor SHOULD fail a
released `authorized` attempt once a fixed bound of it has expired, with the
reason of the first row, and MUST do so before it reports such an attempt in
any answer: no answer reports a released `authorized` attempt whose fixed
bound has expired, except the refusal of section 6.3 when the journal could be
read but not written, which reports the attempt as last recorded. A failed
attempt carries `newIntentMaySucceed` as Core §8.3 states: `true` after an
expiry, `false` after a revocation or a failed recheck.

## 8. Rail adapters

### 8.1 The adapter contract

A rail adapter is trusted code of the Executor. For the intent's selection
(`payment`, Core §8.1) it MUST:

1. **Match the offer.** Derive, from the offer the Executor makes for the
   purchase (rail terms it generated or verified), the selection that offer
   corresponds to, in the form of the intent's `payment` member (Core §8.1),
   and require it to equal the intent's `payment` exactly, apart from
   `fundingAccount` and `redeemableByOthers`, which the intent adds for its
   payer, and `settlementAmount` and `quoteDigest`, which the next sentences
   and item 4 check; and require that the offer moves exactly the effective
   settlement amount (Core §7) to exactly the intent's payee, converted to the
   rail's units exactly, never rounded: an amount the rail's units cannot
   represent exactly fails. When the intent carries a `quoteDigest` and is not
   a conversion (Core §8.4.4), the digest that the rail's mapping derives from
   the rail terms the offer rests on (the adapter profile) equals it. Failure:
   `payment_offer_mismatch`. No adapter for the selection's protocol:
   `payment_rail_unsupported`.
2. **Verify the rail credential** that the request carries in the rail's
   carrier (section 4.4) against the terms the intent signs for it (Core
   §8.1): it uses the selection's `transferMethod` and `paymentFlow` when the
   intent signs them, and debits the intent's `fundingAccount` when it signs
   one, as the rail's mapping reads these from the credential, and, where the
   credential fixes an amount or a recipient, moves exactly the offer's amount
   to the offer's recipient; and refuse one that a party other than the
   Executor can redeem at the rail unless the Executor implements the adapter
   profile and the intent signs `redeemableByOthers`. Failure:
   `payment_credential_invalid`.
3. **Establish funding authority** (section 8.2). Failure:
   `payment_funding_authority_failed`.
4. **Report** the payment identity under which the rail deduplicates the
   payment; the payer-borne fees, exactly; for a converted intent, the
   verified quote of Core §8.4.4, check 2 (exactly `issuer`, `digest`,
   `source`, and `target`), and, apart from it, the quote's expiry; and the
   expiry of the rail terms the credential came with. A quote whose digest
   differs from the intent's `quoteDigest` fails the re-evaluation (rule
   `intent.quote`, Core §8.4.4).
5. **Submit and observe.** Submit the payment once, under the payment
   identity, with the attempt's expiry as the rail's deadline for accepting it
   where the rail enforces one, and report the rail's answer: settled, with
   the transaction reference and the amount moved; pending, with the
   reconciliation reference; failed, with whether the rail says a new intent
   may succeed; or no usable answer. Observe a payment identity on request and
   report the same, or that the rail holds no submission of it, and, for a
   failure, whether the observation found the submission (section 8.3).
6. **Declare** whether it can **close** a payment identity: make the rail
   refuse every later submission of it and confirm whether it held one when
   it closed it.

An adapter MUST NOT report a fact that it did not read from the rail or from
material the rail authenticated. The Executor records no report that is
malformed or contradicts itself (for example a settlement without an amount,
or a `transactionRef` or `reconciliationRef` that is not well-formed Unicode,
Core §8.6, or not 1 to 2,048 code points): it refuses the request
(`payment_evidence_invalid`), and the attempt keeps its recorded
state, so that a submission whose answer was such a report is a lost
submission that later observations resolve (section 8.3). An evidence
reference (Core §9) that is not well-formed Unicode, or that Core §9 does not
admit, is not such a report: section 8.4 omits it. The mapping of each rail to
this contract is the adapter profile's.

### 8.2 Funding authority

Before a payment effect, the Executor MUST establish that the funding source
the rail credential debits may be used for the payer (the verified
`responsibleParty`): it is the payer's, or its holder has authorized its use
on the payer's behalf. The adapter reports the party **for which** the rail
authenticates the use of the funding source — the account holder, or the
party that a mandate, a wallet delegation, or a network token issued for it
names, as the rail binds it — and never copies that party from the request,
the intent, or the Payment Authorization. The Executor refuses
(`payment_funding_authority_failed`) when the reported party is not the
authorization's `responsibleParty`. Possession of a credential alone is not
funding authority, and an approval does not substitute for it.

### 8.3 Lost submissions and recovery

A `submitted` attempt that no call holds is **lost** (section 6.1): its rail
call ended without a usable answer, such as a timeout or a lost response, or
the claim's lease ended, as after a crash before or during the call. The
attempt stays `submitted`, and the Executor does not know whether the rail
holds it. A held-back attempt (section 6.4), in whatever state the journal
holds it, counts as a lost submission for this section. The Executor MUST NOT
submit a lost submission again, and MUST NOT create another attempt for its
intent (section 5.2). It resolves a lost submission only by observing its
payment identity at the rail. When an observation records a state, the
Executor first records `submitted` if the journal holds the attempt
`authorized` (a held-back attempt, section 6.4), so that every recorded
transition is one Core §8.3 allows; an observation that records nothing writes
nothing, and a held-back attempt it leaves unresolved stays held back:

- When the rail answers with the submission's state, the Executor records it
  (section 8.4).
- When the rail answers that it holds no submission of the payment identity,
  that answer alone ends nothing, since the submission may still be in
  transit. Where the rail can close a payment identity, the Executor SHOULD
  then close it if the submission is lost, and MUST NOT close the payment
  identity of a submission that a call still holds. When the rail confirms
  that it closed the identity while holding no submission of it, the Executor
  records the attempt `failed`, with `payment_failed`, basis `close`, and
  `newIntentMaySucceed` `true` (Core §8.3).
- When an observation finds the submission and the rail reports that it
  failed it, the Executor records the attempt `failed`, with `payment_failed`,
  basis `tracked` (a submission the rail found or tracks), and
  `newIntentMaySucceed` as the rail result states (Core §8.3).
- Otherwise the Executor records nothing.

A failure the rail reports in its own answer to the submission (section 8.4)
names no basis, and no failure other than those above names one; the basis
`slot` belongs to the adapter profile. The Executor MUST observe every
`submitted` and `settlement_pending` attempt at least once per reconcile
interval while its rail can answer, and every held-back attempt (section 6.4)
likewise, and SHOULD state an interval of at most 300 seconds.

### 8.4 Recording outcomes

The Executor records an attempt's states, and appends its Payment Outcomes,
as follows (Core §8.3):

- `authorized` when it creates the attempt (step 14);
- `submitted` when it commits to send the submission, at step 16, before
  step 17's reading and the rail call, so that the record precedes any effect
  (Core §8.3: sent, or committed to be sent); a submission recorded but never
  sent ends as step 17 or section 8.3 states;
- `settlement_pending`, with the rail's `reconciliationRef`, when the rail
  reports that it holds the submission unsettled;
- `settled`, with the rail's `transactionRef` and the `effectAmount` the rail
  reported, when the rail reports the payment settled. When the adapter read
  the settlement before the rail's own final state, at a level the payee
  declared final in the Executor's configuration, the Executor records that
  level as `finality`;
- `failed` when the rail reports a terminal failure of the submission
  (`payment_failed`, without a basis, and with `newIntentMaySucceed` as the
  rail result states), when a lost submission is resolved as section 8.3
  states, or when section 7.3 or 7.4 fails the attempt; and
- a correction (`correction: true`, Core §8.3), when the rail's own answer to
  the submission contradicts a failure that named a basis by being `settled`,
  or `settlement_pending` when that basis is `close`.

An attempt that the rail settled for another amount than the effective
settlement amount keeps the rail's amount (Core §8.3); its answer carries
`effectAmountMismatch` (section 9.1). An evidence reference that the adapter
reports and that is not well-formed Unicode or that Core §9 does not admit is
omitted from the outcome's `evidence`; the attempt's answers then carry
`evidenceComplete: false` (section 9.1). Each observation's `updatedAt` is the
later of the recording instance's clock reading and its predecessor's
`updatedAt`, so that it never precedes it (Core §8.3) whatever the instances'
clocks.

## 9. Answers

Once a request is authenticated, the Executor MUST answer it with an MCP tool
result whose `resultType` is `complete` — unless it cannot produce an answer
proof at that moment, when it gives the error of section 9.5 instead — which
carries in its `_meta`, under `org.kya-os/payment-answer`, an answer proof
(section 9.5) for that request. The result carries its payment JSON in
`structuredContent`, and the same JSON as its one content block, of type
`text`, for clients that read only `content`: the block's `text` is a JSON
text whose value equals `structuredContent`. A client MUST reject a result
whose two copies differ as JSON values. The JSON Schema [JSON-SCHEMA] of a
result is `payment-answer.schema.json`, whose `$id` is
`https://schema.kya-os.org/experimental/payment-authority/2026-09-22/answer`.
A result that validates is an answer only once its answer proof verifies for
the request the client sent and its text block equals its `structuredContent`.
A payment tool's result carries no output of the tool's own; a payment tool
that declares an MCP `outputSchema` MUST declare one that admits every
`structuredContent` this section defines, and its `inputSchema` MUST admit the
`payment` argument (section 4.2).

### 9.1 Attempt result

A request that section 7 does not refuse ends at an attempt — the one it
created or claimed, or the one it found at step 9 or step 14 — and is
answered with `isError` absent or `false` and `structuredContent.payment`, the
attempt, with these members (a request that section 7 refuses gets a refusal,
section 9.2, which carries an attempt only as section 9.4 states):

| Member | Presence | Value |
| --- | --- | --- |
| `attemptId` | always | the attempt's id, at most 2,048 code points |
| `state` | always | `authorized`, `submitted`, `settlement_pending`, `settled`, or `failed` |
| `intentDigest` | always | the digest of the intent the attempt pays |
| `authorizationDigest` | always | the digest of the Payment Authorization that created the attempt |
| `rail` | when `settled` or `settlement_pending` | `transactionRef`, required when `settled` and optional when `settlement_pending`; `reconciliationRef`, present exactly when `settlement_pending`; each 1 to 2,048 code points |
| `effectAmount` | exactly when `settled` | the amount the rail reported as moved |
| `effectAmountMismatch` | only when `settled` | `true`, when `effectAmount` differs from the effective settlement amount |
| `correction` | only when `settled` or `settlement_pending` | `true`, when the state is a correction (Core §8.3) |
| `finality` | only when `settled` | the level of section 8.4, 1 to 64 characters of `A-Za-z0-9:._-`, the first a letter or digit |
| `reason` | exactly when `failed` | `{code, newIntentMaySucceed}`, as in the Payment Outcome (Core §8.3), without `basis` or `detailDigest` |
| `evidenceComplete` | always | `false` when the rail result is known but evidence the adapter reported for it was omitted (section 8.4) or could not be mapped to evidence references (Core §9), else `true` |

The attempt never carries a credential, a rail payload, or the journal's
internals.

### 9.2 Refusal result

A refusal of an authenticated request has `isError` `true` and
`structuredContent.paymentRefusal`, with these members:

- `reason`: a wire reason of Core §13 or section 11, other than those that
  only an error before authentication carries (the negotiation reasons of
  Core §11, `proof_missing`, `proof_invalid`, `proof_level_insufficient`, and
  `payment_artifact_invalid`), those that only an Evidence Consumer reports
  (`payment_state_transition_invalid` and `payment_outcome_stream_invalid`),
  and the outcome reasons that only a failed attempt carries in this document
  (`payment_failed` and `payment_authority_recheck_failed`);
- `retryable`: the Executor's advice on whether a repeat (section 10.1) can
  succeed. This rule is the only statement of a refusal's class in this
  document; another section that names a refusal's cause points here. The
  Executor SHOULD set it `true` exactly when the refusal's cause is one of
  these, each of which can change while the covered bytes stay the same:
  1. an **outage**: a service the Executor relies on — its journal, its nonce
     store, a key or DID-document resolution, a status list, its clock, its
     answer signer, an adapter, or the rail — gave no usable answer, or
     an observation the Executor awaits has not yet resolved an attempt
     (section 6.4);
  2. a **renewable bound** that has expired (section 6.2);
  3. a **start bound** the decision time has not reached: an intent's
     `createdAt` more than the skew after it, a request proof's `created`
     more than the request-proof skew after it (section 4.5), a delegation's
     `validFrom`, or a credential's or status list's proof `created` more
     than the skew after it (Core §7.1, §8.4.6);
  4. an **uncovered input**: the delegation carrier (section 4.3) — so a
     refusal of the chain at Core §8.4.6, step 1, before its match with
     `delegationDigest` has succeeded, a mismatch included, but not a refusal
     after it — the rail credential (section 4.4), whose refusals include
     `payment_credential_invalid`, `payment_funding_authority_failed`, and
     `payment_replay`, or rail terms the request carried that the intent does
     not bind by `quoteDigest`, among them the fees or the quote on which a
     re-evaluation rule failed (`intent.fees`, or `intent.quote` with a quote
     whose digest is not the intent's `quoteDigest`; a rule that fails on the
     quote whose digest is `quoteDigest` fails on covered bytes), or the
     request proof: a nonce already consumed, or a proof that does not verify,
     which a fresh request proof over the same covered bytes replaces (section
     4.5); or
  5. a **fault** of the Executor's or its Authority Verifier's own components
     or configuration (section 7.2, step 11; `payment_configuration_invalid`),
     a re-evaluation that cannot complete (section 7.4), or another call that
     held or changed the attempt (section 7.3, step 16).

  Every other refusal SHOULD be **definitive** (`retryable: false`), including
  one that rests on the Executor's own terms — which payees, tenants, rails,
  and extensions it serves, and the offer it makes (`payment_offer_mismatch`)
  — though a fault in its configuration of them is cause 5. A client acts on
  the advice as section 10.2 states; a refusal whose class is wrong costs the
  client time, never a second payment (section 10.3);
- `intentDigest`: the digest of the intent the request carries;
- `attemptRecorded`, as section 9.4 states;
- `attempt`: the intent's attempt, in the form of section 9.1, as section 9.4
  states; and
- `requireApproval`, exactly for `payment_approval_required`: the
  `requireApproval` member of the effective payment constraints (Core §8.4.2),
  so that the client can obtain approval that meets it.

`retryable` affects only when a client repeats; it never allows a client to
replace an intent (section 10.3). A refusal answer names no rule identifier
and no `hop`: the rule and `hop` that Core §8.4.6, steps 6 and 7, has a
refusal name are in the Authority Verifier's refusal, which the Executor does
not disclose in its answer.

### 9.3 Errors before authentication

A refusal at steps 1 to 6 (section 7.1) is a JSON-RPC error, and so is the
error of section 9.5 when no answer proof can be produced. A negotiation error
(`extension_not_declared`, `malformed_declaration`, or
`payment_profile_unsupported`, Core §11) carries the code and members Core §11
states, and no `retryable`. Any other carries the implementation's domain
error code (SPEC-MCP-EXTENSION §5.1) and `error.data` `{reason, retryable}`,
where `retryable` is set by the rule of section 9.2, applied to the error's
cause. These errors are not authenticated, carry no attempt information, and
say nothing about whether an attempt exists (section 10.1).

### 9.4 Who may read an attempt

`attemptRecorded` reports whether the journal holds an attempt for the
intent's digest. The Executor reads it after the request's processing ends,
and MUST include it in a refusal:

- when the intent names a `presenter` and the requester is that presenter
  (the request passed step 7); or
- when the intent names none and the Authority Verifier authorized the
  request at step 11.

It MUST omit it otherwise, and whenever it could not read the journal. It
MUST also omit both `attemptRecorded` and `attempt` from every refusal for an
intent that, when the Executor reads the journal for the answer, is under the
horizon or at or before the retention cutoff with no attempt recorded
(sections 6.4 and 6.5), or whose attempt is held back (section 6.4) —
whichever step refused the request — so that no answer reports "no attempt"
for an intent whose attempt the journal may have lost or deleted. The read
that decides `attemptRecorded`, and the horizon and cutoff it is judged
against, are one linearizable read of the journal (section 6.3). Absence
never means that no attempt exists.

The refusal MUST carry `attempt` when `attemptRecorded` is `true` and the
requester is the attempt's actor. An attempt result (section 9.1) is given
only to the request that created the attempt, to a repeat, and to a
resumption, whose requester is the attempt's actor.

For an intent that names a presenter, every request the Executor processes
past step 7 comes from the presenter, which is the actor of any attempt for
it; so the presenter learns whether its intent was attempted, and in what
state, whenever the journal can say: not for an intent the omissions above
cover.

### 9.5 Answer proof

The answer proof, `org.kya-os/payment-answer.v1`, is the Executor's signature
over one answer to one authenticated request. It is a compact JWS [RFC7515]:

- its three segments are unpadded base64url [RFC4648], each the one encoding
  of its bytes;
- its protected header is exactly `{alg, kid}`, optionally with `typ`
  `kya-payment-answer+jws`; `alg` is `EdDSA` (Ed25519, [RFC8037]) or `ES256`
  (its signature the 64-byte R‖S form of [RFC7518] §3.4); `kid` is the
  string `<iss>#<fragment>`: the value of `iss`, exactly one `#`, and a
  non-empty fragment, at most 2,048 code points in all, which this profile
  constrains no further and compares only as a string;
- its payload is well-formed UTF-8, and those bytes are exactly the RFC 8785
  serialization of an object with exactly these members:
  - `profile`: `org.kya-os/payment-answer.v1`;
  - `iss`: the Executor's DID, which is the intent's `audience`;
  - `aud`: the requester;
  - `requestDigest`: the request digest (Core §10), as a digest string in the
    lowercase form of Core §10;
  - `requestNonce`: the request proof's `nonce`, 1 to 512 code points;
  - `answerDigest`: the digest string, under domain
    `org.kya-os.payments.answer.v1` (Core §10), of the result without its
    top-level `_meta`; and
  - `iat`: the decision time in epoch seconds, rounded down, an integer from
    0 to 2^53 − 1;
- an ES256 signature has its `s` at most half the P-256 group order
  [SP800-186] (low-S); a signer whose `s` exceeds it MUST replace `s` with the
  order minus `s`; and
- the signature verifies under the verification method whose `id` is
  exactly `kid` (a relative `id` taken against `iss`), which the DID document
  of `iss`, resolved under the document-`id` rule of Core §8.2, lists in its
  `assertionMethod` relationship.

`iss` and `aud` are in DID syntax ([DID-CORE] §3.1): `did:`, a method name of
lowercase ASCII letters and digits, `:`, and a method-specific id of
`:`-separated segments of ASCII letters, digits, `.`, `-`, `_`, and
percent-encoded octets, whose last segment is not empty; each is at most 2,048
code points. A proof spelled any other way fails, so an intermediary cannot
re-spell one.

The Executor MUST sign answers only as the intent's `audience`, with a key
that DID's document lists under `assertionMethod`. Before it authenticates
requests, and again at least as often as it refreshes its own DID document,
it MUST check that an answer it signs verifies as a client verifies it, the
key's listing included; while that check fails it refuses at section 7.1,
step 5. An Executor that cannot produce a signature for one answer gives a
JSON-RPC error instead (`payment_configuration_invalid`), which
says nothing.

A client verifies an answer proof before it acts on the answer: first, from
the payload alone, that `iss` is the `audience` of the intent it sent, `aud`
its own DID, `requestDigest` and `requestNonce` those of the request it sent,
and `answerDigest` the digest it computes over the result it received, so
that a forged answer can make it resolve only the DID document of the intent's
`audience`, never a DID or URL that the forger chooses; then the header, the
payload bytes, the signature, and the key's listing, as above. An answer whose
proof fails any check, or whose keys cannot be resolved at that moment, is
unauthenticated. `iat` is informative; freshness comes from `requestNonce`,
which the Executor consumed once. The `profile` claim keeps an answer proof's
payload distinct from every other kind of JWT [RFC8725, §3.12], so a client
does not rely on `typ`; the Executor SHOULD still set it, as explicit typing
recommends [RFC8725, §3.11]. No `_meta` member is
covered (SPEC.md §7.6): the proof rides there beside members, such as trace
context, that intermediaries may add.

The base response proof (`org.kya-os/response-proof`, SPEC.md §7) names no
request instance: its request hash covers the call's content, which every
repeat of one request shares. An Executor MAY attach one too; clients of this
profile do not rely on it. `BASE-AMENDMENTS.md` item 6 proposes a
request-bound response proof for the base.

### 9.6 Example

*This example is informative.* The `answer-proof-valid` vector of Core's
corpus, whose header omits the optional `typ` (section 9.5), is a refusal
answered to requester `did:key:z6MkAgent`, whose request had digest
`sha256:3333…3333` and request-proof nonce
`n-0123456789abcdef0123456789abcdef`:

```json
{
  "resultType": "complete",
  "isError": true,
  "content": [{ "type": "text", "text": "<the structuredContent below, as JSON text>" }],
  "structuredContent": {
    "paymentRefusal": {
      "reason": "payment_constraint_denied",
      "retryable": false,
      "attemptRecorded": false,
      "intentDigest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
    }
  },
  "_meta": { "org.kya-os/payment-answer": "<compact JWS, 629 characters>" }
}
```

Its answer proof's protected header and payload decode to:

```json
{"alg":"EdDSA","kid":"did:web:merchant.example#answers"}
{"answerDigest":"sha256:887466be239c8fdcada90a973ff006376b03ea95261bd1e15b1012548db25df3","aud":"did:key:z6MkAgent","iat":1789952405,"iss":"did:web:merchant.example","profile":"org.kya-os/payment-answer.v1","requestDigest":"sha256:3333333333333333333333333333333333333333333333333333333333333333","requestNonce":"n-0123456789abcdef0123456789abcdef"}
```

The payload bytes are exactly that RFC 8785 serialization, `answerDigest` is
the answer-domain digest of the result without `_meta`, and the signature
verifies under the vector's `publicJwk`; the corpus carries the full result
and JWS.

## 10. Client rules

### 10.1 Verifying answers

A client acts only on **authenticated answers**: results whose answer proof
verifies for the request it sent (section 9.5), which meet section 9, their
text block equal to their `structuredContent`, and which name the intent it
sent (`intentDigest`, and the `intentDigest` of any attempt they carry).
Anything else — no response, an error before authentication, or a result that
is not an authenticated answer — **says nothing** about whether an attempt
exists.

An authenticated answer **shows an attempt** when it is an attempt result, or
a refusal that carries `attempt`. The client's **view** of an intent is the
furthest attempt state that an authenticated answer has shown it, in this
order: `authorized`, `submitted`, `settlement_pending`, `failed`, a
correction to `settlement_pending`, and `settled` (with or without a
correction). An answer that shows a later state than the view **advances**
it; one that shows an earlier state was overtaken in transit and does not
move the view.

To ask again, the client **repeats** its request: it sends the same `params`
without `_meta`, so the same covered bytes and the same binding, under a fresh
request proof. A repeat is never a replacement: it can only continue or report
the one attempt the intent may have.

### 10.2 Decisions

After each **event** for an intent — an authenticated answer, or a request
that got none — the client takes one **decision**:

| Decision | Meaning |
| --- | --- |
| `done` | The purchase is paid. |
| `repeat` | Repeat the request, at a reduced rate if the client chooses. |
| `obtain-approval` | Obtain approval evidence for `intentDigest` that meets `requireApproval`, and send the same intent under the same idempotency key with that evidence: new covered bytes under a key that no attempt binds (section 5.2, rule 1). An approval evidence format is the adapter profile's; a client with none for the requirement resolves with the payer. |
| `wait-then-repeat` | The request cannot succeed and the intent cannot be replaced yet: abandon the purchase, or repeat the request once at or after the intent's `expiresAt` plus the skew, whose answer decides again. |
| `may-replace` | The intent can no longer pay: abandon the purchase or replace the intent (section 10.3). |
| `resolve-with-payer` | The protocol cannot settle the purchase: the client sends the intent no more and resolves the purchase with the payer outside the protocol. |
| `replaced` | The client replaced the intent (section 10.3). |

Its **bound** is the intent's `expiresAt` plus the skew plus the reconcile
interval that the Executor's conformance claim states (section 13.3), or 300
seconds when the client does not know it. Times are read on the clock of the
client instance that takes the reading, which MUST NOT run backward. An
event's **sent time** MUST be a reading taken before the client first hands
the request it answers to the transport, and an answer's **receipt time** a
reading taken after the client received it. The client MUST decide as the
first row of this table that applies states, after moving its view by the
event:

| # | When | Decision |
| --- | --- | --- |
| 1 | The decision is `done` | `done` |
| 2 | The decision is `resolve-with-payer` | `done` if the event shows the attempt `settled` and the client did not replace the intent; else `resolve-with-payer` |
| 3 | The client replaced the intent | `resolve-with-payer` if the event advanced the view to `submitted`, `settlement_pending`, a correction, or `settled`; else `replaced` |
| 4 | The view is `settled` | `done` |
| 5 | The event shows the attempt `failed`, and the view is a correction to `settlement_pending` | `resolve-with-payer` |
| 6 | The event is a definitive `payment_journal_indeterminate` | `resolve-with-payer` |
| 7 | The event reports `attemptRecorded: true` and carries no `attempt` | `resolve-with-payer` |
| 8 | The event reports `attemptRecorded: false`, and its sent time is after the receipt time of the first answer that showed an attempt | `resolve-with-payer` |
| 9 | The view is `failed`, and the client read no correction | `may-replace` |
| 10 | The view is `settlement_pending` or a correction to it | `repeat` |
| 11 | The view is `authorized` or `submitted` | `resolve-with-payer` if the event's sent time is at or after the bound; else `repeat` |
| 12 | The intent names the client as its `presenter`, the event reports `attemptRecorded: false`, and its sent time is at or after the intent's `expiresAt` plus the skew | `may-replace` |
| 13 | The event's sent time is at or after the bound | `resolve-with-payer` |
| 14 | The event is `payment_approval_required` | `obtain-approval` |
| 15 | The event is a refusal with `retryable: true` | `repeat`, correcting the delegation carrier or the rail credential first when the reason concerns it |
| 16 | The event is a definitive refusal with `attemptRecorded: false`, for an intent that names the client as its `presenter` | `wait-then-repeat` |
| 17 | The event is a definitive refusal | `resolve-with-payer` |
| 18 | The event says nothing | `repeat` |

Rows 7 and 8 report an attempt the client cannot follow, or the loss of one it
followed: a request sent after the client received an answer showing the
attempt reached the Executor after the attempt's record was durable (section
6.3, item 1), so `attemptRecorded: false` in its answer means the Executor no
longer holds an attempt that may still move value. An answer to a request sent
earlier may predate the attempt, and rows 10 and 11 keep the decision the view
gives. When different client instances took the two readings, row 8 can
misjudge their order: it then decides `resolve-with-payer`, or leaves the
decision to rows 9 to 11, which the view already governs, so a misjudgment
never reaches `may-replace` through row 12. Row 11 ends the repeats of an
attempt that cannot resolve: a lost submission on a rail that cannot close a
payment identity (section 8.3). `settlement_pending` is the rail's to resolve:
row 10 precedes the bound of rows 11 and 13, so no bound ends its repeats; an
earlier row does.

### 10.3 Replacing an intent

A client MUST NOT create a new intent for a purchase while an intent it sent
for that purchase may still pay, and MUST NOT replace an intent unless its
decision for that intent is `may-replace`, which only two rows of the table
of section 10.2 decide:

- **(a)** the view is `failed` and the client read no correction (row 9): the
  attempt is final (Core §8.3), and the intent has no other (section 5.2,
  rule 2). `newIntentMaySucceed` says whether a replacement can succeed; it
  does not bear on safety; or
- **(b)** the intent names the client as its `presenter`, and an
  authenticated answer to a request the client sent at or after the intent's
  `expiresAt` plus the skew reports `attemptRecorded: false`, while the client
  has seen no attempt for the intent (row 12).

Case (b) rests on three Executor properties: an instance begins a rail call
for an intent only on a step-17 reading of its clock that it takes after the
call's `submitted` record and that is before the attempt's expiry, which is at
most the intent's `expiresAt` (section 7.3); that record is written, and
durable, before the reading (section 7.3, step 17), in a linearizable journal
(section 6.3, item 2); and the Executor reads `attemptRecorded` after it has
received and processed the request it answers (section 9.4). Let the request's
sent time be at least `expiresAt` plus the skew; the client hands the request
on at a later moment t (section 10.2). Its clock never runs backward, so it
reads at least that at t and at every later moment, and every Executor clock,
which differs from it by less than the skew, then reads after `expiresAt`: no
step-17 reading taken at or after t lets a rail call begin. A rail call that a
reading before t let begin, however late the call itself began, follows a
`submitted` record made before t, which the Executor's read, made after t,
observes. So an answer that reports no attempt shows that no reading before t
let a rail call begin, and no reading after t can. Executor clocks need not be
monotonic for this; the clock of the client instance that took the sent time
does need to be.

A shared intent (one that names no presenter) never reaches `may-replace` by
case (b): another agent may hold an attempt that this client cannot read
(section 9.4). Its client resolves the purchase with the party that
constructed the intent, which resolves it with the payer.

Once it replaces an intent, the client MUST NOT send that intent again, MUST
send the new intent under an idempotency key that no request for the replaced
intent used, since under case (a) that key is bound to the failed attempt and
draws `payment_idempotency_conflict` (section 5.2, rule 1), and MUST record
the replacement durably before it creates the new intent; its decision for the
replaced intent becomes `replaced`. Row 3 then reads every later answer about
the replaced intent: one that advances the view to a state in which value may
have moved means value may move for both intents. A failed attempt, or one
still `authorized`, cannot have moved value under case (b), whose guarantee
excludes a submission.

### 10.4 Client state

A client MUST persist an intent, the purchase it is for, and each request with
its sent time before it first hands that request to the transport, and MUST
persist, for each intent it sent: its view; the receipt time of the first
answer that showed an attempt; every request it sent for the intent, so that
it can repeat it, with its sent time; whether it read a correction; and each
decision, before it acts on that decision. Instances of a client that send
requests for one intent MUST share that state, read its latest version before
each decision, and record each decision, a replacement included, by a
compare-and-swap on the version they read, acting only on a decision whose
swap succeeded: of two instances that read one version, at most one acts, so
no instance reads an overtaken answer as new, sends an intent that another
instance replaced, or replaces an intent that another instance replaced. An
instance whose swap fails reads the latest version and decides again on the
event, so that no answer is dropped. A client that lost its state for an
intent MUST NOT replace that intent; it resolves the purchase with the payer.

### 10.5 What the rules guarantee

*This section is informative.*

A client that follows sections 10.1 to 10.4 never causes a second payment for
one purchase through its own requests, whatever an intermediary or an outage
does to its messages, provided that:

1. the clock of every instance of the client and of every instance of the
   Executor differ by less than the skew (Core §7.1), and no client instance's
   clock runs backward (section 10.2);
2. the Executor meets sections 4 to 9: it keeps one attempt per intent in a
   journal that meets section 6.3, applies section 6.4 after any loss of
   records and section 6.5 to every deletion, consumes each nonce once
   (section 4.5), begins a rail call only on a step-17 reading before the
   attempt's expiry, never submits a lost submission again (section 8.3), and
   reads `attemptRecorded` after processing;
3. its rail adapters meet section 8, and the rail deduplicates a payment by
   the payment identity the adapter reports, reports truthfully, and never
   contradicts its own report (so no correction arises, Core §8.3);
4. no party other than the Executor can redeem a rail credential that pays the
   intent at the rail: the client presents no other kind (section 4.4), and
   section 8.1, item 2, refuses one presented anyway; and
5. the client keeps its state as section 10.4 requires.

An intermediary that holds a copy of a request can send it again; the copy
carries a nonce the Executor already consumed, or, before then, is the one
request the Executor processes. It can withhold an answer, which says nothing,
so the client repeats; it can forge an answer, which fails the answer proof.
None of these yields an authenticated answer that case (a) or (b) reads unless
the Executor signed it for the client's own request.

## 11. Error reasons

This document assigns the reasons below, in addition to those of Core §13,
which keep their meanings. A refusal's class is set by its cause, by the rule
of section 9.2 alone.

| Wire reason | Meaning |
| --- | --- |
| `payment_idempotency_conflict` | The binding names an attempt recorded for another request digest, or the intent already has an attempt (section 5.2). |
| `payment_replay` | The payment identity is bound to another intent, or a resumption's payment identity differs from the attempt's (section 5.2, rule 4). |
| `payment_attempt_conflict` | The call's submission claim ended before it recorded `submitted` (section 7.3, step 16). |
| `payment_journal_unavailable` | The journal could not read or write (section 6.3). |
| `payment_journal_indeterminate` | The journal may have lost or deleted the intent's attempt (sections 6.4 and 6.5). |
| `payment_rail_unsupported` | No adapter serves the selection, or the intent signs `redeemableByOthers` and the Executor does not implement the adapter profile (sections 7.2 and 8.1). |
| `payment_offer_mismatch` | The Executor's offer does not match the intent's selection, amount, payee, or `quoteDigest` (section 8.1). |
| `payment_credential_invalid` | The rail adapter refused the rail credential, or it does not meet the terms the intent signs for it (section 8.1). |
| `payment_funding_authority_failed` | The funding source was not shown to be the payer's or authorized on its behalf (section 8.2). |
| `payment_authority_recheck_failed` | The re-evaluation of the final recheck failed (section 7.4). An outcome reason; it appears only in an attempt. |
| `payment_quote_expired` | The bound quote (fixed) or rail terms (renewable) expired (section 7.4). An outcome reason. |
| `payment_failed` | The rail reported a terminal failure, or a lost submission was resolved as failed (section 8.3). An outcome reason; it appears only in an attempt. |
| `payment_evidence_invalid` | A rail adapter reported malformed or conflicting evidence. |

`payment_artifact_unauthenticated` belongs to the adapter profile.

An outcome reason (Core §8.3) is the `reason.code` of a failed attempt; every
failure this document records carries one of them.

## 12. Security and privacy considerations

1. **Replay.** A copy of a request carries a consumed nonce and is refused
   before authentication, or is the only copy the Executor processes
   (section 4.5). A copy cannot be answered as another request: the answer
   proof names the request's digest and nonce.
2. **Uncovered inputs.** The delegation carrier and the rail credential are
   not covered by the request proof. An intermediary that changes them causes
   a refusal or a payment on the terms the intent signs, never another: the
   chain has to match `delegationDigest`, and a rail credential pays only on
   the terms the intent signs for it (section 8.1, item 2), only from a
   funding source bound to the payer (section 8.2), and only under the
   intent's payment identity (section 5.2, rule 4). A client presents no rail
   credential that another party can redeem (section 4.4), so an intermediary
   that copies one has nothing it can pay with.
3. **Answer forgery.** A client acts only on answers whose proof names its own
   request and verifies under a key of the intent's `audience` (section
   10.1). Anyone who relayed the request can compute the binding, so a forged
   answer can make the client resolve that one DID document, never a DID or
   URL that the forger chooses (section 9.5).
4. **Key resolution.** Every DID resolution the Executor and the client rely
   on returns keys only from a DID document whose `id` is exactly the DID
   resolved (Core §8.2).
5. **Journal integrity.** The journal is the record of which intents were
   attempted. Its loss is handled by section 6.4; its corruption is outside
   this document, and a deployment protects it as it protects funds.
6. **Disclosure.** An answer carries no credential, rail payload, or journal
   internals (section 9.1). A requester that section 9.4 does not admit for an
   attempt reads no `attemptRecorded` and no `attempt`. It can still learn
   something from a reason: for an intent under a horizon or at or before the
   retention cutoff, step 9 refuses before the Authority Verifier admits
   anyone (sections 6.4 and 6.5), so whether the request is refused there or
   goes on to a later step shows whether the journal holds an attempt. Only a
   party that holds the intent can ask. The Executor's errors and answers MUST
   NOT echo credentials, policy secrets, or rail payloads.
7. **Denial of service.** Every check works on bounded input: the request
   message, `_meta` included, is refused above 2 MiB or 64 levels of nesting
   before it is parsed (section 4.2), and Core §8.4.6, step 1, bounds the
   chain before any credential, DID, or status work. A client that floods repeats
   holds no claim it does not already hold; claims end at their lease end.
8. **Clocks.** Case (b) of section 10.3 relies on the clock assumption of
   Core §7.1. A client whose clock runs ahead of an Executor instance's by
   the skew or more can reach case (b) too early; a deployment that cannot
   bound its clocks relies on case (a) alone.

## 13. Conformance

### 13.1 Executor

An Executor conforms when it meets sections 4 to 9 and 11 and section 12,
item 6, and passes these test groups:

1. **Request:** refusal of each payment-argument defect of section 4.2,
   including a duplicate member name and a lone surrogate anywhere in the
   request text, `_meta` included; a delegation carrier that does not match
   `delegationDigest`; each profile rule of section 4.5; and the order of
   section 7.1.
2. **Scope:** derivation of the scope for the `scopes` vectors, and refusal of
   each bound.
3. **Idempotency:** the outcomes of steps 9 and 14 for the `idempotency`
   vectors; a repeat of a final attempt answered after its delegation was
   revoked and after its intent expired; two concurrent first requests with
   one binding, of which exactly one creates the attempt; and two concurrent
   first requests for one intent under two bindings, and for one payment
   identity under two intents, of which at most one creates an attempt.
4. **Expiry:** the outcomes of section 7.4 for the `expiry` vectors.
5. **Rail terms:** each refusal of section 8.1 and its reason, among them a
   credential that does not meet the terms the intent signs and an amount the
   rail's units cannot represent exactly.
6. **Submission:** no rail call begun on a step-17 reading at or after an
   attempt's expiry; no second submission of a lost submission; a lost
   submission resolved by observation only; and each recorded state of section
   8.4.
7. **Recovery and retention:** after a simulated restore and after a
   deletion, the refusals and the held-back attempts of sections 6.4 and 6.5
   for the `quarantine` vectors, and the end of holding back once an
   observation resolves an attempt.
8. **Disclosure:** no answer, error, or log entry it produces carries a rail
   credential, a policy secret, or a rail payload (section 12, item 6).
9. **Authority facts**, the Authority Verifier tests of Core §15 that need
   request binding, which this document runs as Executor tests since only an
   Executor binds a request: facts that name another request digest,
   holder-proof digest, intent, or idempotency binding, facts that record an
   approval the request presented no evidence for, and facts the Executor
   cannot read, each refused as section 7.2, step 11, states; and an intent
   whose `audience` the Executor does not answer for, refused at section 7.1,
   step 4.
10. **Answers:** each answer it gives validates against
    `payment-answer.schema.json` and meets the rules of section 9 that the
    `answers` vectors exercise; its answer proofs verify by section 9.5; and
    `attemptRecorded` and `attempt` are given exactly as section 9.4 states.

### 13.2 Client

A client conforms when it builds its requests as sections 4.2 to 4.5 state,
logs no rail credential (section 4.4), verifies answers as sections 9 and 9.5
state, meets section 10, and passes these test groups:

1. **Answers:** it accepts exactly the answers the `answerProofs` vectors mark
   as verifying, accepts exactly the `answers` vectors marked valid, and
   rejects a result whose text block differs from its `structuredContent`.
2. **Decisions:** its decision after each event of each `client` vector.
3. **State:** it persists its decisions before acting on them, refuses to
   replace an intent whose state it lost, and, run as two instances that
   decide on one version of the state at once, acts on at most one decision.

### 13.3 Vector corpus

`vectors/payment-execution-vectors.json` is the execution vector corpus. Its
format follows Core §15.1.1, except that a `code` may also be a reason of
section 11 or of section 7.1, step 6: `corpus`, `specification`,
`corpusDomain` (the vector-corpus domain of Core §10), `corpusDigest`, and
`vectors`, one array per set. An implementation reproduces a vector when it
computes, from the vector's input members, exactly its expected members,
compared as JSON values, with one exception: a vector's `retryable` gives the
class that section 9.2 recommends (a SHOULD), so an implementation that
departs from that recommendation still reproduces the vector if every other
member matches. The sets are:

- `arguments` (the Executor): `name`; `text`, the JSON text of a complete
  `tools/call` request message for tool `checkout.complete`, some with a
  `_meta`; and `expect`, `{"valid": true}` or `{"valid": false, "code":
  <the upper-snake reason>}`, the result of section 4.2;
- `scopes` (the Executor): `name`; `tenant`, a configured tenant, which is
  within its bounds (section 5.1); `caller`; and `toolName`; and `expect`,
  `{"scope": <string>}` or `{"valid": false, "code": <the upper-snake
  reason>}`, the result of sections 4.1 and 5.1;
- `idempotency` (the Executor): `name`; `journal`, the attempts the journal
  holds, each with `scope`, `key`, `requestDigest`, `intentDigest`, `state`,
  `claimed`, and `paymentIdentity`; `request`, with `scope`, `key`,
  `requestDigest`, `intentDigest`, and the `paymentIdentity` the adapter
  reports; and `expect`, the outcome of steps 9 and 14 for a request that
  passes steps 10 to 13: `answer` (step 9 answers the recorded attempt),
  `claim` (a resumption claims it), `create` (a first request creates an
  attempt), or the code of the refusal;
- `expiry` (the Executor), for a first request, whose refusals before a claim
  fail no attempt (section 7.4): `name`; `phase`, `decision` (steps 6 to 12),
  `reevaluation` (step 13), `claim` (step 15), or `call` (step 17); `now`, the
  clock reading; `fixed`, the fixed bounds by name (`intentExpiresAt`, and any
  of `delegationExpiresAt`, `approvalExpiresAt`, `caveatExpiresAt`, and
  `quoteExpiresAt`); `renewable`, the renewable bounds by name
  (`requestProofExpires`, in epoch milliseconds, and optionally
  `railTermsExpiresAt` and `statusFreshUntil`, the status freshness that the
  last status read established, which in the `claim` phase a walk whose
  `status` is `live` or `revoked` renews); `status`, the result of the status
  walk at that reading, which also decides status freshness (`live`,
  `revoked`, `unavailable`, `not-live`, or, for a claim, `incomplete`), which
  only the `decision` and `claim` phases read; `reevaluation`, `pass`, `fail`,
  or `incomplete` (a re-evaluation that cannot complete), and, for a failure
  at step 13, `failedOn`, what the failing rule failed on (`fees`,
  `unbound-quote`, or `bound-quote`, section 9.2, cause 4); and `expect`:
  `{"action": "proceed"}`, or the `action` (`refuse`, `fail`, or `release`)
  with its `code` and, except for `fail`, `retryable`, the result of section
  7.4 (for `call`, of step 17, which reads only the bounds);
- `quarantine` (the Executor): `name`; `horizon`, or `null` when no loss set
  one; `retentionCutoff`, or `null` when nothing was deleted;
  `intentCreatedAt` and `intentExpiresAt`; `attempt`, the journal's attempt
  for the intent or `null`, with its `state` and `writtenUnderHorizon`
  (whether its latest write carries the horizon in force); and `expect`,
  `{"action": "proceed"}` or the refusal of section 6.4 or 6.5, `{"action":
  "refuse", "code": "PAYMENT_JOURNAL_INDETERMINATE", "retryable": <boolean>}`,
  each with `reportsAttempt`, whether a refusal of the request at any step may
  carry `attemptRecorded` (section 9.4);
- `answers` (the client and the Executor): `name`; `result`, an MCP result;
  and `expect`, `{"valid": <boolean>}`, whether the result is a well-formed
  answer by section 9 apart from its proof: the schema, the presence rules of
  sections 9.1 and 9.2, and the text block equal to `structuredContent`;
- `client` (the client): `name`; `intent`, with `presenter` (`true` when it
  names the client) and `expiresAt`; `reconcileInterval`; and `events`, in
  the order the client received them, each with its expected `decision`
  (section 10.2). An event is an authenticated answer (`kind` `payment` or
  `refusal`, with `sentAt`, `receivedAt`, and the answer's `payment` or
  `paymentRefusal` member), a request that got no authenticated answer
  (`kind` `none`, with `sentAt`), or the client's replacement of the intent
  (`kind` `replace`, taken only when the decision before it is
  `may-replace`).

The `answerProofs` set and the two answer vectors of `artifactDigests` are in
Core's corpus (Core §15.1), where Core carries them for this document. An
`answerProofs` vector has `name`; `publicJwk`, the key that `kid` names;
`executor`, the DID the client addressed; `binding`, the `requester`,
`requestDigest`, and `requestNonce` of the request the client sent;
`result`, the MCP result received; and the expected `verifies`, whether the
answer proof verifies by section 9.5 with `publicJwk` taken as the key the
Executor's DID document lists under `assertionMethod`. The two answer vectors
of `artifactDigests` carry `result` and the `answerDigest` input, the result
without its top-level `_meta`.

`vectors/verify_execution_vectors.py`, a standard-library-only Python
verifier, reproduces every vector of this corpus from this document's rules
and checks the `answerProofs` vectors of Core's corpus, and reports `OK: <n>
execution checks and <m> answer-proof checks of the Core corpus reproduced by
the Python verifier (corpus <digest>)`, the digest being this corpus's.
`vectors/execution-schemas.test.ts` checks that the two schemas admit every
valid `arguments` and `answers` input and refuse each invalid one that the
schemas can decide. An Execution-tier conformance claim names the digests of
both corpora and its role; an Executor's claim also names its reconcile
interval (section 8.3), how long it keeps final attempts after their intent's
expiry (section 6.5), and whether its journal is ever restored (section
6.4).

## Open Working Group decisions

1. Whether case (b) of section 10.3 should also accept an answer to a request
   sent once every earlier request proof for the intent has expired, rather
   than the intent itself, which shortens the wait for long-lived intents.
2. Whether a payer, not only the requester, may read an attempt (evidence
   retrieval), and how.
3. Two-phase execution (authorize, then capture), which would add `phase`
   values.
4. Whether a shared intent may be replaced on answers from every agent that
   may present it.
5. Whether the reconcile interval should have a protocol maximum rather than a
   recommended one.
6. Registration of the reasons of section 11 beside those of Core §13.
7. Whether the base specifications should adopt `BASE-AMENDMENTS.md` items 6
   to 8, which this document proposes.

## References

### Normative references

- [Core] KYA-OS Payment Authority Profile: Core Authority,
  `SPEC-PAYMENT-AUTHORITY.md` in this folder.
- [SPEC.md], [SPEC-ENTITY-CARD], [SPEC-MCP-EXTENSION] — the KYA-OS base
  specifications in this repository.
- [RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement
  Levels", BCP 14, RFC 2119.
- [RFC8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key
  Words", BCP 14, RFC 8174.
- [RFC4648] Josefsson, S., "The Base16, Base32, and Base64 Data Encodings",
  RFC 4648.
- [RFC7515] Jones, M., Bradley, J., and N. Sakimura, "JSON Web Signature
  (JWS)", RFC 7515.
- [RFC7518] Jones, M., "JSON Web Algorithms (JWA)", RFC 7518 (ES256, §3.4).
- [RFC8037] Liusvaara, I., "CFRG Elliptic Curve Diffie-Hellman (ECDH) and
  Signatures in JSON Object Signing and Encryption (JOSE)", RFC 8037 (EdDSA).
- [SP800-186] NIST, "Recommendations for Discrete Logarithm-based
  Cryptography: Elliptic Curve Domain Parameters", SP 800-186 (the P-256
  group order).
- [MCP] Model Context Protocol specification, version 2026-07-28 (`tools/call`
  and its result).
- [RFC8785] Rundgren, A., Jordan, B., and S. Erdtman, "JSON Canonicalization
  Scheme (JCS)", RFC 8785.
- [DID-CORE] W3C, "Decentralized Identifiers (DIDs) v1.0".
- [RFC8259] Bray, T., Ed., "The JavaScript Object Notation (JSON) Data
  Interchange Format", STD 90, RFC 8259.
- [JSON-RPC] JSON-RPC Working Group, "JSON-RPC 2.0 Specification".
- [JSON-SCHEMA] Wright, A., et al., "JSON Schema: A Media Type for Describing
  JSON Documents", draft 2020-12.

### Informative references

- [BASE-AMENDMENTS] `BASE-AMENDMENTS.md`, proposed amendments to the KYA-OS
  base that this profile depends on, in this directory.
- [RFC8725] Sheffer, Y., Hardt, D., and M. Jones, "JSON Web Token Best Current
  Practices", BCP 225, RFC 8725.

## Appendix A. Member index

### A.1 Payment argument (`payment-argument.schema.json`)

| Member | Required | Type | Constraints |
| --- | --- | --- | --- |
| `profile` | yes | string | const `org.kya-os/payments.v1` |
| `idempotencyKey` | yes | string | 1 to 256 code points; no CR, LF, or U+0000 |
| `intent` | yes | Payment Intent | Core Appendix A.1 |
| `delegationDigest` | yes | string | `^sha256:[a-f0-9]{64}$` |
| `approvalEvidence` | no | object | exactly `type`, `format`, `value` |
| `approvalEvidence.type` | yes | string | 1 to 2,048 code points; no CR or LF |
| `approvalEvidence.format` | yes | string | 1 to 256 code points; no CR or LF |
| `approvalEvidence.value` | yes | string | at least 1 code point; at most 65,536 UTF-8 bytes (the Executor's check) |

### A.2 Answer (`payment-answer.schema.json`)

| Member | Required | Type | Constraints |
| --- | --- | --- | --- |
| `resultType` | yes | string | const `complete` |
| `isError` | no | boolean | `true` exactly for a refusal |
| `content` | yes | array | exactly one `{type: "text", text}` |
| `structuredContent` | yes | object | exactly one of `payment` (A.2.1) or `paymentRefusal` (A.2.2) |
| `_meta` | yes | object | `org.kya-os/payment-answer`: a compact JWS; other members admitted |

#### A.2.1 Attempt

| Member | Required | Type | Constraints |
| --- | --- | --- | --- |
| `attemptId` | yes | string | 1 to 2,048 code points |
| `state` | yes | string | one of `authorized`, `submitted`, `settlement_pending`, `settled`, `failed` |
| `intentDigest` | yes | string | digest |
| `authorizationDigest` | yes | string | digest |
| `rail` | no | object | `transactionRef`, `reconciliationRef`, each 1 to 2,048 code points; at least one |
| `effectAmount` | no | amount | Core §7; required exactly when `settled` |
| `effectAmountMismatch` | no | boolean | const `true`; only when `settled` |
| `correction` | no | boolean | const `true`; only when `settled` or `settlement_pending` |
| `finality` | no | string | `^[A-Za-z0-9][A-Za-z0-9:._-]{0,63}$`; only when `settled` |
| `reason` | no | object | `code` (an outcome reason, Core §8.3), `newIntentMaySucceed`; required exactly when `failed` |
| `evidenceComplete` | yes | boolean | |

#### A.2.2 Refusal

| Member | Required | Type | Constraints |
| --- | --- | --- | --- |
| `reason` | yes | string | one of the wire reasons section 9.2 admits |
| `retryable` | yes | boolean | |
| `intentDigest` | yes | string | digest |
| `attemptRecorded` | no | boolean | |
| `attempt` | no | object | A.2.1; only with `attemptRecorded` `true` |
| `requireApproval` | no | object | Core's `requireApproval`; exactly when `reason` is `payment_approval_required` |
