# Proposed base amendments for the Payment Authority Profile

**Status:** proposal to the Working Group. Nothing here is part of a ratified
specification. SPEC.md, SPEC-ENTITY-CARD.md, SPEC-MCP-EXTENSION.md, their
schemas, and the conformance suite are unchanged until the Working Group adopts
an item. Each item names the profile section that depends on it and what holds
until adoption. "Profile §n" is a section of this folder's
[`SPEC-PAYMENT-AUTHORITY.md`](./SPEC-PAYMENT-AUTHORITY.md) (Core Authority);
"Execution §n" is a section of its
[`SPEC-PAYMENT-EXECUTION.md`](./SPEC-PAYMENT-EXECUTION.md); "SPEC.md §n" is a
section of the base specification.

Items 6 to 8, on request binding, nonce retention, and the request-proof
nonce, accompany the execution document.

## 1. Profile-defined caveat narrowing (SPEC.md §6.10)

**Current text.** "an unknown caveat type MUST be replicated **verbatim**".

**Proposed text.** "A caveat type the verifier does not implement MUST be
replicated verbatim. A verifier that implements a profile defining a narrowing
relation for a caveat type applies that relation instead. A profile can never
redefine a built-in type (`MaxAmount`, `ValidUntil`), and a relation that fails
or throws rejects the hop. A verifier that implements no such profile behaves
exactly as before."

**Effect.** None on existing verifiers or vectors. A verifier would expose the
relation as an additive option of its chain-verification context; the base
code in this repository is unchanged by this proposal.

**Profile dependency.** Profile §8.4.3. Until adoption, a payment
chain whose caveat narrows verifies only at profile-aware verifiers, and the
profile recommends payment-only chains so verifiers of other actions are
unaffected (Profile §2).

## 2. The root issuer of a payment chain (SPEC.md §6.10, `schemas/card-delegation-credential.json`)

**Current text.** SPEC.md §6.10 requires the root `issuer` to equal the resource
owner *when a resource owner is asserted*. The schema states it without that
condition in two places: the top-level `description` says "the ROOT's
parentCapability equals its invocationTarget with issuer/invocationTarget = the
resource owner / resource", and the `issuer` property's description reads "For
the ROOT credential this is the resource owner and the recomputed
responsibleParty."
The same top-level `description` also lists "depth <= 10" among the chain
rules, whereas SPEC.md §6.10 sets no limit on chain length and leaves a cap to
verifier policy.

**Proposed text.** Top-level `description`: "…and the ROOT's parentCapability
equals its invocationTarget (the resource); when a resource owner is asserted,
the ROOT's issuer is that owner." `issuer` description: "For the ROOT
credential this is the accountable party and the recomputed responsibleParty:
the resource owner when a resource owner is asserted, or the payer under a
profile that roots chains at the payer."
The top-level `description` also drops "depth <= 10" from its list of chain
rules.

**Effect.** Descriptions only; SPEC.md §6.10 already makes the resource-owner
check conditional, and a payment verifier asserts the resource, never a
resource owner (Profile §8.4.6, step 8, and Profile §14, item 29). A
chain-length cap stays verifier policy; the payment profile's ten-credential
limit (Profile §8.4) is such a policy.

**Profile dependency.** Profile §4.1 and §8.1, which describe the root issuer
as the payer; the Payment Authorization's `responsibleParty` (Profile §8.2);
and the scope of a payment chain (Execution §4.3). Until adoption, the schema
description and the profile describe the root issuer differently; the
normative SPEC.md rule is consistent with both.

## 3. Per-hop audience for VC 2.0 + ZCAP chains (SPEC.md §11.6; SPEC-ENTITY-CARD §10, §12.3)

**Current text.** SPEC.md §11.6, invariant 2: "Non-root credentials in a
delegation chain MUST carry an `audience` constraint binding them to a specific
verifying server. This default is `true` as of v1.3.x; opt-out is available
with a one-time per-process warning for legacy integrations."
SPEC-ENTITY-CARD §10: "The rest of that chapter and the core delegation rules,
including the per-hop `audience` constraint on re-delegation (SPEC.md §11.6),
apply unchanged." SPEC-ENTITY-CARD §12.3: "For re-delegated credentials, the
core protocol's per-hop `audience` constraint (SPEC.md §11.6) applies unchanged
alongside this profile." The card delegation credential shape (SPEC.md §6.10)
has no audience member.

**Proposed clarification.** "For a VC 2.0 + ZCAP chain, the constant
`invocationTarget` of every hop, which the verifying resource asserts as its
own protected resource (SPEC.md §6.10), is the audience binding §11.6 requires."

**Profile dependency.** Profile §2; Profile §8.4.6, step 8, which applies
the base chain rules, this one among them, to every multi-hop payment chain;
and Execution §4.3, which binds a payment chain to one Executor by that
reading. Until adoption this reading is
the profile's own. A deployment that
wants an explicit per-hop member can define one as a caveat type and register
its evaluator (Profile §8.4.5).

## 4. `_meta` key registrations (SPEC-ENTITY-CARD §14.1)

SPEC-MCP-EXTENSION §2.2 names SPEC-ENTITY-CARD §14.1 as the registry of
`org.kya-os/*` `_meta` keys. Proposed rows:

| Key | Carries | Section |
| --- | --- | --- |
| `org.kya-os/payment-authority` | On a `tools/list` entry, `{"required": true}`. The same identifier names the MCP extension in `capabilities.extensions` and in the client capabilities a request declares; those are extension identifiers, not `_meta` keys | Profile §11, §11.1 |
| `org.kya-os/delegation-credentials` | The delegation credentials a payment request presents, root first, selected by the proof-covered `delegationDigest` | Profile §11.1; Execution §4.3 |
| `org.kya-os/payment-answer` | On a payment tool result: the Executor's answer proof, a compact JWS naming the request it answers (requester, request digest, request-proof nonce) over the result without `_meta` | Profile §11.1; Execution §9.5 |

**Profile dependency.** Profile §11.1. Until adoption the keys are
profile-defined and listed only there.

The answer proof is the profile's own statement; it asks nothing of the base
response proof (`org.kya-os/response-proof`), which stays as the base defines it.
Like every `_meta` member it is outside any signature's coverage (SPEC.md §7.6).

## 5. Status-read context and time-bounded lists (SPEC.md §6.10 Revocation)

**Current text.** "Each verdict also reports `fresh` - `true` only when read
from a live, in-validity-window (`validFrom`/`validUntil`, or
`issuanceDate`/`expirationDate`) status list." The text does not say whether the
window's end is inclusive, and the revocation seam receives only the status
entry.

**Proposed text.** "A revocation checker MAY receive the listed credential's
issuer, the issuers of the credentials nearer the root of its chain (the
parties §6.5.1 lets revoke it), and the caller's decision clock. Its optional
authenticity seam receives them, so it can require the list's issuer to be one
of those parties, or a list issuer that the deployment's configuration
designates for the credentials of that credential's issuer. In its optional
time-bounded mode a list is fresh only while it declares an end (`validUntil`,
`expirationDate`, or the Bitstring Status List `ttl` of its
`credentialSubject`), every timestamp bound it declares (`validFrom`,
`validUntil`, `issuanceDate`, `expirationDate`) parses as strict RFC 3339 with
an offset, a `ttl` it declares is an integer from 1 through 2^53 − 1 and the
list declares a start, every end it declares is after the decision clock, and
every start it declares (`validFrom`, `issuanceDate`) is at or before it. A
`ttl` is in milliseconds, and its end is `validFrom`, else `issuanceDate`,
plus `ttl`. A validity window's end is exclusive."

**Effect.** Additive, except for the exclusive end. A designated list issuer
holds revocation authority that SPEC.md §6.5.1 does not grant in v1.0, since
it defers delegated revocation authority to v1.1; the deployment's
configuration grants it, and a deployment that designates none is unaffected.
Today the base checker treats a list read at the instant of its `validUntil`
as fresh; adopting this item makes that one instant stale for every caller. No
conformance vector covers that instant, and the conformance suite hash would
be unchanged. A verifier
would take the context and the time-bounded mode as optional parameters of its
revocation checker.

**Profile dependency.** Profile §7.1 and Profile §14, item 19. The profile's
timestamp grammar (Profile §7.1) is narrower than strict RFC 3339: a fraction
has at most three digits, and leap seconds and instants before the Unix epoch
are refused.
A payment verifier therefore treats as stale a list whose timestamp bound the
proposed text would parse but that grammar refuses.

## 6. A request-bound response proof for stateless requests (SPEC.md §7; SPEC-ENTITY-CARD §8)

**Current text.** SPEC-ENTITY-CARD §8.1: "Two orthogonal proof profiles may
appear on one server, each under its OWN `_meta` key: the **legacy
session-bound** `ProofMeta` (carrying `sessionId` + a handshake nonce; retained
untouched for 1.x back-compat) under `_meta["org.kya-os/response-proof"]`".
The response proof names no request instance: its request hash covers the
call's content, which every repeat of one request shares, so a response proof
for one answer also verifies as the answer to any repeat.

**Proposed addition.** "A server that answers a request authenticated by a
self-contained request proof MAY attach, under
`_meta["org.kya-os/request-response-proof"]`, a response proof bound to that
request instance: a compact JWS by a key the server's DID lists under
`assertionMethod`, over the RFC 8785 serialization of `{iss, aud, requestHash,
requestNonce, responseHash, iat}`, where `aud` is the request proof's `did`,
`requestHash` and `requestNonce` are that proof's, and `responseHash` covers
the response with its top-level `_meta` removed (SPEC.md §7.6)."

**Effect.** Additive: it adds one `_meta` key, and no existing verifier,
vector, or `_meta` key changes; `org.kya-os/response-proof` keeps its
`ProofMeta` object.

**Execution dependency.** None. Until adoption, the answer proof of Execution
§9.5 is the only request-bound proof a payment client relies on, and the base
response proof is unchanged. Execution §9.5 defines the answer proof on its
own terms; if the base adopts a request-bound response proof, a later revision
can define the answer proof as a profile of it.

## 7. Nonce retention and the order of the replay check (SPEC-ENTITY-CARD §11.2, §12.2)

**Current text.** SPEC-ENTITY-CARD §11.2 fixes the order of verification: step
8, "**Replay** - `nonce` unseen for `did`, else `nonce_replayed`", comes before
step 9, "Detached JWS verifies over the recomputed covered claims (§8.4), else
`invalid_signature`". §12.2 requires a nonce store that is consumed atomically,
but not how long it keeps a nonce.

**Proposed text.** "A Verifier keeps a consumed nonce at least until no proof
carrying it can be accepted any more: until the proof's `expires` plus the
largest request-proof skew of any Verifier that shares the nonce store, plus
one second, since verification compares whole epoch seconds. It
consumes a nonce only after the signature verifies (steps 8 and 9 swap), so a
party that has only seen a proof cannot spend its nonce with a forged
request."

**Effect.** The first sentence is additive. The second changes which reason a
request with both a replayed nonce and an invalid signature reports; the
Working Group would re-check the conformance vectors for that case before
adopting it. The reference base verifier already behaves so: its
`verifyCardProof` (`src/card/proof/verify.ts`) checks every binding, the
signature included, before it consumes the nonce, and passes the nonce store a
retention floor derived from the proof's `expires`, the skew, and one more
second (`src/providers/nonce-retention.ts`). No conformance vector covers the
reordered case.

**Execution dependency.** Execution §4.5 requires the retention of the first
sentence of every payment Executor. It does not need the second. Until
adoption, a payment Executor keeps that retention under Execution §4.5, and
other verifiers keep the base rule.

## 8. The request-proof nonce is base64url (SPEC-ENTITY-CARD §8.2)

**Current text.** SPEC-ENTITY-CARD §8.2 gives the proof object's nonce as
`"nonce": "<128-bit, client-random or server-issued>"`, with no encoding. The
reference base verifier requires it to be base64url (RFC 4648 §5, unpadded):
its `CardProofMetaSchema` (`src/card/proof/types.ts`) refuses any other nonce
as a malformed proof, because the nonce is embedded verbatim in the
line-oriented RFC 9421 signature base of §8.5, where a line break or other
byte would corrupt it.

**Proposed text.** "`nonce`: a 128-bit value written with only the characters
of the RFC 4648 §5 base64url alphabet, unpadded and not empty; a Verifier
refuses a proof whose nonce has any other character."

**Effect.** Additive for proofs the reference already builds and accepts: it
states the character set the reference base verifier enforces, which admits a
base64url or a hexadecimal nonce, and does not change the base's 128-bit size.
An implementation written from the text alone could today send a nonce the
reference refuses.

**Execution dependency.** Execution §4.5 bounds the nonce an answer proof
names to 512 code points, which this item does not change. Until adoption a
client that follows the text alone may be refused by a verifier that applies
the reference base's rule.
