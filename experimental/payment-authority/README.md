# Payment Authority Profile

Experimental Working Group discussion draft of `org.kya-os/payments.v1`: the
artifacts that bind an agent's delegated authority to one exact payment, built
on the base specification ([`SPEC.md`](../../SPEC.md)). Nothing here is
ratified, published, or deployed at its identifier URL.

The profile has two documents so far:

- [`SPEC-PAYMENT-AUTHORITY.md`](./SPEC-PAYMENT-AUTHORITY.md), **Core
  Authority**: the payment intent, the authorization, the constraints caveat
  and the outcome, with their digests, money, identifiers, evidence
  references, artifact validation and extension negotiation. Its Appendix A
  indexes every member its schemas admit.
- [`SPEC-PAYMENT-EXECUTION.md`](./SPEC-PAYMENT-EXECUTION.md), **Execution**:
  the payment request and its binding to the request proof, idempotency,
  attempts and the journal, the Executor's processing algorithm, the
  rail-adapter contract and lost submissions, the signed answers, and the
  client's rules for repeating a request or replacing an intent.

Concrete rail mappings such as x402, rail credentials that others can redeem,
approval evidence formats, the envelopes that carry an artifact across a trust
boundary, and the Interop mappings belong to a third document in preparation,
which the execution document calls the adapter profile.

| Path | Purpose |
| --- | --- |
| `SPEC-PAYMENT-AUTHORITY.md` | The Core Authority specification |
| `SPEC-PAYMENT-EXECUTION.md` | The execution specification |
| `BASE-AMENDMENTS.md` | The amendments to the base specifications this draft proposes; none is part of a ratified text |
| `payment-intent.schema.json` | The exact economic terms of one payment, covered by the request proof |
| `payment-authorization.schema.json` | The Executor's verified authority for one attempt of that intent |
| `payment-constraints.schema.json` | The payment caveat a delegation carries, attenuated root to leaf |
| `payment-outcome.schema.json` | The result of an attempt, with the rail evidence it rests on |
| `payment-extension-settings.schema.json` | The MCP extension's negotiation settings |
| `payment-argument.schema.json` | The payment argument a payment request carries |
| `payment-answer.schema.json` | The Executor's answer to an authenticated payment request |
| `payment-profile-meta.schema.json` | The meta-schema the profile's schemas declare |
| `payment-profile-vocabulary.schema.json` | The required semantic-validation vocabulary |
| `vectors/payment-authority-vectors.json` | The Core Authority vector corpus, with its corpus digest |
| `vectors/verify_vectors.py` | A standard-library Python verifier that reproduces every vector's expected result, applying to the `semantic` vectors checks V1 to V4 of section 8.7 and its own restatement of the schema rules those vectors exercise; full schema validation is the test's |
| `vectors/schemas.test.ts` | Checks the corpus's artifacts, its semantic vectors, and the intents, caveats, and outcomes its evaluation vectors carry against the schemas, with the vocabulary implemented |
| `vectors/payment-execution-vectors.json` | The execution vector corpus, with its corpus digest |
| `vectors/verify_execution_vectors.py` | A standard-library Python verifier that reproduces every execution vector's expected result, and checks the `answerProofs` vectors of the Core corpus |
| `vectors/execution-schemas.test.ts` | Checks the execution corpus's arguments and answers against the two execution schemas |
| `vectors/profile-validator.ts` | The strict Ajv validator, with the vocabulary's keywords, that both schema tests use |

## The vocabulary is required

The schemas are JSON Schema 2020-12 under a profile meta-schema that requires
one vocabulary (`.../vocabulary/semantic-validation`). Its keywords carry rules
that plain JSON Schema cannot state, such as an expiry that must follow its
creation or a member whose canonical JSON must stay within a byte bound;
section 8.6 of the specification defines each of them. A validator must
implement the vocabulary. One that honours `$vocabulary` but does not
implement this vocabulary refuses every schema that declares the profile
meta-schema; one that runs in a strict mode that
rejects unknown keywords refuses each schema that uses one of them; one that
does neither (Ajv in non-strict mode, for example) would validate with those
rules silently skipped, and must not be used. `vectors/profile-validator.ts`
implements the six keywords for Ajv, and `vectors/schemas.test.ts` shows both
behaviours of a validator without them.

## Checking the corpus

```sh
python3 experimental/payment-authority/vectors/verify_vectors.py
python3 experimental/payment-authority/vectors/verify_execution_vectors.py
npx vitest run experimental/payment-authority/vectors/
```

The verifier needs only the Python standard library. It reports the Core
Authority checks and the execution-profile checks separately, as
`OK: <n> Core Authority checks and <m> execution-profile checks reproduced by
the Python verifier (corpus <digest>)`. The execution-profile
checks cover the vectors for the answer and its proof, which
`SPEC-PAYMENT-EXECUTION.md` defines; they stay in the Core corpus so that its
digest is unchanged. The execution verifier reports `OK: <n> execution checks
and <m> answer-proof checks of the Core corpus reproduced by the Python
verifier (corpus <digest>)`, the digest being the execution corpus's.

`vectors/schemas.test.ts` and `vectors/execution-schemas.test.ts` are part of
the repository's test suite: vitest's default include picks them up, so `npm
test`, and with it `prepublishOnly`, runs them. `vectors/profile-validator.ts`,
which both use, implements the vocabulary's canonical-JSON keywords with the
repository's RFC 8785 canonicalizer, `src/utils/canonical-json.ts`; a change
to that file can therefore change these tests' results.
