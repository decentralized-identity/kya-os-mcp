# Payment Authority Profile: Core Authority

Experimental Working Group discussion draft of `org.kya-os/payments.v1`: the
artifacts that bind an agent's delegated authority to one exact payment, built
on the base specification ([`SPEC.md`](../../SPEC.md)). Nothing here is
ratified, published, or deployed at its identifier URL.

The specification is [`SPEC-PAYMENT-AUTHORITY.md`](./SPEC-PAYMENT-AUTHORITY.md).
It covers the payment intent, the authorization, the constraints caveat and
the outcome, with their digests, money, identifiers, evidence references,
artifact validation and extension negotiation; its Appendix A indexes every
member the schemas admit. Request binding, the processing algorithm,
idempotency and recovery, rail adapters, approval evidence formats, and the
envelopes that carry an artifact across a trust boundary belong to a separate
execution profile in preparation.

| Path | Purpose |
| --- | --- |
| `SPEC-PAYMENT-AUTHORITY.md` | The Core Authority specification |
| `BASE-AMENDMENTS.md` | The amendments to the base specifications this draft proposes; none is part of a ratified text |
| `payment-intent.schema.json` | The exact economic terms of one payment, covered by the request proof |
| `payment-authorization.schema.json` | The Executor's verified authority for one attempt of that intent |
| `payment-constraints.schema.json` | The payment caveat a delegation carries, attenuated root to leaf |
| `payment-outcome.schema.json` | The result of an attempt, with the rail evidence it rests on |
| `payment-extension-settings.schema.json` | The MCP extension's negotiation settings |
| `payment-profile-meta.schema.json` | The meta-schema the profile's schemas declare |
| `payment-profile-vocabulary.schema.json` | The required semantic-validation vocabulary |
| `vectors/payment-authority-vectors.json` | The Core Authority vector corpus, with its corpus digest |
| `vectors/verify_vectors.py` | A standard-library Python verifier that reproduces every vector's expected result, applying to the `semantic` vectors checks V1 to V4 of section 8.7 and its own restatement of the schema rules those vectors exercise; full schema validation is the test's |
| `vectors/schemas.test.ts` | Checks the corpus's artifacts, its semantic vectors, and the intents, caveats, and outcomes its evaluation vectors carry against the schemas, with the vocabulary implemented |

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
rules silently skipped, and must not be used. `vectors/schemas.test.ts`
implements the six keywords for Ajv, and shows both behaviours of a validator
without them.

## Checking the corpus

```sh
python3 experimental/payment-authority/vectors/verify_vectors.py
npx vitest run experimental/payment-authority/vectors/schemas.test.ts
```

The verifier needs only the Python standard library. It reports the Core
Authority checks and the execution-profile checks separately, as
`OK: <n> Core Authority checks and <m> execution-profile checks reproduced by
the Python verifier (corpus <digest>)`. The execution-profile
checks cover the vectors for the answer and its proof, which the execution
profile defines; they stay in the corpus so that one digest identifies the
whole corpus.

`vectors/schemas.test.ts` is part of the repository's test suite: vitest's
default include picks it up, so `npm test`, and with it `prepublishOnly`,
runs it. It implements the vocabulary's canonical-JSON keywords with the
repository's RFC 8785 canonicalizer, `src/utils/canonical-json.ts`; a change
to that file can therefore change this test's results.
