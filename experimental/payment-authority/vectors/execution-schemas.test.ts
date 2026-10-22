/**
 * The execution profile's schemas against its vector corpus (SPEC-PAYMENT-EXECUTION section 13.3). The payment argument
 * schema refers to Core's intent schema, and the answer schema to Core's intent and constraints schemas, so all three
 * are compiled with the semantic-validation vocabulary implemented (`profile-validator.ts`).
 */
import { readFileSync } from 'node:fs';
import type { AnySchema, ValidateFunction } from 'ajv/dist/2020.js';
import { describe, expect, it } from 'vitest';
import { configured, schema } from './profile-validator.js';

type Expect = { valid: boolean };
type Corpus = {
  vectors: {
    arguments: { name: string; text: string; expect: Expect }[];
    answers: { name: string; result: unknown; expect: Expect }[];
  };
};
const corpus = JSON.parse(readFileSync(new URL('./payment-execution-vectors.json', import.meta.url), 'utf8')) as Corpus;
const core = JSON.parse(readFileSync(new URL('./payment-authority-vectors.json', import.meta.url), 'utf8')) as {
  vectors: { answerProofs: { name: string; result: unknown; verifies: boolean }[] };
};

function compile(name: string): ValidateFunction {
  const ajv = configured();
  for (const referenced of ['payment-intent.schema.json', 'payment-constraints.schema.json']) {
    ajv.addSchema(schema(referenced) as AnySchema);
  }
  return ajv.compile(schema(name) as AnySchema);
}

// Refusals no schema can decide (section 4.2): the nesting bound on the message; duplicate member names, lone
// surrogates, and numbers that are not canonical values, anywhere in the message, `_meta` included, which JSON.parse
// silently resolves and the Executor refuses on the text; UTF-8 bytes, which JSON Schema cannot count; and a `__proto__` member in intent extension data, which
// Core's check V1 refuses (Core section 8.7).
const BEYOND_ARGUMENT_SCHEMA = new Set([
  'invalid-duplicate-member',
  'invalid-duplicate-member-escaped',
  'invalid-duplicate-member-in-intent',
  'invalid-duplicate-member-in-other-argument',
  'invalid-lone-surrogate-key',
  'invalid-lone-surrogate-in-intent',
  'invalid-lone-surrogate-in-other-argument',
  'invalid-approval-value-65537-bytes',
  'invalid-approval-value-65537-bytes-multibyte',
  'invalid-proto-member-in-intent-extension',
  'invalid-number-beyond-safe-integer-in-other-argument',
  'invalid-number-overflow-in-other-argument',
  'invalid-number-integral-exponent-in-other-argument',
  'invalid-duplicate-delegation-carrier-in-meta',
  'invalid-duplicate-request-proof-in-meta',
  'invalid-duplicate-client-capabilities-in-meta',
  'invalid-lone-surrogate-in-meta',
  'invalid-number-beyond-safe-integer-in-meta',
  'invalid-duplicate-payment-member',
  'invalid-defects-inside-and-outside',
  'invalid-duplicate-member-in-delegation-credential',
  'invalid-message-depth-65',
  'invalid-message-depth-10000',
]);

// Section 9: a text block whose JSON differs from `structuredContent`, which JSON Schema cannot compare.
const BEYOND_SCHEMA = new Set(['invalid-text-block-differs', 'invalid-text-block-not-json']);

describe('the execution profile schemas', () => {
  it('compile in strict mode with the vocabulary implemented', () => {
    expect(() => compile('payment-argument.schema.json')).not.toThrow();
    expect(() => compile('payment-answer.schema.json')).not.toThrow();
  });

  it('decide every arguments vector as the corpus does, but those no schema can decide', () => {
    const validate = compile('payment-argument.schema.json');
    const named = corpus.vectors.arguments.filter((vector) => BEYOND_ARGUMENT_SCHEMA.has(vector.name)).map((vector) => vector.name);
    expect(named.sort()).toEqual([...BEYOND_ARGUMENT_SCHEMA].sort());
    for (const vector of corpus.vectors.arguments) {
      const message = JSON.parse(vector.text) as { params: { arguments: Record<string, unknown> } };
      const args = message.params.arguments;
      const verdict = typeof args === 'object' && args !== null && 'payment' in args && validate(args.payment);
      const expected = BEYOND_ARGUMENT_SCHEMA.has(vector.name) ? true : vector.expect.valid;
      expect(verdict, `${vector.name}: ${JSON.stringify(validate.errors)}`).toBe(expected);
    }
  });

  it('decide every answers vector as the corpus does, but a text block that differs from structuredContent', () => {
    const validate = compile('payment-answer.schema.json');
    const named = corpus.vectors.answers.filter((vector) => BEYOND_SCHEMA.has(vector.name)).map((vector) => vector.name);
    expect(named.sort()).toEqual([...BEYOND_SCHEMA].sort());
    for (const vector of corpus.vectors.answers) {
      const expected = BEYOND_SCHEMA.has(vector.name) ? true : vector.expect.valid;
      expect(validate(vector.result), `${vector.name}: ${JSON.stringify(validate.errors)}`).toBe(expected);
    }
  });

  it('admit the result of every answer proof vector of the Core corpus', () => {
    const validate = compile('payment-answer.schema.json');
    for (const vector of core.vectors.answerProofs) {
      expect(validate(vector.result), `${vector.name}: ${JSON.stringify(validate.errors)}`).toBe(true);
    }
  });
});
