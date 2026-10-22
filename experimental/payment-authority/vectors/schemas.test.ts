/**
 * The Core Authority schemas against the vector corpus. Each schema that uses the profile's semantic-validation
 * vocabulary compiles in strict mode only once a validator implements it, so a strict validator never ignores its
 * keywords (a non-strict one would, which is why one must not be used). The artifacts the corpus digests, its semantic
 * vectors, and the intents, caveats, and outcomes its evaluation vectors carry are each checked against their schemas. The
 * vocabulary's keywords are implemented in `profile-validator.ts`, beside the schemas, as any validator must implement them.
 */
import { readFileSync } from 'node:fs';
import { Ajv2020, type AnySchema, type ValidateFunction } from 'ajv/dist/2020.js';
import { describe, expect, it } from 'vitest';
import { configured, schema } from './profile-validator.js';

const META_SCHEMA_ID = 'https://schema.kya-os.org/experimental/payment-authority/2026-09-22/meta';
const VOCABULARY_ID = 'https://schema.kya-os.org/experimental/payment-authority/2026-09-22/vocabulary/semantic-validation';

const ARTIFACTS = [
  'payment-intent.schema.json',
  'payment-authorization.schema.json',
  'payment-constraints.schema.json',
  'payment-outcome.schema.json',
  'payment-extension-settings.schema.json',
] as const;

type Vector = { name: string; domain: string; input: unknown };
const corpus = JSON.parse(readFileSync(new URL('./payment-authority-vectors.json', import.meta.url), 'utf8')) as {
  vectors: { artifactDigests: Vector[] };
};

const validators = new Map<string, ValidateFunction>();
function validator(name: string): ValidateFunction {
  if (!validators.has(name)) validators.set(name, configured().compile(schema(name) as AnySchema));
  return validators.get(name)!;
}

const schemaOf: Record<string, string> = {
  'org.kya-os.payments.intent.v1': 'payment-intent.schema.json',
  'org.kya-os.payments.authorization.v1': 'payment-authorization.schema.json',
  'org.kya-os.payments.outcome.v1': 'payment-outcome.schema.json',
  'org.kya-os.payments.constraints.v1': 'payment-constraints.schema.json',
};

describe('the Core Authority schemas', () => {
  it('declare the semantic-validation vocabulary as required', () => {
    const meta = schema('payment-profile-meta.schema.json');
    expect(meta.$id).toBe(META_SCHEMA_ID);
    expect((meta.$vocabulary as Record<string, unknown>)[VOCABULARY_ID]).toBe(true);
  });

  // Ajv does not read `$vocabulary`: what refuses the schemas is its strict mode, which rejects every keyword it does
  // not implement. Each artifact that uses the vocabulary is refused by a strict validator given the meta-schemas
  // but not the keywords.
  for (const name of ARTIFACTS.filter((artifact) => artifact !== 'payment-extension-settings.schema.json')) {
    it(`${name} is refused by a strict validator that does not implement the vocabulary`, () => {
      const unaware = new Ajv2020({ strict: true });
      unaware.addMetaSchema(schema('payment-profile-vocabulary.schema.json'));
      unaware.addMetaSchema(schema('payment-profile-meta.schema.json'));
      expect(() => unaware.compile(schema(name) as AnySchema)).toThrow(/unknown keyword: "kya/);
    });
  }

  it('a non-strict validator that does not implement the vocabulary skips its rules, which is why one must not be used', () => {
    const lax = new Ajv2020({ strict: false });
    lax.addMetaSchema(schema('payment-profile-vocabulary.schema.json'));
    lax.addMetaSchema(schema('payment-profile-meta.schema.json'));
    const intent = corpus.vectors.artifactDigests.find((vector) => vector.name === 'intent')!.input as Record<string, number>;
    const backwards = { ...intent, expiresAt: intent.createdAt - 1 };
    expect(lax.compile(schema('payment-intent.schema.json') as AnySchema)(backwards)).toBe(true);
    expect(validator('payment-intent.schema.json')(backwards)).toBe(false);
  });

  for (const name of ARTIFACTS) {
    it(`${name} compiles in strict mode once the vocabulary is implemented`, () => {
      expect(() => validator(name)).not.toThrow();
    });
  }

  it('every artifact the corpus digests validates against its schema', () => {
    const checked = corpus.vectors.artifactDigests.filter((vector) => vector.domain in schemaOf);
    expect([...new Set(checked.map((vector) => vector.domain))].sort()).toEqual(Object.keys(schemaOf).sort());
    for (const vector of checked) {
      const validate = validator(schemaOf[vector.domain]!);
      expect(validate(vector.input), `${vector.name}: ${JSON.stringify(validate.errors)}`).toBe(true);
    }
  });

  // The corpus's semantic vectors state whether each artifact is valid. The schemas, with the vocabulary, decide every
  // one of them except those the specification's consumer checks V1 to V4 decide (section 8.7): a `__proto__` member,
  // delegates named without the actor, an approval by a delegate or by a principal the chain does not list, an approval
  // whose subject is a delegate. Those pass the schema by design.
  const RUNTIME_ONLY = new Set([
    'intent-proto-member-in-extension-data',
    'authorization-approval-by-delegate',
    'authorization-delegates-without-actor',
    'authorization-approval-by-unlisted-principal',
    'authorization-approval-subject-is-delegate',
  ]);
  const semantic = (corpus.vectors as unknown as { semantic: { name: string; artifact: string; input: unknown; valid: boolean }[] }).semantic;

  it('decide every semantic vector as the corpus does, but those the consumer checks V1 to V4 decide', () => {
    expect(semantic.length).toBeGreaterThan(0);
    expect(semantic.filter((vector) => RUNTIME_ONLY.has(vector.name)).map((vector) => vector.name).sort())
      .toEqual([...RUNTIME_ONLY].sort());
    for (const vector of semantic) {
      const verdict = validator(`payment-${vector.artifact}.schema.json`)(vector.input);
      const expected = RUNTIME_ONLY.has(vector.name) ? true : vector.valid;
      expect(verdict, `${vector.name} (${vector.artifact})`).toBe(expected);
    }
  });

  // The intents, caveats, and outcomes the evaluation vector sets carry conform to their schemas too, but those a vector makes
  // malformed on purpose, which the constraint evaluator's own structure checks refuse (section 8.4.4).
  const MALFORMED_ON_PURPOSE = [
    'constraints/invalid-intent-unknown-member: intent',
    'constraints/invalid-reference-astral-2049: caveat 0',
    'narrowing/malformed-child: child',
    'narrowing/unknown-version: child',
    'narrowing/oversized-child: child',
  ];

  it('admit every intent, caveat, and outcome the evaluation vectors carry, but those a vector makes malformed on purpose', () => {
    const sets = corpus.vectors as unknown as {
      constraints: { name: string; chain: unknown[]; intent: unknown }[];
      narrowing: { name: string; parent: unknown; child: unknown }[];
      caveats: { name: string; intent: unknown }[];
      admission: { name: string; intent: unknown }[];
      outcomeStreams: { name: string; observations: unknown[] }[];
    };
    const intent = validator('payment-intent.schema.json');
    const caveat = validator('payment-constraints.schema.json');
    const outcome = validator('payment-outcome.schema.json');
    const refused: string[] = [];
    for (const vector of sets.constraints) {
      if (!intent(vector.intent)) refused.push(`constraints/${vector.name}: intent`);
      vector.chain.forEach((entry, hop) => {
        if (!caveat(entry)) refused.push(`constraints/${vector.name}: caveat ${hop}`);
      });
    }
    for (const vector of sets.narrowing) {
      if (!caveat(vector.parent)) refused.push(`narrowing/${vector.name}: parent`);
      if (!caveat(vector.child)) refused.push(`narrowing/${vector.name}: child`);
    }
    for (const vector of sets.caveats) {
      if (!intent(vector.intent)) refused.push(`caveats/${vector.name}: intent`);
    }
    for (const vector of sets.admission) {
      if (!intent(vector.intent)) refused.push(`admission/${vector.name}: intent`);
    }
    for (const vector of sets.outcomeStreams) {
      vector.observations.forEach((entry, index) => {
        if (!outcome(entry)) refused.push(`outcomeStreams/${vector.name}: observation ${index}`);
      });
    }
    expect([...refused].sort()).toEqual([...MALFORMED_ON_PURPOSE].sort());
  });

  it('refuses an intent with a member the schema does not define, or without one it requires', () => {
    const intent = corpus.vectors.artifactDigests.find((vector) => vector.name === 'intent')!.input as Record<string, unknown>;
    const validate = validator('payment-intent.schema.json');
    expect(validate({ ...intent, unexpected: true })).toBe(false);
    const { payee: _payee, ...withoutPayee } = intent;
    void _payee;
    expect(validate(withoutPayee)).toBe(false);
  });

  it('refuses an intent whose expiry precedes its creation (the ordered-range keyword)', () => {
    const intent = corpus.vectors.artifactDigests.find((vector) => vector.name === 'intent')!.input as Record<string, number>;
    expect(validator('payment-intent.schema.json')({ ...intent, expiresAt: intent.createdAt - 1 })).toBe(false);
  });
});
