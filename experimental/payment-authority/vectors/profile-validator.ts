/**
 * A strict JSON Schema validator for the Payment Authority Profile's schemas, with the six keywords of its
 * semantic-validation vocabulary implemented (SPEC-PAYMENT-AUTHORITY section 8.6), as any validator must implement
 * them. The schema tests of Core Authority and of the execution profile both use it.
 */
import { readFileSync } from 'node:fs';
import { Ajv2020, type AnySchemaObject } from 'ajv/dist/2020.js';
import { assertCanonicalJsonValue, canonicalizeJson, canonicalizeJsonBytes } from '../../../src/utils/canonical-json.js';

export function schema(name: string): AnySchemaObject {
  return JSON.parse(readFileSync(new URL(`../${name}`, import.meta.url), 'utf8')) as AnySchemaObject;
}

function measure(value: unknown, depth = 1): { depth: number; nodes: number } {
  if (typeof value !== 'object' || value === null) return { depth, nodes: 1 };
  const children = Array.isArray(value) ? value : Object.values(value as Record<string, unknown>);
  let deepest = depth;
  let nodes = 1;
  for (const child of children) {
    const inner = measure(child, depth + 1);
    deepest = Math.max(deepest, inner.depth);
    nodes += inner.nodes;
  }
  return { depth: deepest, nodes };
}

// Section 8.6: a path names own members of objects only; through an array, or to an inherited member, it names nothing.
function propertyAt(value: unknown, path: string): unknown {
  return path.split('.').reduce<unknown>((current, member) =>
    typeof current === 'object' && current !== null && !Array.isArray(current) &&
      Object.prototype.hasOwnProperty.call(current, member)
      ? (current as Record<string, unknown>)[member]
      : undefined, value);
}

/** A strict Ajv that implements the semantic-validation vocabulary's six keywords. */
export function configured(): Ajv2020 {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  ajv.addKeyword({
    keyword: 'kyaOrderedNumberRange', schemaType: 'object', type: 'object', errors: false,
    validate: (rule: { first: string; last: string; exclusive?: boolean }, data: Record<string, unknown>) => {
      const first = data[rule.first];
      const last = data[rule.last];
      if (typeof first !== 'number' || typeof last !== 'number') return true;
      return rule.exclusive ? last > first : last >= first;
    },
  });
  ajv.addKeyword({
    keyword: 'kyaCanonicalJson', schemaType: 'object', errors: false,
    validate: (rule: { maxBytes: number; maxDepth: number; maxNodes: number }, data: unknown) => {
      try {
        assertCanonicalJsonValue(data);
        const size = measure(data);
        return size.depth <= rule.maxDepth && size.nodes <= rule.maxNodes &&
          canonicalizeJsonBytes(data).byteLength <= rule.maxBytes;
      } catch {
        return false;
      }
    },
  });
  ajv.addKeyword({
    keyword: 'kyaCanonicalJsonCollection', schemaType: 'object', type: 'object', errors: false,
    validate: (rule: { property: string; maxBytes: number }, data: Record<string, unknown>) => {
      try {
        let bytes = 0;
        for (const member of Object.values(data)) {
          if (typeof member !== 'object' || member === null) return false;
          const value = (member as Record<string, unknown>)[rule.property];
          assertCanonicalJsonValue(value);
          bytes += canonicalizeJsonBytes(value).byteLength;
          if (bytes > rule.maxBytes) return false;
        }
        return true;
      } catch {
        return false;
      }
    },
  });
  ajv.addKeyword({
    keyword: 'kyaNotAfter', schemaType: 'object', type: 'object', errors: false,
    validate: (rule: { value: string; limitObject: string; limit: string }, data: Record<string, unknown>) => {
      const value = data[rule.value];
      const container = data[rule.limitObject];
      if (typeof value !== 'number' || typeof container !== 'object' || container === null) return true;
      const limit = (container as Record<string, unknown>)[rule.limit];
      return typeof limit !== 'number' || value <= limit;
    },
  });
  ajv.addKeyword({
    keyword: 'kyaUniqueProperty', schemaType: 'object', type: 'object', errors: false,
    validate: (rule: { array: string; property: string }, data: Record<string, unknown>) => {
      const values = data[rule.array];
      if (!Array.isArray(values)) return true;
      const keys = values.map((value) =>
        typeof value === 'object' && value !== null ? (value as Record<string, unknown>)[rule.property] : undefined);
      return new Set(keys).size === keys.length;
    },
  });
  ajv.addKeyword({
    keyword: 'kyaUniqueBy', schemaType: 'array', type: 'object', errors: false,
    validate: (rules: { path: string; properties?: string[] }[], data: Record<string, unknown>) => {
      try {
        return rules.every((rule) => {
          const collection = propertyAt(data, rule.path);
          if (collection === undefined) return true;
          if (!Array.isArray(collection)) return false;
          const keys = collection.map((member) => canonicalizeJson(
            rule.properties === undefined ? member : rule.properties.map((property) => propertyAt(member, property))));
          return new Set(keys).size === keys.length;
        });
      } catch {
        return false;
      }
    },
  });
  ajv.addMetaSchema(schema('payment-profile-vocabulary.schema.json'));
  ajv.addMetaSchema(schema('payment-profile-meta.schema.json'));
  return ajv;
}

