/**
 * Strict RFC 8785 JSON canonicalization for integrity-critical inputs.
 *
 * `json-canonicalize` intentionally follows JSON serialization semantics, which
 * can silently erase or coerce unsupported JavaScript values. Protocol digests
 * must fail closed instead: two distinguishable JavaScript inputs must never be
 * accepted as the same canonical JSON value by accident.
 */

import { canonicalize } from 'json-canonicalize';

const encoder = new TextEncoder();

/** Validate that a value has an unambiguous JSON representation. */
export function assertCanonicalJsonValue(
  value: unknown,
  path = '$',
  ancestors: WeakSet<object> = new WeakSet<object>(),
): void {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return;
  }

  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new TypeError(`Cannot canonicalize non-finite number at ${path}: ${value}`);
    }
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      throw new TypeError(`Cannot canonicalize unsafe integer at ${path}: ${value}`);
    }
    return;
  }

  if (typeof value === 'undefined') {
    throw new TypeError(`Cannot canonicalize undefined at ${path}`);
  }
  if (typeof value === 'function') {
    throw new TypeError(`Cannot canonicalize function at ${path}`);
  }
  if (typeof value === 'symbol') {
    throw new TypeError(`Cannot canonicalize symbol at ${path}`);
  }
  if (typeof value === 'bigint') {
    throw new TypeError(`Cannot canonicalize bigint at ${path}`);
  }

  if (typeof value !== 'object') {
    throw new TypeError(`Cannot canonicalize unsupported value at ${path}`);
  }
  if (ancestors.has(value)) {
    throw new TypeError(`Cannot canonicalize cyclic reference at ${path}`);
  }

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      for (let index = 0; index < value.length; index += 1) {
        if (!(index in value)) {
          throw new TypeError(`Cannot canonicalize sparse array element at ${path}[${index}]`);
        }
        assertCanonicalJsonValue(value[index], `${path}[${index}]`, ancestors);
      }
      return;
    }

    const prototype = Object.getPrototypeOf(value) as object | null;
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError(`Cannot canonicalize non-plain object at ${path}`);
    }

    for (const key of Reflect.ownKeys(value)) {
      if (typeof key === 'symbol') {
        throw new TypeError(`Cannot canonicalize symbol-keyed property at ${path}`);
      }
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor?.enumerable) continue;
      if (!('value' in descriptor)) {
        throw new TypeError(`Cannot canonicalize accessor property at ${path}.${key}`);
      }
      assertCanonicalJsonValue(descriptor.value, `${path}.${key}`, ancestors);
    }
  } finally {
    ancestors.delete(value);
  }
}

/** Canonicalize a strict JSON value according to RFC 8785. */
export function canonicalizeJson(value: unknown): string {
  assertCanonicalJsonValue(value);
  return canonicalize(value);
}

/** Canonical UTF-8 bytes for hashing or signing. */
export function canonicalizeJsonBytes(value: unknown): Uint8Array {
  return encoder.encode(canonicalizeJson(value));
}
