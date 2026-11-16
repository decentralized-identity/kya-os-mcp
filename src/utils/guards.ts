export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Whether `value` is an object literal, an `Object.create(null)` or a frozen one: an object, not an
 * array, whose prototype is this realm's `Object.prototype` or `null`. A class instance, a `Map`, a
 * `Date` and an object made in another realm are not. It is the stricter of the package's two
 * plain-object rules: it holds values this process built, such as configuration and what it is
 * about to serialize, where `isPlainObjectOfAnyRealm` (`delegation/did-document-walk.ts`) also
 * admits another realm's plain object, since a resolver may have parsed a DID document elsewhere.
 */
export function isPlainObjectOfThisRealm(value: unknown): value is Record<string, unknown> {
  if (!isRecord(value)) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/**
 * The issuer an `issuer` member names, as VC Data Model 2.0 §4.7 writes one: the string itself, or
 * the `id` of an object when that is a string; otherwise `undefined`. Nothing is converted.
 */
export function issuerOf(value: unknown): string | undefined {
  if (typeof value === 'string') return value;
  return isRecord(value) && typeof value.id === 'string' ? value.id : undefined;
}
