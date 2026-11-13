export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * The issuer an `issuer` member names, as VC Data Model 2.0 §4.7 writes one: the string itself, or
 * the `id` of an object when that is a string; otherwise `undefined`. Nothing is converted.
 */
export function issuerOf(value: unknown): string | undefined {
  if (typeof value === 'string') return value;
  return isRecord(value) && typeof value.id === 'string' ? value.id : undefined;
}
