/**
 * Values a proof may state as its `proofPurpose` that are not a string, or are a string too long to
 * quote whole, each with the way a refusal names it: a value that is not a string by its JSON type,
 * never converted, and a string by at most its first 64 characters. Every verifier that refuses a
 * stated purpose other than `assertionMethod` names it this way, so their tests share the table.
 */
export const UNQUOTABLE_PURPOSES: readonly (readonly [unknown, string])[] = [
  [['assertionMethod'], 'of type array'],
  [[], 'of type array'],
  [{ purpose: 'assertionMethod' }, 'of type object'],
  [JSON.parse('{"toString":"assertionMethod"}'), 'of type object'],
  ['x'.repeat(100_000), `"${'x'.repeat(64)}"...`],
];
