/**
 * Answers a dependency that promises a boolean can give instead, when the host's code is untyped
 * or has a fault. A verdict read by its truthiness passes on some of each list.
 */

/** Answers that are not the literal `true`: a verdict that passes only on `true` refuses each. */
export const NOT_TRUE: [string, unknown][] = [
  ['{}', {}],
  ['0', 0],
  ['1', 1],
  ['"false"', 'false'],
  ['"true"', 'true'],
  ['undefined', undefined],
  ['null', null],
  ['an object that says valid', { valid: true }],
  ['false', false],
];

/** Answers that are not the literal `false`: a check skipped only on `false` runs on each. */
export const NOT_FALSE: [string, unknown][] = [
  ['{}', {}],
  ['0', 0],
  ['1', 1],
  ['"false"', 'false'],
  ['""', ''],
  ['undefined', undefined],
  ['null', null],
  ['true', true],
];

/** A proxy whose handler was revoked: `typeof` still names it an object, but any other look at it throws, `Array.isArray` included. */
export function revokedProxy(): object {
  const { proxy, revoke } = Proxy.revocable({}, {});
  revoke();
  return proxy;
}
