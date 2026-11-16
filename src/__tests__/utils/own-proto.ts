/**
 * A member named `__proto__`, as one arrives over the wire. `JSON.parse` makes
 * it an own member of the object it reads; assigning or spreading it sets the
 * object's prototype instead, so a test that sends one builds it here.
 */

/**
 * A copy of `value`, read back through JSON, with an own member `__proto__`
 * written after its other members and holding `member`. Its prototype is
 * still `Object.prototype`.
 */
export function withOwnProto<T extends object>(value: T, member: unknown): T {
  const json = JSON.stringify(value);
  if (!json.startsWith('{')) throw new TypeError('withOwnProto takes an object that JSON writes as an object');
  const members = json.slice(0, -1);
  const copy = JSON.parse(`${members}${members === '{' ? '' : ','}"__proto__":${JSON.stringify(member)}}`) as T;
  if (!Object.hasOwn(copy, '__proto__') || Object.getPrototypeOf(copy) !== Object.prototype) {
    throw new TypeError('withOwnProto made no own member __proto__');
  }
  return copy;
}
