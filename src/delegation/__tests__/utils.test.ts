import { describe, it, expect } from "vitest";
import { canonicalizeJSON } from "../utils.js";

describe("canonicalizeJSON", () => {
  it("should canonicalize null", () => {
    expect(canonicalizeJSON(null)).toBe("null");
  });

  it("should canonicalize boolean true", () => {
    expect(canonicalizeJSON(true)).toBe("true");
  });

  it("should canonicalize boolean false", () => {
    expect(canonicalizeJSON(false)).toBe("false");
  });

  it("should canonicalize number zero", () => {
    expect(canonicalizeJSON(0)).toBe("0");
  });

  it("should canonicalize positive number", () => {
    expect(canonicalizeJSON(42)).toBe("42");
  });

  it("should canonicalize negative number", () => {
    expect(canonicalizeJSON(-42)).toBe("-42");
  });

  it("should canonicalize finite fractional numbers", () => {
    expect(canonicalizeJSON(3.14)).toBe("3.14");
  });

  it("should throw for Infinity", () => {
    expect(() => canonicalizeJSON(Infinity)).toThrow(TypeError);
    expect(() => canonicalizeJSON(Infinity)).toThrow("non-finite number");
  });

  it("should throw for NaN", () => {
    expect(() => canonicalizeJSON(NaN)).toThrow(TypeError);
    expect(() => canonicalizeJSON(NaN)).toThrow("non-finite number");
  });

  it("should throw for -Infinity", () => {
    expect(() => canonicalizeJSON(-Infinity)).toThrow(TypeError);
  });

  it("should canonicalize empty string", () => {
    expect(canonicalizeJSON("")).toBe('""');
  });

  it("should canonicalize string", () => {
    expect(canonicalizeJSON("hello")).toBe('"hello"');
  });

  it("should canonicalize string with special characters", () => {
    expect(canonicalizeJSON('hello "world"')).toBe('"hello \\"world\\""');
  });

  it("should canonicalize empty array", () => {
    expect(canonicalizeJSON([])).toBe("[]");
  });

  it("should canonicalize array with primitives", () => {
    const result = canonicalizeJSON([1, "two", true, null]);
    expect(result).toBe('[1,"two",true,null]');
  });

  it("should canonicalize nested arrays", () => {
    const result = canonicalizeJSON([[1, 2], [3, 4]]);
    expect(result).toBe("[[1,2],[3,4]]");
  });

  it("should canonicalize empty object", () => {
    expect(canonicalizeJSON({})).toBe("{}");
  });

  it("should canonicalize object with sorted keys", () => {
    const obj = { z: 3, a: 1, m: 2 };
    const result = canonicalizeJSON(obj);
    expect(result).toBe('{"a":1,"m":2,"z":3}');
  });

  it("should canonicalize object with string values", () => {
    const obj = { name: "test", value: "hello" };
    const result = canonicalizeJSON(obj);
    expect(result).toBe('{"name":"test","value":"hello"}');
  });

  it("should canonicalize nested objects", () => {
    const obj = { a: { b: { c: 1 } } };
    const result = canonicalizeJSON(obj);
    expect(result).toBe('{"a":{"b":{"c":1}}}');
  });

  it("should canonicalize object with array values", () => {
    const obj = { items: [1, 2, 3] };
    const result = canonicalizeJSON(obj);
    expect(result).toBe('{"items":[1,2,3]}');
  });

  it("should canonicalize complex nested structure", () => {
    const obj = {
      z: "last",
      a: {
        nested: [1, { deep: true }],
        value: 42,
      },
      m: ["array", "values"],
    };
    const result = canonicalizeJSON(obj);
    // Keys should be sorted: a, m, z
    expect(result).toContain('"a"');
    expect(result).toContain('"m"');
    expect(result).toContain('"z"');
    expect(result.indexOf('"a"')).toBeLessThan(result.indexOf('"m"'));
    expect(result.indexOf('"m"')).toBeLessThan(result.indexOf('"z"'));
  });

  it("should produce identical output for same input (deterministic)", () => {
    const obj = { z: 3, a: 1, m: 2 };
    const result1 = canonicalizeJSON(obj);
    const result2 = canonicalizeJSON(obj);
    expect(result1).toBe(result2);
  });

  it("should handle object with null values", () => {
    const obj = { a: null, b: "value" };
    const result = canonicalizeJSON(obj);
    expect(result).toBe('{"a":null,"b":"value"}');
  });

  it("should handle object with boolean values", () => {
    const obj = { enabled: true, disabled: false };
    const result = canonicalizeJSON(obj);
    expect(result).toBe('{"disabled":false,"enabled":true}');
  });

  it("should throw for undefined", () => {
    expect(() => canonicalizeJSON(undefined)).toThrow(TypeError);
    expect(() => canonicalizeJSON(undefined)).toThrow("Cannot canonicalize undefined");
  });

  it("should throw for function", () => {
    expect(() => canonicalizeJSON(() => {})).toThrow(TypeError);
    expect(() => canonicalizeJSON(() => {})).toThrow("Cannot canonicalize function");
  });

  it("should throw for symbol", () => {
    expect(() => canonicalizeJSON(Symbol("test"))).toThrow(TypeError);
    expect(() => canonicalizeJSON(Symbol("test"))).toThrow("Cannot canonicalize symbol");
  });

  it("should throw for bigint", () => {
    expect(() => canonicalizeJSON(BigInt(42))).toThrow(TypeError);
    expect(() => canonicalizeJSON(BigInt(42))).toThrow("Cannot canonicalize bigint");
  });

  it("should throw for nested non-finite numbers", () => {
    expect(() => canonicalizeJSON({ a: { b: Infinity } })).toThrow(TypeError);
    expect(() => canonicalizeJSON({ a: { b: Infinity } })).toThrow("$.a.b");
  });

  it("should throw for non-finite numbers in arrays", () => {
    expect(() => canonicalizeJSON([1, NaN, 3])).toThrow(TypeError);
    expect(() => canonicalizeJSON([1, NaN, 3])).toThrow("$[1]");
  });

  it("should throw for undefined in object values", () => {
    expect(() => canonicalizeJSON({ key: undefined })).toThrow(TypeError);
    expect(() => canonicalizeJSON({ key: undefined })).toThrow("$.key");
  });

  it("should handle unicode strings", () => {
    const result = canonicalizeJSON("hello 世界");
    expect(result).toBe('"hello 世界"');
  });

  it("should handle supplementary Unicode characters in values and object keys", () => {
    expect(canonicalizeJSON({ "😀": "launch 🚀" })).toBe('{"😀":"launch 🚀"}');
  });

  it("should reject lone surrogates in values and object keys", () => {
    expect(() => canonicalizeJSON("\ud800")).toThrow("string with lone surrogate at $");
    expect(() => canonicalizeJSON({ "\udc00": "value" })).toThrow(
      "object key with lone surrogate at $",
    );
  });

  it("should handle object with numeric keys (sorted as strings)", () => {
    const obj = { "10": "ten", "2": "two", "1": "one" };
    const result = canonicalizeJSON(obj);
    // Keys sorted lexicographically: "1", "10", "2"
    expect(result).toBe('{"1":"one","10":"ten","2":"two"}');
  });
});
