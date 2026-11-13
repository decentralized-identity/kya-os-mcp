"""JSON as the TypeScript implementation writes and reads it, and nothing looser.

A value is written as RFC 8785 (JCS) has it, exactly: ECMAScript number formatting and UTF-16
code-unit object-key ordering, over the full admitted value space, fractional numbers and non-BMP
keys included. A text is read as JSON.parse reads it. The serializer and the parser both recurse;
the two loops here, which take no stack, say how deep a value or a text nests before either is
handed it.
"""

import json


def _es_number(value) -> str:
    """ECMAScript Number::toString, the number serialization RFC 8785 requires.

    Python's repr provides the same shortest-round-trip digits as ECMAScript but
    formats exponents differently (1e-07 vs 1e-7, and different decimal/exponent
    thresholds), so the digits are reformatted per ECMA-262 7.1.12.1.
    """
    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError("non-finite number")
    if (isinstance(value, int) or value.is_integer()) and abs(value) > 2 ** 53 - 1:
        # The same number however its text was written: 1e16 is an integer too.
        raise ValueError("unsafe integer outside the admitted JCS space")
    if isinstance(value, int):
        return str(value)
    if value == 0.0:
        return "0"
    sign = "-" if value < 0 else ""
    mantissa, _, exponent = repr(abs(value)).partition("e")
    exp10 = int(exponent) if exponent else 0
    integer_part, _, fraction = mantissa.partition(".")
    if integer_part != "0":
        n = len(integer_part) + exp10
    else:
        n = exp10 - (len(fraction) - len(fraction.lstrip("0")))
    digits = (integer_part + fraction).lstrip("0").rstrip("0")
    k = len(digits)
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + digits
    e = n - 1
    mantissa_out = digits[0] + ("." + digits[1:] if k > 1 else "")
    return f"{sign}{mantissa_out}e{'+' if e >= 0 else '-'}{abs(e)}"


def _jcs_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _jcs_serialize(value) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _jcs_string(value)
    if isinstance(value, (int, float)):
        return _es_number(value)
    if isinstance(value, list):
        return "[" + ",".join(_jcs_serialize(item) for item in value) + "]"
    if isinstance(value, dict):
        # RFC 8785 orders keys by UTF-16 code units, not code points: a non-BMP
        # key's surrogates sort before BMP characters above U+D7FF.
        items = sorted(value.items(), key=lambda pair: pair[0].encode("utf-16-be"))
        return "{" + ",".join(
            _jcs_string(key) + ":" + _jcs_serialize(item) for key, item in items
        ) + "}"
    raise ValueError(f"unsupported JCS value type: {type(value).__name__}")


def jcs(value) -> bytes:
    """RFC 8785 (JCS) canonical bytes over the full admitted value space."""
    return _jcs_serialize(value).encode("utf-8")


def nests_deeper_than(value, limit: int) -> bool:
    """Whether the arrays and objects of `value` nest more than `limit` deep.

    `value` itself is level 1 when it is an array or an object, and one that is a member of
    another is one level deeper than it. A value that holds itself is deeper than any limit.
    """
    deepest = {}
    stack = [(value, 1)]
    while stack:
        item, level = stack.pop()
        if not isinstance(item, (list, dict)):
            continue
        if level > limit:
            return True
        # One met again no deeper than before has nothing under it that was not counted then.
        if deepest.get(id(item), 0) >= level:
            continue
        deepest[id(item)] = level
        for member in (item.values() if isinstance(item, dict) else item):
            stack.append((member, level + 1))
    return False


def json_text_nests_deeper_than(text: str, limit: int) -> bool:
    """Whether the arrays and objects of a JSON text nest more than `limit` deep.

    One pass over the text, before any parser reads it: the `[` and `{` open at one place,
    outside a string. A backslash in a string takes the character after it, a quote included.
    """
    depth = 0
    in_string = escaped = False
    for character in text:
        if escaped:
            escaped = False
        elif in_string:
            if character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
        elif character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > limit:
                return True
        elif character in "]}":
            depth -= 1
    return False


def _not_json(constant):
    raise ValueError(f"{constant} is not JSON")


# CPython converts a decimal integer of at most this many digits whatever limit it is run
# with (sys.int_info.str_digits_check_threshold, below which no limit can be set), and 3.9
# has no limit at all. A longer literal has at least 640 digits, past the largest double.
_LONGEST_EXACT_INTEGER = 640


def _json_int(literal: str):
    """An integer literal, read by its length alone: exactly, up to 640 characters, and past
    that as the double nearest it, which is infinite, as JSON.parse reads it.

    SPEC.md 7.8 reads every number as a double first. Read exactly, an integer comes to the
    same: one of magnitude up to 2^53 - 1 is that double, and one above it is refused either
    way. A literal with a fraction or an exponent is read as a double, as json.loads reads it.
    """
    return int(literal) if len(literal) <= _LONGEST_EXACT_INTEGER else float(literal)


def read_json(text):
    """`text` read as JSON and nothing looser: `NaN` and `Infinity` are not JSON.

    A number of any length is read (RFC 8259 sets no limit on one): an integer too long to
    convert under the interpreter's digit limit is infinite, as JSON.parse reads it. Of the
    members of one object that share a name the last is kept (SPEC.md 7.8), as JSON.parse
    keeps it, which json.loads does when it is given no object_pairs_hook.
    """
    return json.loads(text, parse_constant=_not_json, parse_int=_json_int)
