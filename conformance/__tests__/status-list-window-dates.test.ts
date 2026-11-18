/**
 * `conformance/status_list.py` reads the bounds of a status list's validity window (SPEC.md §6.6)
 * as the TypeScript reference reads them, on every Python the suite supports, 3.9 and later. A
 * bound is an RFC 3339 date-time with its zone, whose fraction of a second may have any number of
 * digits (§5.6, `time-secfrac = "." 1*DIGIT`). Python before 3.11 reads a fraction of three or six
 * digits only, so each bound here, read by Python and by `parseDateTime`, must name the same
 * instant to the millisecond, the reference's precision, or be refused by both.
 */

import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { parseDateTime } from '../../src/utils/rfc3339.js';
import { PYTHON_TEST_TIMEOUT_MS, requirePython, type Interpreter } from './python.js';

const HERE = fileURLToPath(new URL('..', import.meta.url));

const BOUNDS = [
  // A fraction of a second of every length from none to nine digits, the vectors' longest.
  '2026-01-01T05:30:00+05:30',
  '2026-01-01T05:30:00.1+05:30',
  '2026-01-01T05:30:00.12+05:30',
  '2026-01-01T05:30:00.123+05:30',
  '2026-01-01T05:30:00.1234+05:30',
  '2026-01-01T05:30:00.12345+05:30',
  '2026-01-01T05:30:00.123456+05:30',
  '2026-01-01T05:30:00.1234567+05:30',
  '2026-01-01T05:30:00.12345678+05:30',
  '2026-01-01T05:30:00.123456789+05:30',
  // Cut to the millisecond, never rounded up past the instant it states.
  '2026-01-01T00:00:00.999999999Z',
  '2998-12-31T18:00:00-06:00',
  '2026-01-01t00:00:00.5z',
  // No date: a day no calendar has, a leap second, no zone, no digit after the point.
  '2026-02-30T00:00:00Z',
  '2026-12-31T23:59:60Z',
  '2026-01-01T00:00:00.123',
  '2026-01-01T00:00:00.Z',
];

/** The instant, in epoch milliseconds, `status_list.window_bound` reads each of `bounds` as, or `null` where it refuses it. */
function pythonInstants([command, ...args]: Interpreter, bounds: readonly string[]): (number | null)[] {
  const reader = [
    'import json, sys', 'sys.path.insert(0, sys.argv[1])',
    'from datetime import datetime, timedelta, timezone', 'from status_list import window_bound',
    'EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)',
    'for line in sys.stdin.buffer:',
    '    try:',
    '        bound = window_bound({"validFrom": json.loads(line)}, "validFrom", "issuanceDate")',
    '        print(json.dumps((bound - EPOCH) // timedelta(milliseconds=1)))',
    '    except ValueError:',
    '        print("null")',
  ].join('\n');
  const output = execFileSync(command, [...args, '-I', '-B', '-c', reader, HERE], {
    input: bounds.map((bound) => JSON.stringify(bound)).join('\n') + '\n', encoding: 'utf8',
  });
  return output.trim().split('\n').map((line) => JSON.parse(line) as number | null);
}

describe("the Python reader of a status list's validity window", () => {
  it('reads each bound as the instant the TypeScript reference reads, or refuses it as the reference does', { timeout: PYTHON_TEST_TIMEOUT_MS }, (context) => {
    const read = pythonInstants(requirePython(context), BOUNDS);

    expect(BOUNDS.map((bound, i) => ({ bound, python: read[i] })))
      .toEqual(BOUNDS.map((bound) => ({ bound, python: parseDateTime(bound) ?? null })));
  });
});
