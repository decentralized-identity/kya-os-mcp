/**
 * How a fixture reports. It runs every case, each whether or not one before it failed, so a run
 * shows every way the library lets the adopter down, then prints one line: `PASS` with what the
 * fixture showed, or one `FAIL` line for each case that failed. The runner reads these lines.
 */

/** One thing a fixture checks: a name a person can read, and a function that throws when it does not hold. */
export interface Case {
  name: string;
  run: () => Promise<void> | void;
}

/** The first line of what `error` says, without the stack. */
function firstLine(error: unknown): string {
  const text = error instanceof Error ? error.message : String(error);
  return text.split('\n')[0] ?? '';
}

/** Write `text` and exit with `code` once it is written, so the line is never lost to an early exit. */
function writeAndExit(text: string, code: number): void {
  process.stdout.write(text, () => process.exit(code));
}

/**
 * Run `cases` in order for the fixture `fixture`, then print its line and exit: 0 when every case
 * held, 1 otherwise. `showed` says what a passing run showed.
 */
export async function runCases(fixture: string, showed: string, cases: readonly Case[]): Promise<void> {
  const failures: string[] = [];
  for (const { name, run } of cases) {
    try {
      await run();
    } catch (error) {
      failures.push(`FAIL ${fixture}: ${name}: ${firstLine(error)}`);
    }
  }
  if (failures.length === 0) {
    writeAndExit(`PASS ${fixture}: ${showed}\n`, 0);
  } else {
    writeAndExit(`${failures.join('\n')}\n`, 1);
  }
}
