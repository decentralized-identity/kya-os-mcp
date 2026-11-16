/**
 * The Python interpreter for the tests that run the suite's Python verifier (`conformance/verify.py`)
 * and its status-list reader. CI runs `pnpm test` on Ubuntu, macOS and Windows without installing
 * Python, and Windows names it `python` or `py -3` more often than `python3`, so each candidate is
 * asked for its version and the first that runs Python 3.9 or later is used: `verify.py` subscripts
 * `list` in annotations Python evaluates on import, which Python 3.8 cannot.
 */

import { spawnSync } from 'node:child_process';

/** A command and the arguments that come before the script's own. */
export type Interpreter = readonly [command: string, ...args: string[]];

export type PythonSearch = { readonly found: Interpreter } | { readonly reason: string };

export const PYTHON_CANDIDATES: readonly Interpreter[] = [['python3'], ['python'], ['py', '-3']];

const MINIMUM_MINOR = 9;
const VERSION_PROBE = 'import sys; print("%d.%d" % sys.version_info[:2])';

/** The first candidate that runs Python 3.9 or later, or why each candidate will not do. */
export function findPython(candidates: readonly Interpreter[] = PYTHON_CANDIDATES): PythonSearch {
  const refusals: string[] = [];
  for (const candidate of candidates) {
    const [command, ...args] = candidate;
    const name = candidate.join(' ');
    const probe = spawnSync(command, [...args, '-c', VERSION_PROBE], { encoding: 'utf8', timeout: 30_000 });
    if (probe.status !== 0) {
      refusals.push(`${name} did not run`);
      continue;
    }
    const version = /^(\d+)\.(\d+)$/.exec(probe.stdout.trim());
    if (!version) {
      refusals.push(`${name} did not report a version`);
      continue;
    }
    if (Number(version[1]) === 3 && Number(version[2]) >= MINIMUM_MINOR) return { found: candidate };
    refusals.push(`${name} is Python ${version[1]}.${version[2]}`);
  }
  return { reason: `no Python 3.${MINIMUM_MINOR} or later found: ${refusals.join('; ')}` };
}

let search: PythonSearch | undefined;

/**
 * The interpreter for this test. When there is none, the test fails on CI, where a missing
 * interpreter would otherwise hide a broken verifier, and is skipped, with the reason, elsewhere.
 */
export function requirePython(
  context: { skip: (note: string) => never },
  result: PythonSearch = (search ??= findPython()),
  env: NodeJS.ProcessEnv = process.env,
): Interpreter {
  if ('found' in result) return result.found;
  if (env.CI) throw new Error(`${result.reason}, and CI must provide one`);
  return context.skip(result.reason);
}
