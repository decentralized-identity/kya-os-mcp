/**
 * Running one compiled fixture with plain `node`, as an adopter runs its app, and reading its verdict
 * from the lines it prints: `PASS <fixture>: ...`, or one `FAIL <fixture>: ...` line per failed case.
 */
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { run } from './exec.mjs';

/** The line that best says why a fixture that printed no `FAIL` line still failed. */
function crashLine(result) {
  const lines = result.stderr.split('\n').map((line) => line.trim()).filter(Boolean);
  const error = lines.find((line) => /^\w*Error\b|^error\b/i.test(line)) ?? lines.at(-1);
  return `exited ${result.code ?? result.signal}${error ? `: ${error}` : ' without a verdict'}`;
}

/**
 * Run the fixture `name` in `projectDir`, without `NODE_ENV`, for at most `timeoutMs`. Resolves with
 * whether it passed, the lines it printed for its verdict, and the first line that says why it failed.
 */
export async function runFixture(projectDir, name, timeoutMs) {
  const entry = join(projectDir, 'dist', `${name}.js`);
  if (!existsSync(entry)) {
    return { name, passed: false, failures: [], firstFailure: 'tsc emitted no JavaScript for it', durationMs: 0 };
  }
  const env = { ...process.env };
  delete env.NODE_ENV;
  const started = Date.now();
  const result = await run(process.execPath, [entry], { cwd: projectDir, env, timeoutMs });
  const durationMs = Date.now() - started;
  const lines = result.stdout.split('\n');
  const passLine = lines.find((line) => line.startsWith(`PASS ${name}: `));
  const failures = lines.filter((line) => line.startsWith(`FAIL ${name}: `));
  const passed = !result.timedOut && result.code === 0 && passLine !== undefined && failures.length === 0;
  let firstFailure;
  if (result.timedOut) firstFailure = `timed out after ${timeoutMs / 1000} s`;
  else if (!passed) firstFailure = failures[0] ?? crashLine(result);
  return { name, passed, passLine, failures, firstFailure, durationMs };
}
