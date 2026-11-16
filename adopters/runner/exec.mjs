/**
 * Running a command and keeping what it printed.
 */
import { spawn } from 'node:child_process';

/** The npm executable, which Windows names with its extension. */
export const NPM = process.platform === 'win32' ? 'npm.cmd' : 'npm';

/**
 * Run `command` with `args` and resolve with its exit code, the signal that ended it, its output,
 * and whether it was killed for running longer than `timeoutMs`. Never rejects on a non-zero exit.
 */
export function run(command, args, { cwd, env, timeoutMs } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      env: env ?? process.env,
      shell: process.platform === 'win32',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    child.stdout.setEncoding('utf8').on('data', (chunk) => (stdout += chunk));
    child.stderr.setEncoding('utf8').on('data', (chunk) => (stderr += chunk));
    const timer =
      timeoutMs === undefined
        ? undefined
        : setTimeout(() => {
            timedOut = true;
            child.kill('SIGKILL');
          }, timeoutMs);
    child.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal, stdout, stderr, timedOut });
    });
  });
}

/** As {@link run}, but rejects with the command and what it printed when it does not exit 0. */
export async function runOrThrow(command, args, options = {}) {
  const result = await run(command, args, options);
  if (result.code !== 0) {
    const said = `${result.stdout}\n${result.stderr}`.trim();
    throw new Error(`${command} ${args.join(' ')} exited ${result.code ?? result.signal}:\n${said}`);
  }
  return result;
}
