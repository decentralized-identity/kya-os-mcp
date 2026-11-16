import { describe, expect, it, vi } from 'vitest';
import { findPython, PYTHON_CANDIDATES, requirePython, type Interpreter } from './python.js';

/** An interpreter that answers the version probe with `version`, whatever it is asked to run. */
const reporting = (version: string): Interpreter => [process.execPath, '-e', `console.log(${JSON.stringify(version)})`, '--'];
const missing: Interpreter = ['kya-os-no-such-python'];
/** An interpreter that answers the version probe with 3.10 and then exits with an error. */
const failing: Interpreter = [process.execPath, '-e', 'console.log("3.10"); process.exit(9)', '--'];

// Each search below starts a process for every candidate, as the other process-spawning tests do, so
// each has the same explicit timeout: a loaded runner must not fail it on the default 5 s.
describe('findPython', () => {
  it('tries python3, then python, then py -3', () => {
    expect(PYTHON_CANDIDATES).toEqual([['python3'], ['python'], ['py', '-3']]);
  });

  it('takes the first candidate that runs Python 3.9 or later', () => {
    expect(findPython([missing, reporting('2.7'), reporting('3.8'), reporting('3.10'), reporting('3.9')]))
      .toEqual({ found: reporting('3.10') });
    expect(findPython([reporting('3.9'), reporting('3.12')])).toEqual({ found: reporting('3.9') });
  }, 60_000);

  it('names every candidate it tried and why it will not do when none will', () => {
    const search = findPython([
      missing, failing, reporting('2.7'), reporting('2.10'), reporting('3.8'), reporting('4.10'), reporting('not a version'),
    ]);
    expect(search).toEqual({
      reason:
        `no Python 3.9 or later found: kya-os-no-such-python did not run; ${failing.join(' ')} did not run; ` +
        `${reporting('2.7').join(' ')} is Python 2.7; ${reporting('2.10').join(' ')} is Python 2.10; ` +
        `${reporting('3.8').join(' ')} is Python 3.8; ${reporting('4.10').join(' ')} is Python 4.10; ` +
        `${reporting('not a version').join(' ')} did not report a version`,
    });
  }, 60_000);
});

describe('requirePython', () => {
  const context = () => ({ skip: vi.fn((note: string): never => { throw new Error(`skipped: ${note}`); }) });

  it('returns the interpreter found, on CI or not', () => {
    for (const env of [{}, { CI: 'true' }]) {
      const test = context();
      expect(requirePython(test, { found: ['python', '-X', 'utf8'] }, env)).toEqual(['python', '-X', 'utf8']);
      expect(test.skip).not.toHaveBeenCalled();
    }
  });

  it('skips the test, stating the reason, when none is found outside CI', () => {
    const test = context();
    expect(() => requirePython(test, { reason: 'no Python 3.9 or later found: python3 did not run' }, {}))
      .toThrow('skipped: no Python 3.9 or later found: python3 did not run');
    expect(test.skip).toHaveBeenCalledOnce();
  });

  it('fails the test, stating the reason, when none is found on CI', () => {
    const test = context();
    expect(() => requirePython(test, { reason: 'no Python 3.9 or later found: python3 did not run' }, { CI: 'true' }))
      .toThrow('no Python 3.9 or later found: python3 did not run, and CI must provide one');
    expect(test.skip).not.toHaveBeenCalled();
  });
});
