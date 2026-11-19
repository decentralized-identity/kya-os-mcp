/**
 * What the operator's log is told while a test acts: every line `logger.warn` was given, each call's
 * arguments joined by a space, in order. A refusal that withholds what a host answered from whoever
 * presented the request logs it there instead, so a test reads the detail it expects from here.
 */

import { vi } from 'vitest';
import { logger } from '../../logging/index.js';

/** `act`'s result, and every line `logger.warn` was given while it ran, joined by a line break. */
export async function withWarnings<T>(act: () => Promise<T>): Promise<{ result: T; logged: string }> {
  const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
  try {
    const result = await act();
    return { result, logged: warn.mock.calls.map((call) => call.map(String).join(' ')).join('\n') };
  } finally {
    warn.mockRestore();
  }
}
