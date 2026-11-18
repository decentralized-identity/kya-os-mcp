/**
 * A warning given once per process: the first time a setup the library still accepts, but should
 * not, is used, rather than on every call.
 */

import { logger } from '../logging/index.js';

/**
 * Log `message` through `logger.warn` unless a warning was already given for `key` in this
 * process. The record is kept on `globalThis`, so every copy of the package a process loads shares
 * it, when `key` is a `Symbol.for` key.
 *
 * `message` is logged as written, with nothing beside it, so a caller that passes fixed text gives
 * a log line no one else can write into.
 */
export function warnOncePerProcess(key: symbol, message: string): void {
  const registry = globalThis as { [key: symbol]: true | undefined };
  if (registry[key]) return;
  registry[key] = true;
  logger.warn(message);
}
