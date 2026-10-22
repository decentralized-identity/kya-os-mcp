import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

/** Node canonicalizes a module URL's symlinks; canonicalize argv the same way. */
export function isMainModule(moduleUrl: string, entrypoint = process.argv[1]): boolean {
  if (!entrypoint) return false;
  try {
    return realpathSync(entrypoint) === realpathSync(fileURLToPath(moduleUrl));
  } catch {
    return false;
  }
}
