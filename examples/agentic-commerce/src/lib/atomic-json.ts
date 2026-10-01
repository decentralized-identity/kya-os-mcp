/** Readers in the separate agent, merchant and RP processes see a complete JSON
 * document or the previous version, never a partially written file. */
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';

export function writeJsonAtomic(file: string, value: unknown): void {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = `${file}.${randomUUID()}.tmp`;
  try {
    fs.writeFileSync(temporary, JSON.stringify(value, null, 2), { mode: 0o600 });
    fs.renameSync(temporary, file);
  } finally {
    fs.rmSync(temporary, { force: true });
  }
}
