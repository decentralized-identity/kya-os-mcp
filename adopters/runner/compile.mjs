/**
 * Type-checking and compiling the fixtures against the installed package. One `tsc` run does both:
 * it emits even when a fixture has type errors, so each fixture still runs and shows what the
 * library does at runtime, and its diagnostics are filed under the fixture they are in.
 */
import { join } from 'node:path';
import { run } from './exec.mjs';

/** A diagnostic's first line: `src/<file>.ts(<line>,<column>): error TS<n>: <message>`. */
const DIAGNOSTIC = /^(?<file>[^(]+)\(\d+,\d+\): error TS\d+: /;

/**
 * Who a diagnostic in `file` belongs to: the fixture whose file it is, `shared` for the helpers
 * every fixture imports, and `project` for anything else, such as the configuration.
 */
function ownerOf(file) {
  const path = file.replaceAll('\\', '/');
  if (path.startsWith('src/shared/')) return 'shared';
  const match = /^src\/([^/]+)\.ts$/.exec(path);
  return match?.[1] ?? 'project';
}

/**
 * Compile the project in `projectDir`. Resolves with its type errors by owner, each the whole
 * diagnostic with any lines that continue it.
 */
export async function compileFixtures(projectDir) {
  const tsc = join(projectDir, 'node_modules', 'typescript', 'bin', 'tsc');
  const { stdout, stderr } = await run(process.execPath, [tsc, '-p', 'tsconfig.json', '--pretty', 'false'], { cwd: projectDir });
  const errors = new Map();
  let current;
  for (const line of `${stdout}\n${stderr}`.split('\n')) {
    if (line.trim() === '') continue;
    const match = DIAGNOSTIC.exec(line);
    if (match) {
      current = { owner: ownerOf(match.groups.file), text: line };
      errors.set(current.owner, [...(errors.get(current.owner) ?? []), current]);
    } else if (current !== undefined && /^\s/.test(line)) {
      current.text += `\n${line}`;
    } else {
      current = { owner: 'project', text: line };
      errors.set('project', [...(errors.get('project') ?? []), current]);
    }
  }
  return new Map([...errors].map(([owner, list]) => [owner, list.map((error) => error.text)]));
}
