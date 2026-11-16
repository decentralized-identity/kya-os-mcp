/**
 * The adopter project: the library built and packed as npm would publish it, and a fresh project
 * beside it that installs the tarball, as an adopter's app installs the package.
 */
import { cpSync, existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { NPM, runOrThrow } from './exec.mjs';

/**
 * Build the library in `repoRoot` (unless `build` is false) and pack it into `destination`.
 * Resolves with the tarball's path, and the name and version it was packed as.
 */
export async function buildAndPack(repoRoot, destination, { build = true } = {}) {
  if (build) await runOrThrow(NPM, ['run', '--silent', 'build'], { cwd: repoRoot });
  const { stdout } = await runOrThrow(NPM, ['pack', '--json', '--pack-destination', destination], { cwd: repoRoot });
  const [packed] = JSON.parse(stdout.slice(stdout.indexOf('[')));
  return { tarball: join(destination, packed.filename), name: packed.name, version: packed.version };
}

/**
 * The version of `name` the repository has installed, so the adopter project compiles with the
 * same TypeScript and types; the range `package.json` declares when it is not installed.
 */
function repositoryVersion(repoRoot, name) {
  const installed = join(repoRoot, 'node_modules', name, 'package.json');
  if (existsSync(installed)) return JSON.parse(readFileSync(installed, 'utf8')).version;
  const manifest = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf8'));
  const declared = manifest.devDependencies?.[name] ?? manifest.dependencies?.[name];
  if (declared === undefined) throw new Error(`the repository declares no version of ${name}`);
  return declared;
}

/** The fixtures in `fixturesDir`: one program per top-level `.ts` file, named by the file. */
export function fixtureNames(fixturesDir) {
  return readdirSync(fixturesDir)
    .filter((file) => file.endsWith('.ts'))
    .map((file) => file.slice(0, -'.ts'.length))
    .sort();
}

/**
 * Write the adopter project into `projectDir` and install it: the fixtures under `src/`, the
 * adopter's `tsconfig.json`, and a `package.json` that depends on the tarball and on what the
 * fixtures import beside it.
 */
export async function createProject({ repoRoot, adoptersDir, projectDir, tarball, libraryName }) {
  cpSync(join(adoptersDir, 'fixtures'), join(projectDir, 'src'), {
    recursive: true,
    filter: (source) => !source.endsWith('.js') && !source.endsWith('.map'),
  });
  cpSync(join(adoptersDir, 'tsconfig.json'), join(projectDir, 'tsconfig.json'));
  const manifest = {
    name: 'kya-os-adopter-fixtures',
    private: true,
    type: 'module',
    dependencies: {
      [libraryName]: `file:${tarball}`,
      '@modelcontextprotocol/sdk': repositoryVersion(repoRoot, '@modelcontextprotocol/sdk'),
    },
    devDependencies: {
      typescript: repositoryVersion(repoRoot, 'typescript'),
      '@types/node': repositoryVersion(repoRoot, '@types/node'),
    },
  };
  writeFileSync(join(projectDir, 'package.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  await runOrThrow(NPM, ['install', '--no-audit', '--no-fund', '--loglevel=error'], { cwd: projectDir });
  return manifest;
}
