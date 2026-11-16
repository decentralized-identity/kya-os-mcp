#!/usr/bin/env node
/**
 * Run the adopter fixtures against the library as npm would publish it.
 *
 *   node adopters/run.mjs [--keep] [--no-build] [fixture ...]
 *
 * It builds the library, packs it into a fresh temporary directory, installs the tarball into a new
 * project there, type-checks and compiles the fixtures against the installed package, runs each with
 * plain `node`, prints a summary, and removes the directory. It exits 1 when a fixture fails or has a
 * type error. `--keep` keeps the directory, `--no-build` packs the `dist/` already built, and naming
 * fixtures runs only those.
 */
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compileFixtures } from './runner/compile.mjs';
import { runFixture } from './runner/execute.mjs';
import { buildAndPack, createProject, fixtureNames } from './runner/project.mjs';
import { printSummary } from './runner/report.mjs';

/** How long one fixture may run, its production child included. */
const FIXTURE_TIMEOUT_MS = 60_000;

const adoptersDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = dirname(adoptersDir);

/** The options and fixture names on the command line. */
function parseArguments(argv) {
  const flags = new Set(argv.filter((arg) => arg.startsWith('--')));
  for (const flag of flags) {
    if (flag !== '--keep' && flag !== '--no-build') throw new Error(`unknown option ${flag}`);
  }
  const all = fixtureNames(join(adoptersDir, 'fixtures'));
  const named = argv.filter((arg) => !arg.startsWith('--'));
  for (const name of named) {
    if (!all.includes(name)) throw new Error(`no fixture named ${name}; there are ${all.join(', ')}`);
  }
  return { keep: flags.has('--keep'), build: !flags.has('--no-build'), fixtures: named.length > 0 ? named : all };
}

/** The type errors that concern `fixtures`: their own, and those of the shared helpers and the project. */
function concerning(typeErrors, fixtures) {
  return new Map([...typeErrors].filter(([owner]) => owner === 'shared' || owner === 'project' || fixtures.includes(owner)));
}

/** Run `work`, printing `label` and how long it took. */
async function step(label, work) {
  const started = Date.now();
  process.stdout.write(`${label} ... `);
  const value = await work();
  console.log(`${((Date.now() - started) / 1000).toFixed(1)} s`);
  return value;
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const workDir = mkdtempSync(join(tmpdir(), 'kya-os-adopters-'));
  const projectDir = join(workDir, 'project');
  mkdirSync(projectDir);
  try {
    const packed = await step(options.build ? 'Building and packing the library' : 'Packing the library', () =>
      buildAndPack(repoRoot, workDir, { build: options.build }),
    );
    await step('Installing the tarball into a new project', () =>
      createProject({ repoRoot, adoptersDir, projectDir, tarball: packed.tarball, libraryName: packed.name }),
    );
    const typeErrors = await step('Type-checking and compiling the fixtures', () => compileFixtures(projectDir));
    const results = [];
    for (const name of options.fixtures) {
      results.push(await step(`Running ${name}`, () => runFixture(projectDir, name, FIXTURE_TIMEOUT_MS)));
    }
    return printSummary({ library: `${packed.name}@${packed.version}`, results, typeErrors: concerning(typeErrors, options.fixtures) });
  } finally {
    if (options.keep) console.log(`\nKept ${workDir}`);
    else rmSync(workDir, { recursive: true, force: true });
  }
}

main().then(
  (passed) => {
    process.exitCode = passed ? 0 : 1;
  },
  (error) => {
    console.error(`\n${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  },
);
