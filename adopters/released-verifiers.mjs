#!/usr/bin/env node
/**
 * Show that the verifiers of released versions accept the proofs this version signs.
 *
 *   node adopters/released-verifiers.mjs [--keep] [--no-build] [version ...]
 *
 * A request proof now states its delegation in its JWS protected header (SPEC.md §7.8), and a
 * server that has not upgraded must go on verifying it. This builds and packs the library, installs
 * the tarball and each released version named into projects of their own in a fresh temporary
 * directory, makes session request proofs and card proofs with this version, and has every
 * installed version verify them: one made without the statement, as the control, one as the
 * generator signs it, which must have the control's verdict, and that one with its statement
 * swapped and stripped after signing, which each verifier must refuse. It prints both tables and
 * exits 1 when a verdict is not the expected one.
 *
 * With no version named it measures 1.11.0, 1.16.0, 1.22.0 and 1.25.0. A run reads the npm registry
 * for the installs, and no other network. It is a measurement to run by hand before a release that
 * changes what a proof carries, and is not part of `pnpm test` or of CI.
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { NPM, runOrThrow } from './runner/exec.mjs';
import { buildAndPack } from './runner/project.mjs';
import { CARD_VERDICTS, SESSION_VERDICTS, cardProofRow, installedLibrary, printRows, sessionProofRow } from './runner/released.mjs';

/** The released versions measured when none is named: the oldest in use, and one from each line since. */
const DEFAULT_VERSIONS = ['1.11.0', '1.16.0', '1.22.0', '1.25.0'];

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));

/** The options and versions on the command line. */
function parseArguments(argv) {
  const flags = new Set(argv.filter((arg) => arg.startsWith('--')));
  for (const flag of flags) {
    if (flag !== '--keep' && flag !== '--no-build') throw new Error(`unknown option ${flag}`);
  }
  const named = argv.filter((arg) => !arg.startsWith('--'));
  for (const version of named) {
    if (!/^\d+\.\d+\.\d+$/.test(version)) throw new Error(`${version} is not a released version, such as 1.25.0`);
  }
  return { keep: flags.has('--keep'), build: !flags.has('--no-build'), versions: named.length > 0 ? named : DEFAULT_VERSIONS };
}

/** A new project in `projectDir` that depends on `name` at `source`, installed. */
async function install(projectDir, name, source) {
  mkdirSync(projectDir, { recursive: true });
  const manifest = { name: 'kya-os-released-verifier', private: true, type: 'module', dependencies: { [name]: source } };
  writeFileSync(join(projectDir, 'package.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  await runOrThrow(NPM, ['install', '--no-audit', '--no-fund', '--loglevel=error'], { cwd: projectDir });
  return installedLibrary(projectDir, name);
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const workDir = mkdtempSync(join(tmpdir(), 'kya-os-released-'));
  try {
    console.log(options.build ? 'Building and packing the library ...' : 'Packing the library ...');
    const packed = await buildAndPack(repoRoot, workDir, { build: options.build });
    console.log(`Installing ${packed.name}@${packed.version} and ${options.versions.join(', ')} ...`);
    const current = await install(join(workDir, 'current'), packed.name, `file:${packed.tarball}`);
    const verifiers = { [`${packed.version}*`]: current };
    for (const version of options.versions) verifiers[version] = await install(join(workDir, version), packed.name, version);

    const session = {};
    const card = {};
    for (const [version, verifier] of Object.entries(verifiers)) {
      session[version] = await sessionProofRow(current.main, verifier.main);
      card[version] = verifier.card === undefined ? 'this version has no card profile' : await cardProofRow(current.card, verifier.card);
    }
    const made = `${packed.name}@${packed.version} on Node ${process.version}`;
    const results = [
      printRows(`Session request proof made by ${made}, verified by assertHolderBinding of each version`, session, SESSION_VERDICTS),
      printRows(`Card proof made by ${made}, verified by verifyCardProof of each version`, card, CARD_VERDICTS),
    ];
    console.log('\n* this version, packed and installed as the others are.');
    const passed = results.every(Boolean);
    console.log(
      passed
        ? 'Every verifier gives a proof that states its delegation the verdict it gives the same proof without the statement, and refuses a statement changed after signing.'
        : 'A verdict is not the expected one.',
    );
    return passed;
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
