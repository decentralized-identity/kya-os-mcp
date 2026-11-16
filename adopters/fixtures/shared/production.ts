/**
 * A check that something refuses to be built under `NODE_ENV=production`. The fixture runs its own
 * compiled file again in a child process whose environment says production, so the variable never
 * leaks into the fixture's other cases, and the child reports, in one line, whether building threw.
 */
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

/** The argument that tells a fixture's file it runs as that child. */
const CHILD_ARGUMENT = '--build-in-production';
/** What starts the child's one line of report. */
const REPORT_PREFIX = 'production-build: ';

/** What the child saw when it built the thing under test. */
export interface ProductionBuild {
  threw: boolean;
  /** The message of what was thrown, or empty when nothing was. */
  message: string;
}

/** Whether this process is the child a fixture started to build something under `NODE_ENV=production`. */
export function isProductionChild(): boolean {
  return process.argv.includes(CHILD_ARGUMENT);
}

/** In the child: run `build`, print whether it threw, and exit. */
export async function reportProductionBuild(build: () => unknown): Promise<void> {
  let report: ProductionBuild = { threw: false, message: '' };
  try {
    await build();
  } catch (error) {
    report = { threw: true, message: error instanceof Error ? error.message : String(error) };
  }
  process.stdout.write(`${REPORT_PREFIX}${JSON.stringify(report)}\n`, () => process.exit(0));
}

/**
 * In the fixture: run the fixture's own file, named by its `import.meta.url`, as the child with
 * `NODE_ENV=production`, and return what it reported. Throws when the child reports nothing.
 */
export function buildInProduction(fixtureUrl: string): ProductionBuild {
  const child = spawnSync(process.execPath, [fileURLToPath(fixtureUrl), CHILD_ARGUMENT], {
    env: { ...process.env, NODE_ENV: 'production' },
    encoding: 'utf8',
    timeout: 30_000,
  });
  const line = child.stdout.split('\n').find((text) => text.startsWith(REPORT_PREFIX));
  if (line === undefined) {
    const said = `${child.stderr}`.trim().split('\n')[0] ?? '';
    throw new Error(`the production child reported nothing (exit ${String(child.status)}): ${said}`);
  }
  return JSON.parse(line.slice(REPORT_PREFIX.length)) as ProductionBuild;
}
