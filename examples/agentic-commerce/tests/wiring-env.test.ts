import { afterEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const directories: string[] = [];
afterEach(() => directories.splice(0).forEach(directory => fs.rmSync(directory, { recursive: true, force: true })));
describe('storage configuration initialization', () => {
  it('loads file-based storage directories before exporting paths, while deployment environment takes precedence', async () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'commerce-wiring-')); directories.push(directory);
    const file = path.join(directory, '.env');
    const variableDirectory = path.join(directory, 'file-var'), dataDirectory = path.join(directory, 'file-data');
    fs.writeFileSync(file, `DEMO_VAR_DIR=${variableDirectory}\nDEMO_DATA_DIR=${dataDirectory}\n`);
    const environment: NodeJS.ProcessEnv = { ...process.env, DEMO_ENV_FILE: file };
    delete environment['DEMO_VAR_DIR']; delete environment['DEMO_DATA_DIR'];
    const script = `const wiring = await import(${JSON.stringify(new URL('../src/lib/wiring.ts', import.meta.url).href)}); process.stdout.write(JSON.stringify({var: wiring.VAR_DIR, data: wiring.DATA_DIR}));`;
    const run = async (env: NodeJS.ProcessEnv) => JSON.parse((await promisify(execFile)(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', script], {
      cwd: fileURLToPath(new URL('..', import.meta.url)), env,
    })).stdout);
    expect(await run(environment)).toEqual({ var: variableDirectory, data: dataDirectory });
    expect(await run({ ...environment, DEMO_VAR_DIR: path.join(directory, 'deployment-var') })).toEqual({ var: path.join(directory, 'deployment-var'), data: dataDirectory });
  });
});
