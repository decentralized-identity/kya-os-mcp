import { describe, expect, it } from 'vitest';
import { runAuditCli } from '../cli.js';

describe('audit CLI', () => {
  it('prints help to stdout and exits successfully', async () => {
    const output: string[] = [];
    const exit = await runAuditCli(['--help'], {
      readText: async () => '{}',
      write: (text) => output.push(text),
      writeError: () => undefined,
    });
    expect(exit).toBe(0);
    expect(output.join('')).toContain('kya-audit verify');
  });

  it('requires trust policy and key material outside the bundle', async () => {
    const errors: string[] = [];
    const exit = await runAuditCli(['verify', 'bundle.json'], {
      readText: async () => '{}',
      write: () => undefined,
      writeError: (text) => errors.push(text),
    });
    expect(exit).toBe(2);
    expect(errors.join('')).toMatch(/cannot bootstrap trust/i);
  });

  it('prints usage for an unknown command', async () => {
    const errors: string[] = [];
    expect(await runAuditCli([], {
      readText: async () => '{}',
      write: () => undefined,
      writeError: (text) => errors.push(text),
    })).toBe(2);
    expect(errors.join('')).toContain('kya-audit verify');
  });
});
