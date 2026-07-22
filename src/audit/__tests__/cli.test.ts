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

  it('does not consume another option as a missing option value', async () => {
    const errors: string[] = [];
    const reads: string[] = [];
    const exit = await runAuditCli(
      ['verify', 'bundle.json', '--policy', '--keys', 'keys.json'],
      {
        readText: async (path) => { reads.push(path); return '{}'; },
        write: () => undefined,
        writeError: (text) => errors.push(text),
      },
    );
    expect(exit).toBe(2);
    expect(reads).toEqual([]);
    expect(errors.join('')).toMatch(/both --policy and --keys are required/i);
  });

  it('validates key-file shape and rejects duplicate or mismatched key IDs', async () => {
    const errors: string[] = [];
    const policy = {
      policyId: 'policy', trustedLedgerEpochs: [], trustedObservers: [],
      authorizedExporters: [], acceptedIntegritySuites: ['suite'],
      acceptedAlgorithms: ['EdDSA'], keyRevocationMode: 'as_observed',
    };
    const exit = await runAuditCli(
      ['verify', 'bundle.json', '--policy', 'policy.json', '--keys', 'keys.json'],
      {
        readText: async (path) => path === 'policy.json'
          ? JSON.stringify(policy)
          : path === 'keys.json'
            ? JSON.stringify({ keys: [{ kid: 'did:key:zA#1', jwk: { kid: 'different' } }] })
            : '{}',
        write: () => undefined,
        writeError: (text) => errors.push(text),
      },
    );
    expect(exit).toBe(2);
    expect(errors.join('')).toMatch(/JWK kid must match/i);
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
