#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import type { JWK } from 'jose';
import { CryptoProviderAuditHasher } from './crypto.js';
import { CompactJwsAuditSignatureVerifier } from './crypto.js';
import { verifyAuditBundle } from './replay-bundle.js';
import { parseAuditVerificationPolicy } from './schemas.js';
import type {
  AuditReplayBundleV1,
  AuditVerificationPolicyV1,
  SignerRef,
} from './types.js';
import { NodeCryptoProvider } from '../providers/node-crypto.js';
import { z } from 'zod';

interface AuditCliKeyFile {
  keys: Array<{ kid: string; jwk: JWK }>;
}

const auditCliKeyFileSchema: z.ZodType<AuditCliKeyFile> = z.object({
  keys: z.array(z.object({
    kid: z.string().min(1).max(2304),
    jwk: z.record(z.string(), z.unknown()),
  }).strict()).max(10_000),
}).strict().superRefine((value, context) => {
  const kids = value.keys.map((item) => item.kid);
  if (new Set(kids).size !== kids.length) {
    context.addIssue({ code: 'custom', path: ['keys'], message: 'Key IDs must be unique' });
  }
  for (const [index, item] of value.keys.entries()) {
    if (typeof item.jwk['kid'] === 'string' && item.jwk['kid'] !== item.kid) {
      context.addIssue({
        code: 'custom',
        path: ['keys', index, 'jwk', 'kid'],
        message: 'JWK kid must match the key-file kid',
      });
    }
  }
});

export interface AuditCliIo {
  readText(path: string): Promise<string>;
  write(text: string): void;
  writeError(text: string): void;
}

const defaultIo: AuditCliIo = {
  readText: (path) => readFile(path, 'utf8'),
  write: (text) => process.stdout.write(text),
  writeError: (text) => process.stderr.write(text),
};

const usage = 'Usage: kya-audit verify <bundle.json> --policy <policy.json> --keys <keys.json>\n';

function option(args: readonly string[], name: string): string | undefined {
  const index = args.indexOf(name);
  if (index < 0 || args.indexOf(name, index + 1) >= 0) return undefined;
  const value = args[index + 1];
  return value === undefined || value.startsWith('-') ? undefined : value;
}

export async function runAuditCli(
  args: readonly string[],
  io: AuditCliIo = defaultIo,
): Promise<number> {
  if (args[0] === '--help' || args[0] === '-h' || args[0] === 'help') {
    io.write(usage);
    return 0;
  }
  if (args[0] !== 'verify' || args[1] === undefined) {
    io.writeError(usage);
    return 2;
  }
  const policyPath = option(args, '--policy');
  const keysPath = option(args, '--keys');
  if (policyPath === undefined || keysPath === undefined) {
    io.writeError('Both --policy and --keys are required; bundle contents cannot bootstrap trust.\n');
    return 2;
  }

  try {
    const [bundle, policy, keyFile] = await Promise.all([
      io.readText(args[1]).then((value) => JSON.parse(value) as AuditReplayBundleV1),
      io.readText(policyPath).then((value) =>
        parseAuditVerificationPolicy(JSON.parse(value)) as AuditVerificationPolicyV1),
      io.readText(keysPath).then((value) => auditCliKeyFileSchema.parse(JSON.parse(value))),
    ]);
    const keys = new Map(keyFile.keys.map((item) => [item.kid, item.jwk]));
    const signatures = new CompactJwsAuditSignatureVerifier({
      async resolve(signer: SignerRef): Promise<JWK | null> {
        return keys.get(signer.kid) ?? null;
      },
    });
    const report = await verifyAuditBundle(bundle, policy, {
      hasher: new CryptoProviderAuditHasher(new NodeCryptoProvider()),
      signatures,
    });
    io.write(`${JSON.stringify(report, null, 2)}\n`);
    const dimensions = Object.values(report).filter((value): value is {
      verdict: string;
      reasonCodes: string[];
    } => typeof value === 'object' && value !== null && 'verdict' in value);
    return dimensions.some((dimension) => dimension.verdict === 'invalid') ? 1 : 0;
  } catch (error) {
    io.writeError(`Audit verification failed: ${error instanceof Error ? error.message : String(error)}\n`);
    return 2;
  }
}

if (process.argv[1]?.endsWith('/audit/cli.js') || process.argv[1]?.endsWith('\\audit\\cli.js')) {
  process.exitCode = await runAuditCli(process.argv.slice(2));
}
