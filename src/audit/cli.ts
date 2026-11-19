#!/usr/bin/env node
import { realpathSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import type { JWK } from 'jose';
import { CryptoProviderAuditHasher } from './crypto.js';
import { CompactJwsAuditSignatureVerifier } from './crypto.js';
import { verifyAuditBundle } from './replay-bundle.js';
import { auditVerificationPolicySchema, parseAuditVerificationPolicy } from './schemas.js';
import { AuditArtifactVerifier } from './verifier.js';
import type { SignerRef } from './types.js';
import { NodeCryptoProvider } from '../providers/node-crypto.js';
import { sanitizeForMessage } from '../utils/message-text.js';
import * as z from 'zod';

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

/** The most UTF-16 code units of a failure the CLI prints. */
const MAX_FAILURE_LENGTH = 1024;

/**
 * The JSON in the file at `path`. A file that is not JSON is reported in fixed
 * words: the parser's message quotes the bytes around the error, and a bundle
 * is a stranger's file, so those bytes never reach the terminal.
 */
async function readJson(io: AuditCliIo, path: string): Promise<unknown> {
  let text: string;
  try {
    text = await io.readText(path);
  } catch (error) {
    throw new Error(`${path} could not be read: ${messageOf(error)}`);
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new Error(`${path} is not valid JSON`);
  }
}

/** `value` as `schema` reads it, or a refusal said on one line as `<path> is not a valid <what>`. */
function validAs<T>(path: string, what: string, schema: z.ZodType<T>, value: unknown): T {
  const result = schema.safeParse(value);
  if (result.success) return result.data;
  const issues = result.error.issues.map((issue) =>
    issue.path.length === 0 ? issue.message : `${issue.path.join('.')}: ${issue.message}`);
  throw new Error(`${path} is not a valid ${what}: ${issues.join('; ')}`);
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

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
      readJson(io, args[1]),
      readJson(io, policyPath).then((value) => parseAuditVerificationPolicy(
        validAs(policyPath, 'verification policy', auditVerificationPolicySchema, value))),
      readJson(io, keysPath).then((value) =>
        validAs(keysPath, 'key file', auditCliKeyFileSchema, value)),
    ]);
    const keys = new Map(keyFile.keys.map((item) => [item.kid, item.jwk]));
    const signatures = new CompactJwsAuditSignatureVerifier({
      async resolve(signer: SignerRef): Promise<JWK | null> {
        return keys.get(signer.kid) ?? null;
      },
    });
    const hasher = new CryptoProviderAuditHasher(new NodeCryptoProvider());
    // The present time, so a policy's constraints that need it (keys that must
    // still be valid, how fresh an observation must be) are decided here and
    // not left `indeterminate` behind an exit code of 0. It is read once, so
    // every check of the run is made at the same instant.
    const verifiedAt = Date.now();
    const report = await verifyAuditBundle(bundle, policy, {
      hasher,
      signatures,
      artifacts: new AuditArtifactVerifier({ hasher, signatures, verifiedAt: () => verifiedAt }),
    });
    io.write(`${JSON.stringify(report, null, 2)}\n`);
    const dimensions = Object.values(report).filter((value): value is {
      verdict: string;
      reasonCodes: string[];
    } => typeof value === 'object' && value !== null && 'verdict' in value);
    return dimensions.some((dimension) => dimension.verdict === 'invalid') ? 1 : 0;
  } catch (error) {
    // Every message is printed free of control characters: a schema's refusal
    // quotes member names, and a file path or a dependency's error may hold any.
    io.writeError(
      `Audit verification failed: ${sanitizeForMessage(messageOf(error), MAX_FAILURE_LENGTH)}\n`,
    );
    return 2;
  }
}

// npm installs the bin as a node_modules/.bin/kya-audit symlink, so argv[1]
// names the link, not this file. Compare resolved paths instead of file names.
export function isEntryPoint(argvPath: string | undefined, moduleUrl: string): boolean {
  if (argvPath === undefined) return false;
  try {
    return realpathSync(argvPath) === realpathSync(fileURLToPath(moduleUrl));
  } catch {
    return false;
  }
}

if (isEntryPoint(process.argv[1], import.meta.url)) {
  process.exitCode = await runAuditCli(process.argv.slice(2));
}
